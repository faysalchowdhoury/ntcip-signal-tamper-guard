"""Runtime invariant monitor and two-tier fail-safe.

Command checks can be evaded (a sequence of individually valid SETs, or a path that bypasses the guard),
so the monitor also watches what the controller actually displays, like a software conflict monitor:

* ``conflicting_greens``: greens on both sides of a barrier;
* ``short_yellow``: a served yellow shorter than the ITE requirement;
* ``starvation``: a phase with waiting vehicles not served for ``starvation_s``;
* ``rapid_cycling``: coordinated greens restarting faster than ``rapid_cycle_frac`` of the cycle;
* ``excessive_green``: a phase green for longer than ``excessive_green_s`` while conflicting calls wait.

Fail-safe response:

* **tier 1** (``restore``): clear all central control bits and restore the last known-good timing. This
  keeps the intersection operating and undoes most tampering.
* **tier 2** (``flash``): if alarms continue after a restore, or on a critical alarm, put the
  intersection in red flash until an operator resets it. Flash is safe but slow (all-way stop).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .controller import ControlledController
from .policy import GuardPolicy
from .vendor.ntcip_ctrl.timing.models import IntersectionTiming


@dataclass(frozen=True)
class Alarm:
    t: float
    kind: str
    phase: int | None
    severity: str
    detail: str


@dataclass
class RuntimeMonitor:
    ctl: ControlledController
    policy: GuardPolicy
    known_good: IntersectionTiming
    starvation_s: float = 240.0
    rapid_cycle_frac: float = 0.6
    excessive_green_s: float = 150.0
    escalate_after_restore_s: float = 300.0
    operator_response_s: float | None = 900.0
    fallback: bool = True
    alarms: list[Alarm] = field(default_factory=list)
    actions: list[tuple[float, str]] = field(default_factory=list)
    _prev: dict[int, str] = field(default_factory=dict)
    _y_start: dict[int, float] = field(default_factory=dict)
    _g_start: dict[int, float] = field(default_factory=dict)
    _wait_since: dict[int, float] = field(default_factory=dict)
    _last_coord_start: float | None = None
    _short_cycles: list[float] = field(default_factory=list)
    _last_restore: float | None = None
    _latched: set[tuple[str, int | None]] = field(default_factory=set)

    def _raise(self, t: float, kind: str, phase: int | None, severity: str, detail: str) -> None:
        key = (kind, phase)
        if key in self._latched:
            return
        self._latched.add(key)
        self.alarms.append(Alarm(t, kind, phase, severity, detail))
        if self.fallback:
            self._respond(t, severity)

    def _respond(self, t: float, severity: str) -> None:
        if self.ctl.flash or (self.actions and abs(self.actions[-1][0] - t) < 1e-6):
            return  # one response per tick
        recent_restore = (self._last_restore is not None
                          and 1.0 <= t - self._last_restore < self.escalate_after_restore_s)
        if severity == "critical" or recent_restore:
            self.ctl.enter_flash()
            self.actions.append((t, "flash"))
        else:
            self.ctl.bits.clear()
            self.ctl.update_timing(self.known_good)
            self._last_restore = t
            self.actions.append((t, "restore"))
            self._rearm()  # alarms that recur after the restore escalate to flash

    def _rearm(self) -> None:
        self._latched.clear()
        self._wait_since.clear()
        self._g_start.clear()
        self._last_coord_start = None
        self._short_cycles = []

    def accept_timing(self, timing: IntersectionTiming) -> None:
        """Record a timing change that passed the policy as the new known-good plan."""
        self.known_good = timing

    def observe(self, waiting: dict[int, int]) -> None:
        """Call once per controller tick with the number of vehicles waiting per phase."""
        c, t = self.ctl, self.ctl.t
        if c.flash:
            self._prev = {}
            if not self.actions or self.actions[-1][1] not in ("flash", "flash_seen"):
                # flash the monitor did not order (commanded from outside, or a controller fault)
                self.alarms.append(Alarm(t, "unexpected_flash", None, "critical", "controller entered flash"))
                self.actions.append((t, "flash_seen"))
            flashed_at = next((a for a, kind in reversed(self.actions) if kind in ("flash", "flash_seen")), None)
            if self.operator_response_s is not None and flashed_at is not None and t - flashed_at >= self.operator_response_s:
                self.reset()  # TMC operator has reviewed the alarm and restarted the controller
                self.actions.append((t, "operator_reset"))
            return
        if c.conflicting_greens():
            self._raise(t, "conflicting_greens", None, "critical", f"greens {sorted(c.greens())}")
        states = c.states()
        greens = c.greens()
        for p, s in states.items():
            prev = self._prev.get(p)
            if s == "Y" and prev == "G":
                self._y_start[p] = t
            if s == "R" and prev == "Y" and p in self._y_start and p in self.policy.phases:
                served = t - self._y_start.pop(p)
                need = self.policy.phases[p].yellow_req_s
                if served < need - 0.15:
                    self._raise(t, "short_yellow", p, "critical", f"phase {p} yellow {served:.1f} s < {need:.1f} s")
            if s == "G" and prev != "G":
                self._g_start[p] = t
                if p in c.timing.coord_phases and p == c.timing.coord_phases[0]:
                    if self._last_coord_start is not None and t - self._last_coord_start < self.rapid_cycle_frac * c.timing.cycle_s:
                        # one short cycle happens with early return to green; repeated ones do not
                        self._short_cycles = [s for s in self._short_cycles if t - s < 300.0] + [t]
                        if len(self._short_cycles) >= 2:
                            self._raise(t, "rapid_cycling", None, "high",
                                        f"{len(self._short_cycles)} cycles < {self.rapid_cycle_frac:.0%} of {c.timing.cycle_s:.0f} s within 5 min")
                    self._last_coord_start = t
            if s == "G" and p in self._g_start and t - self._g_start[p] > self.excessive_green_s:
                if any(waiting.get(q, 0) > 0 for q in c.timing.phases if q not in greens):
                    self._raise(t, "excessive_green", p, "high", f"phase {p} green > {self.excessive_green_s:.0f} s")
            if waiting.get(p, 0) > 0 and s != "G":
                self._wait_since.setdefault(p, t)
                if t - self._wait_since[p] > self.starvation_s:
                    self._raise(t, "starvation", p, "high", f"phase {p} not served for {self.starvation_s:.0f} s")
            else:
                self._wait_since.pop(p, None)
        self._prev = states

    def reset(self) -> None:
        """Operator reset after investigation."""
        self.ctl.bits.clear()
        self.ctl.update_timing(self.known_good)
        self.ctl.exit_flash()
        self._rearm()
        self._last_restore = None
