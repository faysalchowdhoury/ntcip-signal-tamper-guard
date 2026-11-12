"""Command-level safety policy: is this SET safe to pass to the controller?

The controller's own validation only enforces broad ranges (yellow 3-6 s, min green >= 1 s). Many
dangerous values sit inside those ranges, e.g. a 3.0-s yellow on a 45-mph approach. The policy checks
each SET against values derived from the intersection's geometry and the agency's timing standards:

* **ITE change interval**: :math:`Y = t + v / (2a + 2Gg)` with t = 1 s, a = 3.05 m/s^2;
* **ITE red clearance**: :math:`R = (W + L) / v`;
* agency bounds on minimum and maximum green, and on the size of a single timing change;
* control-bit rules: no omit of a coordinated phase, no omit while the phase is called, force-off and
  SET rate limits (rapid cycling and flooding), no flash from central unless allowed;
* source allow-list for SETs (weak on its own: SNMP runs over UDP and source addresses can be spoofed).

Each rule returns a :class:`Violation` with a severity. ``high`` and ``critical`` block the SET;
``medium`` passes with an alert.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Literal

from pydantic import Field

from .controller import ControlledController
from .mib import FLASH_PATTERN, classify, phases_from_mask
from .vendor.ntcip_ctrl.core.config import StrictModel

Severity = Literal["low", "medium", "high", "critical"]
SEV_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
G = 9.81
DECEL = 3.05  # m/s^2 (10 ft/s^2), ITE
PERCEPTION_S = 1.0


def ite_yellow(speed_mps: float, grade: float = 0.0) -> float:
    return PERCEPTION_S + speed_mps / (2 * DECEL + 2 * G * grade)


def ite_red(width_m: float, speed_mps: float, vehicle_length_m: float = 6.1) -> float:
    return (width_m + vehicle_length_m) / speed_mps


class PhaseSafety(StrictModel):
    approach_speed_mph: float = Field(gt=5, le=80)
    grade: float = Field(0.0, ge=-0.1, le=0.1)
    crossing_width_m: float = Field(gt=3, le=80)
    min_green_floor_s: float = Field(4.0, ge=1)
    max_green_cap_s: float = Field(90.0, gt=0)

    @property
    def speed_mps(self) -> float:
        return self.approach_speed_mph * 0.44704

    @property
    def yellow_req_s(self) -> float:
        return ite_yellow(self.speed_mps, self.grade)

    @property
    def red_req_s(self) -> float:
        return ite_red(self.crossing_width_m, self.speed_mps)


class GuardPolicy(StrictModel):
    phases: dict[int, PhaseSafety]
    write_sources: tuple[str, ...] = ("10.0.0.10",)
    max_change_frac: float = Field(0.5, gt=0, le=5)
    max_sets_per_min: int = Field(12, ge=1)
    max_force_offs_per_5min: int = Field(4, ge=0)
    max_holds_per_5min: int = Field(4, ge=0)
    allow_central_flash: bool = False
    allow_central_calls: bool = True
    allow_central_holds: bool = False
    allow_central_omits: bool = False


@dataclass(frozen=True)
class Violation:
    rule: str
    severity: Severity
    detail: str


@dataclass
class PolicyEngine:
    policy: GuardPolicy
    _sets: deque[float] = field(default_factory=deque)
    _force_offs: deque[float] = field(default_factory=deque)
    _holds: deque[float] = field(default_factory=deque)

    @staticmethod
    def _window(q: deque[float], now: float, span: float) -> int:
        while q and q[0] < now - span:
            q.popleft()
        return len(q)

    def check_set(self, oid: tuple[int, ...], value: object, ctl: ControlledController, src: str,
                  now: float) -> list[Violation]:
        pol, out = self.policy, []
        if src not in pol.write_sources:
            out.append(Violation("source_not_authorized", "critical", f"SET from {src}"))
        self._sets.append(now)
        if self._window(self._sets, now, 60.0) > pol.max_sets_per_min:
            out.append(Violation("set_flood", "high", f"> {pol.max_sets_per_min} SETs in 60 s"))
        kind, p = classify(oid)
        if not isinstance(value, int) or isinstance(value, bool):
            return out
        if p is not None and p in pol.phases and p in ctl.timing.phases:
            s, pp = pol.phases[p], ctl.timing.phases[p]
            new = value / {"min_green_s": 1, "passage_s": 10, "max_green_s": 1, "yellow_s": 10, "red_clear_s": 10}[kind]
            old = pp.max_s if kind == "max_green_s" else getattr(pp, kind)
            if kind == "yellow_s" and new < s.yellow_req_s - 0.05:
                out.append(Violation("yellow_below_ite", "critical",
                                     f"phase {p} yellow {new:.1f} s < ITE {s.yellow_req_s:.1f} s at {s.approach_speed_mph:.0f} mph"))
            if kind == "red_clear_s" and new < s.red_req_s - 0.05:
                out.append(Violation("red_below_ite", "high", f"phase {p} red {new:.1f} s < ITE {s.red_req_s:.1f} s"))
            if kind == "min_green_s" and new < s.min_green_floor_s:
                out.append(Violation("min_green_below_floor", "high", f"phase {p} min green {new:.0f} s < {s.min_green_floor_s:.0f} s"))
            if kind == "max_green_s" and (new > s.max_green_cap_s or new < pp.min_green_s):
                out.append(Violation("max_green_out_of_bounds", "high", f"phase {p} max green {new:.0f} s"))
            if old > 0 and abs(new - old) / old > pol.max_change_frac:
                out.append(Violation("large_timing_change", "medium", f"phase {p} {kind} {old:g} -> {new:g}"))
        elif kind == "omit":
            phases = phases_from_mask(value)
            if phases and not pol.allow_central_omits:
                out.append(Violation("central_omit_not_allowed", "high", f"omit {sorted(phases)} from central"))
            if phases & set(ctl.timing.coord_phases):
                out.append(Violation("omit_coordinated", "critical", f"omit of coordinated phase(s) {sorted(phases)}"))
            if phases & ctl._locked:
                out.append(Violation("omit_called_phase", "high", f"omit of phase(s) with waiting calls {sorted(phases & ctl._locked)}"))
        elif kind == "force_off" and value:
            self._force_offs.append(now)
            if self._window(self._force_offs, now, 300.0) > pol.max_force_offs_per_5min:
                out.append(Violation("force_off_rate", "high", "force-off rate suggests rapid cycling"))
        elif kind == "hold" and value:
            if not pol.allow_central_holds:
                out.append(Violation("central_hold_not_allowed", "high", f"hold {sorted(phases_from_mask(value))} from central"))
            self._holds.append(now)
            if self._window(self._holds, now, 300.0) > pol.max_holds_per_5min:
                out.append(Violation("hold_rate", "high", "repeated holds"))
            if phases_from_mask(value) - set(ctl.timing.coord_phases):
                out.append(Violation("hold_noncoordinated", "medium", f"hold on {sorted(phases_from_mask(value))}"))
        elif kind == "veh_call" and value and not pol.allow_central_calls:
            out.append(Violation("central_call_not_allowed", "high", "vehicle call from central"))
        elif kind == "pattern" and value == FLASH_PATTERN and not pol.allow_central_flash:
            out.append(Violation("central_flash", "critical", "flash commanded from central"))
        return out


def blocks(violations: list[Violation]) -> bool:
    return any(SEV_RANK[v.severity] >= SEV_RANK["high"] for v in violations)
