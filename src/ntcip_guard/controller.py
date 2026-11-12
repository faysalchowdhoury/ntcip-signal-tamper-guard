"""NEMA controller with the NTCIP 1202 phase-control inputs a central system (or an attacker) can drive.

The vendored :class:`NemaController` already times the dual-ring, ring-barrier logic. This subclass adds
the external control bits of the NTCIP 1202 ``phaseControlGroupTable`` and a flash state:

* **hold**: a phase in green does not terminate (gap-out, max-out and force-off are suppressed);
* **force-off**: a phase in green terminates as soon as its minimum green has been served;
* **omit**: a phase is never selected, even with a call;
* **vehicle call**: a central call that persists while the bit is set;
* **flash**: all phases flash red (all-way stop). Entered by ``systemPatternControl = 255`` or by the
  guard's fail-safe, left by pattern 0/1 or :meth:`exit_flash`.

The bits persist until overwritten, as a bitmask SET would leave them. Real controllers usually clear
central control bits after a backup timeout; that is configurable here as ``control_timeout_s``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .vendor.ntcip_ctrl.nema.controller import _EPS, NemaController, TerminationReason, _Ring
from .vendor.ntcip_ctrl.timing.models import BARRIER_A, IntersectionTiming


@dataclass
class ControlBits:
    hold: set[int] = field(default_factory=set)
    force_off: set[int] = field(default_factory=set)
    omit: set[int] = field(default_factory=set)
    veh_call: set[int] = field(default_factory=set)

    def clear(self) -> None:
        self.hold.clear()
        self.force_off.clear()
        self.omit.clear()
        self.veh_call.clear()

    def as_masks(self) -> dict[str, int]:
        return {k: sum(1 << (p - 1) for p in getattr(self, k)) for k in ("hold", "force_off", "omit", "veh_call")}


class ControlledController(NemaController):
    def __init__(self, timing: IntersectionTiming, mode: str = "actuated", *, dt: float = 0.1, t0: float = 0.0,
                 control_timeout_s: float | None = None) -> None:
        self.bits = ControlBits()
        self.flash = False
        self.control_timeout_s = control_timeout_s
        self._bits_set_at = 0.0
        super().__init__(timing, mode, dt=dt, t0=t0)  # type: ignore[arg-type]

    # ----------------------------------------------------------- control API
    def set_bits(self, name: str, phases: set[int]) -> None:
        setattr(self.bits, name, {p for p in phases if p in self.timing.phases})
        self._bits_set_at = self.t

    def enter_flash(self) -> None:
        self.flash = True

    def exit_flash(self) -> None:
        """Leave flash at the coordinated begin of green, as a controller does after a start-up sequence."""
        if not self.flash:
            return
        self.flash = False
        self.barrier = 0
        for ring in self.rings:
            self._start_green(ring, next(p for p in ring.groups[0] if p in self.timing.coord_phases))

    # -------------------------------------------------------------- overrides
    def phase_state(self, phase: int) -> str:
        return "F" if self.flash else super().phase_state(phase)

    def greens(self) -> set[int]:
        return set() if self.flash else super().greens()

    def _has_call(self, phase: int) -> bool:
        if phase in self.bits.omit:
            return False
        return super()._has_call(phase) or phase in self.bits.veh_call

    def _wants_to_end(self, ring: _Ring) -> TerminationReason | None:
        p = ring.phase
        if p in self.bits.hold:
            return None
        if p in self.bits.force_off and ring.timer >= self.params(p).min_green_s - _EPS:
            return TerminationReason.FORCE_OFF
        return super()._wants_to_end(ring)

    def step(self, calls: set[int], actuations: set[int]) -> None:
        if self.control_timeout_s is not None and self.t - self._bits_set_at > self.control_timeout_s:
            self.bits.clear()
        if self.flash:
            self.t += self.dt
            return
        super().step(set(calls) | self.bits.veh_call, actuations)

    def conflicting_greens(self) -> bool:
        """True if greens are shown on both sides of a barrier (must never happen; an MMU would flash)."""
        g = self.greens()
        return bool(g & BARRIER_A) and bool(g - BARRIER_A)
