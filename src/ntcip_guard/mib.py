"""NTCIP 1202 object subset served by the emulated controller, and a minimal SNMPv1 agent.

OIDs under the ``asc`` node 1.3.6.1.4.1.1206.4.2.1:

=============================  ==================  ========  ======
object                         OID suffix          units     access
=============================  ==================  ========  ======
phaseMinimumGreen.p            .1.2.1.4.p          s         RW
phasePassage.p                 .1.2.1.5.p          0.1 s     RW
phaseMaximum1.p                .1.2.1.6.p          s         RW
phaseYellowChange.p            .1.2.1.8.p          0.1 s     RW
phaseRedClear.p                .1.2.1.9.p          0.1 s     RW
phaseStatusGroupReds/Yellows/  .1.4.1.{2,3,4}.1    bitmask   RO
  Greens.1
phaseControlGroupPhaseOmit.1   .1.5.1.2.1          bitmask   RW
phaseControlGroupHold.1        .1.5.1.4.1          bitmask   RW
phaseControlGroupForceOff.1    .1.5.1.5.1          bitmask   RW
phaseControlGroupVehCall.1     .1.5.1.6.1          bitmask   RW
systemPatternControl.0         .4.14.0             integer   RW  (0/1 = plan, 255 = flash)
=============================  ==================  ========  ======

Suffixes follow the published NTCIP 1202 v03 MIB; vendors add proprietary objects, so check the
controller's MIB before pointing this at hardware. Bit ``n-1`` of group 1 is phase ``n``.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import ValidationError

from .controller import ControlledController
from .vendor.ntcip_ctrl.core.exceptions import SNMPError
from .vendor.ntcip_ctrl.ntcip.ber import (
    BAD_VALUE,
    GET,
    GET_NEXT,
    NO_ERROR,
    NO_SUCH_NAME,
    READ_ONLY,
    RESPONSE,
    SET,
    Message,
    Value,
)

ASC: tuple[int, ...] = (1, 3, 6, 1, 4, 1, 1206, 4, 2, 1)
PHASE_ENTRY = ASC + (1, 2, 1)
STATUS_ENTRY = ASC + (1, 4, 1)
CONTROL_ENTRY = ASC + (1, 5, 1)
PATTERN_OID = ASC + (4, 14, 0)

PHASE_COLUMNS: dict[int, tuple[str, float]] = {
    4: ("min_green_s", 1.0),
    5: ("passage_s", 10.0),
    6: ("max_green_s", 1.0),
    8: ("yellow_s", 10.0),
    9: ("red_clear_s", 10.0),
}
CONTROL_COLUMNS: dict[int, str] = {2: "omit", 4: "hold", 5: "force_off", 6: "veh_call"}
FLASH_PATTERN = 255


def phases_from_mask(mask: int) -> set[int]:
    return {b + 1 for b in range(16) if mask >> b & 1}


def classify(oid: tuple[int, ...]) -> tuple[str, int | None]:
    """Map an OID to ``(object kind, phase or None)``; kind is a timing field name, a control bit name,
    ``pattern``, ``status`` or ``unknown``."""
    n = len(PHASE_ENTRY)
    if oid[:n] == PHASE_ENTRY and len(oid) == n + 2 and oid[-2] in PHASE_COLUMNS:
        return PHASE_COLUMNS[oid[-2]][0], oid[-1]
    if oid[: len(CONTROL_ENTRY)] == CONTROL_ENTRY and len(oid) == len(CONTROL_ENTRY) + 2 and oid[-2] in CONTROL_COLUMNS:
        return CONTROL_COLUMNS[oid[-2]], None
    if oid == PATTERN_OID:
        return "pattern", None
    if oid[: len(STATUS_ENTRY)] == STATUS_ENTRY:
        return "status", None
    return "unknown", None


@dataclass
class MibView:
    controller: ControlledController

    def _oids(self) -> list[tuple[int, ...]]:
        c = self.controller
        out = [PHASE_ENTRY + (col, p) for col in PHASE_COLUMNS for p in sorted(c.timing.phases)]
        out += [STATUS_ENTRY + (col, 1) for col in (2, 3, 4)]
        out += [CONTROL_ENTRY + (col, 1) for col in CONTROL_COLUMNS]
        out.append(PATTERN_OID)
        return sorted(out)

    def _status(self, col: int) -> int:
        want = {2: "R", 3: "Y", 4: "G"}[col]
        return sum(1 << (p - 1) for p, s in self.controller.states().items() if s == want or (s == "F" and want == "R"))

    def get(self, oid: tuple[int, ...]) -> tuple[int, Value]:
        c = self.controller
        kind, p = classify(oid)
        if p is not None:
            if p not in c.timing.phases:
                return NO_SUCH_NAME, None
            name, scale = PHASE_COLUMNS[oid[-2]]
            pp = c.timing.phases[p]
            val = pp.max_s if name == "max_green_s" else getattr(pp, name)
            return NO_ERROR, int(round(val * scale))
        if kind in CONTROL_COLUMNS.values() and oid[-1] == 1:
            return NO_ERROR, c.bits.as_masks()[kind]
        if kind == "pattern":
            return NO_ERROR, FLASH_PATTERN if c.flash else 1
        if kind == "status" and len(oid) == len(STATUS_ENTRY) + 2 and oid[-2] in (2, 3, 4) and oid[-1] == 1:
            return NO_ERROR, self._status(oid[-2])
        return NO_SUCH_NAME, None

    def get_next(self, oid: tuple[int, ...]) -> tuple[tuple[int, ...] | None, int, Value]:
        for o in self._oids():
            if o > oid:
                err, v = self.get(o)
                return o, err, v
        return None, NO_SUCH_NAME, None

    def set(self, oid: tuple[int, ...], value: Value) -> int:
        c = self.controller
        kind, p = classify(oid)
        if kind == "status":
            return READ_ONLY
        if kind == "unknown":
            return NO_SUCH_NAME
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return BAD_VALUE
        if kind in CONTROL_COLUMNS.values():
            if oid[-1] != 1 or value >= 1 << 16:
                return BAD_VALUE
            c.set_bits(kind, phases_from_mask(value))
            return NO_ERROR
        if kind == "pattern":
            if value == FLASH_PATTERN:
                c.enter_flash()
            elif value in (0, 1):
                c.exit_flash()
            else:
                return BAD_VALUE  # only one coordination pattern is configured
            return NO_ERROR
        assert p is not None
        if p not in c.timing.phases:
            return NO_SUCH_NAME
        name, scale = PHASE_COLUMNS[oid[-2]]
        timing = c.timing
        try:
            new_pp = type(timing.phases[p]).model_validate({**timing.phases[p].model_dump(), name: value / scale})
            new_timing = type(timing).model_validate({**timing.model_dump(), "phases": {**timing.phases, p: new_pp}})
        except (ValidationError, ValueError):
            return BAD_VALUE  # the controller's own range checks (e.g. yellow >= 3 s)
        c.update_timing(new_timing)
        return NO_ERROR


class Agent:
    """SNMPv1 request handler over a :class:`MibView` (transport-agnostic; see ``proxy.py`` for UDP)."""

    def __init__(self, mib: MibView, *, community: bytes = b"public", write_community: bytes = b"private") -> None:
        self.mib = mib
        self.community = community
        self.write_community = write_community

    def handle(self, data: bytes) -> bytes | None:
        try:
            msg = Message.decode(data)
        except SNMPError:
            return None
        if msg.version != 0:
            return None
        if msg.pdu_type == SET and msg.community != self.write_community:
            return None
        if msg.pdu_type != SET and msg.community not in (self.community, self.write_community):
            return None
        out: list[tuple[tuple[int, ...], Value]] = []
        err, idx = NO_ERROR, 0
        for i, (oid, value) in enumerate(msg.varbinds, start=1):
            if msg.pdu_type == GET:
                e, v = self.mib.get(oid)
                out.append((oid, v))
            elif msg.pdu_type == GET_NEXT:
                nxt, e, v = self.mib.get_next(oid)
                out.append((nxt or oid, v))
            elif msg.pdu_type == SET:
                e = self.mib.set(oid, value)
                out.append((oid, value))
            else:
                e = NO_SUCH_NAME
                out.append((oid, None))
            if e != NO_ERROR and err == NO_ERROR:
                err, idx = e, i
        if err != NO_ERROR:
            out = list(msg.varbinds)
        return Message(RESPONSE, msg.request_id, out, msg.community, err, idx).encode()
