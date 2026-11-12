"""The guard: an SNMP-aware filter between central management and the field controller.

``Guard.handle(packet, src)`` decodes an SNMPv1 request. GET and GETNEXT pass through. A SET is checked
varbind by varbind against the :class:`PolicyEngine`; if any varbind blocks, the whole SET is refused with
``genErr`` and an error index (SNMPv1 SETs are all-or-nothing), and nothing reaches the controller.
Accepted timing SETs update the monitor's known-good plan. Every request and decision is logged.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .mib import classify
from .monitor import RuntimeMonitor
from .policy import PolicyEngine, Violation, blocks
from .vendor.ntcip_ctrl.core.exceptions import SNMPError
from .vendor.ntcip_ctrl.ntcip.ber import GEN_ERR, GET, GET_NEXT, RESPONSE, SET, Message

GUARD_MODES = ("off", "monitor", "rules", "full")


@dataclass(frozen=True)
class Event:
    t: float
    src: str
    action: str  # forwarded | blocked | alerted | dropped
    kinds: tuple[str, ...]
    violations: tuple[Violation, ...]


@dataclass
class Guard:
    """``mode``: ``off`` (pass everything), ``monitor`` (runtime monitor only), ``rules`` (command policy
    only), ``full`` (policy + monitor with fail-safe)."""

    upstream: Callable[[bytes], bytes | None]
    engine: PolicyEngine
    monitor: RuntimeMonitor | None
    clock: Callable[[], float]
    mode: str = "full"
    events: list[Event] = field(default_factory=list)
    request_log: list[tuple[float, str, str, tuple[int, ...]]] = field(default_factory=list)

    def handle(self, data: bytes, src: str) -> bytes | None:
        now = self.clock()
        try:
            msg = Message.decode(data)
        except SNMPError:
            self.events.append(Event(now, src, "dropped", ("malformed",), ()))
            return None
        if msg.pdu_type in (GET, GET_NEXT):
            for oid, _ in msg.varbinds:
                self.request_log.append((now, "get", classify(oid)[0], oid))
            return self.upstream(data)
        if msg.pdu_type != SET:
            return None
        kinds = tuple(classify(o)[0] for o, _ in msg.varbinds)
        for oid, _ in msg.varbinds:
            self.request_log.append((now, "set", classify(oid)[0], oid))
        violations: list[Violation] = []
        bad_index = 0
        if self.mode in ("rules", "full") and self.monitor is not None:
            ctl = self.monitor.ctl
            for i, (oid, value) in enumerate(msg.varbinds, start=1):
                v = self.engine.check_set(oid, value, ctl, src, now)
                if blocks(v) and not bad_index:
                    bad_index = i
                violations += v
        if bad_index:
            self.events.append(Event(now, src, "blocked", kinds, tuple(violations)))
            return Message(RESPONSE, msg.request_id, list(msg.varbinds), msg.community, GEN_ERR, bad_index).encode()
        reply = self.upstream(data)
        self.events.append(Event(now, src, "alerted" if violations else "forwarded", kinds, tuple(violations)))
        # only policy-checked timing becomes known-good; in monitor-only mode the provisioned plan stays
        # the restore point, so an attacker's timing cannot poison it
        if self.mode == "full" and self.monitor is not None and reply is not None and Message.decode(reply).error_status == 0:
            if any(k in ("min_green_s", "passage_s", "max_green_s", "yellow_s", "red_clear_s") for k in kinds):
                self.monitor.accept_timing(self.monitor.ctl.timing)
        return reply
