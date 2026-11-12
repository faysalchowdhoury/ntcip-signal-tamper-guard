"""Operator API for a running guard.

``GET  /health``           liveness
``GET  /v1/status``        controller display, control bits, flash, timing in force
``GET  /v1/events``        recent guard decisions (blocked / alerted / forwarded)
``GET  /v1/alarms``        runtime-monitor alarms and fail-safe actions
``POST /v1/inspect``       dry-run a hex-encoded SNMP packet against the policy (no effect on the controller)
``POST /v1/reset``         operator reset after investigation (clear bits, restore known-good, leave flash)
"""

from __future__ import annotations

import os
from dataclasses import asdict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .. import __version__
from ..mib import classify
from ..policy import PolicyEngine, blocks
from ..proxy import GuardedSite
from ..vendor.ntcip_ctrl.core.exceptions import SNMPError
from ..vendor.ntcip_ctrl.ntcip.ber import SET, Message


class InspectRequest(BaseModel):
    packet_hex: str = Field(min_length=4, max_length=8192)
    src: str = "10.0.0.10"


def create_app(site: GuardedSite | None = None) -> FastAPI:
    gs = site or GuardedSite(os.environ.get("NTCIP_GUARD_SITE", "configs/intersection.yaml"))
    app = FastAPI(title="NTCIP tamper guard", version=__version__)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/v1/status")
    def status() -> dict[str, object]:
        c = gs.ctl
        return {"t": round(c.t, 1), "flash": c.flash, "states": c.states(), "control_bits": c.bits.as_masks(),
                "timing": {p: pp.model_dump() for p, pp in c.timing.phases.items()}}

    @app.get("/v1/events")
    def events(limit: int = 100) -> list[dict[str, object]]:
        return [{**asdict(e), "violations": [asdict(v) for v in e.violations]} for e in gs.guard.events[-limit:]]

    @app.get("/v1/alarms")
    def alarms() -> dict[str, object]:
        return {"alarms": [asdict(a) for a in gs.monitor.alarms], "actions": gs.monitor.actions}

    @app.post("/v1/inspect")
    def inspect(req: InspectRequest) -> dict[str, object]:
        try:
            msg = Message.decode(bytes.fromhex(req.packet_hex))
        except (ValueError, SNMPError) as exc:
            raise HTTPException(422, f"not an SNMPv1 message: {exc}") from exc
        if msg.pdu_type != SET:
            return {"pdu": "read", "verdict": "forward", "violations": []}
        engine = PolicyEngine(gs.guard.engine.policy)  # fresh rate state: a dry run must not count
        vs = [v for oid, val in msg.varbinds for v in engine.check_set(oid, val, gs.ctl, req.src, gs.ctl.t)]
        return {"pdu": "set", "objects": [classify(o)[0] for o, _ in msg.varbinds],
                "verdict": "block" if blocks(vs) else ("alert" if vs else "forward"), "violations": [asdict(v) for v in vs]}

    @app.post("/v1/reset")
    def reset() -> dict[str, str]:
        gs.monitor.reset()
        return {"status": "reset"}

    return app
