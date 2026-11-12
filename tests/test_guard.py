from __future__ import annotations

import asyncio
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from ntcip_guard.api.app import create_app
from ntcip_guard.behavior import FEATURES, window_features
from ntcip_guard.controller import ControlledController
from ntcip_guard.guard import Guard
from ntcip_guard.mib import PATTERN_OID, STATUS_ENTRY, Agent, MibView
from ntcip_guard.monitor import RuntimeMonitor
from ntcip_guard.policy import PolicyEngine, blocks, ite_red, ite_yellow
from ntcip_guard.proxy import GuardedSite
from ntcip_guard.scenarios import ATMS_IP, load_site, run, set_ctrl, set_timing
from ntcip_guard.vendor.ntcip_ctrl.ntcip.ber import GEN_ERR, GET, NO_ERROR, SET, Message

SITE = str(Path(__file__).resolve().parents[1] / "configs" / "intersection.yaml")


def _pkt(m: Message, rid: int = 1) -> bytes:
    return Message(m.pdu_type, rid, m.varbinds, m.community).encode()


def _stack(mode: str = "full"):  # type: ignore[no-untyped-def]
    site = load_site(SITE)
    ctl = ControlledController(site.timing, "actuated")
    mon = RuntimeMonitor(ctl, site.policy, site.timing)
    g = Guard(Agent(MibView(ctl)).handle, PolicyEngine(site.policy), mon, lambda: ctl.t, mode=mode)
    return site, ctl, mon, g


def test_ite_clearance_formulas() -> None:
    assert ite_yellow(45 * 0.44704) == pytest.approx(4.30, abs=0.01)  # 1 + 20.1 / 6.1
    assert ite_yellow(30 * 0.44704) == pytest.approx(3.20, abs=0.01)
    assert ite_yellow(45 * 0.44704, grade=-0.04) > ite_yellow(45 * 0.44704)  # downgrade needs longer yellow
    assert ite_red(22, 45 * 0.44704) == pytest.approx((22 + 6.1) / 20.1168, rel=1e-6)


def test_policy_decisions() -> None:
    site, ctl, _, _ = _stack()
    eng = PolicyEngine(site.policy)
    ok = set_timing("passage_s", {4: 3.0}).varbinds[0]
    assert eng.check_set(*ok, ctl, ATMS_IP, 0.0) == []
    short = set_timing("yellow_s", {2: 3.0}).varbinds[0]  # accepted by the controller's own 3-6 s range
    assert [v.rule for v in eng.check_set(*short, ctl, ATMS_IP, 1.0)] == ["yellow_below_ite"]
    for msg, rule in ((set_ctrl("hold", {2, 6}), "central_hold_not_allowed"), (set_ctrl("omit", {4}), "central_omit_not_allowed"),
                      (Message(SET, 0, [(PATTERN_OID, 255)]), "central_flash")):
        vs = eng.check_set(*msg.varbinds[0], ctl, ATMS_IP, 2.0)
        assert rule in {v.rule for v in vs} and blocks(vs)
    assert {v.rule for v in eng.check_set(*ok, ctl, "203.0.113.9", 3.0)} == {"source_not_authorized"}


def test_controller_control_bits() -> None:
    site = load_site(SITE)
    ctl = ControlledController(site.timing, "actuated")
    ctl.set_bits("hold", {2, 6})
    for _ in range(3000):  # 300 s with a side-street call that would normally end phase 2 at its force-off
        ctl.step({4}, set())
    assert ctl.states()[2] == "G" and ctl.stats[4].services == 0
    ctl = ControlledController(site.timing, "actuated")
    ctl.set_bits("omit", {4, 8})
    for _ in range(3000):
        ctl.step({4, 8}, {4, 8})
    assert ctl.stats[4].services == 0 and ctl.stats[8].services == 0
    ctl = ControlledController(site.timing, "actuated")
    ctl.set_bits("force_off", set(range(1, 9)))
    for _ in range(2000):
        ctl.step(set(range(1, 9)), set(range(1, 9)))
    st = ctl.stats[2]  # coordinated phase cut at its 15-s minimum instead of its 27.5-s split green
    assert st.terminations["force_off"] >= 3 and st.green_time_s / st.services < 17.0
    ctl.enter_flash()
    assert set(ctl.states().values()) == {"F"} and not ctl.greens()
    ctl.exit_flash()
    assert ctl.states()[2] == "G"


def test_guard_blocks_without_touching_controller() -> None:
    _, ctl, _, g = _stack()
    before = ctl.timing.phases[2].yellow_s
    reply = Message.decode(g.handle(_pkt(set_timing("yellow_s", {2: 3.0})), ATMS_IP))  # type: ignore[arg-type]
    assert reply.error_status == GEN_ERR and reply.error_index == 1
    assert ctl.timing.phases[2].yellow_s == before
    ok = Message.decode(g.handle(_pkt(set_timing("passage_s", {4: 3.5})), ATMS_IP))  # type: ignore[arg-type]
    assert ok.error_status == NO_ERROR and ctl.timing.phases[4].passage_s == 3.5
    assert g.monitor is not None and g.monitor.known_good.phases[4].passage_s == 3.5  # accepted change is the new restore point
    st = Message.decode(g.handle(_pkt(Message(GET, 0, [(STATUS_ENTRY + (4, 1), None)], b"public")), ATMS_IP))  # type: ignore[arg-type]
    assert st.error_status == NO_ERROR and isinstance(st.varbinds[0][1], int)
    assert [e.action for e in g.events] == ["blocked", "forwarded"]
    assert g.handle(b"\x30\x03garbage", ATMS_IP) is None and g.events[-1].action == "dropped"


def test_monitor_flashes_on_short_yellow_and_escalates_after_restore() -> None:
    site, ctl, mon, _ = _stack()
    ctl.update_timing(site.timing.model_validate({**site.timing.model_dump(),
                                                  "phases": {**site.timing.phases, 2: site.timing.phases[2].model_copy(update={"yellow_s": 3.0, "red_clear_s": 3.5})}}))
    for _ in range(3000):
        ctl.step({4, 8}, set())
        mon.observe({4: 1, 8: 1})
        if ctl.flash:
            break
    assert ctl.flash and mon.alarms[0].kind == "short_yellow"
    site, ctl, mon, _ = _stack()
    ctl.set_bits("hold", {2, 6})
    for _ in range(6000):
        ctl.step({4}, set())
        mon.observe({4: 3})
        if ctl.flash:
            break
    kinds = [k for _, k in mon.actions]
    assert kinds[0] == "restore" and "flash" not in kinds  # restore cleared the hold; nothing re-asserted it


def test_scenarios_end_to_end() -> None:
    site = load_site(SITE)
    off = run(site, "short_yellow", "off", 0, duration=1500.0)
    full = run(site, "short_yellow", "full", 0, duration=1500.0)
    assert off.unsafe_yellows > 0 and full.unsafe_yellows == 0 and full.blocked == 1
    assert full.first_detection_s is not None and full.first_detection_s < 1.0
    benign = run(site, "benign", "full", 1, duration=1500.0)
    assert benign.blocked == 0 and not benign.alarms and not benign.actions


def test_behaviour_features() -> None:
    log = [(1.0, "get", "status", (1,)), (2.0, "set", "veh_call", (2,)), (3.0, "set", "veh_call", (2,)), (70.0, "set", "yellow_s", (3,))]
    starts, x = window_features(log, 0.0, 120.0)
    assert list(starts) == [0.0, 60.0] and x.shape == (2, len(FEATURES))
    f = dict(zip(FEATURES, x[0]))
    assert f["n_set"] == 2 and f["set_veh_call"] == 2 and f["distinct_set_objects"] == 1
    assert dict(zip(FEATURES, x[1]))["set_yellow_s"] == 1 and np.isfinite(x).all()


def test_udp_proxy_round_trip() -> None:
    async def go() -> tuple[int, int]:
        gs = GuardedSite(SITE, speedup=50.0)
        host, port = await gs.start("127.0.0.1", 0)
        loop = asyncio.get_running_loop()
        replies: list[bytes] = []
        done = asyncio.Event()

        class P(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                replies.append(data)
                if len(replies) == 2:
                    done.set()

        tr, _ = await loop.create_datagram_endpoint(P, remote_addr=(host, port))
        # source is 127.0.0.1, which is not the authorised central address: any SET must be refused
        tr.sendto(_pkt(set_timing("passage_s", {4: 3.0}), 1))
        tr.sendto(_pkt(Message(GET, 0, [(STATUS_ENTRY + (4, 1), None)], b"public"), 2))
        await asyncio.wait_for(done.wait(), 2.0)
        tr.close()
        await gs.stop()
        by_id = {Message.decode(r).request_id: Message.decode(r) for r in replies}
        return by_id[1].error_status, by_id[2].error_status

    set_err, get_err = asyncio.run(go())
    assert set_err == GEN_ERR and get_err == NO_ERROR


def test_api() -> None:
    gs = GuardedSite(SITE)
    cl = TestClient(create_app(gs))
    assert cl.get("/health").json()["status"] == "ok"
    s = cl.get("/v1/status").json()
    assert s["flash"] is False and set(s["states"]) == {str(p) for p in range(1, 9)}
    v = cl.post("/v1/inspect", json={"packet_hex": _pkt(set_timing("yellow_s", {6: 3.0})).hex()}).json()
    assert v["verdict"] == "block" and v["violations"][0]["rule"] == "yellow_below_ite"
    assert cl.post("/v1/inspect", json={"packet_hex": "zz"}).status_code == 422
    assert cl.post("/v1/reset").json()["status"] == "reset"
