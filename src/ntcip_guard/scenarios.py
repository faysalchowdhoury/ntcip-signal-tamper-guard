"""Benign central-system traffic, tampering attacks, and the closed-loop run.

The attacker model is deliberately strong and realistic for NTCIP over SNMPv1: community strings travel
in clear text, so the attacker has sniffed the write community and **spoofs the central system's source
address**. The only thing that differs is what the commands do.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from .controller import ControlledController
from .guard import Guard
from .mib import CONTROL_ENTRY, PATTERN_OID, PHASE_ENTRY, STATUS_ENTRY, Agent, MibView
from .monitor import RuntimeMonitor
from .policy import GuardPolicy, PolicyEngine
from .traffic import Approach, QueueModel
from .vendor.ntcip_ctrl.core.config import read_mapping
from .vendor.ntcip_ctrl.ntcip.ber import GET, GET_NEXT, SET, Message
from .vendor.ntcip_ctrl.timing.models import IntersectionTiming

ATMS_IP = "10.0.0.10"
COMMUNITY_W = b"private"
COL = {"min_green_s": 4, "passage_s": 5, "max_green_s": 6, "yellow_s": 8, "red_clear_s": 9}
CTRL = {"omit": 2, "hold": 4, "force_off": 5, "veh_call": 6}
ATTACKS = ("short_yellow", "low_min_green", "hold_coord", "omit_side", "rapid_cycle", "flash", "call_trickle", "replay")
ATTACK_START_S = 1200.0


@dataclass(frozen=True)
class Site:
    timing: IntersectionTiming
    policy: GuardPolicy
    approaches: dict[int, Approach]


def load_site(path: str | Path) -> Site:
    d = read_mapping(path)
    return Site(IntersectionTiming.model_validate(d["timing"]), GuardPolicy.model_validate(d["policy"]),
                {int(k): Approach(**v) for k, v in d["approaches"].items()})


def mask(phases: set[int] | tuple[int, ...]) -> int:
    return sum(1 << (p - 1) for p in phases)


def set_timing(field_: str, values: dict[int, float]) -> Message:
    scale = 10 if field_ in ("passage_s", "yellow_s", "red_clear_s") else 1
    return Message(SET, 0, [(PHASE_ENTRY + (COL[field_], p), int(round(v * scale))) for p, v in values.items()],
                   COMMUNITY_W)


def set_ctrl(name: str, phases: set[int] | tuple[int, ...]) -> Message:
    return Message(SET, 0, [(CONTROL_ENTRY + (CTRL[name], 1), mask(phases))], COMMUNITY_W)


Schedule = list[tuple[float, Message]]


def benign_schedule(seed: int, duration: float) -> Schedule:
    """What a central system does in a normal hour: status polls every second, a timing walk every
    5 min, a time-of-day plan change, an occasional operator passage tweak, an occasional transit call."""
    r = np.random.default_rng(seed)
    out: Schedule = []
    status = [(STATUS_ENTRY + (c, 1), None) for c in (2, 3, 4)]
    for t in np.arange(1.0, duration, 1.0):
        out.append((float(t), Message(GET, 0, list(status), b"public")))
    for t in np.arange(30.0, duration, 300.0):
        oid = PHASE_ENTRY
        for k in range(5):
            out.append((float(t) + 0.1 * k, Message(GET_NEXT, 0, [(oid + (COL["min_green_s"], k + 1), None)], b"public")))
    t_tod = float(r.uniform(1500, 2100))
    out.append((t_tod, set_timing("max_green_s", {4: float(r.choice([30, 31])), 8: float(r.choice([30, 31]))})))
    if r.random() < 0.4:
        out.append((float(r.uniform(60, duration - 60)), set_timing("passage_s", {int(r.choice([4, 8])): float(r.choice([2.5, 3.0, 3.5]))})))
    if r.random() < 0.5:
        t_call = float(r.uniform(60, duration - 60))
        out += [(t_call, set_ctrl("veh_call", {4})), (t_call + 10.0, set_ctrl("veh_call", set()))]
    return out


def attack_schedule(name: str, duration: float, start: float = ATTACK_START_S) -> Schedule:
    s, out = start, []
    if name == "short_yellow":
        out.append((s, set_timing("yellow_s", {2: 3.0, 6: 3.0})))
    elif name == "low_min_green":
        out.append((s, set_timing("min_green_s", {4: 2.0, 8: 2.0})))
    elif name == "hold_coord":  # unauthorised green extension, re-asserted every minute
        out += [(float(t), set_ctrl("hold", {2, 6})) for t in np.arange(s, duration, 60.0)]
    elif name == "omit_side":
        out += [(float(t), set_ctrl("omit", {4, 8})) for t in np.arange(s, duration, 60.0)]
    elif name == "rapid_cycle":  # force everything off and call everything, every 3 s
        for t in np.arange(s, duration, 3.0):
            out += [(float(t), set_ctrl("force_off", tuple(range(1, 9)))), (float(t) + 0.1, set_ctrl("veh_call", tuple(range(1, 9))))]
    elif name == "flash":
        out.append((s, Message(SET, 0, [(PATTERN_OID, 255)], COMMUNITY_W)))
    elif name == "call_trickle":  # low and slow: phantom left-turn calls every 30 s, each individually allowed
        for t in np.arange(s, duration, 30.0):
            out += [(float(t), set_ctrl("veh_call", {3, 7})), (float(t) + 2.0, set_ctrl("veh_call", set()))]
    elif name == "replay":  # replay a captured, valid time-of-day SET at the wrong time, repeatedly
        for t in np.arange(s, duration, 600.0):
            out.append((float(t), set_timing("max_green_s", {4: 24.0, 8: 24.0})))
    else:
        raise ValueError(f"unknown attack {name!r}")
    return out


@dataclass
class RunResult:
    scenario: str
    mode: str
    seed: int
    traffic: dict[str, float]
    unsafe_yellows: int
    flash_s: float
    blocked: int
    alerted: int
    first_detection_s: float | None
    actions: list[tuple[float, str]]
    alarms: list[str]
    request_log: list[tuple[float, str, str, tuple[int, ...]]] = field(repr=False, default_factory=list)


def run(site: Site, scenario: str, mode: str, seed: int, duration: float = 3600.0, dt: float = 0.1) -> RunResult:
    ctl = ControlledController(site.timing, "actuated", dt=dt)
    agent = Agent(MibView(ctl))
    monitor = RuntimeMonitor(ctl, site.policy, site.timing, fallback=mode in ("monitor", "full"))
    guard = Guard(agent.handle, PolicyEngine(site.policy), monitor, lambda: ctl.t, mode=mode)
    qm = QueueModel(site.approaches, seed=seed)
    sched = benign_schedule(seed, duration) + ([] if scenario == "benign" else attack_schedule(scenario, duration))
    sched.sort(key=lambda x: x[0])
    k, rid = 0, 1
    yellow_on: dict[int, float] = {}
    prev: dict[int, str] = {}
    unsafe, flash_s = 0, 0.0
    need = {p: s.yellow_req_s for p, s in site.policy.phases.items()}
    n_steps = int(round(duration / dt))
    for _ in range(n_steps):
        while k < len(sched) and sched[k][0] <= ctl.t + 1e-9:
            m = sched[k][1]
            guard.handle(Message(m.pdu_type, rid, m.varbinds, m.community).encode(), ATMS_IP)
            rid += 1
            k += 1
        calls, acts = qm.step(ctl)
        ctl.step(calls, acts)
        states = ctl.states()
        for p, st in states.items():  # independent safety audit, whatever the guard mode
            if st == "Y" and prev.get(p) == "G":
                yellow_on[p] = ctl.t
            if st == "R" and prev.get(p) == "Y" and p in yellow_on and ctl.t - yellow_on.pop(p) < need[p] - 0.15:
                unsafe += 1
        prev = states
        if mode in ("monitor", "full"):
            monitor.observe(qm.waiting())
        if ctl.flash:
            flash_s += dt
    t_det = [e.t for e in guard.events if e.action in ("blocked", "alerted") and e.t >= ATTACK_START_S - 1e-9]
    t_det += [a.t for a in monitor.alarms if a.t >= ATTACK_START_S - 1e-9]
    first = (min(t_det) - ATTACK_START_S) if (t_det and scenario != "benign") else None
    return RunResult(scenario, mode, seed, qm.summary(ctl.t), unsafe, flash_s,
                     sum(e.action == "blocked" for e in guard.events), sum(e.action == "alerted" for e in guard.events),
                     first, monitor.actions, [f"{a.kind}@{a.t:.0f}" for a in monitor.alarms], guard.request_log)


def run_payload(p: dict[str, Any]) -> RunResult:
    return run(load_site(p["site"]), p["scenario"], p["mode"], p["seed"], p.get("duration", 3600.0))


Runner = Callable[[dict[str, Any]], RunResult]
