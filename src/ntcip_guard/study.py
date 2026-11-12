"""Experiment: every attack against every guard mode, benign false-alarm runs, and the behaviour model."""

from __future__ import annotations

import json
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from .behavior import BehaviorModel, window_features  # noqa: E402
from .controller import ControlledController  # noqa: E402
from .guard import GUARD_MODES, Guard  # noqa: E402
from .mib import Agent, MibView  # noqa: E402
from .monitor import RuntimeMonitor  # noqa: E402
from .policy import PolicyEngine  # noqa: E402
from .scenarios import ATMS_IP, ATTACK_START_S, ATTACKS, RunResult, load_site, run_payload, set_timing  # noqa: E402
from .vendor.ntcip_ctrl.core.logging import get_logger  # noqa: E402
from .vendor.ntcip_ctrl.ntcip.ber import Message  # noqa: E402

log = get_logger(__name__)
DURATION = 3600.0


def _pool(payloads: list[dict[str, Any]], workers: int) -> list[RunResult]:
    with ProcessPoolExecutor(workers) as ex:
        return list(ex.map(run_payload, payloads, chunksize=2))


def _row(r: RunResult) -> dict[str, Any]:
    return {"scenario": r.scenario, "mode": r.mode, "seed": r.seed, **r.traffic, "unsafe_yellows": r.unsafe_yellows,
            "flash_min": r.flash_s / 60, "blocked": r.blocked, "alerted": r.alerted, "monitor_alarms": len(r.alarms),
            "detect_s": r.first_detection_s, "actions": ";".join(f"{k}@{t:.0f}" for t, k in r.actions)}


def guard_latency(site_path: str, n: int = 5000) -> dict[str, float]:
    site = load_site(site_path)
    ctl = ControlledController(site.timing, "actuated")
    g = Guard(Agent(MibView(ctl)).handle, PolicyEngine(site.policy.model_copy(update={"max_sets_per_min": 10**9})),
              RuntimeMonitor(ctl, site.policy, site.timing), lambda: ctl.t, mode="full")
    good = Message(set_timing("passage_s", {4: 3.0}).pdu_type, 1, set_timing("passage_s", {4: 3.0}).varbinds, b"private").encode()
    bad = Message(set_timing("yellow_s", {2: 3.0}).pdu_type, 2, set_timing("yellow_s", {2: 3.0}).varbinds, b"private").encode()
    out = {}
    for name, pkt in (("set_allowed", good), ("set_blocked", bad)):
        ts = []
        for _ in range(n):
            t0 = time.perf_counter()
            g.handle(pkt, ATMS_IP)
            ts.append(time.perf_counter() - t0)
        out[f"{name}_p50_us"] = float(np.percentile(ts, 50) * 1e6)
        out[f"{name}_p99_us"] = float(np.percentile(ts, 99) * 1e6)
    return out


def run(site_path: str, out_dir: str | Path, *, seeds: int = 3, benign_eval: int = 20, benign_train: int = 30,
        workers: int = 2) -> dict[str, Any]:
    out = Path(out_dir)
    (out / "figures").mkdir(parents=True, exist_ok=True)
    grid = [{"site": site_path, "scenario": s, "mode": m, "seed": k, "duration": DURATION}
            for s in ("benign", *ATTACKS) for m in GUARD_MODES for k in range(seeds)]
    extra = [{"site": site_path, "scenario": "benign", "mode": "full", "seed": k, "duration": DURATION}
             for k in range(seeds, benign_eval)]
    train = [{"site": site_path, "scenario": "benign", "mode": "full", "seed": 100 + k, "duration": DURATION}
             for k in range(benign_train)]
    t0 = time.perf_counter()
    res = _pool(grid + extra + train, workers)
    log.info("study.simulated", extra={"runs": len(res), "s": round(time.perf_counter() - t0, 1)})
    n_grid, n_extra = len(grid), len(extra)
    grid_res, extra_res, train_res = res[:n_grid], res[n_grid:n_grid + n_extra], res[n_grid + n_extra:]
    df = pd.DataFrame([_row(r) for r in grid_res])
    df.to_csv(out / "runs.csv", index=False)

    # ---- behaviour model: fit on benign training hours, evaluate on held-out benign hours and attacks
    xtr = np.vstack([window_features(r.request_log, 0.0, DURATION)[1] for r in train_res])
    bm = BehaviorModel.fit(xtr)
    benign_eval_runs = [r for r in grid_res if r.scenario == "benign" and r.mode == "full"] + extra_res
    fp_windows = sum(int(bm.anomalous(window_features(r.request_log, 0.0, DURATION)[1]).sum()) for r in benign_eval_runs)
    beh: dict[str, dict[str, float | None]] = {}
    for a in ATTACKS:
        dets = []
        for r in (x for x in grid_res if x.scenario == a and x.mode == "full"):
            starts, x = window_features(r.request_log, 0.0, DURATION)
            flag = bm.anomalous(x)
            hit = [s + 60.0 - ATTACK_START_S for s, f in zip(starts, flag) if f and s + 60.0 > ATTACK_START_S]
            dets.append(hit[0] if hit else None)
        found = [d for d in dets if d is not None]
        beh[a] = {"detected": len(found) / len(dets), "detect_s": float(np.mean(found)) if found else None}

    benign_all = [r for r in benign_eval_runs]
    fp = {"hours": len(benign_all),
          "blocked_per_h": sum(r.blocked for r in benign_all) / len(benign_all),
          "alerted_per_h": sum(r.alerted for r in benign_all) / len(benign_all),
          "monitor_alarms_per_h": sum(len(r.alarms) for r in benign_all) / len(benign_all),
          "fallbacks_per_h": sum(len(r.actions) for r in benign_all) / len(benign_all),
          "behaviour_windows_flagged_per_h": fp_windows / len(benign_all)}
    summary = {"runs": len(res), "fp": fp, "behaviour": beh, "latency": guard_latency(site_path),
               "agg": df.groupby(["scenario", "mode"]).agg(
                   mean_delay_s=("mean_delay_s", "mean"), max_wait_s=("max_wait_s", "mean"),
                   unsafe_yellows=("unsafe_yellows", "mean"), flash_min=("flash_min", "mean"),
                   blocked=("blocked", "mean"), detect_s=("detect_s", "mean")).reset_index().to_dict("records")}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=float), encoding="utf-8")
    _plot(df, out / "figures")
    write_report(summary, out / "RESULTS.md")
    return summary


def _plot(df: pd.DataFrame, fig_dir: Path) -> None:
    agg = df.groupby(["scenario", "mode"])["mean_delay_s"].mean().unstack()[list(GUARD_MODES)]
    agg = agg.loc[["benign", *ATTACKS]]
    fig, ax = plt.subplots(figsize=(11, 4.2))
    w = 0.2
    x = np.arange(len(agg))
    colors = {"off": "#9e9e9e", "monitor": "#f2a541", "rules": "#4a90d9", "full": "#2e7d32"}
    for i, m in enumerate(GUARD_MODES):
        ax.bar(x + (i - 1.5) * w, agg[m], w, label=f"guard: {m}", color=colors[m])
    ax.axhline(agg.loc["benign", "off"], color="k", lw=0.8, ls="--")
    ax.set_xticks(x, [s.replace("_", "\n") for s in agg.index])
    ax.set_ylabel("mean delay incl. still-queued (s/veh)")
    ax.set_title("What each attack does to delay, by guard mode (1 h, attack from minute 20, 3 seeds)")
    ax.legend(ncol=4, fontsize=8)
    fig.tight_layout()
    fig.savefig(fig_dir / "delay_by_attack.png", dpi=150)
    plt.close(fig)


def write_report(s: dict[str, Any], path: Path) -> Path:
    agg = pd.DataFrame(s["agg"])
    lines = ["# NTCIP tamper guard results", "",
             f"{s['runs']} one-hour runs. Attack starts at minute 20; the attacker spoofs the central system's address "
             "and knows the SNMPv1 write community.", "",
             "## Delay (s/veh, incl. vehicles still queued) / unsafe short yellows / minutes in flash / detection (s)", "",
             "| Scenario | off | monitor | rules | full |", "|---|---|---|---|---|"]
    for sc in ("benign", *ATTACKS):
        cells = []
        for m in GUARD_MODES:
            r = agg[(agg.scenario == sc) & (agg["mode"] == m)].iloc[0]
            det = "-" if pd.isna(r.detect_s) else f"{r.detect_s:.0f}"
            cells.append(f"{r.mean_delay_s:.0f} / {r.unsafe_yellows:.0f} / {r.flash_min:.0f} / {det}")
        lines.append(f"| {sc} | " + " | ".join(cells) + " |")
    fp = s["fp"]
    lines += ["", f"## False alarms ({fp['hours']} benign hours, full guard)", "",
              f"* blocked SETs per hour: {fp['blocked_per_h']:.2f}; alerts per hour: {fp['alerted_per_h']:.2f}",
              f"* monitor alarms per hour: {fp['monitor_alarms_per_h']:.2f}; fail-safe actions per hour: {fp['fallbacks_per_h']:.2f}",
              f"* behaviour model: {fp['behaviour_windows_flagged_per_h']:.2f} flagged 60-s windows per hour", "",
              "## Behaviour model (isolation forest on 60-s command windows)", "", "| Attack | Detected (share of seeds) | Mean time to detect (s) |", "|---|---|---|"]
    for a, b in s["behaviour"].items():
        t_det = "-" if b["detect_s"] is None else f"{b['detect_s']:.0f}"
        lines.append(f"| {a} | {b['detected']:.0%} | {t_det} |")
    lat = s["latency"]
    lines += ["", "## Guard latency per SET (in-process)", "",
              f"allowed p50 {lat['set_allowed_p50_us']:.0f} us, p99 {lat['set_allowed_p99_us']:.0f} us; "
              f"blocked p50 {lat['set_blocked_p50_us']:.0f} us, p99 {lat['set_blocked_p99_us']:.0f} us", "",
              "![Delay by attack](figures/delay_by_attack.png)", ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
