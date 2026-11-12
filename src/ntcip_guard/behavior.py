"""Learned profile of normal central-system command traffic.

Every request through the guard is logged as ``(t, pdu, kind)``. Write traffic is summarised in fixed
windows (60 s) as counts of SETs by object kind, plus the number of distinct objects written. Reads are
left out: polling is constant, and an early version that counted it flagged harmless coincidences
(a routine timing walk in the same minute as a valid SET). An
isolation forest is fitted on windows from benign operation only; a window scoring below the
``quantile`` of the training scores is anomalous. This catches command patterns that pass every
per-command rule (for example a slow trickle of central vehicle calls).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest

KINDS = ("min_green_s", "passage_s", "max_green_s", "yellow_s", "red_clear_s", "omit", "hold", "force_off", "veh_call",
         "pattern")
FEATURES = ("n_set", *(f"set_{k}" for k in KINDS), "distinct_set_objects")


def window_features(log: list[tuple[float, str, str, tuple[int, ...]]], t0: float, t1: float,
                    window_s: float = 60.0) -> tuple[np.ndarray, np.ndarray]:
    """``log`` rows are ``(t, pdu, kind, oid)``. Returns (window start times, feature matrix)."""
    edges = np.arange(t0, t1 + 1e-9, window_s)
    starts = edges[:-1]
    x = np.zeros((len(starts), len(FEATURES)))
    objs: list[set[tuple[int, ...]]] = [set() for _ in starts]
    for t, pdu, kind, oid in log:
        k = int((t - t0) // window_s)
        if not 0 <= k < len(starts):
            continue
        if pdu == "get":
            continue  # polling is constant and says nothing about intent; only writes are profiled
        x[k, 0] += 1
        if kind in KINDS:
            x[k, 1 + KINDS.index(kind)] += 1
        objs[k].add(oid)
    x[:, -1] = [len(o) for o in objs]
    return starts, x


@dataclass
class BehaviorModel:
    forest: IsolationForest
    threshold: float

    @classmethod
    def fit(cls, x: np.ndarray, quantile: float = 0.002, seed: int = 0) -> "BehaviorModel":
        f = IsolationForest(n_estimators=300, random_state=seed).fit(x)
        s = f.score_samples(x)
        return cls(f, float(np.quantile(s, quantile)))

    def anomalous(self, x: np.ndarray) -> np.ndarray:
        return self.forest.score_samples(x) < self.threshold
