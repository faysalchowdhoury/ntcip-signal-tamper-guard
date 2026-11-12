"""Point-queue traffic at one intersection, to measure what tampering does to road users.

Per phase: Poisson arrivals, a FIFO queue, discharge at saturation flow during green after a 2-s start-up
lost time. In red flash the intersection runs as an all-way stop: one vehicle every ``flash_headway_s``
for the whole intersection, taken from the longest queue. Delay is time spent in the queue (stopped
delay), so it is a lower bound on control delay.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

import numpy as np

from .controller import ControlledController

STARTUP_LOST_S = 2.0


@dataclass
class Approach:
    vph: float
    lanes: int = 1
    sat_vphpl: float = 1800.0


@dataclass
class QueueModel:
    approaches: dict[int, Approach]
    seed: int = 0
    flash_headway_s: float = 2.5
    rng: np.random.Generator = field(init=False)
    queues: dict[int, deque[float]] = field(init=False)
    credit: dict[int, float] = field(init=False)
    green_for: dict[int, float] = field(init=False)
    flash_credit: float = 0.0
    served: int = 0
    total_delay: float = 0.0
    max_wait: dict[int, float] = field(init=False)

    def __post_init__(self) -> None:
        self.rng = np.random.default_rng(self.seed)
        self.queues = {p: deque() for p in self.approaches}
        self.credit = {p: 0.0 for p in self.approaches}
        self.green_for = {p: 0.0 for p in self.approaches}
        self.max_wait = {p: 0.0 for p in self.approaches}

    def waiting(self) -> dict[int, int]:
        return {p: len(q) for p, q in self.queues.items()}

    def _serve(self, p: int, t: float) -> None:
        a = self.queues[p].popleft()
        w = t - a
        self.total_delay += w
        self.served += 1
        self.max_wait[p] = max(self.max_wait[p], w)

    def step(self, ctl: ControlledController) -> tuple[set[int], set[int]]:
        """Advance one tick against the controller's current display; returns (calls, actuations)."""
        dt, t = ctl.dt, ctl.t
        acts: set[int] = set()
        for p, a in self.approaches.items():
            if self.rng.random() < a.vph * dt / 3600.0:
                self.queues[p].append(t)
                acts.add(p)
        if ctl.flash:
            self.flash_credit += dt / self.flash_headway_s
            while self.flash_credit >= 1.0:
                p = max(self.queues, key=lambda k: len(self.queues[k]))
                if not self.queues[p]:
                    self.flash_credit = 0.0
                    break
                self._serve(p, t)
                self.flash_credit -= 1.0
        else:
            greens = ctl.greens()
            for p, a in self.approaches.items():
                if p in greens:
                    self.green_for[p] += dt
                    if self.green_for[p] >= STARTUP_LOST_S:
                        self.credit[p] += a.lanes * a.sat_vphpl * dt / 3600.0
                        while self.credit[p] >= 1.0 and self.queues[p]:
                            self._serve(p, t)
                            self.credit[p] -= 1.0
                            acts.add(p)
                        if not self.queues[p]:
                            self.credit[p] = min(self.credit[p], 1.0)
                else:
                    self.green_for[p] = 0.0
                    self.credit[p] = 0.0
        calls = {p for p, q in self.queues.items() if q}
        return calls, acts

    def summary(self, t_end: float) -> dict[str, float]:
        """Delay counts vehicles still queued at ``t_end`` with their wait so far; otherwise an attack that
        stops service would look like *lower* delay."""
        queued = [t_end - a for q in self.queues.values() for a in q]
        n = self.served + len(queued)
        max_wait = max([*self.max_wait.values(), *queued, 0.0])
        return {"vehicles": float(n), "mean_delay_s": (self.total_delay + sum(queued)) / max(n, 1),
                "max_wait_s": max_wait, "left_in_queue": float(len(queued))}
