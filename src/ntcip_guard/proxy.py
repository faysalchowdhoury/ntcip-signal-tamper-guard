"""Live deployment: the emulated controller runs in (optionally accelerated) real time behind the guard,
which listens for SNMP on UDP. Central software points at the guard's address instead of the controller's.

In the field the guard would forward to the controller over the cabinet network and the controller's
own SNMP port would be reachable only from the guard (switch ACL). Here the "upstream" is the in-process
agent, so the same code path is exercised without hardware.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field

from .controller import ControlledController
from .guard import Guard
from .mib import Agent, MibView
from .monitor import RuntimeMonitor
from .policy import PolicyEngine
from .scenarios import load_site
from .traffic import QueueModel
from .vendor.ntcip_ctrl.core.logging import get_logger

log = get_logger(__name__)


@dataclass
class GuardedSite:
    site_path: str
    speedup: float = 1.0
    mode: str = "full"
    ctl: ControlledController = field(init=False)
    guard: Guard = field(init=False)
    monitor: RuntimeMonitor = field(init=False)
    _clock: asyncio.Task[None] | None = None
    _transport: asyncio.DatagramTransport | None = None

    def __post_init__(self) -> None:
        site = load_site(self.site_path)
        self.ctl = ControlledController(site.timing, "actuated")
        self.monitor = RuntimeMonitor(self.ctl, site.policy, site.timing)
        self.guard = Guard(Agent(MibView(self.ctl)).handle, PolicyEngine(site.policy), self.monitor, lambda: self.ctl.t,
                           mode=self.mode)
        self.traffic = QueueModel(site.approaches, seed=0)

    async def _run_clock(self) -> None:
        while True:
            calls, acts = self.traffic.step(self.ctl)
            self.ctl.step(calls, acts)
            self.monitor.observe(self.traffic.waiting())
            await asyncio.sleep(self.ctl.dt / self.speedup)

    async def start(self, host: str = "127.0.0.1", port: int = 1161) -> tuple[str, int]:
        site = self

        class _P(asyncio.DatagramProtocol):
            def connection_made(self, transport: asyncio.BaseTransport) -> None:
                self.transport = transport

            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                reply = site.guard.handle(data, addr[0])
                if reply is not None:
                    self.transport.sendto(reply, addr)  # type: ignore[attr-defined]

        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(_P, local_addr=(host, port))
        self._clock = asyncio.create_task(self._run_clock())
        addr = self._transport.get_extra_info("sockname")
        log.info("guard.listening", extra={"host": addr[0], "port": addr[1]})
        return addr[0], addr[1]

    async def stop(self) -> None:
        if self._clock:
            self._clock.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._clock
        if self._transport:
            self._transport.close()


async def serve(site_path: str, host: str, port: int, *, speedup: float = 1.0) -> None:
    import uvicorn

    from .api.app import create_app

    gs = GuardedSite(site_path, speedup)
    await gs.start(host, port)
    server = uvicorn.Server(uvicorn.Config(create_app(gs), host=host, port=8000, log_level="warning"))
    try:
        await server.serve()
    finally:
        await gs.stop()
