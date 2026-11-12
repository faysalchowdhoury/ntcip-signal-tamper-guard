"""Command line: ``ntcip-guard study`` (experiments), ``ntcip-guard serve`` (UDP proxy + controller + API)."""

from __future__ import annotations

import argparse
import asyncio
import json

from .vendor.ntcip_ctrl.core.logging import get_logger

log = get_logger(__name__)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ntcip-guard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    st = sub.add_parser("study", help="run all attacks against all guard modes")
    st.add_argument("--site", default="configs/intersection.yaml")
    st.add_argument("--out", default="results/attacks")
    st.add_argument("--seeds", type=int, default=3)
    st.add_argument("--workers", type=int, default=2)
    sv = sub.add_parser("serve", help="emulated controller behind the guard, on UDP")
    sv.add_argument("--site", default="configs/intersection.yaml")
    sv.add_argument("--listen", default="0.0.0.0:1161")
    sv.add_argument("--speedup", type=float, default=1.0)
    a = ap.parse_args(argv)
    if a.cmd == "study":
        from .study import run

        s = run(a.site, a.out, seeds=a.seeds, workers=a.workers)
        print(json.dumps(s["fp"], indent=2))
        return 0
    from .proxy import serve

    host, port = a.listen.rsplit(":", 1)
    asyncio.run(serve(a.site, host, int(port), speedup=a.speedup))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
