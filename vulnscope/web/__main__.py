"""
    python -m vulnscope.web [--host 127.0.0.1] [--port 8642]

Runs the web interface. Defaults to localhost only - this tool starts scans
against real infrastructure, so it should not be exposed to a network by
default any more than the CLI's authorization requirement is optional.
"""

from __future__ import annotations

import argparse

import uvicorn


def main():
    ap = argparse.ArgumentParser(prog="vulnscope.web")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8642)
    ap.add_argument("--reload", action="store_true", help="auto-reload on code changes (development only)")
    args = ap.parse_args()
    uvicorn.run("vulnscope.web.app:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
