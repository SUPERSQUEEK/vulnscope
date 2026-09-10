"""
Command-line entry point.

    python -m vulnscope --scope scope.txt --authorized-by "Amir (own infra)" TARGET ...

The authorization arguments are not optional theatre. --scope must point at a
file, and it must actually place each target in scope, or the target is refused.
There is no flag to disable the scope check, and --authorized-by is required so
the report and audit line record who claimed the authority to run it.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from .scope import Scope, ScopeError
from .engine import run_scan
from . import reporting


def _load_scope(path):
    with open(path, encoding="utf-8") as fh:
        return Scope.from_lines(fh.readlines())


def _load_ingest(path):
    """Accept ReconScope-style JSON, or a simple {host: [ports]} map, and reduce
    it to {host: set(ports)}. This is the seam that makes vulnscope the layer
    after recon: point it at recon output and it assesses what recon found."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    out = {}
    if isinstance(data, dict) and "findings" in data:
        for f in data["findings"]:
            host = f.get("target") or f.get("host")
            port = f.get("port")
            if host and port:
                out.setdefault(host, set()).add(int(port))
    elif isinstance(data, dict):
        for host, ports in data.items():
            out[host] = {int(p) for p in ports}
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="vulnscope",
        description="Governed, non-intrusive vulnerability assessment. The scanning layer after reconnaissance.",
    )
    ap.add_argument("targets", nargs="*", help="hostnames or IPs to assess")
    ap.add_argument("--scope", required=True, help="path to the scope file (fail-closed allow/deny rules)")
    ap.add_argument("--authorized-by", required=True, help="who authorized this scan (recorded in the report)")
    ap.add_argument("--ingest", help="JSON of prior recon output to assess instead of sweeping ports")
    ap.add_argument("--timeout", type=float, default=6.0, help="per-connection timeout in seconds")
    ap.add_argument("--json", metavar="PATH", help="write JSON report to PATH")
    ap.add_argument("--html", metavar="PATH", help="write HTML report to PATH")
    ap.add_argument("--quiet", action="store_true", help="suppress progress lines")
    args = ap.parse_args(argv)

    try:
        scope = _load_scope(args.scope)
    except (OSError, ScopeError) as e:
        print(f"scope error: {e}", file=sys.stderr)
        return 2
    if scope.is_empty():
        print("scope error: the scope file allows nothing. Add at least one 'allow' rule.", file=sys.stderr)
        return 2

    ingest = None
    targets = list(args.targets)
    if args.ingest:
        try:
            ingest = _load_ingest(args.ingest)
        except (OSError, json.JSONDecodeError, ValueError) as e:
            print(f"ingest error: {e}", file=sys.stderr)
            return 2
        if not targets:
            targets = list(ingest.keys())

    if not targets:
        print("no targets given (pass them as arguments or via --ingest)", file=sys.stderr)
        return 2

    scope_summary = (
        f"{len(scope.allow_hosts)} host(s), {len(scope.allow_suffixes)} suffix(es), "
        f"{len(scope.allow_nets)} net(s) allowed"
    )
    progress = (lambda m: None) if args.quiet else (lambda m: print(f"  {m}", file=sys.stderr))

    report = run_scan(
        targets, scope,
        authorized_by=args.authorized_by, scope_summary=scope_summary,
        ingest=ingest, timeout=args.timeout, on_event=progress,
    )

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    print(reporting.console(report))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(reporting.to_json(report))
        print(f"\nJSON written to {args.json}", file=sys.stderr)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(reporting.to_html(report))
        print(f"HTML written to {args.html}", file=sys.stderr)

    # Exit code encodes the worst finding, so this can gate CI:
    #   0 nothing above info | 1 low/medium | 2 high | 3 critical
    worst = report.worst()
    return {"info": 0, "low": 1, "medium": 1, "high": 2, "critical": 3}[worst]


if __name__ == "__main__":
    sys.exit(main())
