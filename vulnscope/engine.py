"""
The engine: guard each target, run the checkers, collect findings.

Order matters. PortChecker runs first and hands the discovered open-port set to
every checker after it, so the TLS and HTTP checks only touch ports that are
actually listening. Each target is guarded immediately before its checkers run,
and the guard returns the vetted IP that every checker then connects to.
"""

from __future__ import annotations

from .scope import guard, ScopeError
from .findings import Report
from .checkers.ports import PortChecker
from .checkers.tls import TlsChecker
from .checkers.http import HttpChecker


def run_scan(targets, scope, authorized_by, scope_summary, ingest=None, timeout=6.0, on_event=None):
    """targets: list of hostnames/IPs. ingest: {target: set(ports)} from an
    external scanner, if provided. on_event: optional callback(str) for progress."""
    report = Report(authorized_by=authorized_by, scope_summary=scope_summary, targets=list(targets))

    def emit(msg):
        if on_event:
            on_event(msg)

    port_checker = PortChecker(timeout=timeout)
    followups = [TlsChecker(timeout=timeout), HttpChecker(timeout=timeout)]

    for target in targets:
        # Fail-closed authorization, immediately before we touch anything.
        try:
            ips = guard(scope, target)
        except ScopeError as e:
            report.errors.append(f"REFUSED {target}: {e}")
            emit(f"refused {target}: {e}")
            continue

        ip = ips[0]
        emit(f"scanning {target} ({ip})")

        preset = ingest.get(target) if ingest else None
        port_checker.discovered = set()
        try:
            for f in port_checker.run(target, ip, preset or set()):
                report.add(f)
        except OSError as e:
            report.errors.append(f"{target}: port sweep failed: {e}")

        open_ports = getattr(port_checker, "discovered", set()) or (preset or set())
        if not open_ports:
            emit(f"  no open ports found on {target}")
            continue

        for checker in followups:
            try:
                for f in checker.run(target, ip, open_ports):
                    report.add(f)
            except Exception as e:  # a checker must never abort the whole run
                report.errors.append(f"{target}: {checker.name} error: {e}")

    return report
