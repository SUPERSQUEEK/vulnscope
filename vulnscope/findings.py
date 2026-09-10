"""
Findings and severity.

A finding is one conclusion about one target, with the evidence that produced
it kept attached. Severity uses a small, named scale rather than a raw CVSS
number, because a scanner that reports "6.8" invites false precision - the
inputs to a real CVSS vector (exploitability, privileges required, user
interaction) are things a non-intrusive scanner cannot observe, so inventing
the score would be dishonest. The scale below says what the tool can actually
justify from what it saw.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

# Ordered most severe first. The weight drives sorting and the report summary.
SEVERITY = {
    "critical": 4,   # exploitable-as-observed, or exposure of secrets/source
    "high": 3,       # a weakness an attacker can rely on (e.g. deprecated TLS)
    "medium": 2,     # weakens defence in depth (missing hardening headers)
    "low": 1,        # informational hygiene
    "info": 0,       # context, not a weakness
}


@dataclass
class Finding:
    target: str
    port: int | None
    check: str          # which checker produced this
    title: str
    severity: str
    detail: str         # what was observed
    evidence: str       # the raw thing seen, so the conclusion can be audited
    remediation: str = ""
    reference: str = ""

    def __post_init__(self):
        if self.severity not in SEVERITY:
            raise ValueError(f"Unknown severity {self.severity!r}")

    def weight(self):
        return SEVERITY[self.severity]

    def to_dict(self):
        return asdict(self)


@dataclass
class Report:
    """Everything one run produced. Carries the scope and authorization context
    so the output is self-describing: a report should say what it was allowed to
    do, not just what it found."""
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    authorized_by: str = ""
    scope_summary: str = ""
    targets: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def add(self, finding: Finding):
        self.findings.append(finding)

    def by_severity(self):
        return sorted(self.findings, key=lambda f: (-f.weight(), f.target, f.check))

    def counts(self):
        c = {k: 0 for k in SEVERITY}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def worst(self):
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: f.weight()).severity

    def to_dict(self):
        return {
            "started_at": self.started_at,
            "authorized_by": self.authorized_by,
            "scope_summary": self.scope_summary,
            "targets": self.targets,
            "counts": self.counts(),
            "worst": self.worst(),
            "findings": [f.to_dict() for f in self.by_severity()],
            "errors": self.errors,
        }
