"""
Rendering: a coloured console report, a JSON export, and a standalone HTML file.

The HTML is self-contained (inline CSS, no assets) so a report can be handed to
someone as a single file. All three share the same ordering - most severe first
- and all three lead with the authorization context, because a scan report that
does not state what it was permitted to do is missing the most important line.
"""

from __future__ import annotations

import json
import html

SEV_COLOR = {"critical": "31;1", "high": "33;1", "medium": "36", "low": "90", "info": "90"}
SEV_HTML = {"critical": "#e2554f", "high": "#e0a33a", "medium": "#7aa2ff", "low": "#6b7684", "info": "#3a424c"}


def console(report):
    out = []
    c = report.counts()
    out.append("\033[36mvulnscope\033[0m  " + report.started_at)
    out.append(f"authorized by: {report.authorized_by or '(unnamed)'}")
    out.append(f"scope: {report.scope_summary}")
    out.append(f"targets: {', '.join(report.targets)}")
    out.append("=" * 66)
    summary = "  ".join(f"{k}:{c[k]}" for k in ("critical", "high", "medium", "low", "info"))
    out.append("findings  " + summary)
    out.append("")
    for f in report.by_severity():
        col = SEV_COLOR[f.severity]
        loc = f"{f.target}:{f.port}" if f.port else f.target
        out.append(f"\033[{col}m[{f.severity.upper()}]\033[0m {f.title}  \033[90m{loc}\033[0m")
        out.append(f"    {f.detail}")
        if f.evidence:
            out.append(f"    \033[90mevidence: {f.evidence}\033[0m")
        if f.remediation:
            out.append(f"    \033[90mfix: {f.remediation}\033[0m")
        out.append("")
    if report.errors:
        out.append("errors / refusals:")
        for e in report.errors:
            out.append(f"    {e}")
    return "\n".join(out)


def to_json(report):
    return json.dumps(report.to_dict(), indent=2)


def to_html(report):
    c = report.counts()
    rows = []
    for f in report.by_severity():
        loc = f"{html.escape(f.target)}:{f.port}" if f.port else html.escape(f.target)
        parts = [f"<p class='detail'>{html.escape(f.detail)}</p>"]
        if f.evidence:
            parts.append(f"<p class='ev'>evidence: {html.escape(f.evidence)}</p>")
        if f.remediation:
            parts.append(f"<p class='fix'>fix: {html.escape(f.remediation)}</p>")
        if f.reference:
            parts.append(f"<p class='ev'><a href='{html.escape(f.reference)}'>{html.escape(f.reference)}</a></p>")
        rows.append(
            f"<div class='f' style='border-color:{SEV_HTML[f.severity]}'>"
            f"<h3><span class='sev' style='color:{SEV_HTML[f.severity]}'>{f.severity.upper()}</span> "
            f"{html.escape(f.title)} <span class='loc'>{loc}</span></h3>{''.join(parts)}</div>"
        )
    chips = " ".join(
        f"<span class='chip' style='color:{SEV_HTML[k]}'>{k} {c[k]}</span>"
        for k in ("critical", "high", "medium", "low", "info")
    )
    errs = ""
    if report.errors:
        items = "".join(f"<li>{html.escape(e)}</li>" for e in report.errors)
        errs = f"<h2>Refusals &amp; errors</h2><ul class='errs'>{items}</ul>"
    return f"""<!doctype html><html><head><meta charset='utf-8'>
<title>vulnscope report</title><style>
body{{background:#0b0d10;color:#e8ecf1;font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif;max-width:920px;margin:0 auto;padding:40px 20px}}
h1{{font-size:1.4rem;margin:0 0 4px}}h2{{font-size:.8rem;text-transform:uppercase;letter-spacing:.08em;color:#8b95a3;margin:30px 0 10px}}
.meta{{color:#8b95a3;font-size:.85rem;margin-bottom:4px}}
.chips{{margin:18px 0}}.chip{{border:1px solid #232a33;border-radius:5px;padding:3px 9px;margin-right:6px;font-size:.8rem}}
.f{{border-left:3px solid #6b7684;background:#14181d;padding:13px 17px;margin:11px 0;border-radius:0 8px 8px 0}}
.f h3{{margin:0 0 6px;font-size:.95rem;font-weight:600}}.sev{{font-size:.75rem;margin-right:6px}}
.loc{{color:#6b7684;font-family:ui-monospace,monospace;font-size:.8rem;font-weight:400}}
.detail{{margin:4px 0}}.ev,.fix{{color:#8b95a3;font-size:.82rem;margin:3px 0}}.fix{{color:#9fd3a8}}
.ev{{font-family:ui-monospace,monospace}}a{{color:#7aa2ff}}.errs{{color:#8b95a3;font-size:.85rem}}
</style></head><body>
<h1>vulnscope report</h1>
<p class='meta'>{html.escape(report.started_at)}</p>
<p class='meta'>authorized by: {html.escape(report.authorized_by or '(unnamed)')}</p>
<p class='meta'>scope: {html.escape(report.scope_summary)}</p>
<p class='meta'>targets: {html.escape(', '.join(report.targets))}</p>
<div class='chips'>{chips}</div>
{''.join(rows) if rows else "<p class='meta'>No findings.</p>"}
{errs}
</body></html>"""
