"""
Turning an error string back into something a human can act on.

scope.py and engine.py raise/record precise, technical messages - that's right
for an audit trail, but "X is not within any allow rule" doesn't tell a first-
time operator what to type to fix it. This module is a pattern table: match
the message vulnscope already produced, attach a plain-English reason and a
concrete fix. It never changes the underlying message (still shown verbatim,
so nothing about the audit trail is lost) - it just adds an explanation next
to it, in the CLI, the HTML report, and the web UI alike.
"""

from __future__ import annotations

import re

# (pattern, reason, fix). First match wins, so put specific patterns first.
_RULES = [
    (re.compile(r"Empty target\.?"),
     "One of the target entries was blank.",
     "Remove empty lines from the target list."),

    (re.compile(r"did not resolve; refusing to scan an unknown target"),
     "DNS lookup for this host returned no records, so vulnscope refused to guess where to connect.",
     "Check the hostname for typos, confirm it resolves from here (e.g. `dig <host>` or `nslookup <host>`), "
     "or scan the IP address directly if you already have it."),

    (re.compile(r"is in a permanently denied range"),
     "This address falls in a range vulnscope refuses unconditionally - loopback, link-local, multicast, "
     "or the 169.254.169.254 cloud-metadata endpoint. No scope rule can override this.",
     "Point vulnscope at the target's real address; this specific range cannot be scanned by design."),

    (re.compile(r"matches a deny rule"),
     "An explicit `deny` line in the scope matches this host or one of its resolved IPs, and deny always "
     "overrides allow.",
     "If this was denied in error, remove or narrow the matching `deny` line in the scope."),

    (re.compile(r"is not within any allow rule"),
     "vulnscope denies by default - nothing in the scope explicitly allows this host or the IP(s) it "
     "resolves to.",
     "Add a line to the scope: `allow <exact-host>` for one host, `allow .domain.com` to cover a whole "
     "domain and its subdomains, or `allow <ip/cidr>` for a network."),

    (re.compile(r"scope (file )?allows nothing"),
     "The scope has no `allow` lines at all, so every target is refused before anything is touched.",
     "Add at least one `allow <target>` line to the scope."),

    (re.compile(r"Malformed scope line"),
     "A line in the scope isn't in the required form.",
     "Each non-comment line must be exactly `allow <target>` or `deny <target>` - check for typos or a "
     "missing keyword on that line."),

    (re.compile(r"port sweep failed"),
     "A low-level network error stopped the port sweep before it finished - e.g. no route to the host, "
     "the network is unreachable, or something actively rejected the connection.",
     "Confirm the target is online and reachable from wherever vulnscope is running, and that a local "
     "firewall or proxy isn't blocking outbound connections."),

    (re.compile(r": dns error:"),
     "Neither public resolver vulnscope queries (1.1.1.1, then 8.8.8.8) answered for the SPF/DMARC/"
     "DNSSEC/CAA lookups.",
     "Check that this machine can reach the internet over UDP port 53 - a restrictive firewall or proxy "
     "is the most common cause."),

    (re.compile(r"invalid ingest JSON"),
     "The ingest field wasn't valid JSON, or wasn't the shape vulnscope expects.",
     "Ingest accepts ReconScope's finding JSON, or a plain {\"host\": [port, port, ...]} map."),
]

# For the generic "{target}: {checker} error: {e}" catch-all in engine.py, look
# inside the wrapped exception text for a further hint before giving up.
_INNER_HINTS = [
    (re.compile(r"timed out|timeout", re.I),
     "the target did not respond within the timeout window",
     "increase the timeout, or the target may be filtering/rate-limiting these probes"),
    (re.compile(r"connection refused", re.I),
     "the target actively refused the connection",
     "the port may have closed between discovery and this check - re-run the scan"),
    (re.compile(r"reset by peer", re.I),
     "the target closed the connection abruptly mid-check",
     "this can happen behind an IPS/WAF that terminates unusual traffic patterns - re-running sometimes succeeds"),
]

_CHECKER_ERROR = re.compile(r"^[^:]+: (\w+) error: (.*)$")


def explain(message: str):
    """Return {"reason": str, "fix": str} for a known error message, or None
    if nothing in the table matches. Never raises."""
    if not message:
        return None
    for pattern, reason, fix in _RULES:
        if pattern.search(message):
            return {"reason": reason, "fix": fix}

    m = _CHECKER_ERROR.match(message)
    if m:
        checker, detail = m.group(1), m.group(2)
        for pattern, hint_reason, hint_fix in _INNER_HINTS:
            if pattern.search(detail):
                return {"reason": f"In the {checker} checker: {hint_reason}.", "fix": hint_fix[0].upper() + hint_fix[1:] + "."}
        return {
            "reason": f"An unexpected error occurred in the {checker} checker while assessing this target.",
            "fix": "This is usually transient (a network hiccup or the target behaving unexpectedly). "
                   "Re-run the scan; if it keeps happening, the target may be actively blocking automated probes.",
        }
    return None
