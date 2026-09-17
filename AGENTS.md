# AGENTS.md

Context for AI coding agents working on vulnscope.

## What this project is

vulnscope is a **defensive, non-intrusive vulnerability assessment tool**. It is
the assessment layer after reconnaissance: given targets the operator is
authorized to test, it reports what is exposed and where it is weak, and it
stops there. It does not exploit, and it is designed so that it cannot be
casually turned into something that does.

Every scanner is dual-use, so this repository draws the boundary explicitly and
enforces it in code rather than in documentation. The work here is the
defensive half: vulnerability *validation* and remediation guidance for
infrastructure the operator owns. If a requested change would move the tool
across that line, say so instead of implementing it.

## Invariants — do not break these

These are load-bearing. They are the reason the tool is safe to run, and
several of them exist because the obvious implementation is subtly wrong.

1. **Non-intrusive only.** TCP `connect()` (never SYN/stealth — see
   `checkers/base.py:tcp_connect`), one GET per URL, a TLS handshake that is
   read and closed. Never add exploitation, brute force, fuzzing, payloads,
   directory/content discovery, or wordlists. The curated sensitive-path list
   in `checkers/http.py` is a short fixed list, not a wordlist, and stays that
   way.
2. **`guard()` is called immediately before every socket.** See
   `scope.py:guard`. Fail-closed: a target is refused unless it matches an
   explicit `allow` rule and no `deny` rule. There is no "scan everything"
   flag and none may be added.
3. **Checkers connect to the vetted IP the guard returned; they never
   re-resolve the hostname.** Re-resolving reopens the DNS-rebinding window
   `guard()` just closed. The hostname is still passed through for TLS SNI and
   the HTTP `Host` header, but the socket goes to the vetted address.
4. **`PERMANENTLY_DENIED` overrides any scope file.** Loopback, link-local
   (including `169.254.169.254`, the cloud-metadata SSRF pivot), and multicast
   are unconditionally refused so a careless or hostile scope file cannot
   re-enable them.
5. **Authorization is required in every interface.** `--authorized-by` and a
   non-empty scope on the CLI; `authorized_by` and at least one `allow` line in
   the web API; the same fields in the tkinter GUI. A new interface inherits
   this requirement — the web layer is a different way to drive the same
   governed tool, not a looser one.
6. **Severity stays a named scale, never a fabricated CVSS number.** See the
   rationale in `findings.py`. The real CVSS inputs (exploitability, privileges
   required) are unobservable to a non-intrusive scanner, so a numeric score
   would be false precision.
7. **A checker must never abort the whole run.** `engine.py` wraps each checker
   in a try/except and records the failure in `report.errors`. Keep that
   contract when adding checkers.
8. **The exit code encodes the worst finding:** `0` nothing above info, `1`
   low/medium, `2` high, `3` critical. This is a public contract — it gates CI
   pipelines. Do not renumber it.
9. **The web UI binds localhost by default.** It starts scans against real
   infrastructure; `--host 0.0.0.0` stays an explicit opt-in.
10. **Every finding carries its evidence.** A conclusion without the raw
    observation that produced it cannot be audited, and unauditable findings
    are the failure mode this tool exists to avoid.

## Layout

```
vulnscope/
  scope.py          fail-closed allow/deny policy + guard(). The most
                    security-critical file in the repo.
  engine.py         guards each target, orders the checkers, collects findings
  findings.py       Finding / Report dataclasses, severity scale
  reporting.py      console / JSON / standalone-HTML renderers
  dnsclient.py      minimal DNS client (stdlib only)
  __main__.py       CLI entry point
  gui.py            tkinter desktop app
  checkers/
    base.py         Checker base class + tcp_connect
    ports.py        parallel sweep, short discovery timeout; runs FIRST and
                    hands the open-port set to every later checker
    tls.py          protocol versions, certificate validity/expiry
    http.py         security headers, cookies, CORS, fingerprinting, CVEs
    dns.py          SPF / DMARC / DNSSEC / CAA — never touches the target
    banners.py      reads unprompted service banners; sends nothing
  web/              FastAPI shell over the same engine (app, store, static/)
```

`PortChecker` runs first by design. `DnsChecker` is the one checker that runs
regardless of open ports, because it queries a public resolver about records the
domain owner already published and never connects to the target at all.

## Conventions

- **Python 3.10+, standard library only** for the CLI and the tkinter GUI. No
  dependencies. Only `web/` may import third-party packages (`fastapi`,
  `uvicorn`, in `requirements-web.txt`). Keep it that way — the CLI running
  anywhere Python runs is a feature.
- `from __future__ import annotations` at the top of every module.
- Dataclasses for data, plain functions for behaviour.
- **Module docstrings explain *why*, not *what*.** Read a few before writing —
  they record design decisions and the failure modes that motivated them.
  Match that register: a comment earns its place by explaining a non-obvious
  reason, not by narrating the line below it.
- The web layer must not reimplement scanning logic. It drives `engine`,
  `scope`, and `reporting`.
- Docstrings and code comments use plain hyphens rather than em dashes, since
  the console output is read in Windows terminals. The README is prose and does
  use them; the constraint applies to source files.

## Running and verifying

There is **no automated test suite** — worth knowing before you assume `pytest`
will catch a regression. Verify changes by running the tool against
infrastructure you own, with an explicit scope file:

```bash
python -m vulnscope --scope scope.txt --authorized-by "you (own infra)" your-host.example
python -m vulnscope.web        # http://127.0.0.1:8642
python -m vulnscope.gui
```

`scope.example.txt` shows the format. `scope.txt` is gitignored, as are `*.json`
and `*.html` at the repo root, so generated reports do not get committed.

Changes to `scope.py` deserve the most care in this repo: exercise both the
allow and the deny path, a multi-A-record host, a literal IP, and a target that
should be refused. A scope regression is the one bug class here that turns a
safe tool into an unsafe one.

If adding a checker: subclass `Checker`, yield `Finding`s via `self._finding`,
register it in `engine.py`, and document in the README table *why* the new check
is non-intrusive. That column is not decoration — it is the argument that the
tool stays within its stated line.
