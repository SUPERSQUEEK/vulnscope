# vulnscope

The scanning layer after reconnaissance. Given a target you are authorized to test, it assesses what is exposed and where it is weak — **without ever crossing into exploitation.**

Companion to [ReconScope](https://github.com/SUPERSQUEEK/reconscope): recon finds what is *there*; vulnscope assesses what is *wrong with it*. Point vulnscope at ReconScope's JSON output and it evaluates exactly what recon discovered.

```console
$ python -m vulnscope --scope scope.txt --authorized-by "Amir (own infra)" amirslm.com

vulnscope  2026-09-10T17:41:04+00:00
authorized by: Amir (own infra)
scope: 1 host(s), 0 suffix(es), 0 net(s) allowed
==================================================================
findings  critical:0  high:0  medium:2  low:4  info:6

[MEDIUM] Missing content-security-policy  amirslm.com:443
    No CSP means an injected script runs with full page privileges.
    fix: Define a Content-Security-Policy appropriate to the app.
...
```

---

## The line it will not cross

Every scanner is dual-use, so the boundary is drawn explicitly and enforced in code:

- **Non-intrusive only.** TCP connect (never SYN/stealth), one GET per URL, a TLS handshake it reads and closes. No exploitation, no brute force, no fuzzing, no payloads, no directory brute-forcing. It tells you where to look; it never kicks the door.
- **Fail-closed scope, checked before every connection.** A target is refused unless it matches an explicit `allow` rule and no `deny` rule. There is no "scan everything" flag.
- **Authorization is recorded, not assumed.** `--authorized-by` is required and printed on every report. The tool enforces the scope you give it; it cannot know your authority is genuine, and it says so.

> Only point this at systems you are authorized to test.

## What it checks

| Checker | Looks for | Non-intrusive because |
|---|---|---|
| **ports** | A curated set of common service ports; flags database/RDP/Redis/Telnet exposed to the internet as findings in their own right | One TCP connect per port, completed and closed like any client |
| **tls** | Deprecated protocols (TLS ≤1.1), expired / self-signed / unverifiable certificates, certs expiring within 14 days, TLS 1.2-without-1.3 | Completes a normal handshake, reads the certificate, closes |
| **http** | Missing security headers (HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`), server-version disclosure, and a short fixed list of sensitive paths (`/.git/config`, `/.env`, `/server-status`, …) | One GET per path — no wordlist, no content discovery |

Findings carry a severity, the evidence that produced them, and a remediation. Severity is a **named scale, not a fabricated CVSS number** — the real CVSS inputs (exploitability, privileges required) are things a non-intrusive scanner cannot observe, so inventing a score would be false precision.

## Design decisions worth defending

**Scope is enforced immediately before each connection, and re-checked against every resolved IP.** ReconScope validated scope twice — at scheduling and before each packet — because a check that runs once can be beaten by DNS rebinding: a hostname passes the check, then resolves somewhere new before the socket opens. vulnscope resolves the host inside the guard, checks *every* returned address, and hands the vetted IP to the checker, which connects to that IP and never re-resolves. A permitted hostname cannot become a pivot to a denied address.

**A permanent-deny list that no scope file can override** blocks loopback, link-local (including the `169.254.169.254` cloud-metadata endpoint — the classic SSRF pivot), and multicast. A careless or hostile scope file cannot re-enable them.

**The port sweep runs in parallel with a short discovery timeout.** A sequential sweep pays the full timeout for every *filtered* port (dropped, not refused), turning twenty ports into two minutes of waiting. One thread per port with a 2-second discovery timeout brings a full scan to about four seconds. Discovery only needs to know whether a port answers, so its timeout is deliberately lower than the checkers'.

**The exit code encodes the worst finding** (`0` clean · `1` low/medium · `2` high · `3` critical), so vulnscope can gate a CI pipeline: fail the build if a deploy introduces a critical exposure.

## The recon handoff

```bash
# assess exactly what ReconScope found, instead of re-sweeping
python -m vulnscope --scope scope.txt --authorized-by "..." --ingest recon-export.json
```

`--ingest` accepts ReconScope's finding JSON or a plain `{"host": [ports]}` map, reduces it to open ports per host, and assesses those directly. This is the seam that makes vulnscope a *layer* rather than a standalone tool.

## Usage

```bash
python -m vulnscope --scope scope.txt --authorized-by "you" host1 host2 ...
python -m vulnscope --scope scope.txt --authorized-by "you" --ingest recon.json
python -m vulnscope --scope scope.txt --authorized-by "you" --html report.html host
python -m vulnscope --scope scope.txt --authorized-by "you" --json report.json host
```

A scope file is `allow`/`deny` lines over hostnames, `.suffixes`, IPs, and CIDRs:

```
allow .example.com          # the domain and every subdomain
allow 192.0.2.0/24
deny  admin.example.com     # deny overrides allow
```

## Limitations

Stated plainly, because they bound what a clean report means:

- **Certificate expiry needs a verifying handshake.** Python returns an empty certificate dict for a handshake done with verification off, so expiry is read from the *verified* path; when a cert fails to verify, the tool reports the verification failure itself rather than guessing dates from raw DER. A valid, trusted cert is fully parsed.
- **The port list is curated, not exhaustive.** It targets signal, not coverage. For a real port scan, use ReconScope's nmap adapter and hand the result to `--ingest`.
- **No authenticated scanning.** It sees what an unauthenticated visitor sees — which is the attacker's view, and the point, but it will not find issues that require a login.
- **Findings are what can be observed without intrusion.** A missing header is a fact; whether it is exploitable depends on the app. Severities reflect observable weakness, not confirmed exploitability.

## GUI

A tkinter desktop app ships alongside the CLI - no extra dependencies, since
tkinter is part of the Python standard library on Windows.

```bash
python -m vulnscope.gui          # or double-click vulnscope-gui.pyw
```

Enter target(s) and an authorization string, press **Scan**, and findings
appear in a severity-coloured table; selecting one shows its evidence and fix.
**Save HTML** / **Save JSON** export the same reports as the CLI. The scan runs
on a worker thread and communicates with the UI through a queue drained on a
timer - the standard thread-safe tkinter pattern - so the window stays
responsive while a scan is in flight. The authorization field is required here
exactly as it is on the command line.

## Requires

Python 3.10+ (standard library only). No dependencies.

## License

MIT
