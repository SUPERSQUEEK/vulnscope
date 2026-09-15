"""
HTTP security review: response headers, cookies, CORS, sensitive-path
exposure, and fingerprinting.

Checks, each adding at most one extra GET to '/':

  Headers     - fetch '/', evaluate the security-relevant response headers a
                hardened site is expected to set.
  Cookies     - inspect every Set-Cookie from that same response for the
                Secure/HttpOnly/SameSite attributes.
  Fingerprint - identify CMS/framework from body/header signatures, and match
                the Server banner against a short curated list of landmark CVEs.
  CORS        - one extra GET with a bogus Origin header, to see whether the
                server reflects an arbitrary origin (with credentials allowed).
  Exposure    - request a SHORT, fixed list of paths that should never be public
                (source control metadata, environment files, status endpoints).
                One GET each, no directory brute-forcing, no wordlist. A 200 that
                returns real content is the finding.

The exposure list is deliberately tiny and hand-picked. Content discovery with
a wordlist is a different, noisier activity that belongs behind its own
authorization step - ReconScope documented it as deferred for exactly that
reason, and vulnscope does not sneak it in through the back door.
"""

from __future__ import annotations

import http.client
import re
import socket
import ssl

from .base import Checker

HTTP_PORTS = {80, 8080}
HTTPS_PORTS = {443, 8443}

# Header -> (severity if missing, what it defends against, fix, https_only)
# https_only headers are only meaningful on a TLS response; flagging a missing
# HSTS header on a plaintext :80 endpoint is noise, since HSTS is ignored by
# browsers when delivered over HTTP anyway.
EXPECTED_HEADERS = {
    "strict-transport-security": ("medium", "Without HSTS a network attacker can strip HTTPS and downgrade the connection.", "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."),
    "content-security-policy": ("medium", "No CSP means an injected script runs with full page privileges - the main defence against XSS is absent.", "Define a Content-Security-Policy appropriate to the app."),
    "x-content-type-options": ("low", "Without 'nosniff' a browser may MIME-sniff a response into an executable type.", "Add 'X-Content-Type-Options: nosniff'."),
    "x-frame-options": ("low", "Missing framing protection allows clickjacking (unless a CSP frame-ancestors covers it).", "Add 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive."),
}

# Paths that leak secrets or source when public. Kept short on purpose.
SENSITIVE_PATHS = {
    "/.git/config": ("Exposed Git repository", "critical", "The .git directory is web-accessible; full source and history can be reconstructed.", "Block dotfiles at the web server, or move the repo outside the web root."),
    "/.env": ("Exposed environment file", "critical", "A .env file is web-accessible; these routinely contain database passwords and API keys.", "Remove it from the web root and rotate any exposed secrets."),
    "/server-status": ("Apache server-status exposed", "medium", "mod_status is public, revealing request URLs, client IPs, and server internals.", "Restrict server-status to localhost."),
    "/.aws/credentials": ("Exposed AWS credentials file", "critical", "An AWS credentials file is web-accessible.", "Remove immediately and rotate the keys."),
    "/config.php.bak": ("Backup config file exposed", "high", "A backup of a config file is downloadable in cleartext.", "Delete backup files from the web root."),
}

# body/header signature -> CMS or framework name. First match wins.
CMS_SIGNATURES = [
    (re.compile(rb"wp-content|wp-includes"), "WordPress"),
    (re.compile(rb"/sites/default/|Drupal\.settings"), "Drupal"),
    (re.compile(rb"Joomla!|/media/system/js/core\.js"), "Joomla"),
    (re.compile(rb"content=\"Shopify"), "Shopify"),
    (re.compile(rb"csrf-token.*laravel|laravel_session", re.I), "Laravel"),
]

# Server-header pattern -> landmark, unambiguous CVE. Small and curated, same
# spirit as KNOWN_VULNERABLE in banners.py - not a vulnerability database.
KNOWN_VULNERABLE_SERVERS = [
    (re.compile(r"Apache/2\.4\.(49|50)\b"), "Apache path traversal / RCE (CVE-2021-41773 / CVE-2021-42013)", "critical",
     "This exact Apache build is vulnerable to a path-traversal bug that leads to remote code execution when CGI is enabled.",
     "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"),
    (re.compile(r"nginx/1\.(0\.[0-9]|1\.[0-9]|2\.[0-9])\b"), "End-of-life nginx version", "medium",
     "This nginx version is old enough to predate several years of security fixes.",
     "https://nginx.org/en/security_advisories.html"),
]

# Header name -> attribute the cookie should carry, and why.
COOKIE_ATTR_CHECKS = [
    ("secure", "medium", "sent over HTTP as well as HTTPS if the connection allows it, letting it leak on a downgraded request", "Add the Secure attribute."),
    ("httponly", "medium", "readable by JavaScript, so an XSS bug can steal it directly", "Add the HttpOnly attribute."),
    ("samesite", "low", "sent on cross-site requests, which enables CSRF against endpoints that trust the cookie", "Add SameSite=Lax or SameSite=Strict."),
]


class HttpChecker(Checker):
    name = "http"

    def run(self, host, ip, ports):
        for port in sorted(p for p in ports if p in HTTP_PORTS | HTTPS_PORTS):
            tls = port in HTTPS_PORTS
            resp = self._get(host, ip, port, tls, "/")
            if resp is None:
                continue
            status, hdrs, body, raw_headers = resp
            yield from self._check_headers(host, port, (status, hdrs, body), tls)
            yield from self._check_cookies(host, port, raw_headers)
            yield from self._check_fingerprint(host, port, hdrs, body)
            yield from self._check_cors(host, ip, port, tls)
            yield from self._check_exposure(host, ip, port, tls)

    def _conn(self, host, ip, port, tls):
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            c = http.client.HTTPSConnection(ip, port, timeout=self.timeout, context=ctx)
        else:
            c = http.client.HTTPConnection(ip, port, timeout=self.timeout)
        return c

    def _get(self, host, ip, port, tls, path, extra_headers=None):
        """Return (status, headers_dict, body_prefix, raw_headers) or None.
        raw_headers keeps every header occurrence (needed for repeated
        Set-Cookie lines, which a dict would collapse to the last one). Sends
        Host: host so name-based vhosts route correctly, but connects to the
        vetted ip."""
        try:
            req_headers = {"Host": host, "User-Agent": "vulnscope (authorized scan)"}
            req_headers.update(extra_headers or {})
            c = self._conn(host, ip, port, tls)
            c.request("GET", path, headers=req_headers)
            r = c.getresponse()
            body = r.read(2048)
            raw_headers = r.getheaders()
            hdrs = {k.lower(): v for k, v in raw_headers}
            c.close()
            return (r.status, hdrs, body, raw_headers)
        except (socket.timeout, OSError, http.client.HTTPException):
            return None

    def _check_headers(self, host, port, resp, tls):
        status, hdrs, _ = resp
        server = hdrs.get("server", "")
        if server:
            # Reporting the banner is info; version disclosure is low.
            sev = "low" if any(ch.isdigit() for ch in server) else "info"
            yield self._finding(host, port, "Server banner disclosed", sev,
                                 f"The server identifies itself as '{server}'.",
                                 evidence=f"Server: {server}",
                                 remediation="Suppress or genericise the Server header to avoid version disclosure." if sev == "low" else "")
        for header, (sev, why, fix) in EXPECTED_HEADERS.items():
            # HSTS only means anything over TLS; do not flag it on a plaintext port.
            if header == "strict-transport-security" and not tls:
                continue
            if header not in hdrs:
                yield self._finding(host, port, f"Missing {header}", sev, why,
                                    evidence=f"'{header}' not present in response headers",
                                    remediation=fix)

    def _check_exposure(self, host, ip, port, tls):
        for path, (title, sev, detail, fix) in SENSITIVE_PATHS.items():
            resp = self._get(host, ip, port, tls, path)
            if resp is None:
                continue
            status, hdrs, body, _ = resp
            # A 200 with real content is exposure. Guard against soft-404s that
            # return 200 with an HTML error page by checking the body does not
            # look like markup for the file types we expect to be plaintext.
            if status == 200 and body and not self._looks_like_html_404(path, body):
                yield self._finding(host, port, title, sev, detail,
                                    evidence=f"GET {path} -> 200, {len(body)}+ bytes",
                                    remediation=fix)

    def _check_cookies(self, host, port, raw_headers):
        cookies = [v for k, v in raw_headers if k.lower() == "set-cookie"]
        for cookie in cookies:
            name = cookie.split("=", 1)[0].strip()
            low = cookie.lower()
            for attr, sev, why, fix in COOKIE_ATTR_CHECKS:
                if attr not in low:
                    yield self._finding(host, port, f"Cookie '{name}' missing {attr}", sev,
                                        f"Cookie '{name}' is {why}.",
                                        evidence=cookie, remediation=fix)

    def _check_fingerprint(self, host, port, hdrs, body):
        for pattern, cms in CMS_SIGNATURES:
            if pattern.search(body):
                yield self._finding(host, port, f"{cms} detected", "info",
                                    f"Response content matches {cms}'s known markup signature.",
                                    evidence=f"pattern {pattern.pattern!r} matched response body")
                break  # one CMS identification is enough
        server = hdrs.get("server", "")
        for pattern, title, sev, detail, ref in KNOWN_VULNERABLE_SERVERS:
            if pattern.search(server):
                yield self._finding(host, port, title, sev, detail,
                                    evidence=f"Server: {server}", reference=ref,
                                    remediation="Upgrade to a current, supported release.")

    def _check_cors(self, host, ip, port, tls):
        probe_origin = "https://vulnscope-cors-probe.invalid"
        resp = self._get(host, ip, port, tls, "/", extra_headers={"Origin": probe_origin})
        if resp is None:
            return
        _, hdrs, _, _ = resp
        acao = hdrs.get("access-control-allow-origin", "")
        acac = hdrs.get("access-control-allow-credentials", "").lower() == "true"
        if acao == probe_origin:
            sev = "high" if acac else "medium"
            detail = ("The server reflects an arbitrary Origin back in "
                      "Access-Control-Allow-Origin" + (" and allows credentials" if acac else "") +
                      ", so any site can read this endpoint's responses" +
                      (" while authenticated as the visiting user." if acac else "."))
            yield self._finding(host, port, "CORS reflects arbitrary origin", sev, detail,
                                evidence=f"Origin: {probe_origin} -> Access-Control-Allow-Origin: {acao}"
                                         + (", Access-Control-Allow-Credentials: true" if acac else ""),
                                remediation="Validate Origin against an explicit allow-list instead of reflecting it.")

    def _looks_like_html_404(self, path, body):
        text = body[:512].lower()
        # .git/config and .env are plaintext; if we got HTML back it's a catch-all page.
        if path in ("/.git/config", "/.env", "/config.php.bak", "/.aws/credentials"):
            return b"<html" in text or b"<!doctype" in text
        return False
