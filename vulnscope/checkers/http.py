"""
HTTP security review: response headers and sensitive-path exposure.

Two checks, both single GET requests:

  Headers    - fetch '/', evaluate the security-relevant response headers a
               hardened site is expected to set.
  Exposure   - request a SHORT, fixed list of paths that should never be public
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


class HttpChecker(Checker):
    name = "http"

    def run(self, host, ip, ports):
        for port in sorted(p for p in ports if p in HTTP_PORTS | HTTPS_PORTS):
            tls = port in HTTPS_PORTS
            headers = self._get(host, ip, port, tls, "/")
            if headers is None:
                continue
            yield from self._check_headers(host, port, headers, tls)
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

    def _get(self, host, ip, port, tls, path):
        """Return (status, headers_dict, body_prefix) or None. Sends Host: host
        so name-based vhosts route correctly, but connects to the vetted ip."""
        try:
            c = self._conn(host, ip, port, tls)
            c.request("GET", path, headers={"Host": host, "User-Agent": "vulnscope (authorized scan)"})
            r = c.getresponse()
            body = r.read(2048)
            hdrs = {k.lower(): v for k, v in r.getheaders()}
            c.close()
            return (r.status, hdrs, body)
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
            status, hdrs, body = resp
            # A 200 with real content is exposure. Guard against soft-404s that
            # return 200 with an HTML error page by checking the body does not
            # look like markup for the file types we expect to be plaintext.
            if status == 200 and body and not self._looks_like_html_404(path, body):
                yield self._finding(host, port, title, sev, detail,
                                    evidence=f"GET {path} -> 200, {len(body)}+ bytes",
                                    remediation=fix)

    def _looks_like_html_404(self, path, body):
        text = body[:512].lower()
        # .git/config and .env are plaintext; if we got HTML back it's a catch-all page.
        if path in ("/.git/config", "/.env", "/config.php.bak", "/.aws/credentials"):
            return b"<html" in text or b"<!doctype" in text
        return False
