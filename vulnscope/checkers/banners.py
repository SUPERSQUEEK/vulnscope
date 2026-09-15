"""
Service banner review for SSH/FTP/SMTP/POP3/IMAP.

These protocols send an identification banner unprompted, the instant a client
connects - before any command is sent. Reading it is a passive connect, exactly
what tcp_connect() already does for port discovery; this checker just keeps the
socket open a moment longer to read the line the server offers on its own.

The version table below is small and curated on purpose: it lists a handful of
landmark, unambiguous CVEs identifiable from the banner string alone (the same
"curated for signal, not coverage" stance the port and path lists already
take). It is not a vulnerability database and does not try to be.
"""

from __future__ import annotations

import re
import socket

from .base import Checker

BANNER_PORTS = {21: "ftp", 22: "ssh", 25: "smtp", 110: "pop3", 143: "imap"}

# (compiled pattern over the raw banner, title, severity, detail, reference)
KNOWN_VULNERABLE = [
    (re.compile(r"vsFTPd 2\.3\.4", re.I), "vsftpd 2.3.4 backdoor", "critical",
     "This exact vsftpd build shipped a backdoor (CVE-2011-2523): a ':)' in the username opens a shell on port 6200.",
     "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"),
    (re.compile(r"ProFTPD 1\.3\.3c", re.I), "ProFTPD 1.3.3c backdoor", "critical",
     "This exact ProFTPD build was trojaned at the source-mirror level and contains a backdoor.",
     "https://nvd.nist.gov/vuln/detail/CVE-2010-4221"),
    (re.compile(r"OpenSSH_[1-6]\.[0-9]", re.I), "Outdated OpenSSH major version", "high",
     "OpenSSH versions before 7.0 are past end-of-life and missing years of security fixes.",
     "https://www.openssh.com/releasenotes.html"),
    (re.compile(r"Exim (4\.8[0-9]|4\.9[0-1])", re.I), "Exim version with known RCEs", "high",
     "This Exim range includes several remote-code-execution CVEs (e.g. CVE-2019-10149).",
     "https://nvd.nist.gov/vuln/detail/CVE-2019-10149"),
]


class BannerChecker(Checker):
    name = "banners"

    def run(self, host, ip, ports):
        for port in sorted(p for p in ports if p in BANNER_PORTS):
            banner = self._read_banner(ip, port)
            if not banner:
                continue
            yield from self._evaluate(host, port, banner)

    def _read_banner(self, ip, port):
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((ip, port))
            data = s.recv(256)
            return data.decode("utf-8", "replace").strip()
        except (socket.timeout, OSError):
            return None
        finally:
            try:
                s.close()
            except OSError:
                pass

    def _evaluate(self, host, port, banner):
        service = BANNER_PORTS.get(port, "service")
        has_version = any(ch.isdigit() for ch in banner)
        yield self._finding(host, port, f"{service} banner disclosed",
                             "low" if has_version else "info",
                             f"The {service} service identifies itself as '{banner}'.",
                             evidence=banner,
                             remediation="Suppress or genericise the banner if the service supports it." if has_version else "")
        for pattern, title, sev, detail, ref in KNOWN_VULNERABLE:
            if pattern.search(banner):
                yield self._finding(host, port, title, sev, detail,
                                     evidence=banner, reference=ref,
                                     remediation="Upgrade this service to a current, supported release.")
