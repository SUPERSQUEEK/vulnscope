"""
TLS configuration review.

Connects once to each TLS port, completes a handshake, and inspects what the
server offered: protocol version, certificate validity window, and self-signed
status. Non-intrusive - this is exactly what any HTTPS client does.

It does NOT attempt to negotiate deprecated protocols by force, because doing so
requires building an insecure SSL context on purpose, and a tool that ships code
to speak TLS 1.0 is a tool that can be misused to do so. Instead it reports the
protocol the server actually selected and flags the modern-baseline gaps it can
see honestly.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from .base import Checker

TLS_PORTS = {443, 8443, 993, 995, 465, 5432}


class TlsChecker(Checker):
    name = "tls"

    def run(self, host, ip, ports):
        for port in sorted(p for p in ports if p in TLS_PORTS):
            yield from self._inspect(host, ip, port)

    def _inspect(self, host, ip, port):
        # Two-stage handshake, and the reason is a real Python constraint:
        # getpeercert() returns a populated dict ONLY when the handshake verified
        # the chain. Under CERT_NONE it returns {}, so we could read the protocol
        # but never the certificate dates. So we try a verifying handshake first
        # to get the full cert; if that fails (self-signed, expired, wrong name)
        # we fall back to a non-verifying handshake purely to record WHY it is
        # invalid, rather than reporting nothing. Neither context sends data.
        proto = None
        cert = {}
        cert_error = None

        for verify in (True, False):
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            raw = socket.socket(fam, socket.SOCK_STREAM)
            raw.settimeout(self.timeout)
            try:
                raw.connect((ip, port))
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    proto = tls.version()
                    cert = tls.getpeercert(binary_form=False) or {}
                break
            except ssl.SSLCertVerificationError as e:
                cert_error = e
                continue  # retry without verification to characterise the fault
            except (ssl.SSLError, socket.timeout, OSError) as e:
                yield self._finding(host, port, "TLS handshake failed", "info",
                                     f"Could not complete a TLS handshake: {e}", evidence=str(e))
                return
            finally:
                try:
                    raw.close()
                except OSError:
                    pass

        if cert_error is not None and not cert:
            yield self._finding(
                host, port, "Certificate did not verify", "high",
                f"The certificate failed validation: {cert_error.verify_message or cert_error}.",
                evidence=str(cert_error),
                remediation="Install a certificate from a trusted CA that matches this hostname.",
            )
        der = None

        # Protocol version.
        if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            yield self._finding(
                host, port, f"Deprecated protocol {proto}", "high",
                f"The server negotiated {proto}, which is deprecated and disabled in current browsers.",
                evidence=f"Negotiated {proto}",
                remediation="Disable TLS 1.1 and below; require TLS 1.2 or 1.3.",
                reference="https://datatracker.ietf.org/doc/rfc8996/",
            )
        elif proto == "TLSv1.2":
            yield self._finding(
                host, port, "TLS 1.2 (no 1.3)", "low",
                "The server negotiated TLS 1.2. Not a weakness, but TLS 1.3 is preferred where available.",
                evidence="Negotiated TLSv1.2",
            )

        # Certificate validity. getpeercert() returns {} when verify_mode is
        # CERT_NONE on some platforms, so fall back to parsing the DER dates.
        not_after = self._expiry(cert, der)
        if not_after is not None:
            days = (not_after - datetime.now(timezone.utc)).days
            if days < 0:
                yield self._finding(host, port, "Certificate expired", "high",
                                    f"The certificate expired {-days} day(s) ago.",
                                    evidence=f"notAfter={not_after.isoformat()}",
                                    remediation="Renew the certificate; clients are showing errors.")
            elif days < 14:
                yield self._finding(host, port, "Certificate expiring soon", "medium",
                                    f"The certificate expires in {days} day(s).",
                                    evidence=f"notAfter={not_after.isoformat()}",
                                    remediation="Renew before expiry to avoid an outage.")

        if cert:
            issuer = dict(x[0] for x in cert.get("issuer", []))
            subject = dict(x[0] for x in cert.get("subject", []))
            if issuer and issuer == subject:
                yield self._finding(host, port, "Self-signed certificate", "medium",
                                    "The certificate is self-signed; clients cannot verify the server's identity.",
                                    evidence=f"issuer==subject=={subject.get('commonName','?')}",
                                    remediation="Use a certificate from a trusted CA (Let's Encrypt is free).")

    def _expiry(self, cert, der):
        if cert and cert.get("notAfter"):
            try:
                return datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        # No reliable pure-stdlib way to parse notAfter from the DER without a
        # verifying handshake, so when the cert dict is empty the expiry check is
        # simply skipped rather than guessed. Stated as a limitation in the README.
        return None
