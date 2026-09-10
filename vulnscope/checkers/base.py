"""
Checker base class and the shared connection helper.

Every checker receives an already-vetted IP from the scope guard and must
connect ONLY to that IP, never re-resolve the hostname. Re-resolving would
reopen the DNS-rebinding window the guard just closed. The hostname is still
passed through for TLS SNI and HTTP Host, but the socket goes to the vetted
address.
"""

from __future__ import annotations

import socket
from ..findings import Finding

DEFAULT_TIMEOUT = 6.0


class Checker:
    name = "base"

    def __init__(self, timeout=DEFAULT_TIMEOUT):
        self.timeout = timeout

    def run(self, host, ip, ports):
        """Yield Finding objects. host is the name (for SNI/Host), ip is the
        scope-vetted address to actually connect to, ports is the open set."""
        raise NotImplementedError

    def _finding(self, host, port, title, severity, detail, evidence="", remediation="", reference=""):
        return Finding(
            target=host, port=port, check=self.name, title=title,
            severity=severity, detail=detail, evidence=evidence,
            remediation=remediation, reference=reference,
        )


def tcp_connect(ip, port, timeout):
    """A single non-intrusive TCP connect. Returns True if the port accepted the
    connection. This is a connect() scan, not a SYN scan: it completes the
    handshake and closes cleanly, which is exactly what a normal client does and
    needs no elevated privileges."""
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass
