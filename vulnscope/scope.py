"""
Fail-closed scope enforcement.

The single most important line in a scanning tool is the one that decides
whether a target is allowed to be touched. ReconScope enforced scope twice -
when a job was scheduled and again immediately before each packet - because a
scope check that runs once can be defeated by DNS rebinding, redirects, or a
hostname that resolves somewhere new between the check and the connection.

vulnscope keeps that discipline. Every check calls guard() immediately before
it opens a socket, and guard() denies by default: a target is refused unless it
matches an explicit allow rule AND matches no deny rule. There is no "allow
everything" setting, on purpose.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field


class ScopeError(Exception):
    """Raised when a target is refused. Never caught silently - a scope denial
    must always surface to the operator and the audit log."""


# Ranges that may never be scanned regardless of what the scope file says.
# Scanning these is either pointless (loopback), actively hostile to shared
# infrastructure (link-local, multicast), or a way to turn a scanner into an
# SSRF pivot against a cloud metadata endpoint (169.254.169.254). Denying them
# unconditionally means a careless or malicious scope file cannot re-enable them.
PERMANENTLY_DENIED = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local, incl. cloud metadata
    ipaddress.ip_network("224.0.0.0/4"),      # multicast
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]


@dataclass
class Scope:
    """An allow/deny policy for hostnames and IP networks.

    allow_hosts / deny_hosts are exact hostnames (case-insensitive).
    allow_nets / deny_nets are ip_network objects.
    allow_suffixes lets a whole domain be permitted, e.g. ".example.com".
    """

    allow_hosts: set = field(default_factory=set)
    allow_suffixes: list = field(default_factory=list)
    allow_nets: list = field(default_factory=list)
    deny_hosts: set = field(default_factory=set)
    deny_nets: list = field(default_factory=list)

    @classmethod
    def from_lines(cls, lines):
        """Parse a scope file. Each line is 'allow <target>' or 'deny <target>'.
        A target is a hostname, a hostname suffix beginning with '.', an IP, or
        a CIDR. Blank lines and '#' comments are ignored."""
        s = cls()
        for raw in lines:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 2 or parts[0] not in ("allow", "deny"):
                raise ScopeError(f"Malformed scope line: {raw!r} (expected 'allow <target>' or 'deny <target>')")
            action, target = parts[0], parts[1].lower()
            allow = action == "allow"
            net = _as_network(target)
            if net is not None:
                (s.allow_nets if allow else s.deny_nets).append(net)
            elif target.startswith("."):
                if allow:
                    s.allow_suffixes.append(target)
                else:
                    s.deny_hosts.add(target)  # suffix-deny handled in _host_denied
            else:
                (s.allow_hosts if allow else s.deny_hosts).add(target)
        return s

    def _host_denied(self, host):
        host = host.lower()
        if host in self.deny_hosts:
            return True
        for d in self.deny_hosts:
            if d.startswith(".") and (host == d[1:] or host.endswith(d)):
                return True
        return False

    def _host_allowed(self, host):
        host = host.lower()
        if host in self.allow_hosts:
            return True
        for suf in self.allow_suffixes:
            if host == suf[1:] or host.endswith(suf):
                return True
        return False

    def is_empty(self):
        return not (self.allow_hosts or self.allow_suffixes or self.allow_nets)


def _as_network(target):
    """Return an ip_network if target is an IP or CIDR, else None (it's a host)."""
    try:
        if "/" in target:
            return ipaddress.ip_network(target, strict=False)
        return ipaddress.ip_network(ipaddress.ip_address(target))
    except ValueError:
        return None


def _resolve(host):
    """Resolve a hostname to the set of IPs it currently points at.

    Returned as a set because a host with several A/AAAA records must have
    EVERY address checked - permitting a hostname does not permit whatever a
    single record happens to resolve to this millisecond."""
    ips = set()
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            ips.add(sockaddr[0])
    except socket.gaierror:
        pass
    return {ipaddress.ip_address(ip.split("%")[0]) for ip in ips}


def guard(scope: Scope, host: str):
    """Authorize a single host immediately before connecting to it.

    Fail-closed: raises ScopeError unless the host is explicitly allowed and
    nothing about it is denied. Resolves the host and checks EVERY resolved IP,
    so a permitted hostname cannot be used to reach a denied address via a
    poisoned or rebinding DNS answer.

    Returns the resolved IPs so the caller connects to a vetted address rather
    than re-resolving (and re-opening the rebinding window) later.
    """
    host = host.strip().lower()
    if not host:
        raise ScopeError("Empty target.")

    literal = _as_network(host)

    # 1. Permanent denials first. Nothing overrides these.
    def perm_denied(ip):
        return any(ip in n for n in PERMANENTLY_DENIED)

    if literal is not None:
        for ip in literal:
            if perm_denied(ip):
                raise ScopeError(f"{host} is in a permanently denied range.")
    ips = literal.hosts() if literal is not None and literal.num_addresses > 1 else \
          ([next(iter(literal))] if literal is not None else _resolve(host))
    ips = list(ips)

    if literal is None and not ips:
        raise ScopeError(f"{host} did not resolve; refusing to scan an unknown target.")

    for ip in ips:
        if perm_denied(ip):
            raise ScopeError(f"{host} resolves to {ip}, which is in a permanently denied range.")

    # 2. Explicit deny.
    if literal is None and scope._host_denied(host):
        raise ScopeError(f"{host} matches a deny rule.")
    for ip in ips:
        if any(ip in n for n in scope.deny_nets):
            raise ScopeError(f"{host} resolves to {ip}, which matches a deny rule.")

    # 3. Explicit allow. Denial by default: absence of an allow is a refusal.
    host_ok = literal is None and scope._host_allowed(host)
    net_ok = all(any(ip in n for n in scope.allow_nets) for ip in ips) if scope.allow_nets else False
    # A hostname is in scope if the name is allowed OR every IP it resolves to is
    # inside an allowed network. A literal IP is in scope only via allow_nets.
    if literal is not None:
        if not any(any(ip in n for n in scope.allow_nets) for ip in ips):
            raise ScopeError(f"{host} is not within any allow rule.")
    else:
        if not (host_ok or net_ok):
            raise ScopeError(f"{host} is not within any allow rule.")

    return [str(ip) for ip in ips]
