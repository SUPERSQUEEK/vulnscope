"""
Port discovery - a bounded TCP connect sweep.

Deliberately conservative: a fixed, short list of common service ports, one
connection each, sequential. This is not a substitute for nmap and does not
pretend to be. It exists to answer "what is listening" for the assessment
checkers that follow, without the noise, privilege requirements, or IDS
footprint of a full port scan. An operator who wants a real port scan should
run ReconScope's nmap adapter and feed its output in via --ingest.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from .base import Checker, tcp_connect

# Curated for signal, not coverage. Each port here changes what a later checker
# will do, or is worth flagging on its own (e.g. an exposed database port).
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
    11434: "ollama", 27017: "mongodb",
}

# Ports that should essentially never face the public internet. Finding one open
# is itself a finding, before any deeper check.
SENSITIVE = {
    23: ("Telnet exposed", "high", "Telnet transmits credentials in cleartext and should not be internet-facing."),
    445: ("SMB exposed", "high", "SMB has a long history of wormable vulnerabilities and should never face the internet."),
    3306: ("MySQL exposed", "high", "A database port is directly reachable. It should be firewalled to application hosts only."),
    5432: ("PostgreSQL exposed", "high", "A database port is directly reachable. It should be firewalled to application hosts only."),
    6379: ("Redis exposed", "critical", "Redis defaults to no authentication; an exposed instance is frequently a full compromise."),
    9200: ("Elasticsearch exposed", "high", "Elasticsearch often ships without authentication and leaks all indexed data when exposed."),
    27017: ("MongoDB exposed", "high", "MongoDB has historically defaulted to no authentication; exposure leaks the database."),
    3389: ("RDP exposed", "high", "Internet-facing RDP is a primary ransomware entry vector. Put it behind a VPN or gateway."),
}


class PortChecker(Checker):
    name = "ports"

    def run(self, host, ip, ports):
        # ports may already be supplied via --ingest; only sweep if not.
        found = ports if ports else self._sweep(ip)
        for port in sorted(found):
            service = COMMON_PORTS.get(port, "unknown")
            if port in SENSITIVE:
                title, sev, detail = SENSITIVE[port]
                yield self._finding(
                    host, port, title, sev,
                    detail, evidence=f"TCP {port} ({service}) accepted a connection",
                    remediation="Restrict this port with a firewall or move the service behind a VPN.",
                )
            else:
                yield self._finding(
                    host, port, f"Open port {port}/{service}", "info",
                    f"{service} is listening.", evidence=f"TCP {port} accepted a connection",
                )
        # expose the discovered set to the engine for later checkers
        self.discovered = set(found)

    def _sweep(self, ip):
        # Probed in parallel. A sequential sweep pays the full timeout for every
        # FILTERED port (one that neither accepts nor refuses, just drops the
        # packet), so 20 filtered ports at 6s each is two minutes of waiting for
        # nothing. A short discovery timeout and a thread per port turns that
        # into a couple of seconds. The timeout here is intentionally lower than
        # the checkers' - discovery only needs to know if the port answers, not
        # to hold a working connection.
        discovery_timeout = min(self.timeout, 2.0)
        found = set()
        with ThreadPoolExecutor(max_workers=len(COMMON_PORTS)) as pool:
            futures = {pool.submit(tcp_connect, ip, p, discovery_timeout): p for p in COMMON_PORTS}
            for fut, port in futures.items():
                try:
                    if fut.result():
                        found.add(port)
                except OSError:
                    pass
        return found
