"""
DNS hygiene: SPF, DMARC, DNSSEC, CAA.

Unlike the other checkers this one never opens a connection to the target at
all - it asks a public resolver about records the domain's owner already
published for anyone to read. That makes it the least intrusive checker in the
project, and it runs regardless of what ports the target has open.

Scope note: this checks records for the hostname exactly as given. Most
mail/DNS policy lives at the registrable domain (e.g. example.com), not a
subdomain (www.example.com), so point vulnscope at the apex domain for
meaningful SPF/DMARC results - the tool does not guess the apex from a
subdomain, since that requires a public-suffix list it does not carry.
"""

from __future__ import annotations

from .base import Checker
from ..dnsclient import query, DnsError


class DnsChecker(Checker):
    name = "dns"

    def run(self, host, ip, ports):
        yield from self._spf(host)
        yield from self._dmarc(host)
        yield from self._dnssec(host)
        yield from self._caa(host)

    def _txt(self, name):
        try:
            return query(name, "TXT")
        except DnsError:
            return None  # resolver unreachable; say nothing rather than guess

    def _spf(self, host):
        records = self._txt(host)
        if records is None:
            return
        spf = [r for r in records if r.lower().startswith("v=spf1")]
        if not spf:
            yield self._finding(host, None, "No SPF record", "medium",
                                 "No SPF TXT record was found at this name.",
                                 evidence=f"TXT {host}: {records or '(none)'}",
                                 remediation="Publish an SPF record listing your authorized senders.")
            return
        rec = spf[0]
        if "+all" in rec:
            yield self._finding(host, None, "SPF allows any sender (+all)", "high",
                                 "The SPF record ends in '+all', which authorizes every sender in the world.",
                                 evidence=rec,
                                 remediation="Change +all to ~all (softfail) or -all (hardfail).")
        elif rec.rstrip().endswith("?all"):
            yield self._finding(host, None, "SPF is neutral (?all)", "low",
                                 "The SPF record's catch-all is '?all', which asserts nothing about unlisted senders.",
                                 evidence=rec, remediation="Use ~all or -all once all legitimate senders are listed.")

    def _dmarc(self, host):
        records = self._txt(f"_dmarc.{host}")
        if records is None:
            return
        dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]
        if not dmarc:
            yield self._finding(host, None, "No DMARC record", "medium",
                                 "No DMARC TXT record was found at _dmarc.<domain>.",
                                 evidence=f"TXT _dmarc.{host}: {records or '(none)'}",
                                 remediation="Publish a DMARC record, starting with p=none while monitoring, then moving to quarantine or reject.")
            return
        rec = dmarc[0]
        policy = "none"
        for part in rec.split(";"):
            part = part.strip()
            if part.lower().startswith("p="):
                policy = part.split("=", 1)[1].strip().lower()
        if policy == "none":
            yield self._finding(host, None, "DMARC policy is 'none'", "low",
                                 "DMARC is published but set to monitor-only; spoofed mail is reported, not blocked.",
                                 evidence=rec,
                                 remediation="Move to p=quarantine or p=reject once monitoring shows no false positives.")

    def _dnssec(self, host):
        try:
            keys = query(host, "DNSKEY")
        except DnsError:
            return
        if not keys:
            yield self._finding(host, None, "DNSSEC not enabled", "low",
                                 "No DNSKEY records were published at this name; responses cannot be cryptographically validated.",
                                 evidence="DNSKEY query returned no records",
                                 remediation="Enable DNSSEC signing with your DNS provider or registrar.")
        # Presence of a DNSKEY is a signal, not a validated chain of trust -
        # confirming the chain needs DS-record validation up to the root,
        # which is out of scope for a lightweight, no-dependency client.

    def _caa(self, host):
        try:
            records = query(host, "CAA")
        except DnsError:
            return
        if not records:
            yield self._finding(host, None, "No CAA record", "info",
                                 "No CAA record restricts which certificate authorities may issue for this domain.",
                                 evidence="CAA query returned no records",
                                 remediation="Publish a CAA record naming your certificate authority to reduce mis-issuance risk.")
