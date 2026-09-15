"""
A minimal, dependency-free DNS client: build a query, send it over UDP to a
public resolver, parse the answer. Just enough wire-format support (TXT,
DNSKEY, CAA, NS, name compression) for the dns checker - not a general
resolver library.

Queries go to a public resolver (Cloudflare, falling back to Google), never to
the target itself. SPF/DMARC/DNSSEC/CAA records are published DNS data - the
same records anyone's resolver would answer - so this reads public zone data
rather than touching the target's own infrastructure at all.
"""

from __future__ import annotations

import socket
import struct

RESOLVERS = ["1.1.1.1", "8.8.8.8"]
TYPES = {"A": 1, "NS": 2, "TXT": 16, "DNSKEY": 48, "CAA": 257}


class DnsError(Exception):
    pass


def _encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("ascii")
        if len(b) > 63:
            raise DnsError(f"label too long: {label!r}")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _decode_name(msg, offset):
    """Returns (name, next_offset). Follows compression pointers but never
    advances the caller's cursor past the FIRST pointer encountered."""
    labels = []
    pos = offset
    end = None
    seen = 0
    while True:
        if pos >= len(msg):
            raise DnsError("truncated name")
        length = msg[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if end is None:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | msg[pos + 1]
            seen += 1
            if seen > 64:
                raise DnsError("compression loop")
            continue
        pos += 1
        labels.append(msg[pos:pos + length].decode("ascii", "replace"))
        pos += length
    return ".".join(labels), (end if end is not None else pos)


def _build_query(qname, qtype):
    qid = 0x1234
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = _encode_name(qname) + struct.pack(">HH", TYPES[qtype], 1)
    return qid, header + question


def query(qname, qtype, timeout=3.0):
    """Return a list of decoded RDATA values for qname/qtype, or [] if the
    name has no records of that type. Raises DnsError only on a network or
    protocol failure, not on NXDOMAIN/NODATA (those just mean no records)."""
    if qtype not in TYPES:
        raise DnsError(f"unsupported type {qtype!r}")
    qid, packet = _build_query(qname, qtype)

    last_err = None
    for resolver in RESOLVERS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (resolver, 53))
            data, _ = sock.recvfrom(4096)
            return _parse_response(data, qid, qtype)
        except (socket.timeout, OSError) as e:
            last_err = e
            continue
        finally:
            sock.close()
    raise DnsError(f"no resolver answered: {last_err}")


def _parse_response(msg, expect_id, qtype):
    if len(msg) < 12:
        raise DnsError("short response")
    rid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", msg[:12])
    if rid != expect_id:
        raise DnsError("DNS transaction ID mismatch")
    rcode = flags & 0x0F
    pos = 12
    for _ in range(qdcount):
        _, pos = _decode_name(msg, pos)
        pos += 4  # qtype + qclass
    if rcode != 0:
        return []  # NXDOMAIN etc: no records, not an error

    out = []
    for _ in range(ancount):
        _, pos = _decode_name(msg, pos)
        rtype, _, _, rdlength = struct.unpack(">HHIH", msg[pos:pos + 10])
        pos += 10
        rdata = msg[pos:pos + rdlength]
        pos += rdlength
        if TYPES.get(qtype) != rtype:
            continue
        out.append(_decode_rdata(qtype, rdata, msg, pos - rdlength))
    return out


def _decode_rdata(qtype, rdata, msg, rdata_offset):
    if qtype == "TXT":
        parts = []
        i = 0
        while i < len(rdata):
            n = rdata[i]
            parts.append(rdata[i + 1:i + 1 + n].decode("utf-8", "replace"))
            i += 1 + n
        return "".join(parts)
    if qtype == "NS":
        name, _ = _decode_name(msg, rdata_offset)
        return name
    if qtype == "DNSKEY":
        return rdata.hex()
    if qtype == "CAA":
        flag = rdata[0]
        tag_len = rdata[1]
        tag = rdata[2:2 + tag_len].decode("ascii", "replace")
        value = rdata[2 + tag_len:].decode("ascii", "replace")
        return f"{flag} {tag} {value}"
    return rdata.hex()
