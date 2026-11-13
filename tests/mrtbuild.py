"""Builders for synthetic TABLE_DUMP_V2 dumps, laid out from RFC 6396 sections 2, 4.3.1 and 4.3.2.

The records are constructed here, not copied from an archive: the RFC prints one RIB record
(Figure 19, used in ``test_mrt_records.py``) and one peer table (Figure 18), and every other
scenario a test needs (MOAS, AS_SET, several peers, dates) has to be built.
"""

from __future__ import annotations

import ipaddress
import struct

TS = 1300475700  # 2011-03-18 19:15:00 UTC, the RFC 6396 Appendix A timestamp


def record(rtype: int, subtype: int, body: bytes, when: int = TS) -> bytes:
    return struct.pack(">IHHI", when, rtype, subtype, len(body)) + body


def peer_table(peers: list[tuple[str, int]], when: int = TS) -> bytes:
    """A PEER_INDEX_TABLE with IPv4 or IPv6 peers (address text, AS number), 32-bit ASNs."""
    body = bytes([198, 51, 100, 4]) + struct.pack(">HH", 0, len(peers))
    for address, asn in peers:
        ip = ipaddress.ip_address(address)
        kind = 2 | (1 if ip.version == 6 else 0)
        body += bytes([kind]) + bytes([10, 0, 0, 1]) + ip.packed + struct.pack(">I", asn)
    return record(13, 1, body, when)


def as_path_attrs(*segments: tuple[int, list[int]], extra: bytes = b"") -> bytes:
    """ORIGIN IGP plus an AS_PATH of the given (type, ASNs) segments, 4-octet ASNs."""
    value = b"".join(
        bytes([kind, len(asns)]) + b"".join(struct.pack(">I", a) for a in asns)
        for kind, asns in segments
    )
    if len(value) > 255:
        path = bytes([0x50, 2]) + struct.pack(">H", len(value)) + value
    else:
        path = bytes([0x40, 2, len(value)]) + value
    return bytes([0x40, 1, 1, 0]) + path + extra


def entry(peer: int, attrs: bytes, *, path_id: int | None = None, when: int = TS) -> bytes:
    head = struct.pack(">HI", peer, when)
    if path_id is not None:
        head += struct.pack(">I", path_id)
    return head + struct.pack(">H", len(attrs)) + attrs


def rib(
    prefix: str, entries: list[bytes], *, sequence: int = 0, addpath: bool = False, when: int = TS
) -> bytes:
    """A RIB_IPV4/6_UNICAST (or _ADDPATH) record for ``prefix``."""
    net = ipaddress.ip_network(prefix)
    nbytes = (net.prefixlen + 7) // 8
    body = (
        struct.pack(">I", sequence)
        + bytes([net.prefixlen])
        + net.network_address.packed[:nbytes]
        + struct.pack(">H", len(entries))
        + b"".join(entries)
    )
    subtype = (8 if addpath else 2) if net.version == 4 else (10 if addpath else 4)
    return record(13, subtype, body, when)
