"""MRT record and subtype framing (RFC 6396, RFC 8050).

``iter_records`` reads the MRT Common Header (RFC 6396 section 2) and the Extended Timestamp
variant (section 3) from a binary stream one record at a time, never holding more than one
record body. ``parse_peer_index_table`` decodes the TABLE_DUMP_V2 PEER_INDEX_TABLE
(section 4.3.1). Record bodies are returned raw: BGP attributes are not decoded here, and an
unknown Type or Subtype is surfaced to the caller rather than dropped.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import IO

__all__ = [
    "ADDPATH_SUBTYPES",
    "BGP4MP",
    "BGP4MP_ET",
    "EXTENDED_TIMESTAMP_TYPES",
    "TABLE_DUMP_V2",
    "MrtError",
    "MrtRecord",
    "PeerEntry",
    "PeerIndexTable",
    "iter_records",
    "parse_peer_index_table",
]

# RFC 6396 section 5.3 (type codes). Only the codes this package acts on are named.
TABLE_DUMP_V2 = 13
BGP4MP = 16
BGP4MP_ET = 17
# Types whose Message begins with a 4-octet Microsecond Timestamp (RFC 6396 section 3):
# BGP4MP_ET 17, ISIS_ET 33, OSPFv3_ET 49 (section 5.3).
EXTENDED_TIMESTAMP_TYPES = frozenset({BGP4MP_ET, 33, 49})

# RFC 8050 section 5: ADD-PATH subtype codes, by type. The record layouts are those of
# RFC 6396 with the changes in RFC 8050 sections 3 and 4.
ADDPATH_SUBTYPES: dict[int, frozenset[int]] = {
    TABLE_DUMP_V2: frozenset({8, 9, 10, 11, 12}),  # RIB_*_ADDPATH, RIB_GENERIC_ADDPATH
    BGP4MP: frozenset({8, 9, 10, 11}),  # BGP4MP_MESSAGE*_ADDPATH
    BGP4MP_ET: frozenset({8, 9, 10, 11}),
}

_HEADER = struct.Struct(">IHHI")
_HEADER_LEN = _HEADER.size  # 12 octets, RFC 6396 section 2


class MrtError(ValueError):
    """Malformed or truncated MRT data."""


@dataclass(frozen=True)
class MrtRecord:
    """One MRT record: the Common Header fields and the raw Message.

    ``microseconds`` is set only for the Extended Timestamp types (RFC 6396 section 3); for
    those, ``body`` excludes the 4-octet Microsecond Timestamp.
    """

    timestamp: int
    type: int
    subtype: int
    body: bytes
    microseconds: int | None = None


@dataclass(frozen=True)
class PeerEntry:
    """One peer of a PEER_INDEX_TABLE (RFC 6396 section 4.3.1, Figure 6)."""

    bgp_id: ipaddress.IPv4Address
    address: ipaddress.IPv4Address | ipaddress.IPv6Address
    asn: int


@dataclass(frozen=True)
class PeerIndexTable:
    """A decoded PEER_INDEX_TABLE; a peer's index is its position in ``peers``."""

    collector_bgp_id: ipaddress.IPv4Address
    view_name: str
    peers: tuple[PeerEntry, ...]


def _read_exact(stream: IO[bytes], count: int) -> bytes:
    """Read up to ``count`` octets, looping over short reads; fewer means EOF."""
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def iter_records(stream: IO[bytes], *, max_record: int = 1 << 24) -> Iterator[MrtRecord]:
    """Yield the MRT records of ``stream`` (RFC 6396 sections 2 and 3), one at a time.

    The Length field excludes the 12-octet Common Header (section 2). A Length above
    ``max_record`` is refused before any body octet is read. End of stream is clean only at a
    record boundary; a partial header or body raises ``MrtError``. Unknown types are yielded
    with their raw body.
    """
    if max_record < 0:
        raise ValueError("max_record must not be negative")
    while True:
        header = _read_exact(stream, _HEADER_LEN)
        if not header:
            return
        if len(header) < _HEADER_LEN:
            raise MrtError(f"truncated MRT header: {len(header)} of {_HEADER_LEN} octets")
        timestamp, rtype, subtype, length = _HEADER.unpack(header)
        if length > max_record:
            raise MrtError(f"MRT record length {length} exceeds the cap of {max_record}")
        body = _read_exact(stream, length)
        if len(body) < length:
            raise MrtError(f"truncated MRT body: {len(body)} of {length} octets")
        microseconds = None
        if rtype in EXTENDED_TIMESTAMP_TYPES:
            if length < 4:
                raise MrtError("extended-timestamp record shorter than its Microsecond Timestamp")
            (microseconds,) = struct.unpack(">I", body[:4])
            body = body[4:]
        yield MrtRecord(timestamp, rtype, subtype, body, microseconds)


def parse_peer_index_table(body: bytes) -> PeerIndexTable:
    """Decode a TABLE_DUMP_V2 PEER_INDEX_TABLE Message (RFC 6396 section 4.3.1).

    Peer Type bit 6 (value 2) selects a 32-bit Peer AS and bit 7 (value 1) an IPv6 Peer IP;
    the other bits are not defined and are ignored. The View Name must be UTF-8. Octets left
    over after the last peer raise ``MrtError``.
    """
    view = memoryview(body)
    position = 0

    def take(count: int) -> memoryview:
        nonlocal position
        if position + count > len(view):
            raise MrtError("PEER_INDEX_TABLE is truncated")
        chunk = view[position : position + count]
        position += count
        return chunk

    collector = ipaddress.IPv4Address(bytes(take(4)))
    (name_length,) = struct.unpack(">H", take(2))
    try:
        view_name = bytes(take(name_length)).decode("utf-8")
    except UnicodeDecodeError as error:
        raise MrtError("PEER_INDEX_TABLE view name is not UTF-8") from error
    (count,) = struct.unpack(">H", take(2))
    peers: list[PeerEntry] = []
    for _ in range(count):
        (peer_type,) = take(1)
        bgp_id = ipaddress.IPv4Address(bytes(take(4)))
        address: ipaddress.IPv4Address | ipaddress.IPv6Address
        if peer_type & 1:
            address = ipaddress.IPv6Address(bytes(take(16)))
        else:
            address = ipaddress.IPv4Address(bytes(take(4)))
        if peer_type & 2:
            (asn,) = struct.unpack(">I", take(4))
        else:
            (asn,) = struct.unpack(">H", take(2))
        peers.append(PeerEntry(bgp_id, address, asn))
    if position != len(view):
        raise MrtError(f"{len(view) - position} octets follow the last peer")
    return PeerIndexTable(collector, view_name, tuple(peers))
