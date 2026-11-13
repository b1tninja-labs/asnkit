"""MRT record and subtype framing (RFC 6396, RFC 8050).

``iter_records`` reads the MRT Common Header (RFC 6396 section 2) and the Extended Timestamp
variant (section 3) from a binary stream one record at a time, never holding more than one
record body. ``parse_peer_index_table`` decodes the TABLE_DUMP_V2 PEER_INDEX_TABLE
(section 4.3.1); ``parse_rib_afi_safi`` and ``parse_rib_generic`` decode the RIB subtypes
2-6 (sections 4.3.2 and 4.3.3) and the ADD-PATH subtypes 8-12 (RFC 8050 section 4);
``parse_bgp4mp`` and ``iter_bgp4mp`` decode the BGP4MP and BGP4MP_ET subtypes of section 4.4
and RFC 8050 section 3. BGP attributes and BGP messages are not decoded here: a RIB entry
carries its attribute octets and a BGP4MP message its BGP message octets, undecoded, for
pathattr and for ``asnkit.rib``. An unknown Type or Subtype is surfaced to the caller rather
than dropped.

Reading policy where the RFCs leave a choice: the trailing bits of a prefix (section 4.3.2:
"irrelevant") are cleared, so a /21 stored as ``0a 00 08`` and as ``0a 00 0f`` is the same
prefix; a record whose entries do not exactly fill its Length raises ``MrtError``; a RIB_GENERIC record whose AFI/SAFI this module does not
decode is returned with ``decoded`` false and its remaining octets in ``undecoded``, which is
what section 4.3.3 ("SHOULD discard the remainder") leaves for the caller to account for.
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
    "AFI_SAFI_RIB_SUBTYPES",
    "BGP4MP",
    "BGP4MP_ET",
    "EXTENDED_TIMESTAMP_TYPES",
    "PEER_INDEX_TABLE",
    "RIB_GENERIC",
    "RIB_GENERIC_ADDPATH",
    "RIB_IPV4_MULTICAST",
    "RIB_IPV4_MULTICAST_ADDPATH",
    "RIB_IPV4_UNICAST",
    "RIB_IPV4_UNICAST_ADDPATH",
    "RIB_IPV6_MULTICAST",
    "RIB_IPV6_MULTICAST_ADDPATH",
    "RIB_IPV6_UNICAST",
    "RIB_IPV6_UNICAST_ADDPATH",
    "TABLE_DUMP_V2",
    "Bgp4mpMessage",
    "Bgp4mpStateChange",
    "MrtError",
    "MrtRecord",
    "PeerEntry",
    "PeerIndexTable",
    "RibEntryRecord",
    "RibRecord",
    "iter_bgp4mp",
    "iter_records",
    "parse_bgp4mp",
    "parse_peer_index_table",
    "parse_rib_afi_safi",
    "parse_rib_generic",
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

# RFC 6396 section 4.3 (TABLE_DUMP_V2 subtypes) and RFC 8050 section 5.2 (ADD-PATH subtypes).
PEER_INDEX_TABLE = 1
RIB_IPV4_UNICAST = 2
RIB_IPV4_MULTICAST = 3
RIB_IPV6_UNICAST = 4
RIB_IPV6_MULTICAST = 5
RIB_GENERIC = 6
RIB_IPV4_UNICAST_ADDPATH = 8
RIB_IPV4_MULTICAST_ADDPATH = 9
RIB_IPV6_UNICAST_ADDPATH = 10
RIB_IPV6_MULTICAST_ADDPATH = 11
RIB_GENERIC_ADDPATH = 12

# subtype -> (AFI, SAFI) for the AFI/SAFI-specific subtypes. The AFI is 1 (IPv4) or 2 (IPv6) and
# the SAFI 1 (unicast) or 2 (multicast), the BGP codes of RFC 4760; RFC 6396 section 4.3.2 names
# the subtypes by family and cast.
_AFI_SAFI: dict[int, tuple[int, int]] = {
    RIB_IPV4_UNICAST: (1, 1),
    RIB_IPV4_MULTICAST: (1, 2),
    RIB_IPV6_UNICAST: (2, 1),
    RIB_IPV6_MULTICAST: (2, 2),
    RIB_IPV4_UNICAST_ADDPATH: (1, 1),
    RIB_IPV4_MULTICAST_ADDPATH: (1, 2),
    RIB_IPV6_UNICAST_ADDPATH: (2, 1),
    RIB_IPV6_MULTICAST_ADDPATH: (2, 2),
}
AFI_SAFI_RIB_SUBTYPES = frozenset(_AFI_SAFI)
_ADDPATH_RIB = frozenset({8, 9, 10, 11, 12})

# RFC 6396 section 4.4 and RFC 8050 section 3: BGP4MP subtypes.
_BGP4MP_STATE_CHANGE = {0: False, 5: True}  # subtype -> four-octet AS numbers
# subtype -> (four-octet AS, locally generated, ADD-PATH)
_BGP4MP_MESSAGE = {
    1: (False, False, False),
    4: (True, False, False),
    6: (False, True, False),
    7: (True, True, False),
    8: (False, False, True),
    9: (True, False, True),
    10: (False, True, True),
    11: (True, True, True),
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


class _Reader:
    """Bounds-checked cursor over one record body; every shortfall is an ``MrtError``."""

    def __init__(self, body: bytes, what: str) -> None:
        self.view = memoryview(body)
        self.position = 0
        self.what = what

    def take(self, count: int) -> bytes:
        if count < 0 or self.position + count > len(self.view):
            raise MrtError(f"{self.what} is truncated")
        chunk = bytes(self.view[self.position : self.position + count])
        self.position += count
        return chunk

    def unpack(self, fmt: str) -> tuple[int, ...]:
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))

    @property
    def remaining(self) -> int:
        return len(self.view) - self.position

    def finish(self) -> None:
        if self.remaining:
            raise MrtError(f"{self.remaining} octets follow the end of the {self.what}")


def _prefix(reader: _Reader, afi: int) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Read a ``<length, prefix>`` pair as BGP NLRI encodes it (RFC 6396 section 4.3.2)."""
    width = 32 if afi == 1 else 128
    (length,) = reader.take(1)
    if length > width:
        raise MrtError(f"prefix length {length} exceeds {width}")
    packed = reader.take((length + 7) // 8).ljust(width // 8, b"\x00")
    if afi == 1:
        return ipaddress.IPv4Network((packed, length), strict=False)
    return ipaddress.IPv6Network((packed, length), strict=False)


@dataclass(frozen=True)
class RibEntryRecord:
    """One RIB Entry of a TABLE_DUMP_V2 RIB record (RFC 6396 Figure 10, RFC 8050 Figure 1).

    ``attributes`` are the BGP Path Attribute octets as stored, undecoded. ``path_id`` is the
    Path Identifier of the ADD-PATH subtypes and ``None`` for the others.
    """

    peer_index: int
    originated_time: int
    attributes: bytes
    path_id: int | None = None


@dataclass(frozen=True)
class RibRecord:
    """A decoded TABLE_DUMP_V2 RIB record: subtypes 2-6 and 8-12.

    ``prefix`` is set for the AFI/SAFI-specific subtypes and for a RIB_GENERIC record whose
    AFI/SAFI is IPv4 or IPv6 with SAFI unicast or multicast. For the ADD-PATH RIB_GENERIC
    subtype the NLRI starts with a Path Identifier (RFC 8050 section 4.2: the AFI/SAFI/NLRI
    is "additional-path-enabled"), returned in ``nlri_path_id``. A RIB_GENERIC record of any
    other AFI/SAFI has ``decoded`` false, ``prefix`` ``None``, no entries, and everything after
    SAFI in ``undecoded``.
    """

    subtype: int
    sequence: int
    afi: int
    safi: int
    prefix: ipaddress.IPv4Network | ipaddress.IPv6Network | None
    entries: tuple[RibEntryRecord, ...]
    addpath: bool
    nlri_path_id: int | None = None
    decoded: bool = True
    undecoded: bytes = b""


def _rib_entries(reader: _Reader, count: int, *, addpath: bool) -> tuple[RibEntryRecord, ...]:
    entries = []
    for _ in range(count):
        peer_index, originated = reader.unpack(">HI")
        path_id = reader.unpack(">I")[0] if addpath else None
        (length,) = reader.unpack(">H")
        entries.append(RibEntryRecord(peer_index, originated, reader.take(length), path_id))
    return tuple(entries)


def parse_rib_afi_safi(subtype: int, body: bytes) -> RibRecord:
    """Decode an AFI/SAFI-specific RIB Message: subtypes 2-5 and the ADD-PATH 8-11.

    The layout is Sequence Number, Prefix Length, Prefix, Entry Count and the RIB Entries
    (RFC 6396 section 4.3.2, Figure 8; entries as in section 4.3.4, Figure 10). The ADD-PATH
    subtypes add a 4-octet Path Identifier between Originated Time and Attribute Length of
    each entry (RFC 8050 section 4.1, Figure 1). The Message must be exactly consumed.
    """
    if subtype not in _AFI_SAFI:
        raise MrtError(f"subtype {subtype} is not an AFI/SAFI-specific RIB subtype")
    afi, safi = _AFI_SAFI[subtype]
    reader = _Reader(body, "RIB record")
    (sequence,) = reader.unpack(">I")
    prefix = _prefix(reader, afi)
    (count,) = reader.unpack(">H")
    addpath = subtype in _ADDPATH_RIB
    entries = _rib_entries(reader, count, addpath=addpath)
    reader.finish()
    return RibRecord(subtype, sequence, afi, safi, prefix, entries, addpath)


def parse_rib_generic(subtype: int, body: bytes) -> RibRecord:
    """Decode a RIB_GENERIC Message (subtype 6) or RIB_GENERIC_ADDPATH (subtype 12).

    The layout is Sequence Number, AFI, SAFI, the NLRI and the Entry Count with its entries
    (RFC 6396 section 4.3.3, Figure 9). The NLRI is AFI/SAFI specific, so its length is known
    only for IPv4 and IPv6 unicast and multicast, where it is a ``<length, prefix>`` pair. For
    any other AFI/SAFI the record is returned undecoded (see :class:`RibRecord`). In the
    ADD-PATH form (RFC 8050 section 4.2) the entries are not redefined: they carry no Path
    Identifier, and the NLRI is read with a leading 4-octet Path Identifier.
    """
    if subtype not in (RIB_GENERIC, RIB_GENERIC_ADDPATH):
        raise MrtError(f"subtype {subtype} is not a RIB_GENERIC subtype")
    addpath = subtype == RIB_GENERIC_ADDPATH
    reader = _Reader(body, "RIB_GENERIC record")
    sequence, afi, safi = reader.unpack(">IHB")
    if afi not in (1, 2) or safi not in (1, 2):
        return RibRecord(
            subtype,
            sequence,
            afi,
            safi,
            None,
            (),
            addpath,
            decoded=False,
            undecoded=reader.take(reader.remaining),
        )
    nlri_path_id = reader.unpack(">I")[0] if addpath else None
    prefix = _prefix(reader, afi)
    (count,) = reader.unpack(">H")
    entries = _rib_entries(reader, count, addpath=False)
    reader.finish()
    return RibRecord(subtype, sequence, afi, safi, prefix, entries, addpath, nlri_path_id)


@dataclass(frozen=True)
class Bgp4mpMessage:
    """A BGP4MP / BGP4MP_ET message record (RFC 6396 sections 4.4.2, 4.4.3, 4.4.5, 4.4.6).

    ``message`` is the entire BGP message including the 16-octet marker, the length and the
    type, undecoded. ``as4`` is true when the AS number fields are four octets, ``local`` when
    the message was generated locally (the ``_LOCAL`` subtypes), and ``addpath`` for the RFC
    8050 subtypes 8-11, which tell the reader that the NLRI inside ``message`` carry Path
    Identifiers. ``microseconds`` is set for BGP4MP_ET.
    """

    timestamp: int
    microseconds: int | None
    subtype: int
    peer_as: int
    local_as: int
    interface_index: int
    afi: int
    peer_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    local_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    message: bytes
    as4: bool
    local: bool
    addpath: bool


@dataclass(frozen=True)
class Bgp4mpStateChange:
    """A BGP4MP_STATE_CHANGE or BGP4MP_STATE_CHANGE_AS4 record (RFC 6396 sections 4.4.1, 4.4.4).

    ``old_state`` and ``new_state`` are the BGP FSM state numbers of RFC 6396 section 4.4.1
    (1 Idle through 6 Established), not validated here.
    """

    timestamp: int
    microseconds: int | None
    subtype: int
    peer_as: int
    local_as: int
    interface_index: int
    afi: int
    peer_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    local_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    old_state: int
    new_state: int
    as4: bool


def _address(reader: _Reader, afi: int) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if afi == 1:
        return ipaddress.IPv4Address(reader.take(4))
    if afi == 2:
        return ipaddress.IPv6Address(reader.take(16))
    raise MrtError(f"BGP4MP Address Family {afi} is neither IPv4 (1) nor IPv6 (2)")


def parse_bgp4mp(record: MrtRecord) -> Bgp4mpMessage | Bgp4mpStateChange:
    """Decode a BGP4MP or BGP4MP_ET record (RFC 6396 section 4.4, RFC 8050 section 3).

    ``MrtError`` for another type, for a subtype that is not a state change or message
    subtype of those documents, for an Address Family other than 1 and 2, for truncation, and
    for a BGP message whose Length field disagrees with the record (section 4.4.2: only one
    BGP message is encoded, in full). The peer and local addresses are those of the MRT
    header, which the Address Family covers (section 4.4.2).
    """
    if record.type not in (BGP4MP, BGP4MP_ET):
        raise MrtError(f"type {record.type} is not BGP4MP or BGP4MP_ET")
    reader = _Reader(record.body, "BGP4MP record")
    subtype = record.subtype
    if subtype in _BGP4MP_STATE_CHANGE:
        as4 = _BGP4MP_STATE_CHANGE[subtype]
        local = addpath = False
    elif subtype in _BGP4MP_MESSAGE:
        as4, local, addpath = _BGP4MP_MESSAGE[subtype]
    else:
        raise MrtError(f"BGP4MP subtype {subtype} is not defined by RFC 6396 or RFC 8050")
    peer_as, local_as = reader.unpack(">II" if as4 else ">HH")
    interface_index, afi = reader.unpack(">HH")
    peer_ip = _address(reader, afi)
    local_ip = _address(reader, afi)
    if subtype in _BGP4MP_STATE_CHANGE:
        old_state, new_state = reader.unpack(">HH")
        reader.finish()
        return Bgp4mpStateChange(
            record.timestamp,
            record.microseconds,
            subtype,
            peer_as,
            local_as,
            interface_index,
            afi,
            peer_ip,
            local_ip,
            old_state,
            new_state,
            as4,
        )
    message = reader.take(reader.remaining)
    if len(message) < 19:
        raise MrtError(f"BGP message of {len(message)} octets is shorter than its 19-octet header")
    (declared,) = struct.unpack(">H", message[16:18])
    if declared != len(message):
        raise MrtError(
            f"BGP message Length {declared} disagrees with {len(message)} octets in the record"
        )
    return Bgp4mpMessage(
        record.timestamp,
        record.microseconds,
        subtype,
        peer_as,
        local_as,
        interface_index,
        afi,
        peer_ip,
        local_ip,
        message,
        as4,
        local,
        addpath,
    )


def iter_bgp4mp(
    stream: IO[bytes], *, max_record: int = 1 << 24
) -> Iterator[Bgp4mpMessage | Bgp4mpStateChange | MrtRecord]:
    """Yield the records of ``stream``, BGP4MP and BGP4MP_ET decoded (RFC 6396 section 4.4).

    Every other record, and a BGP4MP record with an unknown subtype, is yielded as the raw
    :class:`MrtRecord` it is, so nothing in an updates file is dropped. A malformed BGP4MP
    record raises ``MrtError`` (see :func:`parse_bgp4mp`); framing errors are those of
    :func:`iter_records`, and ``max_record`` is passed through.
    """
    for record in iter_records(stream, max_record=max_record):
        if record.type in (BGP4MP, BGP4MP_ET) and (
            record.subtype in _BGP4MP_MESSAGE or record.subtype in _BGP4MP_STATE_CHANGE
        ):
            yield parse_bgp4mp(record)
        else:
            yield record
