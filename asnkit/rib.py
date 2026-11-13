"""TABLE_DUMP_V2 RIB rows and the origin of an AS_PATH (RFC 6396, RFC 4271, RFC 6811).

``iter_rib_entries`` turns a TABLE_DUMP_V2 dump into one :class:`RibRow` per RIB Entry: the
prefix, the peer from the PEER_INDEX_TABLE, the Originated Time, the ADD-PATH Path Identifier
when the subtype has one, the BGP attribute octets undecoded, and the AS_PATH value octets
cut out of them, still undecoded. RFC 6396 section 4.3.4 requires every AS number in a stored
AS_PATH to be four octets, which is the only width read here.

``origin_of`` decodes an AS_PATH to its origin by the rule of RFC 6811 section 2 (read through
rfclib): the rightmost AS of a final AS_SEQUENCE segment; the BGP speaker's own AS when the
final segment is AS_CONFED_SEQUENCE or AS_CONFED_SET or the path is empty; and "NONE" for any
other final segment, which is an AS_SET. NONE is reported as an ambiguous origin together with
the set members and never reduced to one of them: RFC 9774 section 4 says route origin
validation never considers a route with an AS_SET Valid, and archives still hold such routes.

AS_PATH decoding and attribute framing are pathattr's (``pathattr.aspath.parse_as_path`` and
``pathattr.attribute.walk``, RFC 4271 section 4.3, RFC 5065 section 3, RFC 6793). asnkit's own
segment decoder was removed on 2026-11-13 (row ``rib.as-path-via-pathattr``) after the two agreed on
every AS_PATH of the real RouteViews RIB in ``tools/corpus.json`` (1,323 paths). A pathattr fault is
re-raised as :class:`AsPathError` so a caller of this module needs no pathattr import to catch it.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pathattr import BgpError
from pathattr.aspath import AsPath, Segment, SegmentType, parse_as_path
from pathattr.attribute import Action, walk

from . import mrt

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from typing import IO

__all__ = [
    "AS_CONFED_SEQUENCE",
    "AS_CONFED_SET",
    "AS_SEQUENCE",
    "AS_SET",
    "AsPathError",
    "Origin",
    "RibRow",
    "Segment",
    "as_path_of",
    "iter_rib_entries",
    "origin_of",
]

# RFC 4271 section 4.3 (types 1 and 2) and RFC 5065 section 3 (types 3 and 4), as pathattr names them.
AS_SET = SegmentType.AS_SET
AS_SEQUENCE = SegmentType.AS_SEQUENCE
AS_CONFED_SEQUENCE = SegmentType.AS_CONFED_SEQUENCE
AS_CONFED_SET = SegmentType.AS_CONFED_SET
_AS_PATH = 2  # attribute type code, RFC 4271 section 4.3 b)


class AsPathError(ValueError):
    """An AS_PATH value that cannot be decoded."""


@dataclass(frozen=True)
class Origin:
    """The origin of a route by RFC 6811 section 2.

    ``kind`` is ``"sequence"`` (``asn`` is the rightmost AS of the final AS_SEQUENCE),
    ``"speaker"`` (the final segment is confederation or the path is empty and the caller gave
    the speaker's own AS), ``"undetermined"`` (the same two cases without a speaker AS) or
    ``"as-set"`` (RFC 6811's NONE; ``asn`` is ``None`` and ``members`` lists the set).
    """

    asn: int | None
    kind: str
    members: tuple[int, ...] = ()

    @property
    def ambiguous(self) -> bool:
        """True when no single origin AS can be named: an AS_SET, or no speaker AS to use."""
        return self.asn is None


def origin_of(
    as_path: bytes | AsPath,
    *,
    speaker_as: int | None = None,
    four_octet: bool = True,
) -> Origin:
    """The origin of a route from its AS_PATH, by RFC 6811 section 2 (see the module docstring).

    ``as_path`` is the AS_PATH value octets or already decoded segments. ``speaker_as`` is the
    BGP speaker's own AS, which RFC 6811 uses when the final segment is AS_CONFED_SEQUENCE or
    AS_CONFED_SET or the path is empty; in a collector's view that is the peer. An AS_SET as
    the final segment gives the ambiguous result of the module docstring. The octets are decoded
    by ``pathattr.aspath.parse_as_path``; ``AsPathError`` when they do not decode.
    """
    if isinstance(as_path, bytes):
        try:
            segments = parse_as_path(as_path, four_octet)
        except BgpError as error:
            raise AsPathError(str(error)) from error
    else:
        segments = as_path
    last = segments[-1] if segments else None
    if last is not None and last.type == AS_SEQUENCE:
        return Origin(last.asns[-1], "sequence")
    if last is None or last.type in (AS_CONFED_SEQUENCE, AS_CONFED_SET):
        if speaker_as is None:
            return Origin(None, "undetermined")
        return Origin(speaker_as, "speaker")
    return Origin(None, "as-set", tuple(sorted(set(last.asns))))


def as_path_of(attributes: bytes) -> bytes | None:
    """The AS_PATH value octets of a BGP Path Attributes field, or ``None`` if there is none.

    The attributes are framed by ``pathattr.attribute.walk`` (RFC 4271 section 4.3: a flags octet,
    a type code, and a one-octet length, or two octets when Extended Length is set); the first
    AS_PATH is returned undecoded. ``MrtError`` when the attribute list cannot be framed, which is
    the RFC 7606 section 4 case that walk reports as treat-as-withdraw with no attribute attached.
    The walk is run as IBGP so that LOCAL_PREF in a RIB entry is kept, not discarded.
    """
    walked = walk(attributes, four_octet_as=True, internal=True)
    for issue in walked.issues:
        if issue.attribute is None and issue.action == Action.TREAT_AS_WITHDRAW:
            raise mrt.MrtError(f"path attributes cannot be framed: {issue.reason}")
    found = walked.get(_AS_PATH)
    return None if found is None else found.value


@dataclass(frozen=True)
class RibRow:
    """One RIB Entry with everything needed to interpret it (RFC 6396 section 4.3).

    ``timestamp`` is that of the MRT record, which is the dump time. ``attributes`` are the
    path attribute octets as stored and ``as_path`` the AS_PATH value octets inside them, both
    undecoded; ``as_path`` is ``None`` when the attributes hold no AS_PATH or could not be
    framed, and ``framing_error`` then says which. ``path_id`` is the ADD-PATH Path Identifier
    of RFC 8050 section 4.1 and ``None`` for subtypes that have none.
    """

    timestamp: int
    sequence: int
    afi: int
    safi: int
    prefix: ipaddress.IPv4Network | ipaddress.IPv6Network
    peer_index: int
    peer: mrt.PeerEntry
    originated_time: int
    path_id: int | None
    attributes: bytes
    as_path: bytes | None
    framing_error: str | None = None

    def origin(self) -> Origin:
        """The origin of this row by :func:`origin_of`, with the peer's AS as the speaker."""
        if self.as_path is None:
            raise AsPathError(self.framing_error or "no AS_PATH attribute in the entry")
        return origin_of(self.as_path, speaker_as=self.peer.asn)


def iter_rib_entries(
    dump: IO[bytes],
    *,
    on_skip: Callable[[mrt.MrtRecord, str], None] | None = None,
    max_record: int = 1 << 24,
) -> Iterator[RibRow]:
    """Yield one :class:`RibRow` per RIB Entry of a TABLE_DUMP_V2 dump (RFC 6396 section 4.3).

    A PEER_INDEX_TABLE must come before the first RIB record (section 4.3.1: the RIB records
    follow it immediately); a later one replaces it. ``MrtError`` for a RIB record before any
    table, a Peer Index beyond the table, or a malformed record. A record that is not a RIB
    row source (another MRT type, an unknown TABLE_DUMP_V2 subtype, or a RIB_GENERIC of an
    AFI/SAFI that :func:`mrt.parse_rib_generic` does not decode, which section 4.3.3 says to
    discard) is passed to ``on_skip(record, reason)``; with no ``on_skip`` it raises
    ``MrtError`` instead of vanishing.
    """
    table: mrt.PeerIndexTable | None = None

    def skip(record: mrt.MrtRecord, reason: str) -> None:
        if on_skip is None:
            raise mrt.MrtError(reason)
        on_skip(record, reason)

    for record in mrt.iter_records(dump, max_record=max_record):
        if record.type != mrt.TABLE_DUMP_V2:
            skip(record, f"MRT type {record.type} is not TABLE_DUMP_V2")
            continue
        if record.subtype == mrt.PEER_INDEX_TABLE:
            table = mrt.parse_peer_index_table(record.body)
            continue
        if record.subtype == mrt.RIB_GENERIC or record.subtype == mrt.RIB_GENERIC_ADDPATH:
            parsed = mrt.parse_rib_generic(record.subtype, record.body)
            if not parsed.decoded:
                skip(record, f"RIB_GENERIC AFI {parsed.afi} SAFI {parsed.safi} is not decoded")
                continue
        elif record.subtype in mrt.AFI_SAFI_RIB_SUBTYPES:
            parsed = mrt.parse_rib_afi_safi(record.subtype, record.body)
        else:
            skip(record, f"TABLE_DUMP_V2 subtype {record.subtype} is not defined here")
            continue
        if table is None:
            raise mrt.MrtError("RIB record before any PEER_INDEX_TABLE")
        if parsed.prefix is None:
            raise mrt.MrtError("decoded RIB record without a prefix")
        for entry in parsed.entries:
            if entry.peer_index >= len(table.peers):
                raise mrt.MrtError(
                    f"Peer Index {entry.peer_index} is beyond the {len(table.peers)} peers"
                )
            as_path: bytes | None
            error: str | None = None
            try:
                as_path = as_path_of(entry.attributes)
            except mrt.MrtError as exc:
                as_path, error = None, str(exc)
            path_id = entry.path_id if entry.path_id is not None else parsed.nlri_path_id
            yield RibRow(
                timestamp=record.timestamp,
                sequence=parsed.sequence,
                afi=parsed.afi,
                safi=parsed.safi,
                prefix=parsed.prefix,
                peer_index=entry.peer_index,
                peer=table.peers[entry.peer_index],
                originated_time=entry.originated_time,
                path_id=path_id,
                attributes=entry.attributes,
                as_path=as_path,
                framing_error=error,
            )
