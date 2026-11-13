"""RIB rows and AS_PATH origins (RFC 6396 section 4.3.4, RFC 6811 section 2, RFC 9774 section 4).

Vectors: Figure 19 of RFC 6396 (corrected by erratum 6640), whose attributes hold the AS_PATH
``64496 64511 64502`` that Figure 20 prints; the origin rule is RFC 6811 section 2 as read
through rfclib on 2026-11-13. The dumps around it are built in ``mrtbuild.py``.
"""

from __future__ import annotations

import io
import ipaddress
import struct

import pytest
from pathattr.aspath import Segment, SegmentType, parse_as_path

from asnkit import mrt
from asnkit import rib as rib_module
from asnkit.rib import (
    AS_CONFED_SEQUENCE,
    AS_CONFED_SET,
    AS_SEQUENCE,
    AS_SET,
    AsPathError,
    Origin,
    as_path_of,
    iter_rib_entries,
    origin_of,
)

from .mrtbuild import TS, as_path_attrs, entry, peer_table, record, rib

FIG19_ATTRS = bytes.fromhex(
    "40 01 01 00 50 02 00 0e 02 03 00 00 fb f0 00 00"
    "fb ff 00 00 fb f6 80 0e 21 20 20 01 0d b8 00 0d"
    "00 ff 00 00 00 00 00 00 01 87 fe 80 00 00 00 00"
    "00 00 02 12 f2 ff fe 9f 1b 00"
)
FIG19_BODY = (
    struct.pack(">I", 42)
    + bytes([32, 0x20, 0x01, 0x0D, 0xB8])
    + struct.pack(">H", 1)
    + struct.pack(">HIH", 15, TS, 58)
    + FIG19_ATTRS
)
PEERS = [(f"192.0.2.{i + 1}", 64000 + i) for i in range(16)]


def rows(data: bytes, **kw):
    return list(iter_rib_entries(io.BytesIO(data), **kw))


def test_figure_19_row_with_its_peer_and_as_path():
    data = peer_table(PEERS) + record(13, 4, FIG19_BODY)
    (row,) = rows(data)
    assert row.prefix == ipaddress.ip_network("2001:db8::/32")
    assert row.peer_index == 15
    assert row.peer.asn == 64015
    assert row.peer.address == ipaddress.ip_address("192.0.2.16")
    assert row.originated_time == TS
    assert row.timestamp == TS
    assert row.sequence == 42
    assert row.path_id is None
    assert row.attributes == FIG19_ATTRS
    assert row.as_path == FIG19_ATTRS[4 + 4 : 4 + 4 + 14]  # the 14 AS_PATH value octets
    assert parse_as_path(row.as_path, True) == (Segment(AS_SEQUENCE, (64496, 64511, 64502)),)
    assert row.origin() == Origin(64502, "sequence")


def test_rows_come_in_dump_order_one_per_entry():
    attrs = as_path_attrs((AS_SEQUENCE, [65001, 65010]))
    data = (
        peer_table([("192.0.2.1", 65001), ("2001:db8::1", 65002)])
        + rib("203.0.113.0/24", [entry(0, attrs), entry(1, as_path_attrs((2, [65002, 65020])))])
        + rib("2001:db8:1::/48", [entry(1, as_path_attrs((2, [65002, 65030])))], sequence=1)
    )
    got = rows(data)
    assert [(str(r.prefix), r.peer.asn, r.origin().asn) for r in got] == [
        ("203.0.113.0/24", 65001, 65010),
        ("203.0.113.0/24", 65002, 65020),
        ("2001:db8:1::/48", 65002, 65030),
    ]
    assert got[2].peer.address == ipaddress.ip_address("2001:db8::1")
    assert got[2].afi == 2


def test_addpath_rows_carry_their_path_identifier():
    attrs = as_path_attrs((AS_SEQUENCE, [65001]))
    data = peer_table([("192.0.2.1", 65001)]) + rib(
        "203.0.113.0/24", [entry(0, attrs, path_id=7), entry(0, attrs, path_id=8)], addpath=True
    )
    assert [r.path_id for r in rows(data)] == [7, 8]


def test_generic_addpath_nlri_path_identifier_is_the_row_path_identifier():
    body = (
        struct.pack(">IHB", 1, 1, 1)
        + struct.pack(">I", 99)
        + bytes([24, 203, 0, 113])
        + struct.pack(">H", 1)
        + entry(0, as_path_attrs((AS_SEQUENCE, [65001])))
    )
    data = peer_table([("192.0.2.1", 65001)]) + record(13, 12, body)
    (row,) = rows(data)
    assert row.path_id == 99
    assert row.prefix == ipaddress.ip_network("203.0.113.0/24")


def test_rib_record_before_any_peer_table_is_refused():
    with pytest.raises(mrt.MrtError, match="before any PEER_INDEX_TABLE"):
        rows(rib("203.0.113.0/24", [entry(0, b"")]))


def test_peer_index_beyond_the_table_is_refused():
    data = peer_table([("192.0.2.1", 1)]) + rib("203.0.113.0/24", [entry(1, b"")])
    with pytest.raises(mrt.MrtError, match="beyond"):
        rows(data)


def test_a_second_peer_table_replaces_the_first():
    one = peer_table([("192.0.2.1", 111)])
    two = peer_table([("192.0.2.2", 222)])
    data = (
        one + rib("203.0.113.0/24", [entry(0, b"")]) + two + rib("203.0.113.0/24", [entry(0, b"")])
    )
    assert [r.peer.asn for r in rows(data)] == [111, 222]


def test_records_that_are_not_rib_rows_raise_or_go_to_on_skip():
    table = peer_table([("192.0.2.1", 65001)])
    other = record(16, 4, b"\x00")  # BGP4MP in a RIB dump
    odd = record(13, 7, b"\x00")  # TABLE_DUMP_V2 subtype 7 is not defined here
    vpls = record(13, 6, struct.pack(">IHB", 1, 25, 65) + b"\x01")
    good = rib("203.0.113.0/24", [entry(0, as_path_attrs((2, [65001])))])
    data = table + other + odd + vpls + good
    with pytest.raises(mrt.MrtError, match="not TABLE_DUMP_V2"):
        rows(data)
    skipped: list[tuple[int, int, str]] = []
    got = rows(data, on_skip=lambda rec, why: skipped.append((rec.type, rec.subtype, why)))
    assert len(got) == 1
    assert [(t, s) for t, s, _ in skipped] == [(16, 4), (13, 7), (13, 6)]
    assert "AFI 25 SAFI 65" in skipped[2][2]


def test_empty_dump_yields_nothing():
    assert rows(b"") == []


# -- AS_PATH framing and decoding ------------------------------------------------------------


def test_as_path_of_reads_both_length_forms():
    short = bytes([0x40, 2, 6, 2, 1]) + struct.pack(">I", 65001) + bytes([0x40, 3, 1, 9])
    assert as_path_of(short) == bytes([2, 1]) + struct.pack(">I", 65001)
    value = bytes([2, 1]) + struct.pack(">I", 65001)
    extended = bytes([0x50, 2]) + struct.pack(">H", len(value)) + value
    assert as_path_of(extended) == value


def test_as_path_of_absent_is_none_and_framing_errors_are_refused():
    assert as_path_of(bytes([0x40, 1, 1, 0])) is None
    assert as_path_of(b"") is None
    for bad in (b"\x40\x02", b"\x40\x02\x05\x01", b"\x50\x02\x00", b"\x50\x02\x00\x09\x01"):
        with pytest.raises(mrt.MrtError):
            as_path_of(bad)


def test_row_with_unframeable_attributes_reports_the_error_and_refuses_an_origin():
    data = peer_table([("192.0.2.1", 65001)]) + rib("203.0.113.0/24", [entry(0, b"\x40\x02\x09")])
    (row,) = rows(data)
    assert row.as_path is None
    assert row.framing_error is not None
    with pytest.raises(AsPathError, match=r"overruns|truncated"):
        row.origin()


def test_row_without_an_as_path_refuses_an_origin():
    data = peer_table([("192.0.2.1", 65001)]) + rib(
        "203.0.113.0/24", [entry(0, b"\x40\x01\x01\x00")]
    )
    (row,) = rows(data)
    assert row.as_path is None
    assert row.framing_error is None
    with pytest.raises(AsPathError, match="no AS_PATH"):
        row.origin()


def test_as_path_decoders_agree():
    """asnkit's own decoder is gone (row rib.as-path-via-pathattr): rib decodes through pathattr.

    These are the vectors the removed ``rib.decode_as_path`` was pinned by, so a regression in the
    replacement shows here: 4- and 2-octet widths, the empty path, and each malformed shape.
    """
    assert rib_module.parse_as_path is parse_as_path
    assert not hasattr(rib_module, "decode_as_path")
    four = bytes([2, 2]) + struct.pack(">II", 4200000000, 5) + bytes([1, 1]) + struct.pack(">I", 9)
    assert parse_as_path(four, True) == (
        Segment(SegmentType.AS_SEQUENCE, (4200000000, 5)),
        Segment(SegmentType.AS_SET, (9,)),
    )
    two = bytes([2, 2]) + struct.pack(">HH", 64496, 64511)
    assert parse_as_path(two, False) == (Segment(SegmentType.AS_SEQUENCE, (64496, 64511)),)
    assert origin_of(four) == Origin(None, "as-set", (9,))
    assert origin_of(b"") == Origin(None, "undetermined")


@pytest.mark.parametrize(
    "raw",
    [
        bytes([5, 1, 0, 0, 0, 1]),
        bytes([2, 0]),
        bytes([2, 2, 0, 0, 0, 1]),
        bytes([2, 1, 0, 0, 0, 1, 2]),
    ],
)
def test_malformed_as_path_values_are_as_path_errors(raw):
    with pytest.raises(AsPathError):
        origin_of(raw)


# -- the origin rule of RFC 6811 section 2 ----------------------------------------------------


def seg(kind: int, *asns: int) -> Segment:
    return Segment(SegmentType(kind), tuple(asns))


def test_origin_is_the_rightmost_as_of_a_final_as_sequence():
    assert origin_of((seg(AS_SEQUENCE, 1, 2, 3),)) == Origin(3, "sequence")
    assert origin_of((seg(AS_SET, 7, 8), seg(AS_SEQUENCE, 1, 2))) == Origin(2, "sequence")


def test_origin_of_a_final_as_set_is_ambiguous_and_never_guessed():
    result = origin_of((seg(AS_SEQUENCE, 1), seg(AS_SET, 9, 4, 9)))
    assert result == Origin(None, "as-set", (4, 9))
    assert result.ambiguous
    # even a one-member set is NONE (RFC 6811 section 2), not that member
    assert origin_of((seg(AS_SET, 5),)).asn is None


@pytest.mark.parametrize("kind", [AS_CONFED_SEQUENCE, AS_CONFED_SET])
def test_origin_of_a_confederation_final_segment_is_the_speaker(kind):
    path = (seg(AS_SEQUENCE, 1), seg(kind, 65001))
    assert origin_of(path, speaker_as=64999) == Origin(64999, "speaker")
    assert origin_of(path) == Origin(None, "undetermined")
    assert origin_of(path).ambiguous


def test_origin_of_an_empty_path_is_the_speaker():
    assert origin_of((), speaker_as=64999) == Origin(64999, "speaker")
    assert origin_of(b"") == Origin(None, "undetermined")


def test_origin_of_accepts_wire_octets_and_two_octet_paths():
    assert origin_of(bytes([2, 2]) + struct.pack(">II", 7, 8)) == Origin(8, "sequence")
    assert origin_of(bytes([2, 2]) + struct.pack(">HH", 7, 8), four_octet=False) == Origin(
        8, "sequence"
    )


def test_origin_of_an_undecodable_path_raises():
    with pytest.raises(AsPathError):
        origin_of(bytes([2, 3, 0, 0]))
