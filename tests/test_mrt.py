"""MRT framing (RFC 6396 sections 2, 3, 4.3.1) and the ADD-PATH subtype codes (RFC 8050).

Vectors: Figure 18 (PEER_INDEX_TABLE) is used as printed in RFC 6396 Appendix A; no erratum
touches it. Figures 16 and 19 carry the two verified errata (5511, 6640, read through rfclib on
2026-11-13) and are used here only in corrected form.
"""

from __future__ import annotations

import io
import ipaddress
import struct

import pytest

from asnkit import mrt

TS = 1300475700  # RFC 6396 Appendix A: 2011-03-18 19:15:00

# Figure 18, field by field from the RFC's own diagram (Length = 34).
FIG18_BODY = (
    bytes([198, 51, 100, 4])  # Collector BGP ID
    + struct.pack(">HH", 0, 2)  # View Name Length, Peer Count
    + bytes([2])
    + bytes([198, 51, 100, 5])
    + bytes([198, 51, 100, 5])
    + struct.pack(">I", 65541)
    + bytes([2])
    + bytes([192, 0, 2, 33])
    + bytes([192, 0, 2, 33])
    + struct.pack(">I", 65542)
)
FIG18 = struct.pack(">IHHI", TS, 13, 1, 34) + FIG18_BODY

# Figure 16 with erratum 5511 applied: attribute length 0x23, NEXT_HOP c6 33 64 bc.
FIG16_UPDATE = bytes.fromhex(
    "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff"
    "00 3e 02 00 00 00 23 40 01 01 02 40 02 0e 02 03"
    "00 00 fb f0 00 00 fb ff 00 00 fb f6 40 03 04 c6"
    "33 64 bc c0 08 04 fb f0 00 0e 18 cb 00 71"
)
FIG16_BODY = (
    struct.pack(">IIHH", 64496, 64497, 0, 1)
    + bytes([192, 0, 2, 85])
    + bytes([198, 51, 100, 4])
    + FIG16_UPDATE
)
FIG16 = struct.pack(">IHHI", TS, 16, 4, 82) + FIG16_BODY

# Figure 19 attributes with erratum 6640 applied (MP_REACH_NLRI in MRT form, length 0x21).
FIG19_ATTRS = bytes.fromhex(
    "40 01 01 00 50 02 00 0e 02 03 00 00 fb f0 00 00"
    "fb ff 00 00 fb f6 80 0e 21 20 20 01 0d b8 00 0d"
    "00 ff 00 00 00 00 00 00 01 87 fe 80 00 00 00 00"
    "00 00 02 12 f2 ff fe 9f 1b 00"
)


def records(data: bytes, **kw: int) -> list[mrt.MrtRecord]:
    return list(mrt.iter_records(io.BytesIO(data), **kw))


def test_iter_records_reads_header_fields():
    (rec,) = records(FIG18)
    assert (rec.timestamp, rec.type, rec.subtype) == (TS, mrt.TABLE_DUMP_V2, 1)
    assert rec.body == FIG18_BODY
    assert rec.microseconds is None


def test_corrected_figure_16_is_self_consistent():
    # Erratum 5511: with the printed 0x1f the attributes overrun; 0x23 fits the record.
    assert len(FIG16_BODY) == 82
    (rec,) = records(FIG16)
    assert rec.body == FIG16_BODY
    msg = FIG16_UPDATE
    assert struct.unpack(">H", msg[16:18])[0] == len(msg) == 62
    assert struct.unpack(">H", msg[19:21])[0] == 0  # withdrawn routes length
    assert struct.unpack(">H", msg[21:23])[0] == 0x23 == len(msg) - 23 - 4  # 4 NLRI octets


def test_corrected_figure_19_mp_reach_is_in_mrt_form():
    # Erratum 6640: MP_REACH_NLRI carries only next hop length + next hop (section 4.3.4),
    # so its length is 1 + 32 = 0x21, not 0x2b. The errata do not restate the Length and
    # Attribute Length fields; they shrink by the 10 removed octets (87 -> 77, 68 -> 58).
    assert len(FIG19_ATTRS) == 58
    mp = FIG19_ATTRS[22:]
    assert mp[:3] == bytes([0x80, 0x0E, 0x21])
    assert len(mp) - 3 == 0x21
    assert mp[3] == 32  # Next Hop Address Length
    body = (
        struct.pack(">I", 42)
        + bytes([32, 0x20, 0x01, 0x0D, 0xB8])
        + struct.pack(">H", 1)
        + struct.pack(">HIH", 15, TS, 58)
        + FIG19_ATTRS
    )
    assert len(body) == 77
    (rec,) = records(struct.pack(">IHHI", TS, 13, 4, 77) + body)
    assert rec.body == body


def test_iter_records_empty_stream_is_clean_eof():
    assert records(b"") == []


@pytest.mark.parametrize("cut", range(1, 12))
def test_iter_records_truncated_header_raises(cut):
    with pytest.raises(mrt.MrtError, match="header"):
        records(FIG18[:cut])


def test_iter_records_truncated_body_raises():
    with pytest.raises(mrt.MrtError, match="body"):
        records(FIG18[:-1])


def test_iter_records_length_cap_refused_before_read():
    class Tripwire(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            if size is not None and size > 12:
                raise AssertionError("body read before the cap was checked")
            return super().read(size)

    data = struct.pack(">IHHI", TS, 13, 2, 0xFFFFFFFF) + b"x" * 8
    with pytest.raises(mrt.MrtError, match="cap"):
        list(mrt.iter_records(Tripwire(data)))


def test_iter_records_clean_eof_after_last_record():
    assert len(records(FIG18 + FIG16)) == 2


def test_iter_records_streams_incrementally():
    class Counting(io.BytesIO):
        high = 0

        def read(self, size: int | None = -1) -> bytes:
            out = super().read(size)
            Counting.high = max(Counting.high, len(out))
            return out

    gen = mrt.iter_records(Counting(FIG18 * 50))
    assert next(gen).subtype == 1
    assert Counting.high <= 34  # never asked for the whole stream


def test_iter_records_survives_short_reads():
    class OneByte(io.RawIOBase):
        def __init__(self, data: bytes) -> None:
            self._buf = io.BytesIO(data)

        def readable(self) -> bool:
            return True

        def read(self, size: int = -1) -> bytes:
            return self._buf.read(1)

    assert len(list(mrt.iter_records(OneByte(FIG18 + FIG16)))) == 2


def test_extended_timestamp_splits_microseconds():
    body = struct.pack(">I", 123456) + b"abc"
    (rec,) = records(struct.pack(">IHHI", TS, mrt.BGP4MP_ET, 4, len(body)) + body)
    assert (rec.microseconds, rec.body) == (123456, b"abc")


def test_extended_timestamp_too_short_raises():
    with pytest.raises(mrt.MrtError, match="Microsecond"):
        records(struct.pack(">IHHI", TS, mrt.BGP4MP_ET, 4, 2) + b"ab")


def test_unknown_type_is_passed_through_not_dropped():
    (rec,) = records(struct.pack(">IHHI", TS, 999, 7, 3) + b"xyz")
    assert (rec.type, rec.subtype, rec.body) == (999, 7, b"xyz")


def test_negative_cap_rejected():
    with pytest.raises(ValueError, match="max_record"):
        records(b"", max_record=-1)


def test_peer_index_table_figure_18():
    table = mrt.parse_peer_index_table(FIG18_BODY)
    assert table.collector_bgp_id == ipaddress.IPv4Address("198.51.100.4")
    assert table.view_name == ""
    assert [(str(p.bgp_id), str(p.address), p.asn) for p in table.peers] == [
        ("198.51.100.5", "198.51.100.5", 65541),
        ("192.0.2.33", "192.0.2.33", 65542),
    ]


def test_peer_index_table_mixed_v4_v6_and_16_32_bit_as():
    v6 = ipaddress.IPv6Address("2001:db8::1").packed
    body = (
        bytes([10, 0, 0, 1])
        + struct.pack(">H", 4)
        + b"view"
        + struct.pack(">H", 4)
        + bytes([0, 1, 1, 1, 1, 192, 0, 2, 1])
        + struct.pack(">H", 64496)
        + bytes([1, 2, 2, 2, 2])
        + v6
        + struct.pack(">H", 64497)
        + bytes([2, 3, 3, 3, 3, 192, 0, 2, 3])
        + struct.pack(">I", 4200000000)
        + bytes([3, 4, 4, 4, 4])
        + v6
        + struct.pack(">I", 65551)
    )
    table = mrt.parse_peer_index_table(body)
    assert table.view_name == "view"
    assert [(p.address.version, p.asn) for p in table.peers] == [
        (4, 64496),
        (6, 64497),
        (4, 4200000000),
        (6, 65551),
    ]


def test_peer_type_reserved_bits_ignored():
    # RFC 6396 defines only bits 6 and 7; the rest are not interpreted.
    body = bytes([1, 2, 3, 4]) + struct.pack(">HH", 0, 1) + bytes([0xFC])
    body += bytes([5, 5, 5, 5]) + bytes([192, 0, 2, 9]) + struct.pack(">H", 7)
    (peer,) = mrt.parse_peer_index_table(body).peers
    assert (peer.address.version, peer.asn) == (4, 7)


def test_peer_index_table_peer_count_exceeds_body():
    body = bytes([1, 2, 3, 4]) + struct.pack(">HH", 0, 60000)
    with pytest.raises(mrt.MrtError, match="truncated"):
        mrt.parse_peer_index_table(body)


def test_peer_index_table_view_name_invalid_utf8():
    body = bytes([1, 2, 3, 4]) + struct.pack(">H", 2) + b"\xff\xfe" + struct.pack(">H", 0)
    with pytest.raises(mrt.MrtError, match="UTF-8"):
        mrt.parse_peer_index_table(body)


def test_peer_index_table_trailing_bytes_refused():
    with pytest.raises(mrt.MrtError, match="follow"):
        mrt.parse_peer_index_table(FIG18_BODY + b"\x00")


@pytest.mark.parametrize("cut", [0, 3, 5, 9, 20])
def test_peer_index_table_truncated_refused(cut):
    with pytest.raises(mrt.MrtError):
        mrt.parse_peer_index_table(FIG18_BODY[:cut])


def test_addpath_subtype_codes_match_rfc_8050_section_5():
    # RFC 8050 5.1 and 5.2, read through rfclib.
    assert mrt.ADDPATH_SUBTYPES[mrt.TABLE_DUMP_V2] == {8, 9, 10, 11, 12}
    assert mrt.ADDPATH_SUBTYPES[mrt.BGP4MP] == {8, 9, 10, 11}
    assert mrt.ADDPATH_SUBTYPES[mrt.BGP4MP_ET] == {8, 9, 10, 11}
