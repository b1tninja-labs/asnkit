"""RIB records (subtypes 2-6, 8-12) and BGP4MP records of RFC 6396 section 4 and RFC 8050.

Vectors from the RFC itself (read through rfclib on 2026-11-13): Figure 19, a RIB_IPV6_UNICAST
record for 2001:0DB8::/32, in the corrected form of erratum 6640 (MP_REACH_NLRI in the section
4.3.4 form, Length 77 and Attribute Length 58), and Figure 16, a BGP4MP_MESSAGE_AS4 record, with
erratum 5511 applied. Everything else is built from the layouts of RFC 6396 sections 4.3.2,
4.3.3, 4.3.4 and 4.4 and of RFC 8050 sections 3 and 4; those tests say so. RFC 8050 prints no
byte vector, so the ADD-PATH bodies are the Figure 19 body with the Path Identifier inserted
where Figure 1 of RFC 8050 puts it.
"""

from __future__ import annotations

import io
import ipaddress
import struct

import pytest

from asnkit import mrt

TS = 1300475700

FIG16_UPDATE = bytes.fromhex(
    "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff"
    "00 3e 02 00 00 00 23 40 01 01 02 40 02 0e 02 03"
    "00 00 fb f0 00 00 fb ff 00 00 fb f6 40 03 04 c6"
    "33 64 bc c0 08 04 fb f0 00 0e 18 cb 00 71"
)
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


def entry(peer: int, attrs: bytes, *, path_id: int | None = None, when: int = TS) -> bytes:
    head = struct.pack(">HI", peer, when)
    if path_id is not None:
        head += struct.pack(">I", path_id)
    return head + struct.pack(">H", len(attrs)) + attrs


def v4_rib(sequence: int, prefix: bytes, plen: int, entries: list[bytes]) -> bytes:
    return (
        struct.pack(">I", sequence)
        + bytes([plen])
        + prefix
        + struct.pack(">H", len(entries))
        + b"".join(entries)
    )


def test_rib_ipv6_unicast_figure_19_corrected():
    record = mrt.parse_rib_afi_safi(mrt.RIB_IPV6_UNICAST, FIG19_BODY)
    assert record.sequence == 42
    assert record.prefix == ipaddress.ip_network("2001:db8::/32")
    assert (record.afi, record.safi) == (2, 1)
    assert not record.addpath
    (one,) = record.entries
    assert (one.peer_index, one.originated_time, one.path_id) == (15, TS, None)
    assert one.attributes == FIG19_ATTRS


@pytest.mark.parametrize(
    ("subtype", "afi", "safi", "prefix", "packed", "plen"),
    [
        (mrt.RIB_IPV4_UNICAST, 1, 1, "192.0.2.0/24", bytes([192, 0, 2]), 24),
        (mrt.RIB_IPV4_MULTICAST, 1, 2, "198.51.100.0/24", bytes([198, 51, 100]), 24),
        (mrt.RIB_IPV6_UNICAST, 2, 1, "2001:db8::/32", bytes([0x20, 1, 0x0D, 0xB8]), 32),
        (mrt.RIB_IPV6_MULTICAST, 2, 2, "ff00::/8", bytes([0xFF]), 8),
    ],
)
def test_each_afi_safi_specific_subtype_fixes_its_family_and_cast(
    subtype, afi, safi, prefix, packed, plen
):
    body = v4_rib(7, packed, plen, [entry(0, b"")])
    record = mrt.parse_rib_afi_safi(subtype, body)
    assert (record.afi, record.safi) == (afi, safi)
    assert record.prefix == ipaddress.ip_network(prefix)
    assert record.sequence == 7


def test_prefix_trailing_bits_are_cleared():
    # RFC 6396 section 4.3.2: "The value of trailing bits is irrelevant". A /21 occupies three
    # octets; 0x0f and 0x08 differ only in the three trailing bits.
    for last in (0x08, 0x0F):
        body = v4_rib(1, bytes([10, 0, last]), 21, [])
        record = mrt.parse_rib_afi_safi(mrt.RIB_IPV4_UNICAST, body)
        assert record.prefix == ipaddress.ip_network("10.0.8.0/21")


def test_default_route_has_no_prefix_octets():
    record = mrt.parse_rib_afi_safi(mrt.RIB_IPV4_UNICAST, v4_rib(1, b"", 0, []))
    assert record.prefix == ipaddress.ip_network("0.0.0.0/0")


@pytest.mark.parametrize(("subtype", "plen"), [(2, 33), (4, 129)])
def test_prefix_length_beyond_the_family_is_refused(subtype, plen):
    body = struct.pack(">I", 1) + bytes([plen]) + b"\x00" * 17 + struct.pack(">H", 0)
    with pytest.raises(mrt.MrtError, match="exceeds"):
        mrt.parse_rib_afi_safi(subtype, body)


@pytest.mark.parametrize("cut", range(0, len(FIG19_BODY)))
def test_rib_record_truncated_at_every_octet_is_refused(cut):
    with pytest.raises(mrt.MrtError, match="truncated"):
        mrt.parse_rib_afi_safi(mrt.RIB_IPV6_UNICAST, FIG19_BODY[:cut])


def test_rib_record_with_trailing_octets_is_refused():
    with pytest.raises(mrt.MrtError, match="follow"):
        mrt.parse_rib_afi_safi(mrt.RIB_IPV6_UNICAST, FIG19_BODY + b"\x00")


def test_rib_entry_count_larger_than_the_body_is_refused():
    body = bytearray(FIG19_BODY)
    body[9:11] = struct.pack(">H", 2)  # Entry Count 2, one entry present
    with pytest.raises(mrt.MrtError, match="truncated"):
        mrt.parse_rib_afi_safi(mrt.RIB_IPV6_UNICAST, bytes(body))


def test_several_entries_for_one_prefix_keep_their_order():
    body = v4_rib(
        3,
        bytes([192, 0, 2]),
        24,
        [entry(2, b"\x40\x01\x01\x00"), entry(0, b""), entry(9, b"\x40\x01\x01\x02")],
    )
    record = mrt.parse_rib_afi_safi(mrt.RIB_IPV4_UNICAST, body)
    assert [e.peer_index for e in record.entries] == [2, 0, 9]
    assert record.entries[1].attributes == b""


def test_wrong_subtype_is_refused_by_each_parser():
    with pytest.raises(mrt.MrtError, match="not an AFI/SAFI"):
        mrt.parse_rib_afi_safi(mrt.RIB_GENERIC, FIG19_BODY)
    with pytest.raises(mrt.MrtError, match="not a RIB_GENERIC"):
        mrt.parse_rib_generic(mrt.RIB_IPV6_UNICAST, FIG19_BODY)


def addpath_body(path_id: int) -> bytes:
    """Figure 19's body with a Path Identifier between Originated Time and Attribute Length."""
    head = FIG19_BODY[: 4 + 5 + 2 + 2 + 4]
    return head + struct.pack(">I", path_id) + struct.pack(">H", 58) + FIG19_ATTRS


@pytest.mark.parametrize(
    ("subtype", "afi", "safi"),
    [(8, 1, 1), (9, 1, 2), (10, 2, 1), (11, 2, 2)],
)
def test_addpath_subtypes_read_the_path_identifier_before_attribute_length(subtype, afi, safi):
    # RFC 8050 section 4.1, Figure 1. Same body shape for each family: only the AFI/SAFI differ.
    body = v4_rib(5, bytes([192, 0, 2]), 24, [entry(1, FIG19_ATTRS, path_id=0xDEADBEEF)])
    if afi == 2:
        body = addpath_body(0xDEADBEEF)
    record = mrt.parse_rib_afi_safi(subtype, body)
    assert record.addpath
    assert (record.afi, record.safi) == (afi, safi)
    (one,) = record.entries
    assert one.path_id == 0xDEADBEEF
    assert one.attributes == FIG19_ATTRS


def test_an_addpath_body_is_not_readable_as_the_plain_subtype():
    # Without the subtype the 4 extra octets shift Attribute Length: the record must not parse.
    with pytest.raises(mrt.MrtError):
        mrt.parse_rib_afi_safi(mrt.RIB_IPV6_UNICAST, addpath_body(7))


def test_a_plain_body_is_not_readable_as_the_addpath_subtype():
    with pytest.raises(mrt.MrtError):
        mrt.parse_rib_afi_safi(mrt.RIB_IPV6_UNICAST_ADDPATH, FIG19_BODY)


def test_addpath_entries_each_carry_their_own_path_identifier():
    body = v4_rib(
        1,
        bytes([192, 0, 2]),
        24,
        [entry(0, b"", path_id=1), entry(0, b"", path_id=2)],
    )
    record = mrt.parse_rib_afi_safi(mrt.RIB_IPV4_UNICAST_ADDPATH, body)
    assert [e.path_id for e in record.entries] == [1, 2]


def generic(afi: int, safi: int, nlri: bytes, entries: list[bytes]) -> bytes:
    return (
        struct.pack(">IHB", 11, afi, safi)
        + nlri
        + struct.pack(">H", len(entries))
        + b"".join(entries)
    )


def test_rib_generic_ipv6_unicast_reads_afi_safi_and_nlri():
    # RFC 6396 section 4.3.3, Figure 9.
    nlri = bytes([48, 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01])
    body = generic(2, 1, nlri, [entry(4, FIG19_ATTRS)])
    record = mrt.parse_rib_generic(mrt.RIB_GENERIC, body)
    assert record.decoded
    assert (record.sequence, record.afi, record.safi) == (11, 2, 1)
    assert record.prefix == ipaddress.ip_network("2001:db8:1::/48")
    assert record.entries[0].peer_index == 4
    assert record.nlri_path_id is None


def test_rib_generic_addpath_reads_a_path_identifier_in_the_nlri_and_none_in_entries():
    # RFC 8050 section 4.2: the subtype's entries are "not redefined"; the NLRI is the
    # additional-path-enabled one, so it leads with a 4-octet Path Identifier.
    nlri = struct.pack(">I", 99) + bytes([24, 192, 0, 2])
    body = generic(1, 1, nlri, [entry(1, b"\x40\x01\x01\x00")])
    record = mrt.parse_rib_generic(mrt.RIB_GENERIC_ADDPATH, body)
    assert record.prefix == ipaddress.ip_network("192.0.2.0/24")
    assert record.nlri_path_id == 99
    assert record.entries[0].path_id is None
    assert record.addpath


def test_rib_generic_of_an_unknown_afi_safi_is_returned_undecoded_with_its_octets():
    # RFC 6396 section 4.3.3: an implementation that does not recognise the AFI/SAFI SHOULD
    # discard the remainder; here the remainder is handed back so the caller accounts for it.
    rest = bytes([1, 2, 3, 4, 5])
    body = struct.pack(">IHB", 12, 25, 65) + rest  # AFI 25 (L2VPN), SAFI 65 (VPLS)
    record = mrt.parse_rib_generic(mrt.RIB_GENERIC, body)
    assert not record.decoded
    assert record.prefix is None
    assert record.entries == ()
    assert record.undecoded == rest
    assert (record.afi, record.safi) == (25, 65)


# -- BGP4MP -------------------------------------------------------------------------------


def bgp4mp_body(
    peer_as: int,
    local_as: int,
    afi: int,
    peer: bytes,
    local: bytes,
    tail: bytes,
    *,
    as4: bool,
) -> bytes:
    asn = ">II" if as4 else ">HH"
    return struct.pack(asn, peer_as, local_as) + struct.pack(">HH", 0, afi) + peer + local + tail


def frame(rtype: int, subtype: int, body: bytes, *, microseconds: int | None = None) -> bytes:
    if microseconds is not None:
        body = struct.pack(">I", microseconds) + body
    return struct.pack(">IHHI", TS, rtype, subtype, len(body)) + body


KEEPALIVE = b"\xff" * 16 + struct.pack(">HB", 19, 4)


def test_bgp4mp_message_as4_figure_16_corrected():
    body = bgp4mp_body(
        64496, 64497, 1, bytes([192, 0, 2, 85]), bytes([198, 51, 100, 4]), FIG16_UPDATE, as4=True
    )
    (message,) = list(mrt.iter_bgp4mp(io.BytesIO(frame(mrt.BGP4MP, 4, body))))
    assert isinstance(message, mrt.Bgp4mpMessage)
    assert (message.peer_as, message.local_as, message.interface_index) == (64496, 64497, 0)
    assert message.peer_ip == ipaddress.ip_address("192.0.2.85")
    assert message.local_ip == ipaddress.ip_address("198.51.100.4")
    assert message.message == FIG16_UPDATE
    assert (message.as4, message.local, message.addpath) == (True, False, False)
    assert message.timestamp == TS
    assert message.microseconds is None


@pytest.mark.parametrize(
    ("subtype", "as4", "local", "addpath"),
    [
        (1, False, False, False),
        (4, True, False, False),
        (6, False, True, False),
        (7, True, True, False),
        (8, False, False, True),
        (9, True, False, True),
        (10, False, True, True),
        (11, True, True, True),
    ],
)
def test_bgp4mp_message_subtype_flags(subtype, as4, local, addpath):
    # RFC 6396 sections 4.4.2, 4.4.3, 4.4.5, 4.4.6 and RFC 8050 section 3.
    body = bgp4mp_body(
        65001,
        65002,
        2,
        b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01",
        b"\x00" * 15 + b"\x02",
        KEEPALIVE,
        as4=as4,
    )
    (message,) = list(mrt.iter_bgp4mp(io.BytesIO(frame(mrt.BGP4MP, subtype, body))))
    assert isinstance(message, mrt.Bgp4mpMessage)
    assert (message.as4, message.local, message.addpath) == (as4, local, addpath)
    assert message.peer_ip == ipaddress.ip_address("2001:db8::1")
    assert message.local_ip == ipaddress.ip_address("::2")


def test_two_octet_as_numbers_are_read_two_octets_wide():
    body = bgp4mp_body(64496, 3, 1, bytes(4), bytes(4), KEEPALIVE, as4=False)
    (message,) = list(mrt.iter_bgp4mp(io.BytesIO(frame(mrt.BGP4MP, 1, body))))
    assert isinstance(message, mrt.Bgp4mpMessage)
    assert (message.peer_as, message.local_as) == (64496, 3)


def test_bgp4mp_et_carries_microseconds():
    body = bgp4mp_body(1, 2, 1, bytes(4), bytes(4), KEEPALIVE, as4=True)
    (message,) = list(
        mrt.iter_bgp4mp(io.BytesIO(frame(mrt.BGP4MP_ET, 4, body, microseconds=123456)))
    )
    assert isinstance(message, mrt.Bgp4mpMessage)
    assert message.microseconds == 123456


@pytest.mark.parametrize(("subtype", "as4"), [(0, False), (5, True)])
def test_bgp4mp_state_change(subtype, as4):
    # RFC 6396 sections 4.4.1 and 4.4.4: Old State 3 (Active), New State 6 (Established).
    body = bgp4mp_body(
        64496,
        64497,
        1,
        bytes([192, 0, 2, 1]),
        bytes([192, 0, 2, 2]),
        struct.pack(">HH", 3, 6),
        as4=as4,
    )
    (change,) = list(mrt.iter_bgp4mp(io.BytesIO(frame(mrt.BGP4MP, subtype, body))))
    assert isinstance(change, mrt.Bgp4mpStateChange)
    assert (change.old_state, change.new_state, change.as4) == (3, 6, as4)
    assert change.peer_as == 64496


def test_bgp4mp_unknown_subtype_and_other_types_pass_through_raw():
    raw_unknown = frame(mrt.BGP4MP, 2, b"\x00\x01")
    raw_other = frame(mrt.TABLE_DUMP_V2, 1, b"abc")
    out = list(mrt.iter_bgp4mp(io.BytesIO(raw_unknown + raw_other)))
    assert [type(r) for r in out] == [mrt.MrtRecord, mrt.MrtRecord]
    assert out[0].subtype == 2
    assert out[1].body == b"abc"


def test_bgp4mp_bad_address_family_is_refused():
    body = bgp4mp_body(1, 2, 3, b"", b"", KEEPALIVE, as4=True)
    with pytest.raises(mrt.MrtError, match="Address Family"):
        list(mrt.iter_bgp4mp(io.BytesIO(frame(mrt.BGP4MP, 4, body))))


def test_bgp4mp_truncated_addresses_are_refused():
    body = bgp4mp_body(1, 2, 1, bytes(4), bytes(2), b"", as4=True)
    with pytest.raises(mrt.MrtError, match="truncated"):
        list(mrt.iter_bgp4mp(io.BytesIO(frame(mrt.BGP4MP, 4, body))))


def test_bgp4mp_message_length_must_match_the_record():
    # RFC 6396 section 4.4.2: only one BGP message, encapsulated in full.
    longer = KEEPALIVE + b"\x00"
    body = bgp4mp_body(1, 2, 1, bytes(4), bytes(4), longer, as4=True)
    with pytest.raises(mrt.MrtError, match="disagrees"):
        list(mrt.iter_bgp4mp(io.BytesIO(frame(mrt.BGP4MP, 4, body))))
    body = bgp4mp_body(1, 2, 1, bytes(4), bytes(4), KEEPALIVE[:10], as4=True)
    with pytest.raises(mrt.MrtError, match="shorter"):
        list(mrt.iter_bgp4mp(io.BytesIO(frame(mrt.BGP4MP, 4, body))))


def test_bgp4mp_tolerant_mode():
    """Row ``mrt.tolerant-bgp4mp``: a defective message is kept with its reason, a record whose
    fixed fields are unreadable goes to ``on_error`` and is yielded raw, and the stream goes on."""
    longer = KEEPALIVE + b"\x00"
    short = KEEPALIVE[:10]
    good = frame(mrt.BGP4MP, 4, bgp4mp_body(1, 2, 1, bytes(4), bytes(4), KEEPALIVE, as4=True))
    trailing = frame(mrt.BGP4MP, 4, bgp4mp_body(1, 2, 1, bytes(4), bytes(4), longer, as4=True))
    cut = frame(mrt.BGP4MP, 4, bgp4mp_body(1, 2, 1, bytes(4), bytes(4), short, as4=True))
    # Address Family 7 is neither IPv4 nor IPv6: nothing can be attributed to a peer.
    unreadable = frame(mrt.BGP4MP, 4, struct.pack(">IIHH", 1, 2, 1, 7) + bytes(8))
    stream = io.BytesIO(good + trailing + cut + unreadable + good)
    errors: list[tuple[int, str]] = []
    items = list(
        mrt.iter_bgp4mp(
            stream, tolerant=True, on_error=lambda r, why: errors.append((r.subtype, why))
        )
    )
    assert [type(i).__name__ for i in items] == [
        "Bgp4mpMessage",
        "Bgp4mpMessage",
        "Bgp4mpMessage",
        "MrtRecord",
        "Bgp4mpMessage",
    ]
    assert items[0].defect is None
    assert "disagrees" in items[1].defect
    assert items[1].message == longer
    assert "shorter" in items[2].defect
    assert items[2].message == short
    assert items[4].defect is None
    assert len(errors) == 1
    assert errors[0][0] == 4
    assert "Address Family 7" in errors[0][1]
    # without the flag the same stream still refuses at the first defect, and says what
    with pytest.raises(mrt.MrtError, match="disagrees"):
        list(mrt.iter_bgp4mp(io.BytesIO(good + trailing)))
    # without on_error the unreadable record is still yielded raw rather than raised
    again = list(mrt.iter_bgp4mp(io.BytesIO(unreadable), tolerant=True))
    assert isinstance(again[0], mrt.MrtRecord)


def test_state_change_with_trailing_octets_is_refused():
    body = bgp4mp_body(1, 2, 1, bytes(4), bytes(4), struct.pack(">HH", 1, 2) + b"\x00", as4=True)
    with pytest.raises(mrt.MrtError, match="follow"):
        list(mrt.iter_bgp4mp(io.BytesIO(frame(mrt.BGP4MP, 5, body))))


def test_parse_bgp4mp_refuses_other_types_and_subtypes():
    with pytest.raises(mrt.MrtError, match="not BGP4MP"):
        mrt.parse_bgp4mp(mrt.MrtRecord(TS, mrt.TABLE_DUMP_V2, 4, b""))
    with pytest.raises(mrt.MrtError, match="not defined"):
        mrt.parse_bgp4mp(mrt.MrtRecord(TS, mrt.BGP4MP, 3, b""))


def test_iter_bgp4mp_streams_a_mixed_file_in_order():
    state = bgp4mp_body(1, 2, 1, bytes(4), bytes(4), struct.pack(">HH", 5, 6), as4=True)
    update = bgp4mp_body(1, 2, 1, bytes(4), bytes(4), KEEPALIVE, as4=True)
    data = frame(mrt.BGP4MP, 5, state) + frame(mrt.BGP4MP, 4, update) + frame(mrt.BGP4MP, 4, update)
    kinds = [type(r).__name__ for r in mrt.iter_bgp4mp(io.BytesIO(data))]
    assert kinds == ["Bgp4mpStateChange", "Bgp4mpMessage", "Bgp4mpMessage"]
