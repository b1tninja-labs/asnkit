"""Date-scoped origin lookups over synthetic RIB dumps (design; origin rule RFC 6811 section 2).

Design decisions under test are stated in ``asnkit.history``: the dump chosen by UTC date, MOAS as
a sorted list, no fall back to a shorter prefix when the longest one has only AS_SET routes, and
per-peer agreement counts. The dumps are built in ``mrtbuild.py`` from the layouts of RFC 6396.
"""

from __future__ import annotations

import bz2
import datetime
import gzip
import io
import ipaddress

import pytest

from asnkit import history, mrt
from asnkit.rib import AS_SEQUENCE, AS_SET

from . import mrtbuild
from .mrtbuild import as_path_attrs, entry, peer_table

DAY1 = 1700000000  # 2023-11-14 22:13:20 UTC
DAY2 = DAY1 + 86400
D1 = datetime.date(2023, 11, 14)
D2 = datetime.date(2023, 11, 15)
PEERS = [("192.0.2.1", 65001), ("192.0.2.2", 65002), ("2001:db8::3", 65003)]


def rib(prefix: str, entries: list[bytes], *, when: int = 1700000000) -> bytes:
    """A RIB record stamped like its dump: DAY1 unless a test says otherwise."""
    return mrtbuild.rib(prefix, entries, when=when)


def path(*asns: int) -> bytes:
    return as_path_attrs((AS_SEQUENCE, list(asns)))


def dump(*records: bytes, when: int = DAY1, peers=PEERS) -> bytes:
    return peer_table(peers, when) + b"".join(records)


def archive_of(*dumps: tuple[bytes, str]) -> history.Archive:
    archive = history.Archive()
    for data, collector in dumps:
        archive.add_dump(io.BytesIO(data), collector=collector)
    return archive


BASE = dump(
    rib("203.0.113.0/24", [entry(0, path(65001, 64500)), entry(1, path(65002, 64500))], when=DAY1),
    rib("203.0.0.0/16", [entry(0, path(65001, 64999))], when=DAY1),
    rib("2001:db8:1::/48", [entry(2, path(65003, 64501))], when=DAY1),
)


def test_lookup_asn_returns_the_origin_of_the_longest_covering_prefix():
    archive = archive_of((BASE, "rv"))
    assert history.lookup_asn(archive, "203.0.113.9", D1) == [64500]
    assert history.lookup_asn(archive, "203.0.7.7", D1) == [64999]  # only the /16 covers it
    assert history.lookup_asn(archive, "2001:db8:1::5", D1) == [64501]


def test_an_unrouted_address_is_an_empty_list_not_an_error():
    archive = archive_of((BASE, "rv"))
    assert history.lookup_asn(archive, "198.18.0.1", D1) == []
    assert history.lookup_asn(archive, "2001:db8:2::1", D1) == []


def test_a_date_without_a_dump_is_a_lookup_error_not_a_neighbouring_day():
    archive = archive_of((BASE, "rv"))
    with pytest.raises(LookupError, match="2023-11-15"):
        history.lookup_asn(archive, "203.0.113.9", D2)


def test_moas_prefix_gives_every_origin_sorted_with_agreement_counts():
    data = dump(
        rib(
            "198.51.100.0/24",
            [
                entry(0, path(65001, 64600)),
                entry(1, path(65002, 64500)),
                entry(2, path(65003, 64500)),
            ],
        )
    )
    result = history.lookup(archive_of((data, "rv")), "198.51.100.1", D1)
    assert result.origins == (64500, 64600)
    assert result.agreement == {64500: 2, 64600: 1}
    assert result.peers_seen == 3
    assert result.ambiguous_peers == 0
    assert result.moas
    assert result.prefix == ipaddress.ip_network("198.51.100.0/24")


def test_a_peer_announcing_twice_counts_once():
    data = dump(
        rib("198.51.100.0/24", [entry(0, path(65001, 64500)), entry(0, path(65001, 64500))])
    )
    result = history.lookup(archive_of((data, "rv")), "198.51.100.1", D1)
    assert result.agreement == {64500: 1}
    assert result.peers_seen == 1


def test_an_as_set_route_is_ambiguous_and_the_answer_does_not_fall_back_to_a_shorter_prefix():
    data = dump(
        rib("198.51.0.0/16", [entry(0, path(65001, 64500))]),
        rib("198.51.100.0/24", [entry(1, as_path_attrs((AS_SEQUENCE, [65002]), (AS_SET, [1, 2])))]),
    )
    result = history.lookup(archive_of((data, "rv")), "198.51.100.1", D1)
    assert result.prefix == ipaddress.ip_network("198.51.100.0/24")
    assert result.origins == ()
    assert result.ambiguous_peers == 1
    assert result.peers_seen == 1
    assert history.lookup_asn(archive_of((data, "rv")), "198.51.7.7", D1) == [64500]


def test_ambiguous_and_clear_peers_for_one_prefix_are_both_reported():
    data = dump(
        rib(
            "198.51.100.0/24",
            [
                entry(0, path(65001, 64500)),
                entry(1, as_path_attrs((AS_SEQUENCE, [65002]), (AS_SET, [1, 2]))),
            ],
        )
    )
    result = history.lookup(archive_of((data, "rv")), "198.51.100.1", D1)
    assert result.origins == (64500,)
    assert result.ambiguous_peers == 1
    assert result.peers_seen == 2


def test_the_dump_for_the_date_is_named_in_the_result():
    day2 = dump(rib("203.0.113.0/24", [entry(0, path(65001, 64777))], when=DAY2), when=DAY2)
    archive = archive_of((BASE, "route-views2"), (day2, "rrc00"))
    first = history.lookup(archive, "203.0.113.9", D1)
    second = history.lookup(archive, "203.0.113.9", D2)
    assert (first.origins, second.origins) == ((64500,), (64777,))
    assert first.dump.collector == "route-views2"
    assert second.dump.collector == "rrc00"
    assert second.dump.date == D2
    assert second.dump.timestamp == DAY2
    assert second.dump.routes == 1
    assert first.dump.routes == 4
    assert first.dump.peers == 3


def test_two_dumps_on_one_date_the_earliest_answers():
    early = dump(rib("203.0.113.0/24", [entry(0, path(65001, 64111))], when=DAY1), when=DAY1)
    late = dump(
        rib("203.0.113.0/24", [entry(0, path(65001, 64222))], when=DAY1 + 3600), when=DAY1 + 3600
    )
    archive = archive_of((late, "late"), (early, "early"))  # added out of order
    assert history.lookup_asn(archive, "203.0.113.1", D1) == [64111]
    assert history.lookup(archive, "203.0.113.1", D1).dump.collector == "early"


def test_date_is_the_utc_date_of_the_dump_timestamp():
    just_before_midnight = datetime.datetime(2023, 11, 14, 23, 59, 59, tzinfo=datetime.UTC)
    stamp = int(just_before_midnight.timestamp())
    data = dump(rib("203.0.113.0/24", [entry(0, path(65001, 64500))], when=stamp), when=stamp)
    archive = archive_of((data, "rv"))
    assert history.lookup_asn(archive, "203.0.113.1", D1) == [64500]
    with pytest.raises(LookupError):
        history.lookup_asn(archive, "203.0.113.1", D2)


def test_routes_with_undecodable_as_paths_are_counted_and_contribute_nothing():
    data = dump(
        rib("203.0.113.0/24", [entry(0, path(65001, 64500)), entry(1, b"\x40\x01\x01\x00")])
    )
    archive = archive_of((data, "rv"))
    assert archive.dumps[0].unreadable == 1
    assert history.lookup_asn(archive, "203.0.113.1", D1) == [64500]


def test_an_empty_stream_has_no_date_and_is_refused():
    with pytest.raises(mrt.MrtError, match="no date"):
        history.Archive().add_dump(io.BytesIO(peer_table(PEERS)), collector="rv")
    with pytest.raises(mrt.MrtError):
        history.Archive().add_dump(io.BytesIO(b""), collector="rv")


def test_a_bad_address_is_refused_like_longest_match():
    archive = archive_of((BASE, "rv"))
    with pytest.raises(ValueError, match="bare IP"):
        history.lookup(archive, "203.0.113.0/24", D1)


@pytest.mark.parametrize(("suffix", "opener"), [(".bz2", bz2.open), (".gz", gzip.open), ("", open)])
def test_add_path_reads_plain_gzip_and_bzip2_dumps(tmp_path, suffix, opener):
    target = tmp_path / ("rib.20231114.2213" + suffix)
    with opener(target, "wb") as handle:
        handle.write(BASE)
    archive = history.Archive()
    info = archive.add_path(target, collector="route-views2")
    assert info.name == target.name
    assert info.collector == "route-views2"
    assert history.lookup_asn(archive, "203.0.113.9", D1) == [64500]


def test_the_archive_lists_its_dumps_in_the_order_added():
    archive = archive_of((BASE, "a"), (BASE, "b"))
    assert [d.collector for d in archive.dumps] == ["a", "b"]
