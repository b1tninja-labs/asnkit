"""Longest-prefix match: the oracle is a brute-force scan over the same entries."""

from __future__ import annotations

import ipaddress
import random

import pytest

from asnkit import lpm
from asnkit.lpm import RibEntry, build_radix, longest_match


def entry(prefix: str, *origins: int, provenance: str = "") -> RibEntry:
    return RibEntry(ipaddress.ip_network(prefix), tuple(origins), provenance)


def brute_force(entries: list[RibEntry], address: str) -> RibEntry | None:
    ip = ipaddress.ip_address(address)
    best = None
    for e in entries:
        covers = e.prefix.version == ip.version and ip in e.prefix
        if covers and (best is None or e.prefix.prefixlen > best.prefix.prefixlen):
            best = e
    return best


def random_entries(rng: random.Random, version: int, count: int) -> list[RibEntry]:
    width = 32 if version == 4 else 128
    cls = ipaddress.IPv4Network if version == 4 else ipaddress.IPv6Network
    out: dict[tuple[int, int], RibEntry] = {}
    pool = [rng.getrandbits(width) for _ in range(8)]  # clustered, so prefixes nest
    for _ in range(count):
        base = rng.choice(pool)
        plen = rng.choice([0, 1, 8, 16, 24, width, rng.randint(0, width)])
        flip = rng.getrandbits(width) & ((1 << rng.randint(0, width)) - 1)
        value = ((base ^ flip) >> (width - plen)) << (width - plen) if plen else 0
        net = cls((value, plen))
        out[(value, plen)] = RibEntry(net, (rng.randint(1, 65000),), "t")
    return list(out.values())


def random_addresses(rng: random.Random, entries: list[RibEntry], version: int, n: int):
    width = 32 if version == 4 else 128
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    for _ in range(n):
        if entries and rng.random() < 0.7:
            net = rng.choice(entries).prefix
            host = rng.getrandbits(width - net.prefixlen) if net.prefixlen < width else 0
            yield str(cls(int(net.network_address) | host))
        else:
            yield str(cls(rng.getrandbits(width)))


@pytest.mark.parametrize("version", [4, 6])
def test_longest_match_equals_bruteforce(version):
    rng = random.Random(20261112 + version)
    entries = random_entries(rng, version, 400)
    tree = build_radix(entries)
    assert len(tree) == len(entries)
    for address in random_addresses(rng, entries, version, 20_000):
        assert longest_match(tree, address) == brute_force(entries, address), address


def test_matches_runs_least_to_most_specific():
    tree = build_radix([entry("10.1.0.0/16", 2), entry("10.0.0.0/8", 1), entry("10.1.2.0/24", 3)])
    assert [e.origins for e in tree.matches("10.1.2.3")] == [(1,), (2,), (3,)]
    assert longest_match(tree, "10.1.2.3").origins == (3,)
    assert longest_match(tree, "10.1.3.3").origins == (2,)


def test_longest_match_default_route():
    tree = build_radix([entry("0.0.0.0/0", 1), entry("10.0.0.0/8", 2)])
    assert longest_match(tree, "8.8.8.8").origins == (1,)
    assert longest_match(tree, "10.9.9.9").origins == (2,)


def test_longest_match_miss_returns_none_not_default():
    tree = build_radix([entry("10.0.0.0/8", 1)])
    assert longest_match(tree, "11.0.0.1") is None


def test_family_isolation():
    tree = build_radix([entry("0.0.0.0/0", 1)])
    assert longest_match(tree, "::1") is None
    assert longest_match(build_radix([entry("::/0", 2)]), "1.2.3.4") is None


def test_ipv4_mapped_ipv6_address_is_ipv6():
    tree = build_radix([entry("1.2.3.0/24", 1)])
    assert longest_match(tree, "::ffff:1.2.3.4") is None
    assert longest_match(build_radix([entry("::ffff:0:0/96", 2)]), "::ffff:1.2.3.4").origins == (2,)


def test_host_routes():
    tree = build_radix([entry("192.0.2.1/32", 1), entry("2001:db8::1/128", 2)])
    assert longest_match(tree, "192.0.2.1").origins == (1,)
    assert longest_match(tree, "192.0.2.2") is None
    assert longest_match(tree, "2001:db8::1").origins == (2,)


def test_duplicate_prefix_merges_origins_sorted():
    tree = build_radix(
        [entry("10.0.0.0/8", 30, provenance="b"), entry("10.0.0.0/8", 20, 30, provenance="a")]
    )
    assert len(tree) == 1
    (only,) = list(tree)
    assert only.origins == (20, 30)
    assert only.provenance == "a; b"


def test_insert_order_independent():
    rng = random.Random(3)
    entries = random_entries(rng, 4, 200) + random_entries(rng, 6, 200)
    a = build_radix(entries)
    shuffled = entries[:]
    rng.shuffle(shuffled)
    b = build_radix(shuffled)
    assert list(a) == list(b)
    assert a.node_count == b.node_count


def test_iteration_is_stable_and_complete():
    entries = [entry("10.1.0.0/16", 1), entry("10.0.0.0/8", 2), entry("2001:db8::/32", 3)]
    tree = build_radix(entries)
    assert [str(e.prefix) for e in tree] == ["10.0.0.0/8", "10.1.0.0/16", "2001:db8::/32"]


@pytest.mark.parametrize("bad", ["10.0.0.1/8", "fe80::1%eth0", "1.2.3", "", "1.2.3.4 "])
def test_bad_address_rejected(bad):
    with pytest.raises(ValueError, match=r".*"):
        longest_match(build_radix([entry("10.0.0.0/8", 1)]), bad)


def test_non_string_address_rejected():
    with pytest.raises(TypeError):
        longest_match(build_radix([]), 167772161)


def test_empty_tree_returns_none():
    assert longest_match(build_radix([]), "1.2.3.4") is None
    assert len(build_radix([])) == 0


def test_build_radix_consumes_a_generator_once():
    tree = build_radix(entry(f"10.{i}.0.0/16", i) for i in range(5))
    assert len(tree) == 5


def test_entry_prefix_must_be_a_network():
    with pytest.raises(TypeError):
        build_radix([RibEntry("10.0.0.0/8", (1,))])


def test_node_count_is_bounded_by_twice_the_entries():
    rng = random.Random(11)
    entries = random_entries(rng, 4, 3_000) + random_entries(rng, 6, 3_000)
    tree = build_radix(entries)
    assert tree.node_count <= 2 * len(tree)


def test_module_exports():
    assert set(lpm.__all__) == {"Radix", "RibEntry", "build_radix", "longest_match"}
