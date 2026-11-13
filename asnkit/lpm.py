"""radix tree with longest-prefix match and a stable iterator.

A pure-Python, path-compressed binary trie, one per address family. IPv4 and IPv6 never
cross: ``::ffff:1.2.3.4`` is an IPv6 address and is matched only by IPv6 entries. A native
fast path is not part of this package (see ROADMAP.md, owner decision on the radix).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

__all__ = [
    "Radix",
    "RibEntry",
    "build_radix",
    "longest_match",
]


@dataclass(frozen=True)
class RibEntry:
    """A prefix, the origin ASNs announcing it, and where that claim came from."""

    prefix: ipaddress.IPv4Network | ipaddress.IPv6Network
    origins: tuple[int, ...]
    provenance: str = ""


class _Node:
    __slots__ = ("children", "entry", "key", "plen")

    def __init__(self, key: int, plen: int, entry: RibEntry | None = None) -> None:
        self.key = key  # the prefix as an integer with host bits zero
        self.plen = plen
        self.entry = entry
        self.children: list[_Node | None] = [None, None]


def _common(width: int, key_a: int, len_a: int, key_b: int, len_b: int) -> int:
    """Length of the common leading bits of two prefixes, capped by both lengths."""
    return min(width - (key_a ^ key_b).bit_length(), len_a, len_b)


def _bit(width: int, key: int, index: int) -> int:
    return (key >> (width - 1 - index)) & 1


def _merge(old: RibEntry, new: RibEntry) -> RibEntry:
    origins = tuple(sorted({*old.origins, *new.origins}))
    provenance = "; ".join(sorted({p for p in (old.provenance, new.provenance) if p}))
    return RibEntry(old.prefix, origins, provenance)


class Radix:
    """Longest-prefix-match table built by :func:`build_radix`."""

    def __init__(self) -> None:
        self._roots: dict[int, _Node | None] = {4: None, 6: None}
        self._entries = 0
        self._nodes = 0

    def __len__(self) -> int:
        return self._entries

    @property
    def node_count(self) -> int:
        """Trie nodes in use; path compression keeps it at most twice the entry count."""
        return self._nodes

    def __iter__(self) -> Iterator[RibEntry]:
        """Entries in a stable order: IPv4 then IPv6, each by address then prefix length."""
        for version in (4, 6):
            stack = [self._roots[version]]
            while stack:
                node = stack.pop()
                if node is None:
                    continue
                if node.entry is not None:
                    yield node.entry
                stack.append(node.children[1])
                stack.append(node.children[0])

    def _add(self, entry: RibEntry) -> None:
        net = entry.prefix
        if not isinstance(net, ipaddress.IPv4Network | ipaddress.IPv6Network):
            raise TypeError("RibEntry.prefix must be an IPv4Network or IPv6Network")
        width = net.max_prefixlen
        key, plen = int(net.network_address), net.prefixlen
        version = net.version
        parent: _Node | None = None
        side = 0
        node = self._roots[version]
        while True:
            if node is None:
                self._place(version, parent, side, _Node(key, plen, entry))
                self._entries += 1
                return
            common = _common(width, node.key, node.plen, key, plen)
            if common == node.plen and common == plen:
                node.entry = entry if node.entry is None else _merge(node.entry, entry)
                if node.entry is entry:
                    self._entries += 1
                return
            if common == node.plen:
                parent, side = node, _bit(width, key, node.plen)
                node = node.children[side]
                continue
            if common == plen:
                fresh = _Node(key, plen, entry)
                fresh.children[_bit(width, node.key, plen)] = node
            else:
                mask = ((1 << common) - 1) << (width - common) if common else 0
                fresh = _Node(key & mask, common)
                fresh.children[_bit(width, node.key, common)] = node
                fresh.children[_bit(width, key, common)] = _Node(key, plen, entry)
                self._nodes += 1
            self._place(version, parent, side, fresh)
            self._entries += 1
            return

    def _place(self, version: int, parent: _Node | None, side: int, node: _Node) -> None:
        self._nodes += 1
        if parent is None:
            self._roots[version] = node
        else:
            parent.children[side] = node

    def matches(self, address: str) -> list[RibEntry]:
        """Every entry covering ``address``, least specific first."""
        ip = _parse_address(address)
        width = ip.max_prefixlen
        key = int(ip)
        found: list[RibEntry] = []
        node = self._roots[ip.version]
        while node is not None:
            if _common(width, node.key, node.plen, key, width) < node.plen:
                break
            if node.entry is not None:
                found.append(node.entry)
            if node.plen == width:
                break
            node = node.children[_bit(width, key, node.plen)]
        return found


def _parse_address(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(address, str):
        raise TypeError("address must be a str")
    if "/" in address or "%" in address:
        raise ValueError(f"not a bare IP address (prefix length or zone id): {address!r}")
    return ipaddress.ip_address(address)


def longest_match(tree: Radix, address: str) -> RibEntry | None:
    """The most specific entry covering ``address``, or None on a miss.

    Behaviour defined by design: equals a brute-force scan for the longest covering prefix
    over the same entries. A /0 entry covers every address of its family and a miss in one
    family never falls back to the other. ``address`` must be a bare IP address; a prefix
    length or zone id raises ``ValueError``.
    """
    found = tree.matches(address)
    return found[-1] if found else None


def build_radix(entries: Iterable[RibEntry]) -> Radix:
    """Build a :class:`Radix` from ``entries``, consuming the iterable once.

    Behaviour defined by design. Entries for the same prefix are merged: origins become the
    sorted union and distinct provenance strings are joined, so the result does not depend on
    insertion order.
    """
    tree = Radix()
    for entry in entries:
        tree._add(entry)
    return tree
