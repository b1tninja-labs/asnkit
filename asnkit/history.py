"""Date-scoped origin lookups over local RIB dumps: which AS announced this address on that day.

The question comes from pkgtrust: the origin AS of a distribution mirror's IP address on a
given date. It needs a local TABLE_DUMP_V2 dump of that date and nothing else: no RPKI, no
RTR, no network. An :class:`Archive` holds the dumps added to it; :func:`lookup` answers with
the origin ASes and the evidence behind them, and :func:`lookup_asn` returns just the ASes.

Design decisions, stated because the RFCs say nothing about them:

* a date selects the dumps whose MRT timestamp falls on that UTC date, and the earliest of
  them answers; a date with no dump raises ``LookupError`` rather than answering from a
  neighbouring day, and the dump used is named in the result;
* the answer is the longest prefix in the dump covering the address, and its origins are the
  ASes the dump's peers announce it from, several when the prefix is MOAS. If the longest
  prefix has only routes whose origin is ambiguous (an AS_SET, see :mod:`asnkit.rib`), the
  answer is an empty list with ``ambiguous_peers`` set: it does not fall back to a shorter
  prefix, which would be a different route;
* an address no prefix covers gives an empty list: "not routed in that dump", which is
  different from "no dump";
* every route is counted per peer (peer address and AS), so ``agreement`` says how many
  peers saw each origin and ``peers_seen`` how many saw the prefix at all.

Not built yet (ROADMAP.md): the on-disk, versioned, integrity-hashed index the README promises
and a full-RIB memory measurement; every dump is indexed in memory when it is added.
"""

from __future__ import annotations

import bz2
import datetime
import gzip
import ipaddress
from dataclasses import dataclass
from typing import IO, TYPE_CHECKING, cast

from . import mrt, rib
from .lpm import Radix, RibEntry, build_radix, longest_match

if TYPE_CHECKING:
    import pathlib

__all__ = [
    "Archive",
    "DumpInfo",
    "Lookup",
    "lookup",
    "lookup_asn",
    "open_dump",
]

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class DumpInfo:
    """Where an answer came from: one indexed dump."""

    collector: str
    name: str
    timestamp: int
    date: datetime.date
    routes: int
    peers: int
    unreadable: int


@dataclass(frozen=True)
class Lookup:
    """The answer to :func:`lookup`, with its evidence.

    ``prefix`` is the longest covering prefix, ``None`` when nothing covers the address.
    ``origins`` are the origin ASes, sorted. ``agreement`` maps each origin to the number of
    distinct peers that announced the prefix from it, ``peers_seen`` is the number of distinct
    peers that had any route for the prefix, and ``ambiguous_peers`` counts those whose route
    ended in an AS_SET and so named no origin.
    """

    address: str
    when: datetime.date
    prefix: Network | None
    origins: tuple[int, ...]
    agreement: dict[int, int]
    peers_seen: int
    ambiguous_peers: int
    dump: DumpInfo

    @property
    def moas(self) -> bool:
        """True when more than one origin AS announced the prefix."""
        return len(self.origins) > 1


@dataclass
class _Dump:
    info: DumpInfo
    tree: Radix
    votes: dict[Network, dict[int, set[tuple[str, int]]]]
    ambiguous: dict[Network, set[tuple[str, int]]]


class Archive:
    """A set of indexed RIB dumps, searched by date. Add dumps with :meth:`add_dump`."""

    def __init__(self) -> None:
        self._dumps: list[_Dump] = []

    @property
    def dumps(self) -> tuple[DumpInfo, ...]:
        """The indexed dumps in the order they were added."""
        return tuple(d.info for d in self._dumps)

    def add_dump(self, stream: IO[bytes], *, collector: str, name: str = "") -> DumpInfo:
        """Read a TABLE_DUMP_V2 dump from ``stream`` and index it.

        ``collector`` names the route collector (it is not in the dump). The dump time is the
        MRT timestamp of its first RIB record. ``MrtError`` for a stream that is not a
        TABLE_DUMP_V2 RIB dump; a route whose AS_PATH cannot be decoded is counted in
        ``unreadable`` and contributes nothing. An empty stream is refused: it has no date.
        """
        votes: dict[Network, dict[int, set[tuple[str, int]]]] = {}
        ambiguous: dict[Network, set[tuple[str, int]]] = {}
        peers: set[tuple[str, int]] = set()
        routes = unreadable = 0
        stamp: int | None = None
        for row in rib.iter_rib_entries(stream):
            if stamp is None:
                stamp = row.timestamp
            routes += 1
            who = (str(row.peer.address), row.peer.asn)
            peers.add(who)
            try:
                origin = row.origin()
            except rib.AsPathError:
                unreadable += 1
                continue
            if origin.asn is None:
                ambiguous.setdefault(row.prefix, set()).add(who)
                votes.setdefault(row.prefix, {})
            else:
                votes.setdefault(row.prefix, {}).setdefault(origin.asn, set()).add(who)
        if stamp is None:
            raise mrt.MrtError("the dump holds no RIB entries, so it has no date")
        when = datetime.datetime.fromtimestamp(stamp, datetime.UTC).date()
        info = DumpInfo(collector, name, stamp, when, routes, len(peers), unreadable)
        tree = build_radix(
            RibEntry(prefix, tuple(sorted(by_origin)), f"{collector} {when}")
            for prefix, by_origin in votes.items()
        )
        self._dumps.append(_Dump(info, tree, votes, ambiguous))
        return info

    def add_path(self, path: pathlib.Path, *, collector: str) -> DumpInfo:
        """Index the dump file at ``path`` (plain, ``.gz`` or ``.bz2``); see :func:`open_dump`."""
        with open_dump(path) as stream:
            return self.add_dump(stream, collector=collector, name=path.name)

    def _dumps_on(self, when: datetime.date) -> list[_Dump]:
        """The dumps dated ``when`` (UTC), earliest first."""
        return sorted(
            (d for d in self._dumps if d.info.date == when), key=lambda d: d.info.timestamp
        )


def open_dump(path: pathlib.Path) -> IO[bytes]:
    """Open a dump file for binary reading, decompressing by the ``.bz2`` or ``.gz`` suffix.

    RouteViews and RIPE RIS publish dumps as ``.bz2`` and ``.gz`` (operational practice, not
    an RFC). The suffix decides; the content is not sniffed.
    """
    suffix = path.suffix.lower()
    if suffix == ".bz2":
        return bz2.open(path, "rb")
    if suffix == ".gz":
        return cast("IO[bytes]", gzip.open(path, "rb"))
    return path.open("rb")


def lookup(archive: Archive, address: str, when: datetime.date) -> Lookup:
    """The origin AS(es) of ``address`` on ``when`` and the evidence (see the module docstring).

    ``LookupError`` when the archive holds no dump dated ``when``; ``ValueError`` for an
    address that is not a bare IP address (a prefix length or a zone id is refused, as
    :func:`asnkit.lpm.longest_match` does).
    """
    candidates = archive._dumps_on(when)
    if not candidates:
        raise LookupError(f"no dump dated {when.isoformat()} in the archive")
    dump = candidates[0]
    found = longest_match(dump.tree, address)
    if found is None:
        return Lookup(address, when, None, (), {}, 0, 0, dump.info)
    by_origin = dump.votes[found.prefix]
    agreement = {asn: len(peers) for asn, peers in sorted(by_origin.items())}
    seen: set[tuple[str, int]] = set(dump.ambiguous.get(found.prefix, ()))
    for peers in by_origin.values():
        seen |= peers
    return Lookup(
        address=address,
        when=when,
        prefix=found.prefix,
        origins=tuple(agreement),
        agreement=agreement,
        peers_seen=len(seen),
        ambiguous_peers=len(dump.ambiguous.get(found.prefix, ())),
        dump=dump.info,
    )


def lookup_asn(archive: Archive, address: str, when: datetime.date) -> list[int]:
    """Origin ASN(s) of ``address`` on ``when`` as a sorted list, several for a MOAS prefix.

    Behaviour defined by design for pkgtrust's mirror question; :func:`lookup` returns the
    same answer with the prefix, the dump and the per-origin peer counts. An empty list means
    the address was not routed in the dump (or only by AS_SET routes); ``LookupError`` means
    there is no dump for the date.
    """
    return list(lookup(archive, address, when).origins)
