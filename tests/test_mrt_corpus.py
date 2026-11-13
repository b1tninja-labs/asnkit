"""Real MRT files, read end to end: row ``mrt.corpus-real-bview``.

The files are pinned in ``tools/corpus.json`` (URL, SHA-256, size, the date read and the operator's
terms) and fetched by ``tools/fetch_corpus.py`` into a cache outside the repository. Nothing here is
vendored. When the cache is absent every test below skips with the command that fills it, so a
green run without the corpus says so in the ``-ra`` summary instead of passing in silence.

The counts are exact, measured on 2026-11-13 from the pinned bytes. A changed count means the
reader changed, because the bytes cannot (the pin is checked before any count is taken). On these
three files nothing is refused: no MRT record by ``asnkit.mrt`` and no BGP message by ``pathattr``.
What the files hold that the RFCs constrain, read through rfclib on 2026-11-13:

* RIS rrc00 writes BGP4MP_MESSAGE (subtype 1) records, whose AS_PATH RFC 6396 section 4.4.2 says
  MUST hold 2-byte AS numbers; all 527 UPDATEs among them decode with 2-octet AS numbers, and the
  173 that carry AS4_PATH also carry AS_TRANS (23456) in AS_PATH, which is the RFC 6793 section
  4.2.2 encoding by an OLD-speaker session.
* RouteViews writes BGP4MP_ET (type 17) only, so every record carries microseconds (RFC 6396
  section 3).
* The RouteViews RIB's PEER_INDEX_TABLE lists, at index 0, a peer with BGP ID 0.0.0.0, address
  0.0.0.0 and AS 0 that no RIB entry references, and three more listed peers have no entries.
  RFC 6396 section 4.3.1 puts no constraint on either, so this is recorded, not refused.
* No ADD-PATH subtype appears in any of the three (RFC 8050 section 5 codes).
"""

from __future__ import annotations

import bz2
import collections
import gzip
import importlib.util
import ipaddress
import pathlib
from typing import IO, Any, cast

import pytest
from pathattr import message
from pathattr.aspath import AS_TRANS, has_as_set, parse_as_path
from pathattr.attribute import Action

from asnkit import mrt, rib

TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "fetch_corpus.py"
BVIEW = "routeviews-iraq-ixp.bgw-rib.20261112.0000.bz2"
RV_UPDATES = "routeviews-route-views2-updates.20261112.0000.bz2"
RIS_UPDATES = "ris-rrc00-updates.20261112.0000.gz"


def _tool() -> Any:
    spec = importlib.util.spec_from_file_location("asnkit_fetch_corpus", TOOL)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FETCH = _tool()


def corpus(name: str) -> pathlib.Path:
    """The cached file, checked against its pin; a loud skip when it is not there."""
    (entry,) = [e for e in FETCH.load_manifest() if e["name"] == name]
    path = FETCH.cached(entry)
    if path is None:
        pytest.skip(
            f"real-data corpus absent: {name} is not in {FETCH.cache_dir()} with its pinned "
            f"SHA-256; run `python tools/fetch_corpus.py` (or set {FETCH.ENV})"
        )
    return path


def opened(path: pathlib.Path) -> IO[bytes]:
    return cast("IO[bytes]", bz2.open(path) if path.suffix == ".bz2" else gzip.open(path))


def test_manifest_pins_every_file_with_a_read_label():
    for entry in FETCH.load_manifest():
        assert entry["url"].startswith("https://"), entry["name"]
        assert len(entry["sha256"]) == 64, entry["name"]
        assert entry["size"] > 0, entry["name"]
        assert entry["read"] == "2026-11-13", entry["name"]
        assert "vendored" in entry["terms"], entry["name"]


def record_counts(path: pathlib.Path) -> collections.Counter[tuple[int, int]]:
    with opened(path) as stream:
        return collections.Counter((r.type, r.subtype) for r in mrt.iter_records(stream))


def test_real_bview_excerpt():
    """The smallest real TABLE_DUMP_V2 RIB, every record and every RIB entry."""
    path = corpus(BVIEW)
    assert record_counts(path) == {(13, 1): 1, (13, 2): 380, (13, 4): 242}
    skipped: list[str] = []
    with opened(path) as stream:
        rows = list(rib.iter_rib_entries(stream, on_skip=lambda _r, why: skipped.append(why)))
    assert skipped == []
    assert len(rows) == 1323
    assert collections.Counter(r.afi for r in rows) == {1: 838, 2: 485}
    assert all(r.path_id is None for r in rows)  # no ADD-PATH subtype
    assert all(r.framing_error is None and r.as_path is not None for r in rows)
    assert collections.Counter(r.origin().kind for r in rows) == {"sequence": 1323}
    used = collections.Counter(r.peer_index for r in rows)
    assert used == {6: 372, 5: 367, 10: 241, 11: 241, 1: 95, 3: 3, 7: 2, 4: 1, 8: 1}
    with opened(path) as stream:
        first = next(mrt.iter_records(stream))
    table = mrt.parse_peer_index_table(first.body)
    peers = table.peers
    assert len(peers) == 13
    unspecified = ipaddress.IPv4Address(0)
    assert (peers[0].bgp_id, peers[0].address, peers[0].asn) == (unspecified, unspecified, 0)
    assert sorted(set(range(13)) - set(used)) == [0, 2, 9, 12]


def bgp_census(path: pathlib.Path) -> dict[str, collections.Counter[Any]]:
    records: collections.Counter[Any] = collections.Counter()
    messages: collections.Counter[Any] = collections.Counter()
    updates: collections.Counter[Any] = collections.Counter()
    with opened(path) as stream:
        for item in mrt.iter_bgp4mp(stream):
            records[type(item).__name__] += 1
            if not isinstance(item, mrt.Bgp4mpMessage):
                continue
            assert not item.addpath
            decoded = message.decode(item.message, four_octet_as=item.as4)
            messages[type(decoded).__name__] += 1
            if not isinstance(decoded, message.Update):
                continue
            updates[decoded.action] += 1
            as_path = next((a for a in decoded.attributes if a.type_code == 2), None)
            segments = parse_as_path(as_path.value, item.as4) if as_path is not None else ()
            updates["as_set"] += has_as_set(segments)
            if not item.as4:
                updates["two_octet"] += 1
                if any(a.type_code == 17 for a in decoded.attributes):
                    updates["as4_path"] += 1
                    updates["as_trans"] += any(AS_TRANS in s.asns for s in segments)
    return {"records": records, "messages": messages, "updates": updates}


def test_real_routeviews_updates_end_to_end():
    path = corpus(RV_UPDATES)
    assert record_counts(path) == {(17, 4): 100953}
    census = bgp_census(path)
    assert census["records"] == {"Bgp4mpMessage": 100953}
    assert census["messages"] == {"Update": 100953}
    assert census["updates"] == {Action.NONE: 100953, "as_set": 6}


def test_real_ris_updates_end_to_end():
    path = corpus(RIS_UPDATES)
    assert record_counts(path) == {(16, 0): 113, (16, 1): 538, (16, 4): 194188, (16, 5): 57}
    census = bgp_census(path)
    assert census["records"] == {"Bgp4mpMessage": 194726, "Bgp4mpStateChange": 170}
    assert census["messages"] == {"Update": 194162, "Keepalive": 547, "Open": 11, "Notification": 6}
    assert census["updates"] == {
        Action.NONE: 194162,
        "as_set": 10,
        "two_octet": 527,
        "as4_path": 173,
        "as_trans": 173,
    }
