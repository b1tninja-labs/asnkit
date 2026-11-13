# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

### Added

- `mrt.parse_rib_afi_safi`, `mrt.parse_rib_generic`: TABLE_DUMP_V2 RIB records, subtypes 2-6 and the RFC 8050 ADD-PATH subtypes 8-12.
- `mrt.parse_bgp4mp`, `mrt.iter_bgp4mp`: BGP4MP and BGP4MP_ET message and state-change records, including the `_AS4`, `_LOCAL` and `_ADDPATH` variants.
- `rib.iter_rib_entries`, `rib.origin_of`: one row per RIB entry with the AS_PATH octets cut out raw, and the RFC 6811 section 2 origin with an AS_SET reported as ambiguous.
- `history.Archive`, `history.lookup`, `history.lookup_asn`: origin AS of an address on a date from local RIB dumps, with the dump and per-origin peer counts as evidence.
- `tools/fetch_corpus.py` and `tools/corpus.json`: three real MRT files (a RouteViews RIB and one RouteViews and one RIS updates file), fetched into a cache outside the repository and pinned by SHA-256 and size; `tests/test_mrt_corpus.py` reads them end to end and skips loudly without them.

### Changed

- AS_PATH decoding and attribute framing in `rib` now go through `pathattr` (`aspath.parse_as_path`, `attribute.walk`), a sibling by path. `rib.decode_as_path` and `rib.AsSegment` are removed; segments are `pathattr.aspath.Segment` (re-exported as `rib.Segment`).
- `tests/` is a package, so a sibling checkout on the path cannot shadow it.

The rest of the package is a shell: the public surface exists as typed stubs that raise
`NotImplementedError`, and [ROADMAP.md](ROADMAP.md) lists what has to happen first.

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for asnkit.
- `asnkit.apps` namespace reserved for composition that is not protocol behaviour.
