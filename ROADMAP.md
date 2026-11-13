# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation asnkit could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `mrt.iter_records()` | RFC 6396 sections 2, 3 | `[ok]` | `tests/test_mrt.py::test_iter_records_reads_header_fields`, `tests/test_mrt.py::test_iter_records_length_cap_refused_before_read`, `tests/test_mrt.py::test_iter_records_streams_incrementally`, `tests/test_mrt.py::test_extended_timestamp_splits_microseconds` | M1 |
| `mrt.parse_peer_index_table()` | RFC 6396 section 4.3.1 (Figure 18 vector as printed; no erratum touches it) | `[ok]` | `tests/test_mrt.py::test_peer_index_table_figure_18`, `tests/test_mrt.py::test_peer_index_table_mixed_v4_v6_and_16_32_bit_as` | M1 |
| `mrt.parse_rib_afi_safi()` / `mrt.parse_rib_generic()`: RIB subtypes 2-6 (4.3.2, 4.3.3) with the entry header and raw entries, plus the RFC 8050 `*_ADDPATH` subtypes 8-12 (Path Identifier before Attribute Length; RIB_GENERIC_ADDPATH unchanged). The subtype codes are pinned already; the layouts are not parsed | RFC 6396 sections 4.3.2-4.3.4, RFC 8050 sections 4, 5.2 | `[ ]` | `tests/test_mrt.py::test_addpath_subtype_codes_match_rfc_8050_section_5` pins the codes only | M1 |
| `mrt.iter_bgp4mp()`: BGP4MP / BGP4MP_ET message records, `_AS4` and `_ADDPATH` variants, so bgpfeed consumes one MRT codec | RFC 6396 section 4.4, RFC 8050 section 3 | `[ ]` | `tests/test_mrt.py::test_iter_bgp4mp` (to be written) | M1 |
| `rib.iter_rib_entries()`: AS_PATH bytes kept raw (the entry carries the attribute octets undecoded); IPv6 and ADD-PATH are acceptance criteria. Decoding waits for pathattr | RFC 6396 section 4.3.4 | `[ ]` | `tests/test_obligations.py::test_iter_rib_entries` (to be written) | M1 |
| `rib.origin_of()`: decode AS_PATH to an origin through pathattr. An AS_SET as the last segment is reported as ambiguous, never guessed (RFC 9774 deprecates originating one, but archives still hold them); the MP_REACH_NLRI form in MRT entries is the 4.3.4 exception | RFC 6396 section 4.3.4, RFC 9774 | `[ ]` | `tests/test_obligations.py::test_origin_of` (to be written) | M1 |
| `lpm.longest_match()` | design: equals a brute-force scan for the longest covering prefix over the same entries | `[ok]` | `tests/test_lpm.py::test_longest_match_equals_bruteforce` | M2 |
| `lpm.build_radix()` | design: path-compressed, pure Python, duplicates merged, insertion-order independent | `[ok]` | `tests/test_lpm.py::test_insert_order_independent`, `tests/test_lpm.py::test_node_count_is_bounded_by_twice_the_entries` | M2 |
| `history.lookup_asn()`: origin ASN of an address on a date, as a list (MOAS). The pkgtrust use is the origin ASN of a distribution mirror's IP. It needs M1 and M2 and a local RIB dump only: no RPKI, no RTR | design | `[ ]` | `tests/test_obligations.py::test_lookup_asn` (to be written) | M3 |
| `history.lookup_asn()` provenance: collector, dump timestamp, peers that saw the prefix and how many agree; plus an index format, versioned and integrity-hashed, since the README promises no per-archive build step | design | `[ ]` | `tests/test_obligations.py::test_lookup_provenance` (to be written) | M3 |
| `rov.annotate()`: also reproduces the RFC 6811 classification, defined once with routevalid | RFC 6480, RFC 6811 | `[ ]` | `tests/test_obligations.py::test_annotate` (to be written) | M4 |

## 2. Milestones

- M1 MRT reader for TABLE_DUMP_V2 with a streaming test corpus. Common header and PEER_INDEX_TABLE are done; the RIB records, BGP4MP and AS_PATH are not. **M1-M3 need pathattr** (`D:\code\pathattr`, in progress), not rpkit or rtrkit, which block only M4. Until pathattr lands the reader keeps AS_PATH bytes raw
- M2 radix LPM, pure Python (done 2026-11-13); a native fast path is not planned, see section 5
- M3 date-scoped history over several RIB dumps
- M4 validation join from rtrkit, with reason codes carried into the answer
- M5 CLI parity with pyasn so a migration is a one-line change
- M6 publication: 0.1.0 with a migration note from pyasn

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 4271 carries 9 verified errata and 12 updates. Consult them before trusting any UPDATE parsing recipe copied from a blog post.
- RFC 6396 carries 2 verified errata, both in Appendix A (5511: Figure 16 attribute length 0x1f -> 0x23 and NEXT_HOP c6 33 64 55 -> c6 33 64 bc; 6640: Figure 19 MP_REACH_NLRI must be in the 4.3.4 form, length 0x2b -> 0x21, trailing reserved octet and NLRI removed) and 1 held (3817, editorial, section 5.7 cross-references). Tests use the corrected bytes only (`tests/test_mrt.py`). Erratum 6640 does not restate the record Length and Attribute Length fields; they shrink by 10 (87 -> 77, 68 -> 58), which is our derivation, checked in `test_corrected_figure_19_mp_reach_is_in_mrt_form`.
- RFC 8050 (MRT with ADD-PATH, Proposed Standard, 2017-05, no errata) extends RFC 6396 but rfclib shows no "updates" link, so tooling will not warn. It is in the spine now.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| a BGP speaker or session FSM | `[no]` | a named document requires it |
| flow data | `[no]` | a named document requires it |
| a hosted API that hides where the answer came from | `[no]` | a named document requires it |

## 5. Open questions

- **Owner decision, recorded 2026-11-13: no native radix.** M2 originally planned an optional native fast path. A compiled extension conflicts with the stdlib-only rule and, per PORTFOLIO, a new dependency becomes its own project. Not built. The pure-Python trie is the implementation; revisit only if a full-RIB benchmark (not yet run: `[ ]` row below) shows it unusable, and then as an owner decision.
- M5 (CLI parity with pyasn) has no row: add one naming the CLI surface, or drop the rung
- Full-RIB benchmark of the pure-Python radix (memory and lookups per second on a RouteViews `bview`): not measured; the `test_node_count_is_bounded_by_twice_the_entries` test bounds structure only.

## 5a. Follow-up rows from the 2026-11-13 deep dive

- Dependency: add pathattr to `docs/plan.md` (generated from the PORTFOLIO plan: change it there). M1-M3 do not depend on rpkit or rtrkit; only M4 does.
- Corpus: commit a small real RouteViews or RIS `bview` excerpt with provenance (collector, date, sha256) under `tests/data/`; bytes are verified by hash, not by the TLS download.
- Policy: RFC 6811 and RFC 8481 classification is shared with routevalid; define it once.
- Operational sources (not RFCs): RouteViews and RIPE RIS archive layout need rows like bgpfeed's.
- RFC 4760 (MP_REACH exception) and RFC 6793 (4-octet AS in TABLE_DUMP_V2 AS_PATH) belong to the spine once pathattr decoding is wired in.
- MRT ownership: asnkit owns MRT parsing (common header, TABLE_DUMP_V2, BGP4MP, ADD-PATH); bgpfeed imports it. Recorded in `bgpfeed/ROADMAP.md` as an owner decision.
- CLI rows (M5), `history` index format: see the rows in section 1.
- Stale plan statement: `docs/plan.md` lists rpkit and rtrkit as blockers for the whole project; true for M4 only.
- Removed the optional `fast = ["msgspec"]` extra from `pyproject.toml`: third-party packages are not allowed here (owner rule 2026-11-13).


## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
