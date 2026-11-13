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
| `mrt.parse_rib_afi_safi()` / `mrt.parse_rib_generic()`: RIB subtypes 2-6 (4.3.2, 4.3.3) with the entry header and raw entries, plus the RFC 8050 `*_ADDPATH` subtypes 8-12 (Path Identifier before Attribute Length; RIB_GENERIC_ADDPATH: NLRI leads with a Path Identifier, entries unchanged). Vector: RFC 6396 Figure 19 with erratum 6640; RFC 8050 prints no bytes, so the ADD-PATH bodies are Figure 19 with the identifier inserted where RFC 8050 Figure 1 puts it, and say so | RFC 6396 sections 4.3.2-4.3.4, RFC 8050 sections 4, 5.2 | `[ok]` | `tests/test_mrt_records.py::test_rib_ipv6_unicast_figure_19_corrected`, `tests/test_mrt_records.py::test_each_afi_safi_specific_subtype_fixes_its_family_and_cast`, `tests/test_mrt_records.py::test_addpath_subtypes_read_the_path_identifier_before_attribute_length`, `tests/test_mrt_records.py::test_an_addpath_body_is_not_readable_as_the_plain_subtype`, `tests/test_mrt_records.py::test_rib_generic_addpath_reads_a_path_identifier_in_the_nlri_and_none_in_entries`, `tests/test_mrt_records.py::test_rib_record_truncated_at_every_octet_is_refused` | M1 |
| `mrt.iter_bgp4mp()`: BGP4MP / BGP4MP_ET message and state-change records, `_AS4`, `_LOCAL` and `_ADDPATH` variants, so bgpfeed consumes one MRT codec. The BGP message stays raw (pathattr decodes it); a message whose Length field disagrees with the record is refused (policy, see `mrt.tolerant-bgp4mp`) | RFC 6396 section 4.4, RFC 8050 section 3 | `[ok]` | `tests/test_mrt_records.py::test_bgp4mp_message_as4_figure_16_corrected`, `tests/test_mrt_records.py::test_bgp4mp_message_subtype_flags`, `tests/test_mrt_records.py::test_bgp4mp_state_change`, `tests/test_mrt_records.py::test_bgp4mp_et_carries_microseconds`, `tests/test_mrt_records.py::test_bgp4mp_message_length_must_match_the_record` | M1 |
| `rib.iter_rib_entries()`: one row per RIB Entry with the peer, prefix (IPv4 and IPv6), Path Identifier and the attribute octets undecoded, the AS_PATH value octets cut out raw; records that are not RIB rows go to `on_skip` or raise | RFC 6396 section 4.3.4 | `[ok]` | `tests/test_rib.py::test_figure_19_row_with_its_peer_and_as_path`, `tests/test_rib.py::test_rows_come_in_dump_order_one_per_entry`, `tests/test_rib.py::test_addpath_rows_carry_their_path_identifier`, `tests/test_rib.py::test_records_that_are_not_rib_rows_raise_or_go_to_on_skip` | M1 |
| `rib.origin_of()`: the RFC 6811 section 2 origin rule on the AS_PATH octets: rightmost AS of a final AS_SEQUENCE; the speaker AS for a final confederation segment or an empty path; an AS_SET as the final segment is reported as ambiguous with its members, never guessed (RFC 9774 section 4: ROV never considers a route with an AS_SET Valid). The segments come from `pathattr.aspath.parse_as_path` since 2026-11-13 (`rib.as-path-via-pathattr`) | RFC 6396 section 4.3.4, RFC 6811 section 2, RFC 9774 | `[ok]` | `tests/test_rib.py::test_origin_is_the_rightmost_as_of_a_final_as_sequence`, `tests/test_rib.py::test_origin_of_a_final_as_set_is_ambiguous_and_never_guessed`, `tests/test_rib.py::test_origin_of_a_confederation_final_segment_is_the_speaker`, `tests/test_rib.py::test_figure_19_row_with_its_peer_and_as_path`, `tests/test_mrt_corpus.py::test_real_bview_excerpt` | M1 |
| `lpm.longest_match()` | design: equals a brute-force scan for the longest covering prefix over the same entries | `[ok]` | `tests/test_lpm.py::test_longest_match_equals_bruteforce` | M2 |
| `lpm.build_radix()` | design: path-compressed, pure Python, duplicates merged, insertion-order independent | `[ok]` | `tests/test_lpm.py::test_insert_order_independent`, `tests/test_lpm.py::test_node_count_is_bounded_by_twice_the_entries` | M2 |
| `history.lookup_asn()`: origin ASN of an address on a date, as a list (MOAS). The pkgtrust use is the origin ASN of a distribution mirror address. It needs M1 and M2 and a local RIB dump only: no RPKI, no RTR. The date selects dumps by UTC date of their timestamp (a date with no dump is `LookupError`, never a neighbouring day) and an AS_SET-only longest prefix answers empty, not a shorter prefix | design | `[ok]` | `tests/test_history.py::test_lookup_asn_returns_the_origin_of_the_longest_covering_prefix`, `tests/test_history.py::test_moas_prefix_gives_every_origin_sorted_with_agreement_counts`, `tests/test_history.py::test_a_date_without_a_dump_is_a_lookup_error_not_a_neighbouring_day`, `tests/test_history.py::test_an_as_set_route_is_ambiguous_and_the_answer_does_not_fall_back_to_a_shorter_prefix` | M3 |
| `history.lookup_asn()` provenance: collector, dump timestamp and date, peers that saw the prefix and how many agree per origin (`history.lookup`, `DumpInfo`). The versioned, integrity-hashed on-disk index the README promises is not built: row `history.index-format` | design | `[part]` | `tests/test_history.py::test_the_dump_for_the_date_is_named_in_the_result`, `tests/test_history.py::test_a_peer_announcing_twice_counts_once`, `tests/test_history.py::test_ambiguous_and_clear_peers_for_one_prefix_are_both_reported` | M3 |
| `rib.as-path-via-pathattr` | done 2026-11-13: `rib.decode_as_path` and `rib.AsSegment` are removed and `rib` decodes with `pathattr.aspath.parse_as_path` (RFC 4271 section 4.3, RFC 5065, RFC 6793); `rib.as_path_of` frames with `pathattr.attribute.walk`. Before the removal the two decoders agreed on all 1,323 AS_PATHs of the real RouteViews RIB; the removed decoder's vectors now pin pathattr through `rib`. `pythonpath`, `mypy_path` and the CI checkout name `../pathattr` | `[ok]` | `tests/test_rib.py::test_as_path_decoders_agree`, `tests/test_rib.py::test_malformed_as_path_values_are_as_path_errors`, `tests/test_rib.py::test_as_path_of_absent_is_none_and_framing_errors_are_refused` | M1 |
| `rib.mp-reach-mrt-form` | RFC 6396 section 4.3.4: in a RIB entry MP_REACH_NLRI holds only Next Hop Length and Next Hop (no Reserved octet, no NLRI), so a generic attribute decoder misreads it; the decoding belongs to pathattr and needs a flag for the MRT form. asnkit keeps the octets raw and Figure 19 (corrected by erratum 6640) is the vector | `[ ]` | `tests/test_rib.py::test_mp_reach_mrt_form_next_hop` (to be written) | M1 |
| `mrt.tolerant-bgp4mp` | real archives hold BGP4MP records whose message is truncated or has trailing octets; `parse_bgp4mp` refuses them (RFC 6396 section 4.4.2: one message, encapsulated in full). A reading mode that yields the record with an error marker, as `rib.iter_rib_entries(on_skip=...)` does, is needed before bgpfeed meets an update archive Done 2026-11-13: `parse_bgp4mp(record, tolerant=True)` and `iter_bgp4mp(..., tolerant=True, on_error=...)` keep a message with a bad Length, trailing octets or fewer than 19 octets, with the octets as found and the reason in `Bgp4mpMessage.defect`; a record whose fixed fields cannot be read goes to `on_error` and is yielded raw. bgpfeed uses it (`mrt.tolerant-reading`). No real archive of the pinned three holds such a record, so the vectors are built. | `[ok]` | `tests/test_mrt_records.py::test_bgp4mp_tolerant_mode` | M1 |
| `mrt.peer-table-adjacency` | RFC 6396 section 4.3.1: the RIB records MUST immediately follow the PEER_INDEX_TABLE. `iter_rib_entries` accepts any RIB record after a table, and a later table replaces the earlier one; a strict mode that refuses interleaved record types is not built | `[ ]` | `tests/test_rib.py::test_peer_table_adjacency_strict` (to be written) | M1 |
| `mrt.corpus-real-bview` | real files read end to end, downloads approved by the owner 2026-11-13. Not vendored: `tools/fetch_corpus.py` fetches the files pinned (URL, SHA-256, size, read date, operator terms) in `tools/corpus.json` into a cache outside the tree, one request per second, and the tests skip loudly without them. The RIB is the smallest of 54 collectors measured with HEAD (RouteViews iraq-ixp.bgw, 7,000 octets, 623 records, 1,323 RIB entries); the updates are RouteViews route-views2 (100,953 BGP4MP_ET records) and RIS rrc00 (194,896 BGP4MP records). Exact counts by type and subtype, no ADD-PATH, no refusal by `asnkit.mrt` or `pathattr`; the RFC 6396, 8050 and 6793 checks are in `docs/rfc-map.md` | `[ok]` | `tests/test_mrt_corpus.py::test_real_bview_excerpt`, `tests/test_mrt_corpus.py::test_real_routeviews_updates_end_to_end`, `tests/test_mrt_corpus.py::test_real_ris_updates_end_to_end` | M1 |
| `mrt.corpus-full-rib` | a full-table RIB (route-views2 is 78,672,876 octets for 2026-11-12 00:00 by HEAD) for the radix benchmark in section 5 and for RIB_GENERIC and multicast subtypes, which the smallest RIB does not hold. Downloads are approved; not fetched, to keep this round's total small | `[ ]` | `tests/test_mrt_corpus.py::test_full_rib` (to be written) | M2 |
| `mrt.iana-registry-check` | the MRT type and subtype codes (RFC 6396 section 5, RFC 8050 section 5) against the IANA `mrt` registry (https://www.iana.org/assignments/mrt); primarysource now has an `iana` collection, but no tool for it was available in the 2026-11-13 session, so the codes are cited from the RFCs only | `[ ]` | `tests/test_mrt.py::test_codes_match_iana_registry` (to be written) | M1 |
| `history.index-format` | a versioned, integrity-hashed on-disk index so a lookup does not re-read a dump (README promise); `Archive` indexes each dump in memory when added, and the memory and time of that for a full RIB is unmeasured (the full-RIB benchmark in section 5) | `[ ]` | `tests/test_history.py::test_index_roundtrip_and_hash` (to be written) | M3 |
| `history.collector-from-name` | RouteViews and RIS file names and directory layout carry the collector and dump time; `Archive.add_path` takes the collector from the caller. bgpfeed owns the archive layout rows, so this waits for `routeviews.index_parse` | `[ ]` | `tests/test_history.py::test_collector_from_routeviews_name` (to be written) | M3 |
| `mrt.legacy-table-dump` | RFC 6396 Appendix B deprecates TABLE_DUMP (type 12), BGP4MP_ENTRY and the older types; old archives hold them. Not read, and `iter_rib_entries` passes them to `on_skip` | `[no]` | `tests/test_rib.py::test_records_that_are_not_rib_rows_raise_or_go_to_on_skip` | M1 |
| `rov.annotate()`: also reproduces the RFC 6811 classification, defined once with routevalid | RFC 6480, RFC 6811 | `[ ]` | `tests/test_obligations.py::test_annotate` (to be written) | M4 |

## 2. Milestones

- M1 MRT reader for TABLE_DUMP_V2 with a streaming test corpus. Common header, PEER_INDEX_TABLE, the RIB records (subtypes 2-6 and the ADD-PATH 8-12), BGP4MP and the RIB rows are done (2026-11-13); AS_PATH decoding is pathattr's (`rib.as-path-via-pathattr`, 2026-11-13), and three real archive files are read end to end (`mrt.corpus-real-bview`). **M1-M3 need pathattr** (`D:\code\pathattr`, in progress), not rpkit or rtrkit, which block only M4. Until pathattr lands the reader keeps attribute octets raw
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
- Corpus: done 2026-11-13 without vendoring (row `mrt.corpus-real-bview`): the files live in a cache and are verified by pinned SHA-256 and size, not by the TLS download.
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
