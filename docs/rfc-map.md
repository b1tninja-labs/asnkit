# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 6396 | Proposed Standard | 2011-10 | 2026-11-05 |
| RFC 4271 | Draft Standard | 2006-01 | 2026-11-05 |
| RFC 6480 | Informational | 2012-02 | 2026-11-05 |
| RFC 8210 | Proposed Standard | 2017-09 | 2026-11-05 |
| RFC 8050 | Proposed Standard, current, no errata | 2017-05 | 2026-11-13 |
| RFC 6811 | Proposed Standard, current; updated by RFC 8481, RFC 8893 | 2013-01 | 2026-11-13 |
| RFC 8481 | Proposed Standard, current; updates RFC 6811; updated by RFC 9324 | 2018-09 | 2026-11-13 |
| RFC 9774 | Proposed Standard, current; obsoletes RFC 6472; updates RFC 4271, RFC 5065 | 2025-05 | 2026-11-13 |
| RFC 4760 | Draft Standard, current; updated by RFC 7606; 1 verified erratum (not yet read) | 2007-01 | 2026-11-13 |
| RFC 6793 | Proposed Standard, current; updates RFC 4271 | 2012-12 | 2026-11-13 |

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.

## Notes from the 2026-11-13 pass

- RFC 6396 (current, 2 verified errata, 1 held): both verified errata are in Appendix A. Erratum 5511 corrects
  Figure 16 (Total Path Attribute Length 0x1f to 0x23, NEXT_HOP c6 33 64 55 to c6 33 64 bc); erratum 6640
  corrects Figure 19 (MP_REACH_NLRI must be in the section 4.3.4 form: length 0x2b to 0x21, the reserved octet
  and NLRI dropped). Erratum 6640 leaves the record Length (87) and Attribute Length (68) fields alone; with the
  10 octets removed they become 77 and 58. That arithmetic is ours and is pinned in `tests/test_mrt.py`.
  Figure 18 (PEER_INDEX_TABLE) is unaffected and is used as printed. Held erratum 3817 is editorial (section
  5.7 cross-references).
- RFC 8050 does not appear as an "updates" of RFC 6396 in the RFC Editor record, so tooling will not warn
  that the `*_ADDPATH` subtypes (BGP4MP 8-11, TABLE_DUMP_V2 8-12) exist. Its RIB Entry gains a 4-octet Path
  Identifier between Originated Time and Attribute Length (section 4.1).
- Types 17, 33 and 49 (`_ET`) carry a 4-octet Microsecond Timestamp counted in Length (RFC 6396 section 3).
- Non-RFC inputs, not verifiable through rfclib: RouteViews and RIPE RIS archive layout.
- Read in full on 2026-11-13 for the RIB and BGP4MP work: RFC 6396 sections 4.3 (all of it) and 4.4 (all of it), Appendix A Figures 16 to 20; RFC 8050 sections 3, 4 and 5; RFC 6811 section 2 (the origin rule, `rib.origin_of`); RFC 9774 section 4 (ROV never counts a route with an AS_SET as Valid); RFC 4271 section 4.3 (attribute framing and the AS_PATH segment layout). RFC 6396 section 4.3.4 requires 4-octet AS numbers in a stored AS_PATH; BGP4MP_MESSAGE (subtype 1) carries 2-octet ones (section 4.4.2). The Appendix A Figure 20 text gives the AS_PATH of Figure 19 as `64496 64511 64502`, which `tests/test_rib.py` decodes.
- AS_PATH segment types, read in full: RFC 4271 section 4.3 b) gives 1 AS_SET and 2 AS_SEQUENCE; RFC 5065 section 3 (current, Draft Standard, 1 verified erratum elsewhere, none on section 3) adds 3 AS_CONFED_SEQUENCE and 4 AS_CONFED_SET. `pathattr.aspath.parse_as_path` reads exactly these four; asnkit's own decoder was removed on 2026-11-13 after the two agreed on all 1,323 AS_PATHs of the real RouteViews RIB.
- Real data, 2026-11-13 (`tests/test_mrt_corpus.py`): no record of the three pinned files is refused by `asnkit.mrt` and no BGP message by `pathattr`. Checked through rfclib against what they hold: RFC 6396 section 4.4.2 (BGP4MP_MESSAGE carries only 2-byte AS numbers in its AS_PATH; RIS rrc00 writes 538 such records, and every AS_PATH decodes at that width), RFC 6793 section 4.2.2 (the 173 of those UPDATEs that carry AS4_PATH all put AS_TRANS in AS_PATH), RFC 6396 section 3 (RouteViews writes BGP4MP_ET only), RFC 6396 section 4.3.1 (a peer entry with BGP ID 0.0.0.0, address 0.0.0.0 and AS 0, referenced by no RIB entry; the section sets no constraint on it), RFC 8050 section 5 (no ADD-PATH subtype in any file).
- RFC 6396 section 4.3.3: a RIB_GENERIC record of an AFI/SAFI the reader does not decode SHOULD be discarded; this package returns it undecoded and `rib.iter_rib_entries` raises or calls `on_skip`, so nothing is dropped silently.
