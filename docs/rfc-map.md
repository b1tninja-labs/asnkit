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
