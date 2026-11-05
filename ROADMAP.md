# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation asnkit could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `mrt.iter_records()` | RFC 6396 | `[ ]` | `tests/test_obligations.py::iter_records` |
| `rib.iter_rib_entries()` | RFC 6396 | `[ ]` | `tests/test_obligations.py::iter_rib_entries` |
| `lpm.longest_match()` | RFC 6396 | `[ ]` | `tests/test_obligations.py::longest_match` |
| `lpm.build_radix()` | design | `[ ]` | `tests/test_obligations.py::build_radix` |
| `history.lookup_asn()` | design | `[ ]` | `tests/test_obligations.py::lookup_asn` |
| `rov.annotate()` | RFC 6480 | `[ ]` | `tests/test_obligations.py::annotate` |

## 2. Milestones

- M1 MRT reader for TABLE_DUMP_V2 with a streaming test corpus
- M2 radix LPM with a pure-Python reference and a native fast path behind the interface
- M3 date-scoped history over several RIB dumps
- M4 validation join from rtrkit, with reason codes carried into the answer
- M5 CLI parity with pyasn so a migration is a one-line change
- M6 publication: 0.1.0 with a migration note from pyasn

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 4271 carries 9 verified errata and 12 updates. Consult them before trusting any UPDATE parsing recipe copied from a blog post.
- RFC 6396 carries 2 verified errata.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| a BGP speaker or session FSM | `[no]` | a named document requires it |
| flow data | `[no]` | a named document requires it |
| a hosted API that hides where the answer came from | `[no]` | a named document requires it |

## 5. Open questions

- pure-Python radix versus an optional native one, decided by a benchmark on a full RIB

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
