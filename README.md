# asnkit

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
No protocol behaviour is implemented: every public function raises `NotImplementedError`,
and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

asnkit -- prefix to ASN, current and historical

pyasn is the tool everyone uses and it stopped moving in 2023: 1.6.2, 2023-09-01, a C extension out of a Python 2 lineage with no type hints, no async and no ROV state. MRT parsing alone is covered by a dozen one-off scripts; what is missing is a typed library that answers the question an operator actually asks, which AS, on which date, and what did RPKI say about it, while streaming its input instead of demanding a build step. The RIB index sits behind an interface so the pure-Python radix and an optional native one are interchangeable.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| pyasn | 1.6.2 | 2023-09-01 | the incumbent: C extension, no typing, no ROV, a build-a-db step |
| netflow | 0.12.2 | 2023-08-20 | flow export codecs, adjacent rather than overlapping |
| py-radix | - | - | a trie primitive; no MRT, no history |

What this project intends to add:

- a streaming TABLE_DUMP_V2 reader that never loads a whole RIB into memory
- historical lookups by date from the same index, without a per-archive build step
- validation state joined at query time from rtrkit or an rpkit assertion set
- typed API with an explicit provenance field on every answer

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 6396 | Proposed Standard | 2011-10 | MRT format: table dumps, BGP messages, state changes |
| RFC 4271 | Draft Standard | 2006-01 | UPDATE and path attribute semantics inside a table dump |
| RFC 6480 | Informational | 2012-02 | what a validation state joined onto a RIB row means |
| RFC 8210 | Proposed Standard | 2017-09 | a live feed via rtrkit instead of a static dump |

### Errata watch

- RFC 4271 carries 9 verified errata and 12 updates. Consult them before trusting any UPDATE parsing recipe copied from a blog post.
- RFC 6396 carries 2 verified errata.

## Module layout

| Module | Responsibility |
|---|---|
| `mrt` | MRT record and subtype framing (RFC 6396) |
| `rib` | TABLE_DUMP_V2 view, prefix and AS_PATH records (RFC 6396, RFC 4271) |
| `lpm` | radix tree with longest-prefix match and a stable iterator |
| `history` | date-scoped indexes over multiple RIB dumps |
| `rov` | origin validation join from rtrkit or an rpkit assertion set (RFC 6480) |

## What it does not do

- a BGP speaker or session FSM
- flow data
- a hosted API that hides where the answer came from


## Install

```bash
git clone https://github.com/b1tninja/asnkit.git
cd asnkit
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy asnkit
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
