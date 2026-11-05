"""asnkit -- prefix to ASN, current and historical.

pyasn is the tool everyone uses and it stopped moving in 2023: 1.6.2, 2023-09-01, a C
extension out of a Python 2 lineage with no type hints, no async and no ROV state.
"""

from __future__ import annotations

from . import apps, cli, history, lpm, mrt, rib, rov
from .history import lookup_asn
from .lpm import build_radix, longest_match
from .mrt import iter_records
from .rib import iter_rib_entries
from .rov import annotate

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "annotate",
    "apps",
    "build_radix",
    "cli",
    "history",
    "iter_records",
    "iter_rib_entries",
    "longest_match",
    "lookup_asn",
    "lpm",
    "mrt",
    "rib",
    "rov",
]
