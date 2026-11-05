"""date-scoped indexes over multiple RIB dumps.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Archive = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "lookup_asn",
]


def lookup_asn(archive: Archive, address: str, when: datetime.date) -> list:
    """Pending behaviour defined by design.

    Not implemented yet. See the ``history.lookup_asn()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("lookup_asn() is not implemented: design")
