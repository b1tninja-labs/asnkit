"""origin validation join from rtrkit or an rpkit assertion set (RFC 6480).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import Any

    RovFeed = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "annotate",
]


def annotate(entries: Iterable, feed: RovFeed) -> Iterable:
    """Pending behaviour defined by RFC 6480.

    Not implemented yet. See the ``rov.annotate()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("annotate() is not implemented: RFC 6480")
