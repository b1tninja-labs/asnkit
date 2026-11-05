"""radix tree with longest-prefix match and a stable iterator.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import Any

    Radix = Any  # placeholder: give it a real type in the milestone that needs it
    RibEntry = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "build_radix",
    "longest_match",
]


def longest_match(tree: Radix, address: str) -> RibEntry | None:
    """Pending behaviour defined by RFC 6396.

    Not implemented yet. See the ``lpm.longest_match()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("longest_match() is not implemented: RFC 6396")


def build_radix(entries: Iterable) -> Radix:
    """Pending behaviour defined by design.

    Not implemented yet. See the ``lpm.build_radix()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("build_radix() is not implemented: design")
