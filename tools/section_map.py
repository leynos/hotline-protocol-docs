"""Reviewed section correspondences for the audit refresh.

A section map is a JSON object with an optional ``files`` object (old path to
new path, for relocated documents) and an optional ``sections`` list of
``{"old": [path, ordinal], "new": [path, ordinal]}`` entries. Ordinals count
from one. Several old sections may map to one new section. An entry may add
``"also": [[path, ordinal], ...]`` when the old section was split: ``new`` is
the part that gap sources follow, and every part receives a copy of the old
section's review coverage.
"""

import dataclasses as dc
import json
import typing as typ

from tool_support import MissingInputError, ToolError

if typ.TYPE_CHECKING:
    from pathlib import Path

type Location = tuple[str, int]

PAIR_LENGTH = 2


class RefreshRefusedError(ToolError):
    """The refresh would lose or alter information, so nothing was written."""


@dc.dataclass(frozen=True, slots=True)
class SectionMap:
    """Reviewed correspondences for documents that moved or were restructured.

    Attributes
    ----------
    files : dict[str, str]
        New path for each relocated document, keyed by its old path.
    sections : dict[tuple[str, int], tuple[str, int]]
        New ``(path, ordinal)`` for each explicitly mapped old section.
    also : dict[tuple[str, int], tuple[tuple[str, int], ...]]
        Further new sections that took content from a split old section.
    """

    files: dict[str, str]
    sections: dict[Location, Location]
    also: dict[Location, tuple[Location, ...]] = dc.field(default_factory=dict)


def _is_pair(value: object) -> typ.TypeGuard[list[typ.Any]]:
    """Say whether ``value`` is a ``[path, ordinal]`` pair.

    Parameters
    ----------
    value : object
        The parsed JSON value.

    Returns
    -------
    bool
        ``True`` for a string and an integer of at least one, in a list.
    """
    if not isinstance(value, list) or len(value) != PAIR_LENGTH:
        return False
    return isinstance(value[0], str) and isinstance(value[1], int) and value[1] >= 1


def _pair(value: object, where: str) -> Location:
    """Validate one ``[path, ordinal]`` pair from a section map.

    Parameters
    ----------
    value : object
        The parsed JSON value.
    where : str
        A description for error messages.

    Returns
    -------
    tuple[str, int]
        The path and the one-based ordinal.

    Raises
    ------
    RefreshRefusedError
        If the value is not a valid pair.
    """
    if _is_pair(value):
        return value[0], value[1]
    message = f"section map {where}: expected [path, ordinal] with ordinal >= 1"
    raise RefreshRefusedError(message)


def load_section_map(path: Path | None) -> SectionMap:
    """Read a section map file.

    Parameters
    ----------
    path : pathlib.Path | None
        The JSON file, or ``None`` for an empty map.

    Returns
    -------
    SectionMap
        The parsed map.

    Raises
    ------
    MissingInputError
        If a path is given but the file is absent.
    """
    if path is None:
        return SectionMap({}, {})
    if not path.is_file():
        message = f"section map {path} is absent"
        raise MissingInputError(message)
    raw = json.loads(path.read_text(encoding="utf-8"))
    sections: dict[Location, Location] = {}
    also: dict[Location, tuple[Location, ...]] = {}
    for index, entry in enumerate(raw.get("sections", [])):
        old = _pair(entry.get("old"), f"entry {index} old")
        sections[old] = _pair(entry.get("new"), f"entry {index} new")
        parts = entry.get("also", [])
        if parts:
            also[old] = tuple(_pair(part, f"entry {index} also") for part in parts)
    return SectionMap(dict(raw.get("files", {})), sections, also)
