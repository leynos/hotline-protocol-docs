"""Follow moved documents through ``gap-register.json`` (obligation INV-MOVE).

The register embeds Markdown links in its string fields. They are written
relative to where ``gap-analysis.md`` lives, so that file's old path is the
linking source. The protected fields (:data:`audit_model.PROTECTED_FIELDS`)
must come out byte-identical: a link inside one that would need rewriting
stops the run instead of being edited.

The structured ``path`` values of gap sources and of the review coverage are
followed only on request, because the audit refresh does that itself, through
its section map, and needs the old paths to find the previous revision.
"""

import copy
import typing as typ
from pathlib import PurePosixPath

from audit_model import PROTECTED_FIELDS
from layout_rewrite import Moves, rewrite_text
from tool_support import ToolError

type Json = str | float | bool | list[Json] | dict[str, Json] | None
type Register = dict[str, typ.Any]

LEDGER_POINTER = "validity_ledger"


class ProtectedFieldError(ToolError):
    """A protected field holds a link that the relocation would have to edit."""


def _fix(value: Json, source: PurePosixPath, moves: Moves) -> tuple[Json, int]:
    """Rewrite the links of every string inside ``value``.

    Parameters
    ----------
    value : Json
        A JSON value.
    source : pathlib.PurePosixPath
        The old path of ``gap-analysis.md``, the base of embedded links.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.

    Returns
    -------
    tuple[object, int]
        The rewritten value and how many links changed.
    """
    match value:
        case str():
            text, changes = rewrite_text(value, source, moves)
            return text, len(changes)
        case list():
            pairs = [_fix(item, source, moves) for item in value]
            return [item for item, _ in pairs], sum(count for _, count in pairs)
        case dict():
            total = 0
            for key, item in value.items():
                value[key], count = _fix(item, source, moves)
                total += count
            return value, total
        case _:
            return value, 0


def _check_protected(
    gap: dict[str, typ.Any], source: PurePosixPath, moves: Moves
) -> None:
    """Refuse a gap whose protected fields hold a link that would change.

    Parameters
    ----------
    gap : dict[str, typing.Any]
        One gap of the register.
    source : pathlib.PurePosixPath
        The old path of ``gap-analysis.md``.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.

    Raises
    ------
    ProtectedFieldError
        If a protected field would change.
    """
    for field in PROTECTED_FIELDS:
        before = gap.get(field)
        after, count = _fix(copy.deepcopy(before), source, moves)
        if count or after != before:
            message = (
                f"{gap.get('id')}: protected field {field} holds a link to rewrite"
            )
            raise ProtectedFieldError(message)


def rewrite_register(
    register: Register, source: PurePosixPath, moves: Moves, *, paths: bool = False
) -> tuple[Register, int]:
    """Return the register with its embedded links and pointers followed.

    Parameters
    ----------
    register : dict[str, typing.Any]
        The parsed register.
    source : pathlib.PurePosixPath
        The old path of ``gap-analysis.md``.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.
    paths : bool
        Also rewrite the structured ``path`` of every gap source and coverage
        entry. Leave this off when the audit refresh will follow them.

    Returns
    -------
    tuple[dict[str, typing.Any], int]
        The new register and the number of values rewritten.
    """
    result = copy.deepcopy(register)
    for gap in result["gaps"]:
        _check_protected(gap, source, moves)
    count = _fix(result, source, moves)[1]
    pointer = PurePosixPath(result.get(LEDGER_POINTER, ""))
    if pointer in moves:
        result[LEDGER_POINTER] = moves[pointer].as_posix()
        count += 1
    if paths:
        entries = [s for gap in result["gaps"] for s in gap["sources"]]
        for entry in [*entries, *result["review_coverage"]]:
            target = moves.get(PurePosixPath(entry["path"]))
            if target is not None:
                entry["path"] = target.as_posix()
                count += 1
    return result, count


__all__ = ["ProtectedFieldError", "Register", "rewrite_register"]
