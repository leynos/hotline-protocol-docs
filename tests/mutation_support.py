"""Inject recorded faults into retained evidence and report how a check ends.

A verifier refuses a corrupt record with the first check that the record fails.
Which check that is depends on the order of the checks, so a pair of faults in
the same record shows the order: the message that comes back belongs to the check
that runs first. The order-pinning tests of a verifier replay a table of such
faults, each stored as paths into the evidence with a named
change, and the ending that the version of the scripts before the refactoring
produced. A line of a table has three tab-separated columns: the subject, the
faults (``path:change``, joined by ``;``, a path having its steps separated
by ``>``) and the ending.
"""

import copy
import hashlib
import json
import typing as typ

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

type Json = dict[str, Json] | list[Json] | str | int | float | bool | None
type Fault = tuple[str, str]

DELETE_KEY = "delete-key"
PATH_SEPARATOR = ">"
OK_DIGEST_CHARS = 16
MESSAGE_CHARS = 100


def step_into(node: Json, step: str) -> int | str:
    """Take one step of a path into a list or a mapping.

    Returns
    -------
    int | str
        The step as the list index or the mapping key that it names.
    """
    return int(step) if isinstance(node, list) else step


def changes(value: object) -> dict[str, object]:
    """Name the changes that can be made to one JSON value.

    Returns
    -------
    dict[str, object]
        The replacement for each named change: ``not`` for a flag, ``inc`` for
        a number, ``flip`` and ``empty`` for a string, and three list changes.
    """
    out: dict[str, object] = {}
    match value:
        case bool():
            out["not"] = not value
        case int():
            out["inc"] = value + 1
        case str():
            out["flip"] = (
                value[:-1] + ("0" if value[-1:] != "0" else "1") if value else "x"
            )
            if value:
                out["empty"] = ""
        case list() if value:
            out["drop-last"] = value[:-1]
            out["drop-first"] = value[1:]
            out["reverse"] = list(reversed(value))
    return out


def fault_state(state: Json, faults: list[Fault]) -> Json:
    """Apply each fault, in order, to a deep copy of ``state``.

    Each fault is a path and a change from :func:`changes`, or ``delete-key`` to
    remove the key at the path.

    Returns
    -------
    Json
        The changed copy.
    """
    state = copy.deepcopy(state)
    for text, change in faults:
        steps = text.split(PATH_SEPARATOR) if text else []
        parent: typ.Any = state
        for step in steps[:-1]:
            parent = parent[step_into(parent, step)]
        key = step_into(parent, steps[-1])
        if change == DELETE_KEY:
            del parent[key]
        else:
            parent[key] = changes(parent[key])[change]
    return state


def ending(call: cabc.Callable[..., object], state: Json) -> str:
    """Run ``call`` on ``state`` and describe how it ended.

    Returns
    -------
    str
        ``ok`` and a digest of the result, or the exception type and message on
        one line.
    """
    try:
        result = call(state)
    except Exception as exc:  # ruff: ignore[blind-except]  # every ending is recorded
        return " ".join(f"{type(exc).__name__}: {exc}".split())[:MESSAGE_CHARS]
    blob = json.dumps(result, sort_keys=True, default=repr)
    return "ok " + hashlib.sha256(blob.encode()).hexdigest()[:OK_DIGEST_CHARS]


def read_table(path: Path) -> list[tuple[str, list[Fault], str]]:
    """Read a table of recorded endings.

    Returns
    -------
    list[tuple[str, list[tuple[str, str]], str]]
        For each line, the subject, the faults and the recorded ending. A line
        with no faults records the ending of the unchanged evidence.
    """
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        subject, faults, expected = line.split("\t")
        parsed = [
            (text, change)
            for item in faults.split(";")
            if item
            for text, _, change in [item.rpartition(":")]
        ]
        rows.append((subject, parsed, expected))
    return rows
