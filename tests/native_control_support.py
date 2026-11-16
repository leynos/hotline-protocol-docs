"""Share the helpers of the characterization tests of ``native_control_readiness``.

The gates are exercised on the reports of the retained ban-control corpus, so each
is shown to accept the real capture and to refuse one change at a time.
"""

import json
import sys
import typing as typ
from pathlib import Path

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    import types

type Report = dict[str, typ.Any]

ROOT = Path(__file__).resolve().parents[1]
CAPTURES = (
    ROOT / "evidence/gap-remediation/2026-11-14/native-ban-control-01/case-c56/captures"
)


def captured(phase: str) -> Report:
    """Load one phase's capture report from the retained corpus.

    Returns
    -------
    dict[str, typing.Any]
        The parsed report.
    """
    return json.loads((CAPTURES / phase / "report.json").read_text())


def home(function: cabc.Callable[..., object]) -> types.ModuleType:
    """Find the module whose globals a function reads its helpers from.

    Returns
    -------
    types.ModuleType
        The module that defines the function, which is this one's own subject
        for a single-file script and a helper module after a split.
    """
    return sys.modules[function.__module__]


def reply_frame(report: Report, identifier: int, connection: str = "main") -> Report:
    """Find the reply frame of a request in a report.

    Returns
    -------
    dict[str, typing.Any]
        The frame, shared with the report.
    """
    return next(
        f
        for f in report["frames"]
        if f["is_reply"] and f["id"] == identifier and f["connection"] == connection
    )


def field_of(frame: Report, number: int) -> Report:
    """Find one field of a frame.

    Returns
    -------
    dict[str, typing.Any]
        The field, shared with the frame.
    """
    return next(item for item in frame["fields"] if item["id"] == number)


def flip(field: Report) -> None:
    """Change the last byte of a field's value."""
    value = field["hex"]
    field["hex"] = value[:-2] + ("00" if value[-2:] != "00" else "ff")
