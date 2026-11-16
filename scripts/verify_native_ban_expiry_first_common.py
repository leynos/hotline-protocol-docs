"""Provide the checks and readers that the temporary-ban verifiers share.

The later verifier imports these names from here, so that both families apply
the same rules to the files that the two corpora hold.
"""

import datetime as dt
import hashlib
import json
import tempfile
import typing as typ
from pathlib import Path

if typ.TYPE_CHECKING:
    import types


def need(ok: bool, reason: str) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]  # the checks pass their condition positionally
    """Raise a ``ValueError`` with ``reason`` unless ``ok`` holds.

    Parameters
    ----------
    ok : bool
        The condition that must hold.
    reason : str
        The message of the error that is raised when the condition fails.

    Raises
    ------
    ValueError
        When ``ok`` is false.
    """
    if not ok:
        raise ValueError(reason)


def read(path: Path) -> dict:
    """Read the JSON document at ``path``.

    Parameters
    ----------
    path : Path
        The file to read.

    Returns
    -------
    dict
        The decoded document.
    """
    return json.loads(path.read_text())


def sha(path: Path) -> str:
    """Return the SHA-256 digest of the bytes of ``path``.

    Parameters
    ----------
    path : Path
        The file to digest.

    Returns
    -------
    str
        The hexadecimal digest.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def when(value: str) -> dt.datetime:
    """Parse a timestamp, reading a trailing ``Z`` as ``+00:00``.

    Parameters
    ----------
    value : str
        The timestamp in ISO 8601 form.

    Returns
    -------
    dt.datetime
        The parsed timestamp.
    """
    text = value.replace("Z", "+00:00")
    return dt.datetime.fromisoformat(text)


def replay_view(folder: Path, adapted: dict, capture: types.ModuleType) -> None:
    """Verify an adapted case report inside a temporary generic replay view.

    Parameters
    ----------
    folder : Path
        The case folder whose ``plan.json`` is copied into the view.
    adapted : dict
        The report to write into the view in place of the case's own report.
    capture : types.ModuleType
        The module whose ``verify_capture`` checks the view.
    """
    with tempfile.TemporaryDirectory() as temporary:
        view = Path(temporary)
        (view / "plan.json").write_bytes((folder / "plan.json").read_bytes())
        (view / "report.json").write_text(json.dumps(adapted) + "\n")
        (view / "checksums.sha256").write_text(
            "".join(
                f"{sha(view / name)}  {name}\n" for name in ("plan.json", "report.json")
            )
        )
        capture.verify_capture(view)
