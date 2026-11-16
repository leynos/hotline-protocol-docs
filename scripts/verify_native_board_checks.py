"""Checks that the board corpus's manifest, file inventory and digests are as recorded.

The readers and the ``need`` check here are shared by the other verify_native_board
modules. A refused corpus always fails with the ``ValueError`` that ``need`` raises.
"""

import datetime as dt
import hashlib
import json
import typing as typ

from verify_native_board_pins import (
    CASES,
    DEADLINE,
    PID,
    PLAN,
    RUNNER,
    SCHEMA,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

SIDECAR_FILES = 2  # manifest.json and SHA256SUMS, which name no hash of their own
MAX_FILES = 250  # the approved number of files in the corpus, sidecars included
MAX_CORPUS_BYTES = 80 * 1024 * 1024  # the approved size bound of the corpus


def need(
    ok: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers pass a condition positionally, as the checks always have
    message: str,
) -> None:
    """Raise a ``ValueError`` with ``message`` unless ``ok`` holds.

    Raises
    ------
    ValueError
        With ``message`` when ``ok`` is false.
    """
    if not ok:
        raise ValueError(message)


def read(path: Path) -> Report:
    """Parse the JSON document at ``path``.

    Returns
    -------
    dict[str, typing.Any]
        The parsed document.
    """
    return json.loads(path.read_text())


def sha(path: Path) -> str:
    """Return the SHA-256 digest of the bytes of the file at ``path``.

    Returns
    -------
    str
        The hexadecimal digest.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc(value: str) -> dt.datetime:
    """Parse an ISO 8601 timestamp whose ``Z`` suffix means UTC.

    Returns
    -------
    datetime.datetime
        The parsed timestamp.
    """
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))  # ruff: ignore[fromisoformat-replace-z]  # the replacement keeps the ValueError text of a malformed date unchanged


def inventory(corpus: Path) -> Report:
    """Check the corpus manifest, its file inventory, its size and its digests.

    Returns
    -------
    dict[str, typing.Any]
        The parsed manifest.
    """
    manifest = read(corpus / "manifest.json")
    need(
        corpus.name == SCHEMA
        and manifest["schema"] == SCHEMA
        and manifest["profile"] == "control-only"
        and manifest["full_file_baseline"] == "not_exercised"
        and manifest["actual_pid"] == PID
        and manifest["runner_sha256"] == RUNNER
        and manifest["cases_sha256"] == CASES
        and manifest["plan_sha256"] == PLAN
        and manifest["fixed_deadline_utc"] == DEADLINE,
        "Corpus schema, source or fixed deadline differs",
    )
    files = manifest["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(
        actual == set(files) and len(files) + SIDECAR_FILES <= MAX_FILES,
        "Corpus inventory differs",
    )
    need(
        sum((corpus / name).stat().st_size for name in files) <= MAX_CORPUS_BYTES,
        "Corpus size exceeds approved bound",
    )
    for name, digest in files.items():
        need(sha(corpus / name) == digest, f"Corpus SHA differs: {name}")
    need(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{digest}  {name}" for name, digest in sorted(files.items())],
        "SHA256SUMS differs",
    )
    return manifest
