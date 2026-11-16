"""Checks of the liveness corpus's manifest, file inventory and frozen sources.

The readers and the ``need`` check here are shared by the other
verify_native_liveness modules. A refused corpus always fails with the
``ValueError`` that ``need`` raises.
"""

import datetime as dt
import hashlib
import importlib
import json
import sys
import typing as typ
from contextlib import contextmanager

from verify_native_liveness_pins import CASES, DEADLINE, PID, PLAN, RUNNER, SCHEMA

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

type Report = dict[str, typ.Any]

META_FILES = 2  # manifest.json and SHA256SUMS, which name no hash of their own
MAX_FILES = 250  # the approved number of files in the corpus, sidecars included
MAX_CORPUS_BYTES = 80 * 1024 * 1024  # the approved size bound of the corpus


def need(
    ok: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers pass a condition positionally, as the checks always have
    reason: str,
) -> None:
    """Raise a ``ValueError`` with ``reason`` unless ``ok`` holds.

    Parameters
    ----------
    ok : bool
        The condition that must hold.
    reason : str
        The message of the error raised when it does not.

    Raises
    ------
    ValueError
        With ``reason`` when ``ok`` is false.
    """
    if not ok:
        raise ValueError(reason)


def read(path: Path) -> Report:
    """Parse the JSON document at ``path``.

    Parameters
    ----------
    path : pathlib.Path
        The JSON file to read.

    Returns
    -------
    dict[str, typing.Any]
        The parsed document.
    """
    return json.loads(path.read_text())


def sha(path: Path) -> str:
    """Return the SHA-256 digest of the bytes of the file at ``path``.

    Parameters
    ----------
    path : pathlib.Path
        The file to hash.

    Returns
    -------
    str
        The hexadecimal digest.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc(value: str) -> dt.datetime:
    """Parse an ISO 8601 timestamp, treating a trailing ``Z`` as UTC.

    Parameters
    ----------
    value : str
        The timestamp.

    Returns
    -------
    datetime.datetime
        The parsed timestamp.
    """
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))  # ruff: ignore[fromisoformat-replace-z]  # the replacement keeps the parsed value of every input


@contextmanager
def frozen(corpus: Path) -> cabc.Iterator[tuple[typ.Any, ...]]:
    """Import the frozen protocol modules of the corpus, then restore the state.

    The corpus's own copies of the sources are imported ahead of any other
    module of the same name. On exit the module table, the path and the
    bytecode setting are restored.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Yields
    ------
    tuple[typing.Any, ...]
        The control, case, readiness, capture and TCP modules, in that order.
    """
    original_modules = sys.modules.copy()
    original_path = sys.path.copy()
    original_bytecode = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        path = str(corpus / "sources/protocol")
        closure = read(corpus / "sources/dependency-closure.json")
        for name in closure["hashes"]:
            sys.modules.pop(name, None)
        if path in sys.path:
            sys.path.remove(path)
        sys.path.insert(0, path)
        yield (
            importlib.import_module("native_liveness_control"),
            importlib.import_module("native_liveness_cases"),
            importlib.import_module("native_control_readiness"),
            importlib.import_module("protocol_capture"),
            importlib.import_module("pcap_tcp"),
        )
    finally:
        for name in set(sys.modules) - original_modules.keys():
            del sys.modules[name]
        sys.modules.update(original_modules)
        sys.path[:] = original_path
        sys.dont_write_bytecode = original_bytecode


def inventory(corpus: Path) -> Report:
    """Check the manifest, the file inventory, the sizes and the digests.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

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
        and manifest["runner_sha256"] == RUNNER
        and manifest["cases_sha256"] == CASES
        and manifest["plan_sha256"] == PLAN
        and manifest["actual_pid"] == PID
        and manifest["fixed_deadline_utc"] == DEADLINE,
        "Corpus profile, source or deadline differs",
    )
    files = manifest["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(
        actual == set(files) and len(files) + META_FILES <= MAX_FILES,
        "Corpus inventory differs",
    )
    need(
        sum((corpus / name).stat().st_size for name in files) <= MAX_CORPUS_BYTES,
        "Corpus size bound exceeded",
    )
    for name, expected in files.items():
        need(sha(corpus / name) == expected, f"Corpus SHA differs: {name}")
    need(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{digest}  {name}" for name, digest in sorted(files.items())],
        "SHA256SUMS differs",
    )
    return manifest
