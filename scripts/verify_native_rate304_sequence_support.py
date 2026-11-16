"""Read, hash and pin the corpus files that the rate304 sequence verifier checks.

The helpers here are used by the identity, event, observation and capture checks,
and by the verifier's entry point, which re-exports them.
"""

import hashlib
import json
import typing as typ

from verify_native_rate304_sequence_constants import PIN_FIELDS, PLAN, SCHEMA

if typ.TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType

type Report = dict[str, typ.Any]
type Modules = tuple[ModuleType, ModuleType, ModuleType, ModuleType, ModuleType]


def need(
    value: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # a check's verdict
    message: str,
) -> None:
    """Raise ``ValueError`` with ``message`` unless the check holds.

    Parameters
    ----------
    value : bool
        The verdict of the check.
    message : str
        The text of the error raised when the check fails.

    Raises
    ------
    ValueError
        When ``value`` is false.
    """
    if not value:
        raise ValueError(message)


def sha(path: Path) -> str:
    """Return the SHA-256 hex digest of the bytes of ``path``.

    Parameters
    ----------
    path : pathlib.Path
        The file to hash.

    Returns
    -------
    str
        The lowercase hexadecimal digest.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def pin(path: Path) -> dict[str, str]:
    """Parse a ``digest  name`` pin file into a mapping from name to digest.

    Parameters
    ----------
    path : pathlib.Path
        The pin file.

    Returns
    -------
    dict[str, str]
        The digest of each name.
    """
    lines = path.read_text().splitlines()
    entries = [line.split() for line in lines]
    need(
        all(len(item) == PIN_FIELDS for item in entries), "Approved pin syntax differs"
    )
    result = {name: digest for digest, name in entries}
    need(len(lines) == len(result), "Approved pin duplicates path")
    return result


def inventory(corpus: Path) -> Report:
    """Check the manifest, the file inventory and the root-relative checksums.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The parsed ``manifest.json``.
    """
    manifest = read(corpus / "manifest.json")
    need(
        manifest["schema"] == SCHEMA
        and manifest["case_status"] == "failed"
        and manifest["plan_sha256"] == PLAN,
        "Corpus scope/status differs",
    )
    files = manifest["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(actual == set(files), "Corpus file inventory differs")
    for name, digest in files.items():
        need(sha(corpus / name) == digest, f"Corpus file SHA differs: {name}")
    prefix = "evidence/gap-remediation/2026-11-14/native-rate304-sequence-01/"
    need(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{digest}  {prefix}{name}" for name, digest in sorted(files.items())],
        "Root-relative SHA256SUMS differs",
    )
    return manifest
