"""Shared gate, readers and pin parser of the path-fields verifier."""

import hashlib
import json
import typing as typ

from verify_native_path_fields_constants import DIGEST_LENGTH, PIN_FIELDS

if typ.TYPE_CHECKING:
    from pathlib import Path


def need(condition: bool, message: str) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers pass the condition positionally
    """Raise a ValueError with the message unless the condition holds.

    Raises
    ------
    ValueError
        If the condition does not hold.
    """
    if not condition:
        raise ValueError(message)


def sha(path: Path) -> str:
    """Return the SHA-256 hexadecimal digest of a file's bytes.

    Returns
    -------
    str
        The digest in hexadecimal.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: Path) -> dict:
    """Return the JSON object held in a file.

    Returns
    -------
    dict
        The decoded object.
    """
    return json.loads(path.read_text())


def pins(path: Path) -> dict[str, str]:
    """Return the name-to-digest map of a pin file, after checking its syntax.

    Returns
    -------
    dict[str, str]
        The digest of each pinned name.
    """
    lines = path.read_text().splitlines()
    entries = [line.split("  ") for line in lines]
    need(
        all(
            len(entry) == PIN_FIELDS and len(entry[0]) == DIGEST_LENGTH
            for entry in entries
        ),
        "Pin syntax differs",
    )
    result = {name: digest for digest, name in entries}
    need(len(result) == len(lines), "Duplicate pinned path")
    return result
