"""Read, hash and check the retained files of the configured-ban corpus.

The checks of each topic module raise through :func:`need`, so the message of the
first failed check is the one the verifier reports. :class:`pathlib.Path` is bound
here at run time and imported from this module by the topic modules, so that
``inspect`` can evaluate the annotations of the functions the original defined.
"""

import datetime as dt
import hashlib
import json
from pathlib import Path  # ruff: ignore[typing-only-standard-library-import]  # inspect evaluates the annotations


def need(value: bool, reason: str) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]  # callers pass the check and its message positionally
    """Raise ``ValueError`` with ``reason`` unless ``value`` holds.

    Parameters
    ----------
    value : bool
        The condition that the corpus must satisfy.
    reason : str
        The message of the refusal.

    Raises
    ------
    ValueError
        If ``value`` does not hold.
    """
    if not value:
        raise ValueError(reason)


def read(path: Path) -> dict:
    """Return the JSON object in the file at ``path``.

    Parameters
    ----------
    path : pathlib.Path
        The JSON file.

    Returns
    -------
    dict[str, typing.Any]
        The parsed object.
    """
    return json.loads(path.read_text())


def sha(path: Path) -> str:
    """Return the SHA-256 digest of the file at ``path``.

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


def instant(path: Path) -> dt.datetime:
    """Return the ISO 8601 instant that the file at ``path`` records.

    Parameters
    ----------
    path : pathlib.Path
        A file holding one timestamp, with a comma or a full stop as its decimal mark.

    Returns
    -------
    datetime.datetime
        The recorded instant.
    """
    return dt.datetime.fromisoformat(path.read_text().strip().replace(",", "."))
