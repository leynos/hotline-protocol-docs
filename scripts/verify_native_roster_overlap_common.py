"""Pin the identity of the native roster overlap corpus and read its files.

The constants are the values that the verifier checks the corpus against. The
helpers read JSON, hash files, load the frozen copies of the modules that the
corpus ran and report a failed check as a ``ValueError``.
"""

import hashlib
import importlib
import json
import sys
import typing as typ

if typ.TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType

SCHEMA = "native-roster-overlap-01"
PID, START, NS, INODE = 953125, "6421050", "net:[4026532547]", 5973041789
DEADLINE = "2026-11-14T07:09:57.615913+00:00"
SOURCE_HEAD = "58494d779b319853cfb543c9f0c5c06997da07f2"
ORACLE = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
RSRC = "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12"
EXE = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
BASE = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
ROM = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
A7 = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"
# The text of a field that must be empty; compared by value, not by truthiness.
NO_TEXT = ""


def need(ok: bool, reason: str) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers pass the condition positionally
    """Raise a ``ValueError`` with ``reason`` unless ``ok`` holds.

    Parameters
    ----------
    ok : bool
        The condition that a check requires.
    reason : str
        The message of the error that is raised when the condition fails.

    Raises
    ------
    ValueError
        When ``ok`` is false.
    """
    if not ok:
        raise ValueError(reason)


def read(path: Path) -> dict[str, typ.Any]:
    """Parse the JSON document at ``path``.

    Parameters
    ----------
    path : pathlib.Path
        The file to read.

    Returns
    -------
    dict[str, typing.Any]
        The parsed document, as the original annotation states. Some route
        documents are lists; callers compare them and do not index them.
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


def frozen(corpus: Path) -> tuple[ModuleType, ...]:
    """Load the frozen copies of the modules that the corpus ran.

    The copies are imported from ``raw/sources`` of the corpus, which is put at
    the front of ``sys.path``, and bytecode is not written.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    tuple[types.ModuleType, ...]
        The control, cases, readiness, capture and TCP modules, in that order.
    """
    sys.dont_write_bytecode = True
    path = str(corpus / "raw/sources")
    if path not in sys.path:
        sys.path.insert(0, path)
    return (
        importlib.import_module("native_roster_overlap_control"),
        importlib.import_module("native_roster_overlap_cases"),
        importlib.import_module("native_control_readiness"),
        importlib.import_module("protocol_capture"),
        importlib.import_module("pcap_tcp"),
    )
