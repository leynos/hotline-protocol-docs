"""Constants and shared checks of the direct-reply acceptance verifier.

The entry module :mod:`verify_mxd_direct_ack` and the gate checks import these
names from here, so that none of them imports the entry module.
"""

import hashlib
import typing as typ
from pathlib import Path

type Manifest = dict[str, typ.Any]

BASE = "481294915b48f4db06943c8af86cf31b7e47597a"
FINAL = "20e891a059de7dd9dec5a657d7099570987d860d"
UNIT = "mxd-c9-full-20261113-1835.service"
INVOCATION = "cb3d33916da34bcb863e8185b15cd417"
PREFIX = "evidence/gap-remediation/2026-11-13/mxd-direct-ack-02/"
COUNTS = [
    (557, 557, 0),
    (561, 561, 0),
    (543, 543, 0),
    (3, 3, 0),
    (69, 69, 1),
    (8, 8, 0),
    (7, 7, 0),
]
DOCTESTS = [(7, 0), (5, 4)]
SOURCE_FILES = 19  # the candidate sources that the first gate froze
C8_FILES = 18  # the files of the copied raw C8 corpus
CAPTURE_LIMIT = 8_000_000  # the most that the watcher capture may hold
TEST_THREADS = 2  # the nextest threads of the controlled run
BUILD_JOBS = 1  # the cargo build jobs of the controlled run
CONTROLS = (
    "NEXTEST_TEST_THREADS=2",
    "CARGO_NET_OFFLINE=true",
    "CARGO_BUILD_JOBS=1",
    "unset PG_DATA_DIR",
    "PG_EMBED_ROOT=",
    "PG_RUNTIME_DIR=/var/tmp/pg-embed-1000/install",
    "test-rstest-bdd-ui: export CARGO_TARGET_DIR",
)


def fail(message: str) -> typ.NoReturn:
    """Stop verification with the failed check's message.

    Parameters
    ----------
    message : str
        The text that names the failed check.

    Raises
    ------
    ValueError
        Always, with ``message``.
    """
    raise ValueError(message)


def sha256(path: Path) -> str:
    """Hash an evidence or source file.

    Returns
    -------
    str
        The hexadecimal SHA-256 digest of the file's bytes.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_object(kind: str, data: bytes) -> str:
    """Name a Git object by the SHA-1 of its header and content.

    Returns
    -------
    str
        The object name.
    """
    header = kind.encode() + b" " + str(len(data)).encode() + b"\0"
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()


def check_sums(evidence: Path, prefix: str) -> None:
    """Check a complete root-relative package inventory.

    Parameters
    ----------
    evidence : pathlib.Path
        The package directory, which holds ``SHA256SUMS``.
    prefix : str
        The path that every listed entry must start with.
    """
    listed: set[Path] = set()
    for line in (evidence / "SHA256SUMS").read_text().splitlines():
        digest, relative = line.split("  ", 1)
        if not relative.startswith(prefix):
            fail("checksum path leaves package")
        part = Path(relative.removeprefix(prefix))
        if part.is_absolute() or ".." in part.parts:
            fail("unsafe or duplicate checksum path")
        if part in listed:
            fail("unsafe or duplicate checksum path")
        listed.add(part)
        if sha256(evidence / part) != digest:
            fail(f"checksum mismatch: {part}")
    actual = {p.relative_to(evidence) for p in evidence.rglob("*") if p.is_file()}
    if listed != actual - {Path("SHA256SUMS")}:
        fail("checksum inventory differs")


def properties(path: Path) -> dict[str, str]:
    """Read retained systemd properties.

    Returns
    -------
    dict[str, str]
        The properties, keyed by name.
    """
    return dict(line.split("=", 1) for line in path.read_text().splitlines())
