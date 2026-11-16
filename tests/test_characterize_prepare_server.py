"""Characterize the Mac server preparation script and the evidence packager.

``prepare_hotline_server`` and ``package-protocol-evidence`` had no test, so the
endings of the cases below were recorded on the scripts as they stood before they
were brought to the standard (commit 8a3f8cd), in
``data/characterize_prepare_server.tsv``, before either was restructured. The
cases build their inputs in memory: a synthetic AppleDouble sidecar, a stand-in
oracle whose digest replaces the recorded one, and small Git repositories.
"""

import hashlib
import os
import shutil
import struct
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # the packager runs Git
import tempfile
import typing as typ
from pathlib import Path
from unittest import mock

import prepare_hotline_server as prepare_server
import pytest
from characterize_support import Cases, record, replay
from script_loading import load_script

if typ.TYPE_CHECKING:
    import types

TABLE = Path(__file__).with_name("data") / "characterize_prepare_server.tsv"
MAGIC = bytes.fromhex("0005160700020000")
FINDER_BYTES = 32
HEADER_BYTES = 26
ENTRY_BYTES = 12
GIT = shutil.which("git") or "git"
CLOCK = "2026-01-01T00:00:00+0000"  # a fixed commit time makes the archive repeatable


def sidecar(entries: dict[int, bytes], *, count: int | None = None) -> bytes:
    """Build an AppleDouble v2 sidecar holding the entries.

    Returns
    -------
    bytes
        The sidecar, with the entry table first and the data after it.
    """
    declared = len(entries) if count is None else count
    table = HEADER_BYTES + len(entries) * ENTRY_BYTES
    head = MAGIC + bytes(16) + struct.pack(">H", declared)
    body = b""
    rows = b""
    for tag, data in entries.items():
        rows += struct.pack(">III", tag, table + len(body), len(data))
        body += data
    return head + rows + body


GOOD = {9: bytes(range(FINDER_BYTES)), 2: b"resource-fork"}


def decode(data: bytes) -> object:
    """Decode a sidecar and show its entries.

    Returns
    -------
    object
        The entries by tag, as hexadecimal text.
    """
    return {tag: value.hex() for tag, value in prepare_server.appledouble(data).items()}


def duplicate() -> bytes:
    """Build a sidecar whose second entry repeats the tag of the first.

    Returns
    -------
    bytes
        The sidecar.
    """
    good = sidecar({9: GOOD[9], 2: GOOD[2]})
    return (
        good[: HEADER_BYTES + ENTRY_BYTES]
        + struct.pack(">III", 9, 0, 0)
        + good[HEADER_BYTES + 2 * ENTRY_BYTES :]
    )


def prepared(*, oracle: bool, side: bytes | None, agreement: bool) -> object:
    """Prepare a shared folder from a stand-in source and describe the result.

    Returns
    -------
    object
        The files that were written, with their digests, and the manifest.
    """
    binary = b"oracle-bytes"
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        source = base / "source"
        source.mkdir()
        (source / "HLserver19").write_bytes(binary if oracle else b"other")
        if side is not None:
            (source / "._HLserver19").write_bytes(side)
        if agreement:
            (source / "Agreement.txt").write_bytes(b"agree")
        destination = base / "destination"
        with mock.patch.object(
            prepare_server, "ORACLE_SHA256", hashlib.sha256(binary).hexdigest()
        ):
            prepare_server.prepare(source, destination)
        return {
            str(path.relative_to(destination)): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in sorted(destination.rglob("*"))
            if path.is_file()
        }


def existing_destination() -> object:
    """Prepare into a destination that exists already.

    Returns
    -------
    object
        What ``prepare`` raised.
    """
    binary = b"oracle-bytes"
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        (base / "HLserver19").write_bytes(binary)
        (base / "._HLserver19").write_bytes(sidecar(GOOD))
        with mock.patch.object(
            prepare_server, "ORACLE_SHA256", hashlib.sha256(binary).hexdigest()
        ):
            return prepare_server.prepare(base, base)


def short_table() -> bytes:
    """Build a sidecar that declares more entries than it holds.

    Returns
    -------
    bytes
        The sidecar.
    """
    return sidecar(GOOD, count=9)


def packager() -> types.ModuleType:
    """Load the evidence packager, whose file name has a hyphen.

    Returns
    -------
    types.ModuleType
        The module.
    """
    scripts = Path(prepare_server.__file__).resolve().parent
    return load_script(scripts / "package-protocol-evidence.py", "package_evidence")


def git(repository: Path, *arguments: str) -> None:
    """Run Git in a repository."""
    fixed = {"GIT_AUTHOR_DATE": CLOCK, "GIT_COMMITTER_DATE": CLOCK}
    subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv, no shell
        [GIT, "-c", "user.name=t", "-c", "user.email=t@example.invalid", *arguments],
        cwd=repository,
        env={**os.environ, **fixed},
        check=True,
        capture_output=True,
    )


def repository(base: Path, *, dirty: bool) -> Path:
    """Make a repository with one commit, and a changed file if ``dirty``.

    Returns
    -------
    pathlib.Path
        The repository.
    """
    root = base / "repo"
    root.mkdir()
    git(root, "init", "-q")
    (root / "a.txt").write_text("a\n")
    git(root, "add", "a.txt")
    git(root, "commit", "-q", "-m", "one")
    if dirty:
        (root / "a.txt").write_text("changed\n")
    return root


def revision_of(*, dirty: bool) -> object:
    """Ask the packager for the revision of a clean or a changed repository.

    Returns
    -------
    object
        The revision's length, or what the packager raised.
    """
    with tempfile.TemporaryDirectory() as temporary:
        root = repository(Path(temporary), dirty=dirty)
        return len(packager().revision(root))


def archive_of() -> object:
    """Archive a one-commit repository and list what the archive holds.

    Returns
    -------
    object
        The archive's names and the digest of its bytes.
    """
    with tempfile.TemporaryDirectory() as temporary:
        root = repository(Path(temporary), dirty=False)
        module = packager()
        commit = module.revision(root)
        data = module.archive(root, commit)
        return {"digest": hashlib.sha256(data).hexdigest()[:16], "size": len(data)}


CASES: Cases = {
    "appledouble-short": lambda: decode(b"short"),
    "appledouble-magic": lambda: decode(bytes(30)),
    "appledouble-good": lambda: decode(sidecar(GOOD)),
    "appledouble-truncated-table": lambda: decode(short_table()),
    "appledouble-duplicate": lambda: decode(duplicate()),
    "appledouble-no-finder": lambda: decode(sidecar({2: b"x"})),
    "appledouble-no-resource": lambda: decode(sidecar({9: bytes(FINDER_BYTES)})),
    "appledouble-bad-finder": lambda: decode(sidecar({9: b"short", 2: b"x"})),
    "prepare-wrong-oracle": lambda: prepared(
        oracle=False, side=sidecar(GOOD), agreement=False
    ),
    "prepare-wrong-oracle-and-bad-sidecar": lambda: prepared(
        oracle=False, side=b"x", agreement=False
    ),
    "prepare-bad-sidecar": lambda: prepared(
        oracle=True, side=b"short", agreement=False
    ),
    "prepare-no-sidecar": lambda: prepared(oracle=True, side=None, agreement=False),
    "prepare-good": lambda: prepared(oracle=True, side=sidecar(GOOD), agreement=False),
    "prepare-with-agreement": lambda: prepared(
        oracle=True, side=sidecar(GOOD), agreement=True
    ),
    "prepare-destination-exists": existing_destination,
    "revision-clean": lambda: revision_of(dirty=False),
    "revision-changed": lambda: revision_of(dirty=True),
    "archive": archive_of,
}


class PrepareServerCharacterizationTests:
    """Keep the preparation and packaging scripts as they were recorded."""

    @pytest.mark.parametrize("name", sorted(CASES))
    def test_each_case_ends_as_it_did(self, name: str) -> None:
        """Each case ends with the exception or result recorded earlier."""
        now, recorded = replay(CASES, TABLE, name)
        assert now == recorded, "ending differs"


def table() -> str:
    """Say how every case ends, for the table; run it only on the earlier scripts.

    Returns
    -------
    str
        The table text.
    """
    return record(CASES)
