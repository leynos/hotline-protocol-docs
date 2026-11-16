"""Read a script at the Git commit that carries the hash recorded for it.

Sixteen scripts are named by hashes that were recorded when evidence was
captured. A verifier used to hash the live file, so the script could never
change. It now asks this module for the file at its pinned commit instead, as
``scripts/pinned-sources.json`` records: the commit, the path at that commit
and the SHA-256 of the bytes there. The bytes are checked against the recorded
hash before they are returned, so a wrong record or a rewritten history fails
loudly instead of passing quietly.

The commit must be in the local history, so the check does not work in a
shallow clone. The module imports under a bare ``python3``, because the
evidence-held verifiers import the scripts beside them and it uses nothing
outside the standard library. Its command line is :mod:`pinned_source_cli`.
"""

import dataclasses as dc
import functools
import hashlib
import json
import re
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # reads Git, no shell
import typing as typ
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECORD = Path(__file__).with_name("pinned-sources.json")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


class PinnedSourceError(Exception):
    """A pinned script could not be read or did not match its record."""


class RecordError(PinnedSourceError):
    """The record is absent, unreadable or malformed."""


class UnknownSourceError(PinnedSourceError):
    """The record does not pin the script that was asked for."""


class CommitUnavailableError(PinnedSourceError):
    """The pinned commit is not in the local history."""


class SourcePathError(PinnedSourceError):
    """The pinned commit exists but does not contain the script."""


class SourceMismatchError(PinnedSourceError):
    """The bytes at the pinned commit do not carry the recorded hash."""


@dc.dataclass(frozen=True, slots=True)
class PinnedSource:
    """One script's pin.

    Attributes
    ----------
    path : str
        The path of the script at ``commit``, from the repository root.
    commit : str
        The full commit identifier.
    sha256 : str
        The SHA-256 of the script's bytes at ``commit``.
    """

    path: str
    commit: str
    sha256: str

    @property
    def name(self) -> str:
        """The file name, by which a script is looked up."""
        return self.path.rsplit("/", 1)[-1]


def _parse_entry(item: dict[str, typ.Any]) -> PinnedSource:
    """Validate one record entry.

    Returns
    -------
    PinnedSource
        The entry.

    Raises
    ------
    RecordError
        If a field is absent or malformed.
    """
    path, commit, digest = (item.get(key) for key in ("path", "commit", "sha256"))
    if not isinstance(path, str) or not path.rsplit("/", 1)[-1]:
        message = f"path of a record entry has no file name: {path!r}"
        raise RecordError(message)
    if not isinstance(commit, str) or not COMMIT_PATTERN.fullmatch(commit):
        message = f"commit of {path} is not 40 lower-case hexadecimal digits"
        raise RecordError(message)
    if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
        message = f"sha256 of {path} is not 64 lower-case hexadecimal digits"
        raise RecordError(message)
    return PinnedSource(path, commit, digest)


def _load(record: Path) -> dict[str, PinnedSource]:
    """Read the record, keyed by file name.

    Returns
    -------
    dict[str, PinnedSource]
        The pins in record order.

    Raises
    ------
    RecordError
        If the record cannot be read, or two entries name one file.
    """
    try:
        document = json.loads(record.read_text(encoding="utf-8"))
        items = document["sources"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        message = f"cannot read the pin record {record}: {error}"
        raise RecordError(message) from error
    pins: dict[str, PinnedSource] = {}
    for item in items:
        pin = _parse_entry(item)
        if pin.name in pins:
            message = f"the record pins {pin.name} twice"
            raise RecordError(message)
        pins[pin.name] = pin
    return pins


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    """Run Git in ``repo`` and capture its output.

    Returns
    -------
    subprocess.CompletedProcess[bytes]
        The finished process; the caller reads the exit code.

    Raises
    ------
    CommitUnavailableError
        If Git itself cannot be started.
    """
    try:
        return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv
            ["git", "-C", str(repo), *args],  # ruff: ignore[start-process-with-partial-path]  # Git from PATH, as the Makefile does
            capture_output=True,
            check=False,
        )
    except OSError as error:
        message = f"cannot run Git to read a pinned script: {error}"
        raise CommitUnavailableError(message) from error


class Pins:
    """The pinned scripts of one record, read from one repository."""

    def __init__(self, record: Path = RECORD, repo: Path = ROOT) -> None:
        """Load and validate the record.

        Parameters
        ----------
        record : pathlib.Path
            The record file.
        repo : pathlib.Path
            A directory inside the repository whose history holds the commits.
        """
        self.record = record
        self.repo = repo
        self.pins = _load(record)
        self.verified: dict[str, bytes] = {}

    def names(self) -> list[str]:
        """List the pinned file names in record order.

        Returns
        -------
        list[str]
            The names.
        """
        return list(self.pins)

    def _pin(self, name: str) -> PinnedSource:
        """Find the pin for ``name``.

        Returns
        -------
        PinnedSource
            The pin.

        Raises
        ------
        UnknownSourceError
            If the record does not pin ``name``.
        """
        if name not in self.pins:
            message = f"{name} is not pinned in {self.record.name}"
            raise UnknownSourceError(message)
        return self.pins[name]

    def _require_commit(self, pin: PinnedSource) -> None:
        """Check that the pinned commit is in the local history.

        Raises
        ------
        CommitUnavailableError
            If it is not; the message says when the clone is shallow.
        """
        found = _git(self.repo, "cat-file", "-e", f"{pin.commit}^{{commit}}")
        if found.returncode == 0:
            return
        shallow = _git(self.repo, "rev-parse", "--is-shallow-repository")
        cause = (
            " (this is a shallow clone: fetch the full history)"
            if shallow.stdout.strip() == b"true"
            else ""
        )
        message = (
            f"commit {pin.commit}, which pins {pin.name}, is not in the history "
            f"of {self.repo}{cause}"
        )
        raise CommitUnavailableError(message)

    def read(self, name: str) -> bytes:
        """Return a script's bytes at its pinned commit.

        Parameters
        ----------
        name : str
            The file name, for example ``"protocol_capture.py"``.

        Returns
        -------
        bytes
            The bytes, which carry the recorded hash.

        Raises
        ------
        SourcePathError
            If the commit does not contain the path.
        SourceMismatchError
            If the bytes at the commit do not carry the recorded hash.
        """
        pin = self._pin(name)
        if name in self.verified:
            return self.verified[name]
        self._require_commit(pin)
        blob = _git(self.repo, "cat-file", "blob", f"{pin.commit}:{pin.path}")
        if blob.returncode != 0:
            message = f"commit {pin.commit} does not contain {pin.path}"
            raise SourcePathError(message)
        actual = hashlib.sha256(blob.stdout).hexdigest()
        if actual != pin.sha256:
            message = (
                f"{pin.path} at {pin.commit} has SHA-256 {actual}, "
                f"but the record says {pin.sha256}"
            )
            raise SourceMismatchError(message)
        self.verified[name] = blob.stdout
        return blob.stdout

    def sha256(self, name: str) -> str:
        """Return the hash of a script's verified pinned bytes.

        Returns
        -------
        str
            The hexadecimal SHA-256.
        """
        return hashlib.sha256(self.read(name)).hexdigest()

    def check(self) -> list[str]:
        """Verify every pin.

        Returns
        -------
        list[str]
            The names, all verified.
        """
        for name in self.pins:
            self.read(name)
        return self.names()

    def stage(self, destination: Path) -> list[str]:
        """Overwrite each pinned script in ``destination`` with its pinned bytes.

        Every pin is verified before any file is written, so a failing pin
        leaves ``destination`` as it was.

        Parameters
        ----------
        destination : pathlib.Path
            A directory, normally a scratch copy of ``scripts/``.

        Returns
        -------
        list[str]
            The names written.
        """
        self.check()
        for name in self.pins:
            (destination / name).write_bytes(self.read(name))
        return self.names()


@functools.cache
def default_pins() -> Pins:
    """Open this repository's record once.

    Returns
    -------
    Pins
        The pins of ``scripts/pinned-sources.json``.
    """
    return Pins()


def pinned_bytes(name: str) -> bytes:
    """Return a script's bytes at its pinned commit.

    Returns
    -------
    bytes
        The verified bytes.
    """
    return default_pins().read(name)


def pinned_sha256(name: str) -> str:
    """Return the SHA-256 of a script's bytes at its pinned commit.

    Returns
    -------
    str
        The hexadecimal digest.
    """
    return default_pins().sha256(name)
