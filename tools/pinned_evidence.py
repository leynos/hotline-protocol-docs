"""Pin each retained evidence ``.py`` file to the Git commit that captured it.

Every evidence ``SHA256SUMS`` line, manifest, report and verifier constant that
names the hash of an evidence ``.py`` file records the bytes as they were
imported. Editing such a file, even to add a docstring, would break every one of
those records. ``scripts/pinned-evidence.json`` therefore names, for each file,
the commit whose copy carries the recorded hash. The recorded hashes stay as
they are: they are statements about the bytes at that commit, and a check reads
them from there with ``git cat-file``.

The pin check also keeps the live file honest. A live file is accepted when it
equals its pinned bytes, or when it differs from them only by docstrings (the
two syntax trees are equal once every docstring is removed). Any other edit to
the code fails the check, so documenting a capture cannot change what it does.

The commits must be in the local history, so the check does not work in a
shallow clone. The command line is :mod:`pinned_evidence_cli`.
"""

import ast
import dataclasses as dc
import json
import os
import re
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # reads Git, no shell
import typing as typ

from tool_support import MissingInputError, ToolError

if typ.TYPE_CHECKING:
    from pathlib import Path

RECORD_RELATIVE = "scripts/pinned-evidence.json"
EVIDENCE_PREFIX = "evidence/"
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
READ_SIZE = 1 << 20
ENCODING_LINE = re.compile(rb"^[ \t\f]*#.*?coding[:=][ \t]*[-\w.]+")


class PinRecordError(ToolError):
    """The pin record is absent, unreadable or malformed."""


class PinUnavailableError(ToolError, OSError):
    """A pinned file's bytes could not be read from the history.

    It is an ``OSError`` too, so that code which reads a pinned file through
    the evidence pin view handles the failure as it handles any unreadable file.
    """


def run_git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    """Run Git in ``root`` and capture its output.

    Returns
    -------
    subprocess.CompletedProcess[bytes]
        The finished process; the caller reads the exit code.

    Raises
    ------
    PinUnavailableError
        If Git cannot be started.
    """
    try:
        return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv
            ["git", "-C", str(root), *args],  # ruff: ignore[start-process-with-partial-path]  # Git from PATH, as the Makefile does
            capture_output=True,
            check=False,
        )
    except OSError as error:
        message = f"cannot run Git to read a pinned evidence file: {error}"
        raise PinUnavailableError(message) from error


@dc.dataclass(slots=True)
class PinRecord:
    """The pinned evidence files of one repository.

    Attributes
    ----------
    root : pathlib.Path
        The repository root, whose history holds the commits.
    pins : dict[str, str]
        The capture commit of each pinned path, keyed by repository-relative
        POSIX path.
    blobs : dict[str, bytes]
        Bytes already read, so a file is read from Git once.
    """

    root: Path
    pins: dict[str, str]
    blobs: dict[str, bytes] = dc.field(default_factory=dict)

    def read(self, path: str) -> bytes:
        """Return a pinned file's bytes at its capture commit.

        Parameters
        ----------
        path : str
            The repository-relative path.

        Returns
        -------
        bytes
            The bytes at the pinned commit.

        Raises
        ------
        PinUnavailableError
            If the commit or the path is not in the local history.
        """
        if path not in self.blobs:
            commit = self.pins[path]
            blob = run_git(self.root, "cat-file", "blob", f"{commit}:{path}")
            if blob.returncode != 0:
                shallow = run_git(self.root, "rev-parse", "--is-shallow-repository")
                hint = (
                    " (a shallow clone: fetch the full history)"
                    if shallow.stdout.strip() == b"true"
                    else ""
                )
                message = f"commit {commit} does not provide {path}{hint}"
                raise PinUnavailableError(message)
            self.blobs[path] = blob.stdout
        return self.blobs[path]


def load_record(root: Path) -> PinRecord:
    """Read ``scripts/pinned-evidence.json``.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.

    Returns
    -------
    PinRecord
        The record.

    Raises
    ------
    MissingInputError
        If the record file does not exist. A record that exists but cannot be
        read raises the ``OSError``, never ``MissingInputError``.
    PinRecordError
        If it is malformed.
    """
    record = root / RECORD_RELATIVE
    try:
        text = record.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        message = f"{RECORD_RELATIVE} does not exist"
        raise MissingInputError(message) from error
    try:
        document = json.loads(text)
        pins = {item["path"]: item["commit"] for item in document["files"]}
    except (ValueError, KeyError, TypeError) as error:
        message = f"cannot read {RECORD_RELATIVE}: {error}"
        raise PinRecordError(message) from error
    for path, commit in pins.items():
        if not path.startswith(EVIDENCE_PREFIX) or not path.endswith(".py"):
            message = f"{path} is not an evidence .py file"
            raise PinRecordError(message)
        if not (isinstance(commit, str) and COMMIT_PATTERN.fullmatch(commit)):
            message = f"the commit of {path} is not 40 lower-case hexadecimal digits"
            raise PinRecordError(message)
    return PinRecord(root, pins)


def optional_record(root: Path) -> PinRecord | None:
    """Read the pin record, or return ``None`` when the tree has none.

    Returns
    -------
    PinRecord | None
        The record. An unreadable or malformed record raises, so that no caller
        falls back to the live bytes.
    """
    try:
        return load_record(root)
    except MissingInputError:
        return None


def read_live(path: Path) -> bytes:
    """Read the bytes on disk, never the capture-time view of a pinned file.

    The Makefile runs this tool with the evidence pin view loaded, which
    redirects ``open``. A read through ``os.open`` is not redirected, so the
    comparison sees the file as it is.

    Returns
    -------
    bytes
        The file's content.
    """
    descriptor = os.open(path, os.O_RDONLY)
    try:
        chunks = []
        while chunk := os.read(descriptor, READ_SIZE):
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _interpreter_lines(source: bytes) -> list[tuple[int, bytes]]:
    """List the shebang and encoding lines among the first two lines, by position.

    They are comments, so the syntax tree does not hold them, but they decide how
    the file is run and read, and a shebang works only on the first line.

    Returns
    -------
    list[tuple[int, bytes]]
        The index and text of each line that is a shebang or an encoding
        declaration.
    """
    lines = source.split(b"\n", 2)[:2]
    return [
        (index, line)
        for index, line in enumerate(lines)
        if line.startswith(b"#!") or ENCODING_LINE.match(line)
    ]


def _is_docstring(statement: ast.stmt) -> bool:
    """Say whether a statement is a string expression, as a docstring is.

    Returns
    -------
    bool
        ``True`` for a bare string constant.
    """
    if not isinstance(statement, ast.Expr):
        return False
    value = statement.value
    return isinstance(value, ast.Constant) and isinstance(value.value, str)


def _without_docstrings(source: bytes) -> str:
    """Dump the syntax tree of ``source`` with every docstring removed.

    Returns
    -------
    str
        A canonical dump, equal for two sources that differ only by docstrings.
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (
            isinstance(
                node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
            )
            and body
        ):
            first = body[0]
            if _is_docstring(first):
                del body[0]
    return ast.dump(tree)


def differs_only_by_docstrings(live: bytes, pinned: bytes) -> bool:
    """Say whether two sources have the same code once docstrings are removed.

    Parameters
    ----------
    live : bytes
        The working-tree bytes.
    pinned : bytes
        The bytes at the capture commit.

    Returns
    -------
    bool
        ``True`` for equal bytes or equal docstring-free trees; ``False`` for
        a code difference or a source that does not parse.
    """
    if live == pinned:
        return True
    if _interpreter_lines(live) != _interpreter_lines(pinned):
        return False
    try:
        return _without_docstrings(live) == _without_docstrings(pinned)
    except SyntaxError, ValueError:
        return False


def tracked_evidence_python(root: Path) -> list[str]:
    """List the tracked ``evidence/**/*.py`` paths.

    Returns
    -------
    list[str]
        The paths, sorted.

    Raises
    ------
    PinUnavailableError
        If Git cannot list the files.
    """
    listing = run_git(root, "ls-files", "-z", "--", ":(glob)evidence/**/*.py")
    if listing.returncode != 0:
        message = f"git ls-files failed: {listing.stderr.decode(errors='replace')}"
        raise PinUnavailableError(message)
    return sorted(name for name in listing.stdout.decode().split("\0") if name)


def check(root: Path) -> list[str]:
    """Verify the record against the tree and the history.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.

    Returns
    -------
    list[str]
        One message per finding; empty when every pin holds.
    """
    record = load_record(root)
    tracked = tracked_evidence_python(root)
    failures = [
        f"{name}: tracked but not pinned" for name in tracked if name not in record.pins
    ]
    for path in sorted(record.pins):
        try:
            live = read_live(root / path)
        except OSError:
            failures.append(f"{path}: pinned but not in the tree")
            continue
        try:
            pinned = record.read(path)
        except PinUnavailableError as error:
            failures.append(f"{path}: {error}")
            continue
        if not differs_only_by_docstrings(live, pinned):
            failures.append(
                f"{path}: differs from {record.pins[path]} by more than docstrings"
            )
    return failures
