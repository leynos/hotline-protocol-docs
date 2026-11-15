"""File-system helpers for writing an audit revision."""

import hashlib
import json
import typing as typ

from check_json import canonical
from repo_files import git
from tool_support import MissingInputError

if typ.TYPE_CHECKING:
    from pathlib import Path

type Json = dict[str, typ.Any]

RELEASE_DIRECTORY = "protocol-gap-analysis"


def read_json(path: Path) -> Json:
    """Read a JSON object, treating absence as a missing input.

    Parameters
    ----------
    path : pathlib.Path
        The file.

    Returns
    -------
    dict[str, typing.Any]
        The parsed object.

    Raises
    ------
    MissingInputError
        If the file does not exist.
    """
    if not path.is_file():
        message = f"{path} is absent"
        raise MissingInputError(message)
    return json.loads(path.read_text(encoding="utf-8"))


def relative(target: Path, base: Path) -> str:
    """Express ``target`` relative to ``base``, climbing out where needed.

    Parameters
    ----------
    target : pathlib.Path
        The path to express.
    base : pathlib.Path
        The directory it is relative to.

    Returns
    -------
    str
        A POSIX path such as ``../mothra/evidence/...``.
    """
    return target.resolve().relative_to(base.resolve(), walk_up=True).as_posix()


def git_output(root: Path, *args: str) -> str:
    """Run Git in ``root`` and return its trimmed output.

    Parameters
    ----------
    root : pathlib.Path
        The checkout.
    *args : str
        The Git arguments.

    Returns
    -------
    str
        Standard output without surrounding whitespace.

    Raises
    ------
    MissingInputError
        If ``root`` is not a Git checkout.
    """
    result = git("-C", str(root), *args).run_sync()
    if result.exit_code != 0:
        message = f"{root} is not a Git checkout ({' '.join(args)} failed)"
        raise MissingInputError(message)
    return (result.stdout or "").strip()


def dump(value: object) -> bytes:
    """Render JSON in the canonical layout.

    Parameters
    ----------
    value : object
        A JSON-serializable value.

    Returns
    -------
    bytes
        The UTF-8 bytes.
    """
    return canonical(json.dumps(value)).encode("utf-8")


def write_revision(directory: Path, files: dict[str, bytes]) -> None:
    """Write a revision's files and its ``SHA256SUMS``.

    The sums record each path relative to the directory that holds the
    ``evidence`` tree, so that they verify from that directory's root.

    Parameters
    ----------
    directory : pathlib.Path
        The new directory, ``<evidence>/protocol-gap-analysis/<date>/revision-N``.
    files : dict[str, bytes]
        Content per path relative to ``directory``.
    """
    base = directory.parent.parent.parent.parent
    lines: list[str] = []
    for name in sorted(files):
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(files[name])
        digest = hashlib.sha256(files[name]).hexdigest()
        lines.append(f"{digest}  {target.relative_to(base).as_posix()}\n")
    (directory / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")


def record_local_corpus(directory: Path, reason: str) -> None:
    """List a revision made here in the evidence tree's local-corpora record.

    The record, ``<evidence>/local-corpora.json``, names every corpus that was
    created in this repository and so is absent from the import source; the
    curation check reads it.

    Parameters
    ----------
    directory : pathlib.Path
        The new directory, ``<evidence>/protocol-gap-analysis/<date>/revision-N``.
    reason : str
        Why the revision was cut.
    """
    evidence = directory.parent.parent.parent
    record = evidence / "local-corpora.json"
    listed: Json = (
        read_json(record) if record.is_file() else {"schema_version": 1, "corpora": []}
    )
    path = directory.relative_to(evidence.parent).as_posix()
    listed["corpora"].append({"path": path, "reason": reason})
    record.write_bytes(dump(listed))
