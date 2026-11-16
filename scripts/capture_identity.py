r"""Name the scripts that made a capture (decision D31).

A capture records which scripts made it. Until decision D31 a capture
recorded the SHA-256 of one file, so a script could never be split without
the record naming the wrong code. A capture now records an *identity*: the Git
commit of the repository, the modules that make up the script, the hash of
each and a digest of the set.

The record
----------
:func:`identity` returns a JSON-ready mapping with these keys.

``schema_version``
    ``1``.
``commit``
    The 40-digit commit at the head of the repository, or ``None`` when Git
    cannot name one.
``dirty``
    The paths, in order, of listed files whose bytes differ from the commit (an
    edited or untracked file). A capture from uncommitted scripts is never
    refused, but it says so here, and :func:`problems` calls it unsound. With
    no commit every file is listed.
``files``
    A list of ``{"path", "sha256"}`` entries in the order the script declares
    its modules. Paths are relative to the repository root, with forward
    slashes.
``digest``
    The SHA-256 of the text made of one line, ``"<sha256>  <path>\n"``, for
    each file in that order. That is the output of ``sha256sum`` on the files,
    so ``sha256sum scripts/a.py scripts/b.py | sha256sum`` recomputes it.

Where a record sits
-------------------
A report keeps the field name it always had and puts the digest there: the
``driver_sha256`` of a new capture is the digest of the driver's module set,
where it was the hash of one file. Beside it a sibling field named for the role,
``driver_identity``, holds the full record. A report of the earlier form has
only the single-file field. A reader tells the forms apart by the sibling field
and, for the digest alone, by its meaning here: it hashes a listing, so it
never equals the hash of any one file. A verifier keeps its existing comparison
for the earlier form and adds one call of ``capture_acceptance.driver_in`` or
``driver_is`` for the new.

Which files
-----------
A script that is split declares the set as a module-level constant,
``CAPTURE_MODULES``: its own file name first, then the modules split out of it,
each named ``<script>_*.py``. A test requires that the constant equal the set of
such modules the script imports, so a helper added without being declared
fails it. A library that several scripts share, such as ``pcap_tcp``, is not in
any set: the commit identifies it.

The module imports under a bare ``python3`` and uses only the standard
library, because the verifiers that held under ``evidence/`` import scripts
beside them.
"""

import hashlib
import re
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # reads Git, no shell
import typing as typ
from pathlib import Path

if typ.TYPE_CHECKING:
    import collections.abc as cabc

SCHEMA_VERSION = 1
SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")

type Record = dict[str, typ.Any]


def sha256_of(data: bytes) -> str:
    """Hash bytes.

    Returns
    -------
    str
        The SHA-256 in lower-case hexadecimal.
    """
    return hashlib.sha256(data).hexdigest()


def set_digest(files: cabc.Iterable[cabc.Mapping[str, str]]) -> str:
    r"""Digest a list of files as ``sha256sum`` would list them.

    Parameters
    ----------
    files : collections.abc.Iterable[collections.abc.Mapping[str, str]]
        Entries with ``path`` and ``sha256``, in order.

    Returns
    -------
    str
        The SHA-256 of the lines ``"<sha256>  <path>\n"``.
    """
    listing = "".join(f"{item['sha256']}  {item['path']}\n" for item in files)
    return sha256_of(listing.encode())


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes] | None:
    """Run Git in ``root``.

    Returns
    -------
    subprocess.CompletedProcess[bytes] | None
        The finished process, or ``None`` when Git cannot be started.
    """
    try:
        return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv
            ["git", "-C", str(root), *args],  # ruff: ignore[start-process-with-partial-path]  # Git from PATH, as the Makefile does
            capture_output=True,
            check=False,
        )
    except OSError:
        return None


def _head(root: Path) -> str | None:
    """Name the commit at the head of the repository.

    Returns
    -------
    str | None
        The commit, or ``None`` when ``root`` is not in a repository or Git is
        absent.
    """
    done = _git(root, "rev-parse", "--verify", "HEAD")
    if done is None or done.returncode != 0:
        return None
    commit = done.stdout.decode().strip()
    return commit if COMMIT_PATTERN.fullmatch(commit) else None


def _blob(root: Path, commit: str, path: str) -> bytes | None:
    """Read a file as a commit holds it.

    Returns
    -------
    bytes | None
        The bytes, or ``None`` when the commit lacks the path.
    """
    done = _git(root, "cat-file", "blob", f"{commit}:./{path}")
    return done.stdout if done is not None and done.returncode == 0 else None


def _listing(modules: cabc.Sequence[str], directory: Path) -> list[dict[str, str]]:
    """Hash each module in the order given.

    Returns
    -------
    list[dict[str, str]]
        One ``path`` and ``sha256`` entry per module.

    Raises
    ------
    ValueError
        If ``modules`` is empty or names a file twice.
    """
    if not modules:
        message = "a capture identity needs at least one module"
        raise ValueError(message)
    if len(set(modules)) != len(modules):
        message = "a module is listed more than once"
        raise ValueError(message)
    return [
        {
            "path": (directory / name).relative_to(directory.parent).as_posix(),
            "sha256": sha256_of((directory / name).read_bytes()),
        }
        for name in modules
    ]


def _differs(root: Path, commit: str | None, item: cabc.Mapping[str, str]) -> bool:
    """Say whether a live file differs from the commit's copy.

    Returns
    -------
    bool
        ``True`` with no commit, with no copy at the commit, or with other bytes.
    """
    if commit is None:
        return True
    held = _blob(root, commit, item["path"])
    return held is None or sha256_of(held) != item["sha256"]


def identity(modules: cabc.Sequence[str], *, directory: Path = SCRIPTS) -> Record:
    """Describe the scripts that are about to make a capture.

    Parameters
    ----------
    modules : collections.abc.Sequence[str]
        The file names, in the fixed order of the script's declared set.
    directory : pathlib.Path
        The directory that holds them; its parent is the repository root.

    Returns
    -------
    dict[str, typing.Any]
        The record described in the module documentation.
    """
    files = _listing(modules, directory)
    root = directory.parent
    commit = _head(root)
    dirty = [item["path"] for item in files if _differs(root, commit, item)]
    return {
        "schema_version": SCHEMA_VERSION,
        "commit": commit,
        "dirty": dirty,
        "files": files,
        "digest": set_digest(files),
    }


def differences(
    record: Record, modules: cabc.Sequence[str], *, directory: Path = SCRIPTS
) -> list[str]:
    """Compare a record with the live modules, as a capture-time check does.

    The commit and the dirty list are not compared: only the files and the
    digest, so a later commit of the same bytes still matches.

    Parameters
    ----------
    record : dict[str, typing.Any]
        A record made by :func:`identity`.
    modules : collections.abc.Sequence[str]
        The file names to hash now, in order.
    directory : pathlib.Path
        The directory that holds them.

    Returns
    -------
    list[str]
        One line for each way the live files differ; empty when they match.
    """
    live = _listing(modules, directory)
    recorded = record.get("files")
    found: list[str] = []
    if [item["path"] for item in live] != [item.get("path") for item in recorded or []]:
        found.append("the recorded files are not the live files, or not in order")
    else:
        found.extend(
            f"{now['path']} has SHA-256 {now['sha256']}, recorded {was['sha256']}"
            for now, was in zip(live, recorded or [], strict=True)
            if now["sha256"] != was.get("sha256")
        )
    if record.get("digest") != set_digest(live):
        found.append("the digest of the set differs from the live files")
    return found


def check(
    record: Record, modules: cabc.Sequence[str], *, directory: Path = SCRIPTS
) -> bool:
    """Say whether the live modules are the ones a record describes.

    Returns
    -------
    bool
        ``True`` when :func:`differences` finds nothing.
    """
    return not differences(record, modules, directory=directory)


def _shape(record: object) -> list[str]:
    """Check that a stored record has the form :func:`identity` gives.

    Returns
    -------
    list[str]
        The faults; empty when the form is right.
    """
    if not isinstance(record, dict):
        return ["the identity record is not a mapping"]
    faults: list[str] = []
    if record.get("schema_version") != SCHEMA_VERSION:
        faults.append("the schema version is not 1")
    commit = record.get("commit")
    if commit is not None and not (
        isinstance(commit, str) and COMMIT_PATTERN.fullmatch(commit)
    ):
        faults.append("the commit is not 40 lower-case hexadecimal digits")
    if not isinstance(record.get("dirty"), list):
        faults.append("dirty is not a list")
    files = record.get("files")
    if not isinstance(files, list) or not files:
        faults.append("files is not a non-empty list")
    elif not all(
        isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and SHA256_PATTERN.fullmatch(str(item.get("sha256")))
        for item in files
    ):
        faults.append("a file entry lacks a path or a 64-digit sha256")
    return faults


def _history(root: Path, record: Record) -> list[str]:
    """Check each listed file against the commit.

    Returns
    -------
    list[str]
        The faults, among them a commit that the history lacks.
    """
    commit = record["commit"]
    if commit is None:
        return ["the record has no commit, so its files cannot be recovered"]
    known = _git(root, "cat-file", "-e", f"{commit}^{{commit}}")
    if known is None or known.returncode != 0:
        return [f"commit {commit} is not in the history of {root}"]
    faults: list[str] = []
    for item in record["files"]:
        blob = _blob(root, commit, item["path"])
        if blob is None:
            faults.append(f"commit {commit} does not contain {item['path']}")
        elif sha256_of(blob) != item["sha256"]:
            faults.append(
                f"{item['path']} at {commit} does not carry its recorded hash"
            )
    return faults


def problems(record: object, *, root: Path = ROOT) -> list[str]:
    """Check a stored record, as a verifier does before it accepts a capture.

    A record is sound when it has the right form, its digest is the digest of
    its files, no file was uncommitted at capture, and each file's recorded hash
    is that of the bytes the commit holds. The commit must be in the local
    history, so the check does not work in a shallow clone.

    Parameters
    ----------
    record : object
        The value of an ``*_identity`` field.
    root : pathlib.Path
        A directory inside the repository whose history holds the commit.

    Returns
    -------
    list[str]
        The faults found first; empty when the record is sound.
    """
    faults = _shape(record)
    if faults:
        return faults
    stored = typ.cast("Record", record)
    if stored.get("digest") != set_digest(stored["files"]):
        return ["the digest is not that of the listed files"]
    if stored["dirty"]:
        return [f"captured from uncommitted files: {', '.join(stored['dirty'])}"]
    return _history(root, stored)
