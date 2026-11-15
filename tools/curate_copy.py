"""Copy the included evidence corpora from the source, byte for byte."""

import dataclasses as dc
import filecmp
import shutil
import typing as typ

from curate_select import withheld_paths
from evidence_corpus import INCLUDED, corpus_of, load_curation
from evidence_files import list_files
from tool_support import ToolError

if typ.TYPE_CHECKING:
    from pathlib import Path

CURATION_RELATIVE = "evidence/curation.json"
EXECUTABLE = 0o111


class CopyConflictError(ToolError):
    """A destination file exists with different content."""


@dc.dataclass(frozen=True, slots=True)
class CopyRequest:
    """What ``copy`` is asked to do.

    Attributes
    ----------
    source_root : pathlib.Path
        The tree to copy from.
    root : pathlib.Path
        The repository to copy into.
    withheld : pathlib.Path | None
        The withheld manifest; those paths are skipped.
    curation : pathlib.Path | None
        The curation file; defaults to ``evidence/curation.json`` in ``root``.
    """

    source_root: Path
    root: Path
    withheld: Path | None = None
    curation: Path | None = None


@dc.dataclass(frozen=True, slots=True)
class CopyResult:
    """The counts of a copy.

    Attributes
    ----------
    copied : int
        Files written.
    identical : int
        Files already present with identical bytes.
    withheld : int
        Files skipped because they are withheld.
    """

    copied: int
    identical: int
    withheld: int


def _plan(request: CopyRequest) -> tuple[list[str], int]:
    """Choose the files to copy.

    Returns
    -------
    tuple[list[str], int]
        The paths, and how many withheld files were left out.
    """
    curation = request.curation or request.root / CURATION_RELATIVE
    included = {c.path for c in load_curation(curation) if c.disposition == INCLUDED}
    withheld = withheld_paths(request.withheld, request.root)
    names = [
        name for name in list_files(request.source_root) if corpus_of(name) in included
    ]
    return [n for n in names if n not in withheld], sum(n in withheld for n in names)


def copy_evidence(request: CopyRequest) -> CopyResult:
    """Copy every file of every included corpus.

    Parameters
    ----------
    request : CopyRequest
        The source, destination and manifests.

    Returns
    -------
    CopyResult
        The counts.

    Raises
    ------
    CopyConflictError
        If a destination file exists with different bytes; nothing is copied.
    """
    names, withheld = _plan(request)
    pairs = [(request.source_root / n, request.root / n) for n in names]
    differing = [
        str(dst)
        for src, dst in pairs
        if dst.exists() and not filecmp.cmp(src, dst, shallow=False)
    ]
    if differing:
        message = f"{len(differing)} existing files differ, first {differing[0]}"
        raise CopyConflictError(message)
    copied = 0
    for src, dst in pairs:
        if dst.exists():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        if src.stat().st_mode & 0o111:
            dst.chmod(dst.stat().st_mode | 0o111)
        copied += 1
    return CopyResult(copied, len(pairs) - copied, withheld)
