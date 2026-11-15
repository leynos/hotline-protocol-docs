"""List evidence files and find the evidence paths that text cites.

Names are kept as file-system text (bytes that are not UTF-8 survive as
surrogate escapes), so a name holding a carriage return or other control
character is handled like any other.
"""

import dataclasses as dc
import os
import re
import typing as typ
from pathlib import Path

from git_lossless import as_arg, git_names

if typ.TYPE_CHECKING:
    import collections.abc as cabc

# The lookbehind keeps a longer word, such as a shell variable named
# agreement_evidence or the directory docs/native-evidence, from being read as
# the start of an evidence path.
CITATION = re.compile(rb"(?<![A-Za-z0-9_-])evidence/[A-Za-z0-9_./-]+")
TRIM = "./"
SKIPPED_DIRECTORIES = frozenset({".git", "__pycache__", ".venv", "node_modules"})


@dc.dataclass(frozen=True, slots=True)
class CitingRoot:
    """A file or directory whose text is scanned for evidence citations.

    Attributes
    ----------
    kind : str
        ``document``, ``register``, ``ledger``, ``script``, ``recipe`` or
        ``linked-document``.
    path : pathlib.Path
        The file, or a directory whose files are all scanned.
    """

    kind: str
    path: Path


def parse_citing(spec: str) -> CitingRoot:
    """Parse a ``KIND=PATH`` command-line value.

    Parameters
    ----------
    spec : str
        The text after ``--citing``.

    Returns
    -------
    CitingRoot
        The kind and path.
    """
    kind, _, path = spec.partition("=")
    return CitingRoot(kind, Path(path))


def list_files(root: Path) -> list[str]:
    """List the evidence files below ``root``, as repository-relative paths.

    Inside a Git checkout the listing is tracked plus untracked-but-not-ignored
    files, so build caches and local withheld copies are left out. Elsewhere
    every file is listed.

    Parameters
    ----------
    root : pathlib.Path
        The repository root (or a source checkout).

    Returns
    -------
    list[str]
        Sorted POSIX paths that start with ``evidence/`` and exist on disk.
    """
    if (root / ".git").exists():
        names = git_names(
            root,
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "evidence",
        )
        found = {as_arg(name) for name in names}
    else:
        found = {
            (Path(here) / name).relative_to(root).as_posix()
            for here, _, files in os.walk(root / "evidence")
            for name in files
        }
    return sorted(name for name in found if (root / name).is_file())


def citing_files(citing: CitingRoot) -> cabc.Iterator[Path]:
    """Yield the files that a citing root stands for.

    Parameters
    ----------
    citing : CitingRoot
        A file or a directory.

    Yields
    ------
    pathlib.Path
        The file itself, or every file below the directory.
    """
    if citing.path.is_file():
        yield citing.path
        return
    for here, directories, files in os.walk(citing.path):
        directories[:] = sorted(d for d in directories if d not in SKIPPED_DIRECTORIES)
        for name in sorted(files):
            yield Path(here) / name


def cited_paths(data: bytes) -> set[str]:
    """Find every evidence path that ``data`` names.

    Parameters
    ----------
    data : bytes
        File content, in any encoding that keeps ASCII intact.

    Returns
    -------
    set[str]
        The paths, with trailing dots and slashes removed.
    """
    return {match.decode("ascii").rstrip(TRIM) for match in CITATION.findall(data)}
