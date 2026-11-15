"""The Git LFS storage rule for evidence.

Under ``evidence/`` every ``*.png``, ``*.pcap`` and ``*.gz`` file is an LFS
object and nothing else is. The index must hold a pointer for exactly those
paths, and the working tree must hold their content, not the pointer text.
"""

import typing as typ

from git_lossless import as_path, git_names
from withheld_model import NotedReport

if typ.TYPE_CHECKING:
    from pathlib import Path

LFS_SUFFIXES = (".png", ".pcap", ".gz")
POINTER_PREFIX = b"version https://git-lfs.github.com/spec/v1"
# A pointer is three short lines; real ones are about 130 bytes.
POINTER_MAX_BYTES = 200


def _working_tree_pointers(root: Path, tracked: list[str]) -> list[str]:
    """List tracked files whose working-tree content is pointer text.

    Returns
    -------
    list[str]
        The paths, as Latin-1 text.
    """
    found: list[str] = []
    for name in tracked:
        target = root / as_path(name)
        if not target.is_file():
            continue
        with target.open("rb") as handle:
            if handle.read(len(POINTER_PREFIX)) == POINTER_PREFIX:
                found.append(name)
    return found


def _index_pointers(root: Path) -> set[str]:
    """List the paths under ``evidence/`` whose index entry is an LFS pointer.

    The index is read directly. ``git lfs ls-files`` lists staged files that
    share one object only once, so it under-reports before the first commit.
    An entry is a pointer when its blob is no larger than a pointer can be and
    a line of it is the pointer's version line.

    Returns
    -------
    set[str]
        The paths, as Latin-1 text.
    """
    small = {
        entry.split(" ", 1)[1]
        for entry in git_names(
            root, "ls-files", "-z", "--format=%(objectsize) %(path)", "--", "evidence"
        )
        if int(entry.split(" ", 1)[0]) <= POINTER_MAX_BYTES
    }
    marked = git_names(
        root,
        *("grep", "--cached", "-l", "-z", "-e", f"^{POINTER_PREFIX.decode('ascii')}$"),
        *("--", "evidence"),
        ok=(0, 1),
    )
    return small & set(marked)


def check_lfs(root: Path) -> NotedReport:
    """Check that exactly the large and binary evidence is stored through LFS.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.

    Returns
    -------
    NotedReport
        One failure per path stored the wrong way, and per pointer left in the
        working tree; one note counts the paths examined.
    """
    tracked = git_names(root, "ls-files", "-z", "--", "evidence")
    stored = _index_pointers(root)
    wanted = {name for name in tracked if name.endswith(LFS_SUFFIXES)}
    report = NotedReport(checked=len(tracked))
    report.failures += [
        f"{name}: stored in ordinary Git, but the rule makes it an LFS object"
        for name in sorted(wanted - stored)
    ]
    report.failures += [
        f"{name}: wrongly stored in LFS, the rule keeps it in ordinary Git"
        for name in sorted(stored - wanted)
        if name.startswith("evidence/")
    ]
    report.failures += [
        f"{name}: the working tree holds an LFS pointer; run git lfs pull"
        for name in _working_tree_pointers(root, tracked)
    ]
    report.notes.append(
        f"{len(tracked)} tracked paths, {len(wanted)} expected in LFS, "
        f"{len(stored & set(tracked))} stored in LFS"
    )
    return report
