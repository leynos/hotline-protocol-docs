"""The Git LFS storage rule for evidence.

Under ``evidence/`` every ``*.png``, ``*.pcap`` and ``*.gz`` file is an LFS
object and nothing else is. The index must hold a pointer for exactly those
paths, and the working tree must hold their content, not the pointer text.
"""

import typing as typ

from git_lossless import as_path, git_names, git_text
from withheld_model import NotedReport

if typ.TYPE_CHECKING:
    from pathlib import Path

LFS_SUFFIXES = (".png", ".pcap", ".gz")
POINTER_PREFIX = b"version https://git-lfs.github.com/spec/v1"


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
    stored = set(git_text(root, "lfs", "ls-files", "--name-only").splitlines())
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
