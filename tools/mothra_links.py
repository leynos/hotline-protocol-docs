"""Policy for links that point at the mothra repository.

Two forms exist. A relative link such as ``../mothra/evidence/x`` reaches a
sibling checkout and is resolved against a ``--mothra`` path. An absolute
GitHub link must be a commit permalink, ``blob/<40-hex>/<path>``, whose path
exists at that commit in the local clone; Git is called through ``cuprum``.
"""

import re
import typing as typ
import urllib.parse as urlparse

from repo_files import git
from tool_support import MissingInputError

if typ.TYPE_CHECKING:
    from pathlib import Path

GITHUB_MOTHRA = re.compile(
    r"^https?://github\.com/leynos/mothra(?:[/#?]|$)", re.IGNORECASE
)
PERMALINK = re.compile(
    r"^https://github\.com/leynos/mothra/blob/([0-9a-f]{40})/([^#?]+)"
)


def is_mothra_url(target: str) -> bool:
    """Say whether ``target`` is a GitHub URL for the mothra repository.

    Parameters
    ----------
    target : str
        A link destination.

    Returns
    -------
    bool
        ``True`` for any ``github.com/leynos/mothra`` URL.
    """
    return GITHUB_MOTHRA.match(target) is not None


def path_exists_at_commit(clone: Path | None, commit: str, path: str) -> bool:
    """Ask the local clone whether ``path`` exists at ``commit``.

    Parameters
    ----------
    clone : pathlib.Path | None
        The local mothra clone.
    commit : str
        A full commit identifier.
    path : str
        A repository-relative POSIX path.

    Returns
    -------
    bool
        ``True`` when ``git cat-file -e <commit>:<path>`` succeeds.

    Raises
    ------
    MissingInputError
        If no clone was given, or it is not a directory.
    """
    if clone is None or not clone.is_dir():
        message = "a local mothra clone (--mothra) is required to verify permalinks"
        raise MissingInputError(message)
    result = git("-C", str(clone), "cat-file", "-e", f"{commit}:{path}").run_sync()
    return result.exit_code == 0


def judge_github_link(target: str, clone: Path | None) -> str | None:
    """Judge a mothra GitHub URL under the permalink rule.

    Parameters
    ----------
    target : str
        A destination for which :func:`is_mothra_url` is true.
    clone : pathlib.Path | None
        The local mothra clone used to verify the path.

    Returns
    -------
    str | None
        A reason the link is unacceptable, or ``None`` when it is a permalink
        to a path that exists at that commit.
    """
    match = PERMALINK.match(target)
    if match is None:
        return "not a commit permalink (blob/<40-hex>/<path>)"
    commit, path = match[1], urlparse.unquote(match[2])
    if path_exists_at_commit(clone, commit, path):
        return None
    return f"path is absent at commit {commit[:12]}"
