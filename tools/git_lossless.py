"""Run Git so that its output survives any byte sequence unchanged.

Path names may hold control characters or bytes that are not UTF-8. Cuprum
decodes output with a text codec, so these helpers choose Latin-1, which maps
every byte to one character and back. A path is converted to a
:class:`pathlib.Path` through the file-system encoding with surrogate escapes.
"""

import os
from pathlib import Path

from cuprum import ExecutionContext
from repo_files import git
from tool_support import ToolError

LOSSLESS = ExecutionContext(encoding="latin-1", errors="strict")
NUL = "\0"


class GitCommandError(ToolError):
    """A Git command exited with a failure that the caller cannot tolerate."""


def git_text(repository: Path, *args: str, ok: tuple[int, ...] = (0,)) -> str:
    """Run ``git -C repository args`` and return its stdout as Latin-1 text.

    Parameters
    ----------
    repository : pathlib.Path
        The repository to run in.
    *args : str
        The Git sub-command and its arguments.
    ok : tuple[int, ...]
        Exit codes that are not failures.

    Returns
    -------
    str
        Standard output, one character per byte.

    Raises
    ------
    GitCommandError
        If Git exits with a code outside ``ok``.
    """
    result = git("-C", str(repository), *args).run_sync(context=LOSSLESS)
    if result.exit_code not in ok:
        message = (
            f"git {args[0]} failed in {repository}: {(result.stderr or '').strip()}"
        )
        raise GitCommandError(message)
    return result.stdout or ""


def git_names(repository: Path, *args: str, ok: tuple[int, ...] = (0,)) -> list[str]:
    """Run a Git command that prints NUL-terminated names and split them.

    Parameters
    ----------
    repository : pathlib.Path
        The repository to run in.
    *args : str
        The Git sub-command and its arguments.
    ok : tuple[int, ...]
        Exit codes that are not failures.

    Returns
    -------
    list[str]
        The names, each as Latin-1 text.
    """
    return [name for name in git_text(repository, *args, ok=ok).split(NUL) if name]


def as_arg(latin1: str) -> str:
    """Convert Latin-1 text that stands for raw bytes into a command argument.

    Parameters
    ----------
    latin1 : str
        A name from :func:`git_names`.

    Returns
    -------
    str
        The same bytes as file-system text with surrogate escapes, which is the
        form that process arguments and paths expect.
    """
    return os.fsdecode(latin1.encode("latin-1"))


def as_path(latin1: str) -> Path:
    """Convert Latin-1 text that stands for raw bytes into a path.

    Parameters
    ----------
    latin1 : str
        A name from :func:`git_names`.

    Returns
    -------
    pathlib.Path
        A path that names the same bytes on disk.
    """
    return Path(as_arg(latin1))
