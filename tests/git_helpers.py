"""Build throw-away Git repositories for tests, through cuprum."""

import typing as typ

from repo_files import git

if typ.TYPE_CHECKING:
    from pathlib import Path

IDENTITY = ("-c", "user.name=test", "-c", "user.email=test@example.invalid")


def commit_files(root: Path, files: dict[str, str]) -> str:
    """Create a repository below ``root`` holding ``files`` in one commit.

    Parameters
    ----------
    root : pathlib.Path
        An existing empty directory.
    files : dict[str, str]
        Relative path to text content.

    Returns
    -------
    str
        The full 40-hexadecimal commit identifier.
    """
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    base = ("-C", str(root))
    git(*base, "init", "--quiet").run_sync()
    git(*base, "add", "--all").run_sync()
    git(*base, *IDENTITY, "commit", "--quiet", "-m", "fixture").run_sync()
    result = git(*base, "rev-parse", "HEAD").run_sync()
    return (result.stdout or "").strip()


def init_repo(root: Path) -> None:
    """Commit everything already below ``root`` as one commit.

    Parameters
    ----------
    root : pathlib.Path
        A directory that already holds files.
    """
    base = ("-C", str(root))
    git(*base, "init", "--quiet").run_sync()
    git(*base, "add", "--all").run_sync()
    git(*base, *IDENTITY, "commit", "--quiet", "-m", "fixture").run_sync()
