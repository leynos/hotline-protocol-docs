"""List the files of a repository through Git, without a shell."""

from pathlib import Path

from cuprum import Program, ProgramCatalogue, ProjectSettings, sh
from tool_support import MissingInputError, ToolError

CATALOGUE = ProgramCatalogue(
    projects=(
        ProjectSettings(
            name="hotline-protocol-docs-tools",
            programs=(Program("git"),),
            documentation_locations=(),
            noise_rules=(),
        ),
    )
)
git = sh.make(Program("git"), catalogue=CATALOGUE)


class GitListingError(ToolError):
    """Git could not list the repository's files."""


def _git_listing(root: Path) -> list[str]:
    """List the paths that Git shows: tracked, plus untracked and not ignored.

    Parameters
    ----------
    root : pathlib.Path
        The checkout to list.

    Returns
    -------
    list[str]
        POSIX paths relative to ``root``.

    Raises
    ------
    GitListingError
        If Git exits with a failure.
    """
    result = git(
        "-C",
        str(root),
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
    ).run_sync()
    if result.exit_code != 0:
        message = f"git ls-files failed in {root}: {(result.stderr or '').strip()}"
        raise GitListingError(message)
    return [name for name in (result.stdout or "").split("\0") if name]


def _walk_listing(root: Path) -> list[str]:
    """List every file below ``root``, skipping dot-directories and caches.

    Parameters
    ----------
    root : pathlib.Path
        The directory to walk.

    Returns
    -------
    list[str]
        POSIX paths relative to ``root``.
    """
    names: list[str] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        hidden = any(
            part.startswith(".") or part == "__pycache__" for part in relative.parts
        )
        if path.is_file() and not hidden:
            names.append(relative.as_posix())
    return names


def repo_files(root: Path, suffix: str) -> list[Path]:
    """List the repository's files that end with ``suffix``.

    Inside a Git checkout the listing is ``git ls-files`` over tracked and
    untracked-but-not-ignored files. Elsewhere (for example a temporary test
    tree) every file below ``root`` is listed, skipping dot-directories.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    suffix : str
        The file-name ending to select, for example ``".json"``.

    Returns
    -------
    list[pathlib.Path]
        Sorted paths relative to ``root`` that exist on disk.

    Raises
    ------
    MissingInputError
        If ``root`` is not a directory. A ``.git`` entry that Git cannot list
        raises ``GitListingError``.
    """
    if not root.is_dir():
        message = f"root directory {root} is absent"
        raise MissingInputError(message)
    names = _git_listing(root) if (root / ".git").exists() else _walk_listing(root)
    return sorted(
        Path(name)
        for name in names
        if name.endswith(suffix) and (root / name).is_file()
    )
