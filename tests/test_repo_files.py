"""Tests for listing repository files through Git or a directory walk."""

import typing as typ
from pathlib import Path

import pytest
from repo_files import git, repo_files

if typ.TYPE_CHECKING:
    from tree_helpers import TreeBuilder


def test_walk_lists_matching_files_and_skips_dot_directories(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Outside a Git checkout the walk finds files and ignores hidden trees."""
    make_tree(tmp_path, {"a.json": "{}", "d/b.json": "{}", ".venv/c.json": "{}"})
    found = repo_files(tmp_path, ".json")
    assert found == [Path("a.json"), Path("d/b.json")], (
        "expected found == [Path('a.json'), Path('d/b.json')]"
    )


def test_git_lists_tracked_and_untracked_but_not_ignored(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Inside a checkout the listing honours ``.gitignore``."""
    make_tree(
        tmp_path,
        {".gitignore": "ignored.json\n", "a.json": "{}", "ignored.json": "{}"},
    )
    result = git("-C", str(tmp_path), "init", "--quiet").run_sync()
    assert result.exit_code == 0, "expected result.exit_code == 0"
    assert repo_files(tmp_path, ".json") == [Path("a.json")], (
        "expected repo_files(tmp_path, '.json') == [Path('a.json')]"
    )


def test_missing_root_is_a_missing_input(tmp_path: Path) -> None:
    """A root that does not exist is reported as a missing input."""
    from tool_support import MissingInputError

    with pytest.raises(MissingInputError, match="absent"):
        repo_files(tmp_path / "absent", ".json")
