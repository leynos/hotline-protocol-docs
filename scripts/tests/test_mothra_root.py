"""Tests for the mothra checkout locator."""

from pathlib import Path

import mothra_root
import pytest


class MothraRootTests:
    """Locate the mothra checkout from the environment and the sibling layout."""

    @pytest.fixture
    def base(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        """Provide a resolved temporary base with ``MOTHRA_ROOT`` unset.

        Returns
        -------
        pathlib.Path
            The resolved temporary directory.
        """
        monkeypatch.delenv("MOTHRA_ROOT", raising=False)
        return tmp_path.resolve()

    @pytest.fixture
    def repo(self, base: Path) -> Path:
        """Provide the hotline-protocol-docs checkout under the base.

        Returns
        -------
        pathlib.Path
            The created repository directory.
        """
        path = base / "work" / "hotline-protocol-docs"
        path.mkdir(parents=True)
        return path

    def test_environment_variable_wins(
        self, base: Path, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A configured ``MOTHRA_ROOT`` is returned before any sibling."""
        (base / "work" / "mothra").mkdir()
        monkeypatch.setenv("MOTHRA_ROOT", str(base / "elsewhere"))
        assert mothra_root.mothra_root(repo) == base / "elsewhere", (
            "the configured root is not used"
        )

    def test_sibling_checkout(self, base: Path, repo: Path) -> None:
        """The sibling of the repository is found next to it."""
        (base / "work" / "mothra").mkdir()
        assert mothra_root.mothra_root(repo) == base / "work" / "mothra", (
            "the sibling checkout is not found"
        )

    def test_sibling_of_the_main_checkout_from_a_linked_worktree(
        self, base: Path, repo: Path
    ) -> None:
        """A linked worktree finds the mothra checkout beside the main checkout."""
        (base / "mothra").mkdir()
        assert mothra_root.mothra_root(repo) == base / "mothra", (
            "the main checkout's sibling is not found"
        )

    def test_nearer_sibling_preferred(self, base: Path, repo: Path) -> None:
        """The nearer sibling wins over the one beside the main checkout."""
        (base / "work" / "mothra").mkdir()
        (base / "mothra").mkdir()
        assert mothra_root.mothra_root(repo) == base / "work" / "mothra", (
            "the farther sibling is preferred"
        )

    def test_conventional_place_when_absent(self, base: Path, repo: Path) -> None:
        """With no checkout present, the conventional nearest place is named."""
        assert mothra_root.mothra_root(repo) == base / "work" / "mothra", (
            "the conventional place is not named"
        )

    def test_default_repository_is_the_parent_of_scripts(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The default repository is the parent of ``scripts``."""
        monkeypatch.setenv("MOTHRA_ROOT", "/somewhere")
        assert mothra_root.mothra_root() == Path("/somewhere"), (
            "the configured root is not used by default"
        )
        monkeypatch.delenv("MOTHRA_ROOT")
        repo = Path(mothra_root.__file__).resolve().parents[1]
        assert mothra_root.mothra_root() in {
            repo.parent / "mothra",
            repo.parent.parent / "mothra",
        }, "the default repository's sibling is not named"

    def test_empty_variable_is_ignored(
        self, base: Path, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An empty ``MOTHRA_ROOT`` falls back to the sibling layout."""
        monkeypatch.setenv("MOTHRA_ROOT", "")
        assert mothra_root.mothra_root(repo) == base / "work" / "mothra", (
            "an empty variable is not ignored"
        )
