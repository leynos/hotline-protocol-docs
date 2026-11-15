"""Tests for the mothra checkout locator."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import mothra_root


class MothraRootTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / "work" / "hotline-protocol-docs"
        self.repo.mkdir(parents=True)
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("MOTHRA_ROOT", None)

    def test_environment_variable_wins(self) -> None:
        (self.base / "work" / "mothra").mkdir()
        os.environ["MOTHRA_ROOT"] = str(self.base / "elsewhere")
        self.assertEqual(mothra_root.mothra_root(self.repo), self.base / "elsewhere")

    def test_sibling_checkout(self) -> None:
        (self.base / "work" / "mothra").mkdir()
        self.assertEqual(
            mothra_root.mothra_root(self.repo), self.base / "work" / "mothra"
        )

    def test_sibling_of_the_main_checkout_from_a_linked_worktree(self) -> None:
        (self.base / "mothra").mkdir()
        self.assertEqual(mothra_root.mothra_root(self.repo), self.base / "mothra")

    def test_nearer_sibling_preferred(self) -> None:
        (self.base / "work" / "mothra").mkdir()
        (self.base / "mothra").mkdir()
        self.assertEqual(
            mothra_root.mothra_root(self.repo), self.base / "work" / "mothra"
        )

    def test_conventional_place_when_absent(self) -> None:
        self.assertEqual(
            mothra_root.mothra_root(self.repo), self.base / "work" / "mothra"
        )

    def test_default_repository_is_the_parent_of_scripts(self) -> None:
        os.environ["MOTHRA_ROOT"] = "/somewhere"
        self.assertEqual(mothra_root.mothra_root(), Path("/somewhere"))
        os.environ.pop("MOTHRA_ROOT")
        repo = Path(mothra_root.__file__).resolve().parents[1]
        self.assertIn(
            mothra_root.mothra_root(),
            {repo.parent / "mothra", repo.parent.parent / "mothra"},
        )

    def test_empty_variable_is_ignored(self) -> None:
        os.environ["MOTHRA_ROOT"] = ""
        self.assertEqual(
            mothra_root.mothra_root(self.repo), self.base / "work" / "mothra"
        )


if __name__ == "__main__":
    unittest.main()
