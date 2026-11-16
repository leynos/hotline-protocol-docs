"""Test the perturbation that proves a pinned script is free to change."""

import typing as typ

import pin_experiment
import pytest

if typ.TYPE_CHECKING:
    from pathlib import Path


class PerturbationTests:
    """Append a comment to each named script and always put the bytes back."""

    @staticmethod
    def tree(tmp_path: Path) -> tuple[Path, Path]:
        """Create two scripts below ``tmp_path``.

        Returns
        -------
        tuple[pathlib.Path, pathlib.Path]
            The two script paths.
        """
        scripts = tmp_path / "scripts"
        scripts.mkdir()
        first, second = scripts / "a.py", scripts / "b.py"
        first.write_bytes(b"x = 1\n")
        second.write_bytes(b"y = 2")  # no final newline, as some scripts have
        return first, second

    def test_each_script_gains_a_comment_that_changes_its_bytes(
        self, tmp_path: Path
    ) -> None:
        """Inside the context every named script differs and still compiles."""
        first, second = self.tree(tmp_path)
        with pin_experiment.perturbed(tmp_path, ["a.py", "b.py"]):
            for path, before in ((first, b"x = 1\n"), (second, b"y = 2")):
                after = path.read_bytes()
                assert after != before, "expected after != before"
                assert after.startswith(before), "expected after.startswith(before)"
                compile(after, str(path), "exec")

    def test_the_original_bytes_return_after_the_context(self, tmp_path: Path) -> None:
        """Leaving the context restores both files exactly."""
        first, second = self.tree(tmp_path)
        with pin_experiment.perturbed(tmp_path, ["a.py", "b.py"]):
            pass
        assert first.read_bytes() == b"x = 1\n", (
            "expected first.read_bytes() == b'x = 1\\n'"
        )
        assert second.read_bytes() == b"y = 2", (
            "expected second.read_bytes() == b'y = 2'"
        )

    @staticmethod
    def fail_inside(root: Path) -> None:
        """Raise from inside the context.

        Raises
        ------
        RuntimeError
            Always.
        """
        with pin_experiment.perturbed(root, ["a.py", "b.py"]):
            message = "boom"
            raise RuntimeError(message)

    def test_the_original_bytes_return_after_a_failure(self, tmp_path: Path) -> None:
        """An exception inside the context still restores every file."""
        first, second = self.tree(tmp_path)
        with pytest.raises(RuntimeError, match="boom"):
            self.fail_inside(tmp_path)
        assert first.read_bytes() == b"x = 1\n", (
            "expected first.read_bytes() == b'x = 1\\n'"
        )
        assert second.read_bytes() == b"y = 2", (
            "expected second.read_bytes() == b'y = 2'"
        )
