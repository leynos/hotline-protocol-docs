"""Tests for the Git LFS storage rule for evidence."""

import typing as typ

import check_sums
import lfs_rule
from tool_support import EXIT_FINDINGS, EXIT_OK
from withheld_helpers import seed_repo

if typ.TYPE_CHECKING:
    from pathlib import Path

POINTER = (
    "version https://git-lfs.github.com/spec/v1\noid sha256:" + "0" * 64 + "\nsize 4\n"
)


def committed(
    root: Path, files: dict[str, str | bytes], real: dict[str, bytes]
) -> None:
    """Commit ``files`` and then put ``real`` content in the working tree."""
    seed_repo(root, files)
    for name, data in real.items():
        (root / name).write_bytes(data)


def test_exactly_the_expected_paths_in_lfs_pass(tmp_path: Path) -> None:
    """PNG, PCAP and gzip files are pointers; JSON is ordinary Git."""
    files: dict[str, str | bytes] = {
        "evidence/a.png": POINTER,
        "evidence/dir/b.pcap": POINTER,
        "evidence/dir/c.tar.gz": POINTER,
        "evidence/d.json": "{}\n",
        "docs/outside.png": "ordinary",
    }
    real = {name: b"real" for name in files if name.endswith((".png", ".pcap", ".gz"))}
    del real["docs/outside.png"]
    committed(tmp_path, files, real)
    report = lfs_rule.check_lfs(tmp_path)
    assert not report.failures, report.failures
    assert report.notes == ["4 tracked paths, 3 expected in LFS, 3 stored in LFS"], (
        report.notes
    )


def test_a_png_in_ordinary_git_fails(tmp_path: Path) -> None:
    """A path that the rule selects must be a pointer in the index."""
    committed(tmp_path, {"evidence/a.png": "plain"}, {})
    failures = lfs_rule.check_lfs(tmp_path).failures
    assert any("a.png" in f and "ordinary Git" in f for f in failures), failures


def test_a_json_file_in_lfs_fails(tmp_path: Path) -> None:
    """A path the rule does not select must not be a pointer."""
    committed(tmp_path, {"evidence/a.json": POINTER}, {"evidence/a.json": b"{}\n"})
    failures = lfs_rule.check_lfs(tmp_path).failures
    assert any("a.json" in f and "wrongly" in f for f in failures), failures


def test_a_pointer_left_in_the_working_tree_fails_with_the_remedy(
    tmp_path: Path,
) -> None:
    """Pointer text where content belongs names ``git lfs pull``."""
    committed(tmp_path, {"evidence/a.png": POINTER}, {})
    failures = lfs_rule.check_lfs(tmp_path).failures
    assert any("git lfs pull" in f and "a.png" in f for f in failures), failures


def test_command_line_exit_codes(tmp_path: Path) -> None:
    """The ``lfs`` command exits 0 when the rule holds and 1 when it does not."""
    committed(tmp_path, {"evidence/a.png": POINTER}, {"evidence/a.png": b"x"})
    assert check_sums.main(["lfs", "--root", str(tmp_path)]) == EXIT_OK, "holds"
    (tmp_path / "evidence/b.png").write_bytes(b"plain")
    seed_repo(tmp_path, {})
    code = check_sums.main(["lfs", "--root", str(tmp_path)])
    assert code == EXIT_FINDINGS, "a PNG in ordinary Git must fail"
