"""Tests for the history scan of the withheld-files gate."""

import typing as typ

import check_withheld
from git_helpers import init_repo
from tool_support import EXIT_FINDINGS, EXIT_OK
from withheld_helpers import (
    FORK,
    MOTHRA_WITHHELD,
    build,
    seed_repo,
    write_mothra_manifest,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

    import pytest


def test_history_scan_finds_a_blob_with_a_withheld_hash(tmp_path: Path) -> None:
    """A committed blob whose SHA-256 is withheld fails the scan."""
    repo = tmp_path / "leaky"
    repo.mkdir()
    seed_repo(repo, {"innocent/name.bin": FORK})
    clean = tmp_path / "clean"
    build(clean)
    report = check_withheld.check(clean, history=repo)
    assert any("sha256" in f for f in report.failures), report.failures
    assert any(note.endswith("1 withheld objects") for note in report.notes), (
        report.notes
    )


def test_history_scan_finds_the_container_magic_in_a_large_blob(
    tmp_path: Path,
) -> None:
    """A blob over 100 kB that begins with the PEF magic fails the scan."""
    repo = tmp_path / "leaky"
    repo.mkdir()
    seed_repo(repo, {"x.bin": b"Joy!peffpwpc" + b"\x01" * 120_000})
    clean = tmp_path / "clean"
    build(clean)
    report = check_withheld.check(clean, history=repo)
    assert any("magic" in f for f in report.failures), report.failures


def test_history_scan_passes_a_clean_repository_and_counts_blobs(
    tmp_path: Path,
) -> None:
    """A clean repository reports its blob count and no withheld objects."""
    repo = tmp_path / "ok"
    repo.mkdir()
    seed_repo(repo, {"a.txt": "a", "b.txt": "b", "c.bin": b"Joy!peffpwpc"})
    clean = tmp_path / "clean"
    build(clean)
    report = check_withheld.check(clean, history=repo)
    assert not report.failures, report.failures
    assert "3 blobs scanned, 0 withheld objects" in report.notes, report.notes


def test_history_scan_sees_blobs_that_only_an_old_commit_holds(
    tmp_path: Path,
) -> None:
    """A withheld blob deleted in a later commit is still found."""
    repo = tmp_path / "old"
    repo.mkdir()
    seed_repo(repo, {"fork.bin": FORK})
    (repo / "fork.bin").unlink()
    (repo / "other.txt").write_text("later")
    init_repo(repo)
    clean = tmp_path / "clean"
    build(clean)
    failures = check_withheld.check(clean, history=repo).failures
    assert failures, "the old blob must still be found"


def test_cli_prints_the_history_summary_and_exit_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The command line exits 0 on a clean tree and 1 on a finding."""
    build(tmp_path)
    assert check_withheld.main(["check", "--root", str(tmp_path)]) == EXIT_OK, "clean"
    leaky = tmp_path / "leaky"
    leaky.mkdir()
    seed_repo(leaky, {"fork.bin": FORK})
    argv = ["check", "--root", str(tmp_path), "--scan-history", "--repository"]
    argv.append(str(leaky))
    assert check_withheld.main(argv) == EXIT_FINDINGS, "a leak is a finding"
    out = capsys.readouterr().out
    assert "1 blobs scanned, 1 withheld objects" in out, out


MOTHRA_BLOBS = {
    "997cf1eb2b5b58a1337c3093a1acac114a9a3ca0",
    "9e007da29fbc6f20196f1edef571a082fc49f6ac",
    "ba624e4203d431d28233eaadc15855a87b5d6bbf",
}


def test_scan_of_the_real_mothra_history_sees_the_withheld_blobs(
    tmp_path: Path, mothra: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Negative control: the scan finds the known blobs in mothra's history."""
    write_mothra_manifest(tmp_path, mothra)
    ignored = "\n".join(path for _, path in MOTHRA_WITHHELD) + "\n"
    seed_repo(tmp_path, {".gitignore": ignored})
    argv = ["check", "--root", str(tmp_path), "--scan-history", "--repository"]
    check_withheld.main([*argv, str(mothra)])
    out = capsys.readouterr().out
    found = {oid for oid in MOTHRA_BLOBS if oid in out}
    assert found == MOTHRA_BLOBS, out
    assert "3 withheld objects" in out, out
