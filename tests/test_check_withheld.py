"""Tests for the withheld-files gate (obligation INV-WITHHELD)."""

import typing as typ

import bsdiff4
import check_withheld
import pytest
import withheld_model
from repo_files import git
from tool_support import EXIT_MISSING
from withheld_helpers import (
    CONTAINER,
    CONTAINER_PATH,
    FORK,
    FORK_PATH,
    FORK_SIZE,
    IGNORE,
    PATCH,
    PATCH_PATH,
    build,
    digest,
    entry,
    patch_block,
    seed_repo,
)

if typ.TYPE_CHECKING:
    from pathlib import Path


def test_absent_files_are_reported_as_withheld_and_pass(tmp_path: Path) -> None:
    """A withheld file that is not on disk is expected, not a failure."""
    build(tmp_path)
    report = check_withheld.check(tmp_path)
    assert not report.failures, report.failures
    assert f"{FORK_PATH}: withheld (absent)" in report.notes, report.notes


def test_present_file_with_matching_hash_passes(tmp_path: Path) -> None:
    """A local copy that matches its recorded size and hash is verified."""
    repo = build(tmp_path)
    repo.put(FORK_PATH, FORK)
    report = check_withheld.check(tmp_path)
    assert not report.failures, report.failures
    assert f"{FORK_PATH}: verified" in report.notes, report.notes


def test_present_file_with_wrong_hash_fails(tmp_path: Path) -> None:
    """A local copy whose bytes differ is rejected by name."""
    repo = build(tmp_path)
    repo.put(FORK_PATH, b"x" * FORK_SIZE)
    report = check_withheld.check(tmp_path)
    assert len(report.failures) == 1, report.failures
    assert FORK_PATH in report.failures[0], report.failures[0]
    assert "sha256" in report.failures[0], report.failures[0]


def test_present_file_with_wrong_size_fails(tmp_path: Path) -> None:
    """A local copy of the wrong length is rejected by name."""
    repo = build(tmp_path)
    repo.put(FORK_PATH, FORK[:-1])
    report = check_withheld.check(tmp_path)
    assert any("size" in f and FORK_PATH in f for f in report.failures), report.failures


def test_tracked_entry_fails(tmp_path: Path) -> None:
    """A withheld path that Git tracks is a leak."""
    build(tmp_path, ignore=IGNORE, extra={FORK_PATH: FORK})
    # The ignore rule keeps the file out of the commit, so force-add it.
    git("-C", str(tmp_path), "add", "--force", FORK_PATH).run_sync()
    report = check_withheld.check(tmp_path)
    assert any("tracked" in f and FORK_PATH in f for f in report.failures), (
        report.failures
    )


def test_entry_not_matched_by_gitignore_fails(tmp_path: Path) -> None:
    """A withheld path must be ignored so a copy cannot be added by accident."""
    build(tmp_path, ignore=f"{CONTAINER_PATH}\n")
    report = check_withheld.check(tmp_path)
    assert any("not ignored" in f and FORK_PATH in f for f in report.failures), (
        report.failures
    )


def test_patch_round_trip_succeeds_when_the_base_is_present(tmp_path: Path) -> None:
    """Applying the patch to the base reproduces the recorded result."""
    repo = build(tmp_path)
    repo.put(FORK_PATH, FORK)
    report = check_withheld.check(tmp_path)
    assert not report.failures, report.failures
    assert any("patch verified" in note for note in report.notes), report.notes


def test_patch_is_not_exercised_when_the_base_is_absent(tmp_path: Path) -> None:
    """Without the base the patch cannot be applied, which is not a failure."""
    build(tmp_path)
    report = check_withheld.check(tmp_path)
    assert not report.failures, report.failures
    assert any("patch not exercised: base absent" in n for n in report.notes), (
        report.notes
    )


def test_wrong_patch_base_hash_fails(tmp_path: Path) -> None:
    """A recorded base hash that the local base does not match is rejected."""
    entries = [
        entry(FORK_PATH, FORK, fork="resource"),
        entry(CONTAINER_PATH, CONTAINER, patch_block(b"other"), fork="container"),
    ]
    repo = build(tmp_path, entries=entries)
    repo.put(FORK_PATH, FORK)
    report = check_withheld.check(tmp_path)
    assert any("base" in f and CONTAINER_PATH in f for f in report.failures), (
        report.failures
    )


def test_wrong_patch_file_hash_fails(tmp_path: Path) -> None:
    """The stored patch must hash to the recorded value."""
    repo = build(tmp_path)
    repo.put(FORK_PATH, FORK)
    (tmp_path / PATCH_PATH).write_bytes(PATCH + b"!")
    report = check_withheld.check(tmp_path)
    assert any("patch" in f and "sha256" in f for f in report.failures), report.failures


def test_wrong_result_hash_fails(tmp_path: Path) -> None:
    """A patch that rebuilds the wrong bytes is rejected."""
    block = patch_block() | {"result_sha256": digest(b"other")}
    entries = [
        entry(FORK_PATH, FORK, fork="resource"),
        entry(CONTAINER_PATH, CONTAINER, block, fork="container"),
    ]
    repo = build(tmp_path, entries=entries)
    repo.put(FORK_PATH, FORK)
    report = check_withheld.check(tmp_path)
    assert any("result" in f and CONTAINER_PATH in f for f in report.failures), (
        report.failures
    )


def test_missing_patch_file_fails(tmp_path: Path) -> None:
    """The patch file must exist."""
    build(tmp_path)
    (tmp_path / PATCH_PATH).unlink()
    failures = check_withheld.check(tmp_path).failures
    assert any("missing" in f and PATCH_PATH in f for f in failures), failures


def test_untracked_patch_file_fails(tmp_path: Path) -> None:
    """The patch file must be tracked, or it would not be published."""
    build(tmp_path, ignore=IGNORE + "*.bsdiff\n")
    failures = check_withheld.check(tmp_path).failures
    assert any("untracked" in f and PATCH_PATH in f for f in failures), failures


def test_manifest_problems_are_reported_as_errors(tmp_path: Path) -> None:
    """A malformed manifest raises a domain error that names the problem."""
    build(tmp_path)
    (tmp_path / "evidence/withheld.json").write_text('{"schema_version": 2}\n')
    with pytest.raises(withheld_model.ManifestError, match="schema_version"):
        check_withheld.check(tmp_path)


@pytest.mark.parametrize(
    ("patch", "word"),
    [
        ({"format": "BSDIFF40", "path": "wrong.bsdiff"}, "patch path"),
        ({"format": "OTHER"}, "format"),
    ],
)
def test_bad_patch_declarations_are_rejected(
    tmp_path: Path, patch: dict[str, str], word: str
) -> None:
    """The patch object must be of format BSDIFF40 and stored beside its path."""
    bad = entry(FORK_PATH, FORK, patch, fork="resource")
    build(tmp_path, entries=[bad])
    with pytest.raises(withheld_model.ManifestError, match=word):
        check_withheld.check(tmp_path)


def test_missing_manifest_is_a_missing_input(tmp_path: Path) -> None:
    """No manifest means exit code 2."""
    seed_repo(tmp_path, {"a.txt": "x"})
    code = check_withheld.main(["check", "--root", str(tmp_path)])
    assert code == EXIT_MISSING, code


def write_request(root: Path, source: Path) -> check_withheld.ManifestRequest:
    """Build the request that records the fork and its patched container.

    Returns
    -------
    check_withheld.ManifestRequest
        The request.
    """
    return check_withheld.ManifestRequest(
        root=root,
        source_root=source,
        reason="test",
        specs=(("resource", FORK_PATH), ("container", CONTAINER_PATH)),
        patch_bases={CONTAINER_PATH: FORK_PATH},
    )


def test_write_manifest_records_hashes_and_a_working_patch(tmp_path: Path) -> None:
    """The manifest holds real hashes and the patch rebuilds the container."""
    source = tmp_path / "source"
    (source / "evidence/inputs").mkdir(parents=True)
    (source / FORK_PATH).write_bytes(FORK)
    (source / CONTAINER_PATH).write_bytes(CONTAINER)
    target = tmp_path / "target"
    (target / "evidence").mkdir(parents=True)
    manifest = check_withheld.write_manifest(write_request(target, source))
    by_path = {e.path: e for e in manifest.files}
    assert by_path[FORK_PATH].sha256 == digest(FORK), by_path
    patch = by_path[CONTAINER_PATH].patch
    assert patch is not None, "container entry must carry a patch"
    stored = (target / PATCH_PATH).read_bytes()
    assert bsdiff4.patch(FORK, stored) == CONTAINER, "patch must rebuild the file"
    assert patch.patch_sha256 == digest(stored), patch
    text = (target / "evidence/withheld.json").read_text()
    assert text == withheld_model.render_manifest(manifest), "file must be canonical"
    reloaded = withheld_model.load_manifest(target / "evidence/withheld.json")
    assert reloaded == manifest, "the file must parse back to the manifest"


def test_a_written_manifest_passes_its_own_check(tmp_path: Path) -> None:
    """Round trip: write-manifest, commit, then check succeeds."""
    source = tmp_path / "source"
    (source / "evidence/inputs").mkdir(parents=True)
    (source / FORK_PATH).write_bytes(FORK)
    (source / CONTAINER_PATH).write_bytes(CONTAINER)
    target = tmp_path / "target"
    (target / "evidence").mkdir(parents=True)
    check_withheld.write_manifest(write_request(target, source))
    seed_repo(target, {".gitignore": IGNORE})
    report = check_withheld.check(target)
    assert not report.failures, report.failures
