"""Tests for the evidence ``.py`` pins and the read view that serves them."""

import hashlib
import io
import json
import os
import shutil
import typing as typ

import evidence_pin_view
import pinned_evidence
import pinned_evidence_cli
import pytest
from git_helpers import commit_files
from repo_files import git
from tool_support import EXIT_FINDINGS, EXIT_MISSING, EXIT_OK

if typ.TYPE_CHECKING:
    from pathlib import Path

NAME = "evidence/gap-remediation/2026-11-13/native-pm-01/verify.py"
ORIGINAL = "import json\n\n\ndef verify(path):\n    return json.loads(path)\n"
DOCUMENTED = (
    '"""Verify the capture."""\n'
    "import json\n\n\n"
    'def verify(path):\n    """Parse the capture."""\n    return json.loads(path)\n'
)
CHANGED = "import json\n\n\ndef verify(path):\n    return json.load(path)\n"


def build(root: Path, content: str = ORIGINAL) -> str:
    """Commit one evidence file and write its pin record.

    Returns
    -------
    str
        The capture commit.
    """
    commit = commit_files(root, {NAME: content})
    record = {"schema_version": 1, "files": [{"path": NAME, "commit": commit}]}
    (root / pinned_evidence.RECORD_RELATIVE).parent.mkdir(exist_ok=True)
    (root / pinned_evidence.RECORD_RELATIVE).write_text(json.dumps(record))
    return commit


def test_a_file_as_captured_passes(tmp_path: Path) -> None:
    """An unedited file verifies."""
    build(tmp_path)
    assert pinned_evidence.check(tmp_path) == [], "an unedited file verifies"


def test_docstrings_alone_are_accepted(tmp_path: Path) -> None:
    """Module and function docstrings do not change the tree that is compared."""
    build(tmp_path)
    (tmp_path / NAME).write_text(DOCUMENTED, encoding="utf-8")
    assert pinned_evidence.check(tmp_path) == [], "docstrings alone are accepted"


def test_a_code_edit_is_named(tmp_path: Path) -> None:
    """A change to the code fails even when a docstring accompanies it."""
    commit = build(tmp_path)
    (tmp_path / NAME).write_text(CHANGED, encoding="utf-8")
    failures = pinned_evidence.check(tmp_path)
    assert failures == [f"{NAME}: differs from {commit} by more than docstrings"], (
        "a code edit is named"
    )


def test_a_tracked_file_without_a_pin_is_named(tmp_path: Path) -> None:
    """A new evidence .py file cannot escape the record."""
    build(tmp_path)
    other = "evidence/gap-remediation/2026-11-13/native-pm-01/other.py"
    (tmp_path / other).write_text("x = 1\n", encoding="utf-8")
    git("-C", str(tmp_path), "add", other).run_sync()
    assert pinned_evidence.check(tmp_path) == [f"{other}: tracked but not pinned"], (
        "an unpinned file is named"
    )


def test_a_missing_commit_is_named(tmp_path: Path) -> None:
    """A record that names a commit outside the history fails with its path."""
    build(tmp_path)
    record = tmp_path / pinned_evidence.RECORD_RELATIVE
    text = record.read_text().replace(
        json.loads(record.read_text())["files"][0]["commit"], "0" * 40
    )
    record.write_text(text)
    (failure,) = pinned_evidence.check(tmp_path)
    assert failure.startswith(f"{NAME}: commit {'0' * 40} does not provide"), (
        "a missing commit is named"
    )


def test_a_malformed_record_is_refused(tmp_path: Path) -> None:
    """A path outside evidence/ or a short commit is a record error."""
    (tmp_path / "scripts").mkdir()
    record = tmp_path / pinned_evidence.RECORD_RELATIVE
    record.write_text(json.dumps({"files": [{"path": "a.py", "commit": "1" * 40}]}))
    with pytest.raises(pinned_evidence.PinRecordError):
        pinned_evidence.load_record(tmp_path)
    record.write_text(json.dumps({"files": [{"path": NAME, "commit": "abc"}]}))
    with pytest.raises(pinned_evidence.PinRecordError):
        pinned_evidence.load_record(tmp_path)


def test_generate_pins_each_file_to_its_adding_commit(tmp_path: Path) -> None:
    """The generator records the commit that added a file, and refuses edited files."""
    commit = build(tmp_path)
    assert pinned_evidence_cli.generate(tmp_path) == {NAME: commit}, (
        "the adding commit is recorded"
    )
    (tmp_path / NAME).write_text(DOCUMENTED, encoding="utf-8")
    with pytest.raises(pinned_evidence.PinRecordError):
        pinned_evidence_cli.generate(tmp_path)


def test_the_command_line_reports_and_exits(tmp_path: Path) -> None:
    """Exit 0 for a sound record, 1 for a finding and 2 without a record."""
    assert (
        pinned_evidence_cli.main(["check", "--root", str(tmp_path)]) == EXIT_MISSING
    ), "no record exits 2"
    build(tmp_path)
    assert pinned_evidence_cli.main(["check", "--root", str(tmp_path)]) == EXIT_OK, (
        "a sound record exits 0"
    )
    (tmp_path / NAME).write_text(CHANGED, encoding="utf-8")
    assert (
        pinned_evidence_cli.main(["check", "--root", str(tmp_path)]) == EXIT_FINDINGS
    ), "a code edit exits 1"


class View:
    """A repository whose evidence file has gained docstrings, read through the view."""

    def __init__(self, root: Path) -> None:
        """Commit the original and edit the working file."""
        build(root)
        (root / NAME).write_text(DOCUMENTED, encoding="utf-8")
        self.root = root
        self.record = pinned_evidence.load_record(root)


@pytest.fixture
def view(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> View:
    """Point the view at a scratch repository, with every patched function restored.

    Returns
    -------
    View
        The repository.
    """
    repo = View(tmp_path / "hotline-protocol-docs")
    monkeypatch.setattr(evidence_pin_view, "ROOT", repo.root)
    monkeypatch.setattr(evidence_pin_view, "_state", {})
    for owner, name in (
        (io, "open"),
        (os, "stat"),
        (os, "lstat"),
        (os, "link"),
        (shutil, "copyfile"),
    ):
        monkeypatch.setattr(owner, name, getattr(owner, name))
    monkeypatch.setattr("builtins.open", open)
    evidence_pin_view.install()
    return repo


def test_the_view_serves_the_captured_bytes(view: View) -> None:
    """A read, a hash and a size of a pinned file see the capture-time bytes."""
    path = view.root / NAME
    assert path.read_bytes() == ORIGINAL.encode(), "bytes are as captured"
    assert path.read_text(encoding="utf-8") == ORIGINAL, "text is as captured"
    assert path.stat().st_size == len(ORIGINAL), "size is as captured"
    assert (
        hashlib.sha256(path.read_bytes()).hexdigest()
        == hashlib.sha256(ORIGINAL.encode()).hexdigest()
    ), "the hash is as captured"


def test_the_view_covers_copies_and_links(view: View, tmp_path: Path) -> None:
    """A copy or a hard link of a pinned file holds the capture-time bytes."""
    shutil.copyfile(view.root / NAME, tmp_path / "copy.py")
    os.link(view.root / NAME, tmp_path / "link.py")
    assert (tmp_path / "copy.py").read_bytes() == ORIGINAL.encode(), (
        "a copy holds the captured bytes"
    )
    assert (tmp_path / "link.py").read_bytes() == ORIGINAL.encode(), (
        "a link holds the captured bytes"
    )


def test_the_view_follows_a_symbolic_link(view: View, tmp_path: Path) -> None:
    """A test that links a corpus file from a scratch directory sees the pin."""
    link = tmp_path / "linked.py"
    link.symlink_to(view.root / NAME)
    assert link.read_bytes() == ORIGINAL.encode(), "a symbolic link sees the pin"


def test_the_view_leaves_other_files_alone(view: View, tmp_path: Path) -> None:
    """A same-named file outside the repository is untouched."""
    elsewhere = tmp_path / "evidence/gap-remediation/2026-11-13/native-pm-01/verify.py"
    elsewhere.parent.mkdir(parents=True)
    elsewhere.write_text("kept\n", encoding="utf-8")
    assert elsewhere.read_text(encoding="utf-8") == "kept\n", (
        "a file elsewhere is untouched"
    )
    assert (view.root / pinned_evidence.RECORD_RELATIVE).read_text().startswith("{"), (
        "the record is plain JSON"
    )


def test_a_write_reaches_the_live_file(view: View) -> None:
    """Only reads are redirected, so a rewritten live file is still caught."""
    (view.root / NAME).write_text(CHANGED, encoding="utf-8")
    (failure,) = pinned_evidence.check(view.root)
    assert failure.endswith("by more than docstrings"), "a code edit is caught"
