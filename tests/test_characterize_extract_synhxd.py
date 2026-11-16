"""Characterize ``extract-synhxd-evidence.py`` before it is refactored.

Every expectation below was observed on the script at its pinned commit
(``scripts/pinned-sources.json``), and the same tests must give the same
outcomes on the refactored script. Synthetic archives break each check alone,
and the retained snapshots are verified read-only.
"""

import hashlib
import json
import runpy
import typing as typ

import pytest
from script_loading import ROOT, load_script

if typ.TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType

CHARACTERIZES = "extract-synhxd-evidence.py"
RETAINED = ROOT / "evidence/hotline-server-1.9/synhxd-source"
REVISION = "1.2"
TEXT = "first line\nan @ sign\nlast line\n"
# An RCS archive stores the full trunk text between ``@`` marks, doubling each ``@``.
ARCHIVE = (
    "head\t1.2;\n\n"
    f"\n{REVISION}\nlog\n@initial@\ntext\n@first line\nan @@ sign\nlast line\n@\n"
)


@pytest.fixture(scope="module")
def extractor() -> ModuleType:
    """Load the script under test.

    Returns
    -------
    types.ModuleType
        The executed script.
    """
    return load_script(ROOT / "scripts" / CHARACTERIZES, "extract_synhxd_under_test")


def sha(data: bytes) -> str:
    """Hash bytes.

    Returns
    -------
    str
        The lower-case hexadecimal SHA-256.
    """
    return hashlib.sha256(data).hexdigest()


def directory_with(tmp_path: Path, *, snapshot: str = TEXT, **record: str) -> Path:
    """Write a one-record snapshot directory.

    Returns
    -------
    pathlib.Path
        The directory.
    """
    entry = {
        "saved_archive": "a.c.rcs",
        "archive_sha256": sha(ARCHIVE.encode("latin1")),
        "selected_revision": REVISION,
        "snapshot": "a.c",
        "snapshot_sha256": sha(TEXT.encode("latin1")),
    }
    entry.update(record)
    (tmp_path / "manifest.json").write_text(json.dumps([entry]))
    (tmp_path / "a.c.rcs").write_bytes(ARCHIVE.encode("latin1"))
    (tmp_path / "a.c").write_bytes(snapshot.encode("latin1"))
    return tmp_path


class SyntheticArchiveTests:
    """Each check of ``verify_snapshots`` has an archive that breaks it."""

    def test_a_sound_directory_prints_the_snapshot_and_revision(
        self,
        extractor: ModuleType,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The doubled at-sign is undone and a line names the snapshot."""
        extractor.verify_snapshots(directory_with(tmp_path))
        assert capsys.readouterr().out == "a.c 1.2 verified\n", "expected one line"

    def test_a_changed_archive_is_refused(
        self, extractor: ModuleType, tmp_path: Path
    ) -> None:
        """The archive must hash to the recorded value."""
        directory = directory_with(tmp_path, archive_sha256="0" * 64)
        with pytest.raises(ValueError, match=r"^Archive changed: a\.c\.rcs$"):
            extractor.verify_snapshots(directory)

    def test_a_missing_revision_is_refused(
        self, extractor: ModuleType, tmp_path: Path
    ) -> None:
        """A selected revision with no text block is refused."""
        directory = directory_with(tmp_path, selected_revision="9.9")
        with pytest.raises(ValueError, match=r"^Full trunk text not found: a\.c\.rcs$"):
            extractor.verify_snapshots(directory)

    def test_an_extraction_that_misses_the_recorded_hash_is_refused(
        self, extractor: ModuleType, tmp_path: Path
    ) -> None:
        """The extracted text must hash to the recorded snapshot hash."""
        directory = directory_with(tmp_path, snapshot_sha256="0" * 64)
        with pytest.raises(ValueError, match=r"^Extraction mismatch: a\.c$"):
            extractor.verify_snapshots(directory)

    def test_a_changed_saved_snapshot_is_refused(
        self, extractor: ModuleType, tmp_path: Path
    ) -> None:
        """The saved snapshot file must equal the extraction."""
        directory = directory_with(tmp_path, snapshot=TEXT + "edited\n")
        with pytest.raises(ValueError, match=r"^Snapshot changed: a\.c$"):
            extractor.verify_snapshots(directory)

    def test_the_archive_check_comes_before_the_extraction(
        self, extractor: ModuleType, tmp_path: Path
    ) -> None:
        """A changed archive is reported although its revision is also absent."""
        directory = directory_with(
            tmp_path, archive_sha256="0" * 64, selected_revision="9.9"
        )
        with pytest.raises(ValueError, match="Archive changed"):
            extractor.verify_snapshots(directory)

    def test_the_text_check_comes_before_the_hash_check(
        self, extractor: ModuleType, tmp_path: Path
    ) -> None:
        """A missing text block is reported before a wrong snapshot hash."""
        directory = directory_with(
            tmp_path, selected_revision="9.9", snapshot_sha256="0" * 64
        )
        with pytest.raises(ValueError, match="Full trunk text not found"):
            extractor.verify_snapshots(directory)

    def test_the_hash_check_comes_before_the_saved_file_check(
        self, extractor: ModuleType, tmp_path: Path
    ) -> None:
        """A wrong snapshot hash is reported before a changed saved file."""
        directory = directory_with(
            tmp_path, snapshot=TEXT + "edited\n", snapshot_sha256="0" * 64
        )
        with pytest.raises(ValueError, match="Extraction mismatch"):
            extractor.verify_snapshots(directory)

    def test_a_missing_saved_archive_is_a_file_not_found_error(
        self, extractor: ModuleType, tmp_path: Path
    ) -> None:
        """The archive is read before anything else is checked."""
        directory = directory_with(tmp_path, saved_archive="gone.rcs")
        with pytest.raises(FileNotFoundError):
            extractor.verify_snapshots(directory)

    def test_a_missing_manifest_is_a_file_not_found_error(
        self, extractor: ModuleType, tmp_path: Path
    ) -> None:
        """An empty directory has no manifest."""
        with pytest.raises(FileNotFoundError):
            extractor.verify_snapshots(tmp_path)

    def test_a_record_without_a_field_is_a_key_error(
        self, extractor: ModuleType, tmp_path: Path
    ) -> None:
        """A record lacking ``saved_archive`` fails on that key first."""
        (tmp_path / "manifest.json").write_text(json.dumps([{"snapshot": "a.c"}]))
        with pytest.raises(KeyError, match="saved_archive"):
            extractor.verify_snapshots(tmp_path)

    def test_records_stop_at_the_first_failure_after_printing_earlier_ones(
        self,
        extractor: ModuleType,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The first record prints its line before the second is refused."""
        directory = directory_with(tmp_path)
        records = json.loads((directory / "manifest.json").read_text())
        records.append({**records[0], "snapshot": "b.c", "archive_sha256": "0" * 64})
        (directory / "manifest.json").write_text(json.dumps(records))
        with pytest.raises(ValueError, match="Archive changed"):
            extractor.verify_snapshots(directory)
        assert capsys.readouterr().out == "a.c 1.2 verified\n", "expected the first"

    def test_an_empty_manifest_verifies_nothing(
        self,
        extractor: ModuleType,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """No record, no output, no error."""
        (tmp_path / "manifest.json").write_text("[]")
        extractor.verify_snapshots(tmp_path)
        assert not capsys.readouterr().out, "expected no output"


class RetainedSnapshotTests:
    """The retained SynHX snapshots are verified, read-only."""

    def test_every_retained_snapshot_is_verified_in_manifest_order(
        self, extractor: ModuleType, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """One line per manifest record, naming snapshot and revision."""
        records = json.loads((RETAINED / "manifest.json").read_text())
        extractor.verify_snapshots(RETAINED)
        expected = [
            f"{record['snapshot']} {record['selected_revision']} verified"
            for record in records
        ]
        assert capsys.readouterr().out.splitlines() == expected, (
            "expected a line per record"
        )

    def test_the_program_verifies_the_retained_directory_of_its_tree(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Run as a program, the script reads the evidence of the tree around it."""
        runpy.run_path(str(ROOT / "scripts" / CHARACTERIZES), run_name="__main__")
        lines = capsys.readouterr().out.splitlines()
        assert lines, "expected output"
        assert all(line.endswith(" verified") for line in lines), "expected verified"
