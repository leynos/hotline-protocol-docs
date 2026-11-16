"""Test the helper that reads a script at the Git commit that carries its hash."""

import hashlib
import json
import typing as typ

import pinned_source
import pinned_source_cli
import pytest
from git_helpers import IDENTITY, commit_files
from repo_files import git

if typ.TYPE_CHECKING:
    from pathlib import Path

BODY = b"VALUE = 1\n"
BODY_SHA = hashlib.sha256(BODY).hexdigest()
ABSENT_COMMIT = "0123456789abcdef0123456789abcdef01234567"


def write_record(path: Path, entries: list[dict[str, str]]) -> Path:
    """Write a record that holds ``entries``.

    Returns
    -------
    pathlib.Path
        The record file.
    """
    path.write_text(json.dumps({"schema_version": 1, "sources": entries}))
    return path


def entry(commit: str, sha256: str = BODY_SHA, path: str = "scripts/tool.py") -> dict:
    """Build one record entry.

    Returns
    -------
    dict
        The entry for ``tool.py`` unless ``path`` says otherwise.
    """
    return {"path": path, "commit": commit, "sha256": sha256, "recorded_in": ["x"]}


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, str]:
    """Create a repository whose one commit holds ``scripts/tool.py``.

    Returns
    -------
    tuple[pathlib.Path, str]
        The repository directory and the commit.
    """
    root = tmp_path / "repo"
    root.mkdir()
    commit = commit_files(root, {"scripts/tool.py": BODY.decode()})
    return root, commit


def sources(tmp_path: Path, root: Path, entries: list[dict]) -> pinned_source.Pins:
    """Open a record in ``tmp_path`` against the repository ``root``.

    Returns
    -------
    pinned_source.Pins
        The pins.
    """
    return pinned_source.Pins(write_record(tmp_path / "record.json", entries), root)


class ReadTests:
    """Return the bytes at the pinned commit, once they match the record."""

    def test_the_bytes_at_the_commit_are_returned(
        self, tmp_path: Path, repo: tuple[Path, str]
    ) -> None:
        """A matching record yields the committed bytes and their hash."""
        root, commit = repo
        pins = sources(tmp_path, root, [entry(commit)])
        assert pins.read("tool.py") == BODY, "expected pins.read('tool.py') == BODY"
        assert pins.sha256("tool.py") == BODY_SHA, (
            "expected pins.sha256('tool.py') == BODY_SHA"
        )

    def test_the_live_file_is_not_consulted(
        self, tmp_path: Path, repo: tuple[Path, str]
    ) -> None:
        """Editing the working copy changes nothing: the commit decides."""
        root, commit = repo
        (root / "scripts/tool.py").write_bytes(BODY + b"# edited\n")
        pins = sources(tmp_path, root, [entry(commit)])
        assert pins.read("tool.py") == BODY, "expected pins.read('tool.py') == BODY"

    def test_a_name_that_is_not_pinned_is_refused(
        self, tmp_path: Path, repo: tuple[Path, str]
    ) -> None:
        """Asking for a script that the record omits is a domain error."""
        root, commit = repo
        pins = sources(tmp_path, root, [entry(commit)])
        with pytest.raises(pinned_source.UnknownSourceError, match=r"other\.py"):
            pins.read("other.py")


class FailureTests:
    """Report each way the pin can fail, naming the script and the cause."""

    def test_a_wrong_hash_in_the_record_is_reported(
        self, tmp_path: Path, repo: tuple[Path, str]
    ) -> None:
        """Bytes that differ from the recorded hash raise a mismatch error."""
        root, commit = repo
        pins = sources(tmp_path, root, [entry(commit, sha256="0" * 64)])
        with pytest.raises(pinned_source.SourceMismatchError, match=r"tool\.py"):
            pins.read("tool.py")

    def test_a_commit_that_does_not_contain_the_file_is_reported(
        self, tmp_path: Path, repo: tuple[Path, str]
    ) -> None:
        """A real commit without the path raises a missing-path error."""
        root, commit = repo
        pins = sources(tmp_path, root, [entry(commit, path="scripts/absent.py")])
        with pytest.raises(pinned_source.SourcePathError, match=r"absent\.py"):
            pins.read("absent.py")

    def test_a_commit_outside_the_history_is_reported(
        self, tmp_path: Path, repo: tuple[Path, str]
    ) -> None:
        """An unknown commit raises an unavailable-commit error."""
        root, _commit = repo
        pins = sources(tmp_path, root, [entry(ABSENT_COMMIT)])
        with pytest.raises(pinned_source.CommitUnavailableError, match=ABSENT_COMMIT):
            pins.read("tool.py")

    def test_a_shallow_clone_names_its_cause(
        self, tmp_path: Path, repo: tuple[Path, str]
    ) -> None:
        """A clone that lacks the older commit says that it is shallow."""
        root, first = repo
        (root / "scripts/tool.py").write_bytes(BODY + b"# second\n")
        base = ("-C", str(root))
        git(*base, "add", "--all").run_sync()
        git(*base, *IDENTITY, "commit", "--quiet", "-m", "second").run_sync()
        clone = tmp_path / "clone"
        git("clone", "--quiet", "--depth", "1", f"file://{root}", str(clone)).run_sync()
        pins = sources(tmp_path, clone, [entry(first)])
        with pytest.raises(pinned_source.CommitUnavailableError, match="shallow"):
            pins.read("tool.py")

    def test_a_directory_that_is_not_a_repository_is_reported(
        self, tmp_path: Path
    ) -> None:
        """Without Git history the pin cannot be read, and the error says so."""
        empty = tmp_path / "empty"
        empty.mkdir()
        pins = sources(tmp_path, empty, [entry(ABSENT_COMMIT)])
        with pytest.raises(pinned_source.CommitUnavailableError):
            pins.read("tool.py")

    @pytest.mark.parametrize(
        ("field", "value"),
        [("commit", "abc123"), ("sha256", "XYZ"), ("path", "scripts/")],
    )
    def test_a_malformed_record_is_refused(
        self, tmp_path: Path, repo: tuple[Path, str], field: str, value: str
    ) -> None:
        """A short commit, a bad hash or a path with no file name is rejected."""
        root, commit = repo
        bad = {**entry(commit), field: value}
        with pytest.raises(pinned_source.RecordError, match=field):
            sources(tmp_path, root, [bad])

    def test_a_duplicate_name_is_refused(
        self, tmp_path: Path, repo: tuple[Path, str]
    ) -> None:
        """Two entries for one file name leave the pin ambiguous."""
        root, commit = repo
        with pytest.raises(pinned_source.RecordError, match=r"tool\.py"):
            sources(tmp_path, root, [entry(commit), entry(commit)])


class StageTests:
    """Write the pinned bytes into a scratch copy of ``scripts/``."""

    def test_staging_replaces_a_file_with_its_pinned_bytes(
        self, tmp_path: Path, repo: tuple[Path, str]
    ) -> None:
        """A changed copy is overwritten and an unrelated file is untouched."""
        root, commit = repo
        pins = sources(tmp_path, root, [entry(commit)])
        stage = tmp_path / "stage"
        stage.mkdir()
        (stage / "tool.py").write_bytes(b"changed\n")
        (stage / "other.py").write_bytes(b"keep\n")
        assert pins.stage(stage) == ["tool.py"], (
            "expected pins.stage(stage) == ['tool.py']"
        )
        assert (stage / "tool.py").read_bytes() == BODY, (
            "expected (stage / 'tool.py').read_bytes() == BODY"
        )
        assert (stage / "other.py").read_bytes() == b"keep\n", (
            "expected (stage / 'other.py').read_bytes() == b'keep\\n'"
        )

    def test_staging_stops_on_a_failing_pin(
        self, tmp_path: Path, repo: tuple[Path, str]
    ) -> None:
        """A pin that fails to verify aborts the staging with its error."""
        root, commit = repo
        pins = sources(tmp_path, root, [entry(commit, sha256="1" * 64)])
        stage = tmp_path / "stage"
        stage.mkdir()
        with pytest.raises(pinned_source.SourceMismatchError):
            pins.stage(stage)
        assert not (stage / "tool.py").exists(), (
            "expected not (stage / 'tool.py').exists()"
        )


class CommandLineTests:
    """Drive the helper as the Makefile does."""

    def test_check_exits_with_zero_for_a_sound_record(
        self, tmp_path: Path, repo: tuple[Path, str]
    ) -> None:
        """``check`` reports the verified names and returns 0."""
        root, commit = repo
        record = write_record(tmp_path / "r.json", [entry(commit)])
        code = pinned_source_cli.main([
            "check",
            "--record",
            str(record),
            "--repo",
            str(root),
        ])
        assert code == 0, "expected a sound record to exit with 0"

    def test_check_exits_with_one_for_a_failing_pin(
        self, tmp_path: Path, repo: tuple[Path, str], capsys: pytest.CaptureFixture[str]
    ) -> None:
        """``check`` prints the failure and returns 1."""
        root, commit = repo
        record = write_record(tmp_path / "r.json", [entry(commit, sha256="2" * 64)])
        code = pinned_source_cli.main([
            "check",
            "--record",
            str(record),
            "--repo",
            str(root),
        ])
        assert code == 1, "expected code == 1"
        assert "tool.py" in capsys.readouterr().err, (
            "expected 'tool.py' in capsys.readouterr().err"
        )


class RecordedPinsTests:
    """The committed record must hold in this repository's history."""

    def test_every_recorded_pin_verifies_here(self) -> None:
        """Each of the sixteen pins resolves and matches its recorded hash.

        A shallow clone lacks the commits, so this test fails there with a
        message that names the cause; fetch the full history to run it.
        """
        pins = pinned_source.Pins()
        assert len(pins.names()) == 16, (
            "expected len(pins.names()) == 16"
        )  # the sixteen scripts of D29
        assert pins.check() == pins.names(), "expected pins.check() == pins.names()"
