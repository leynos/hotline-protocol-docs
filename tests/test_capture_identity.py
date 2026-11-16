"""Test the record that names the scripts that made a capture (decision D31).

The records are built in throw-away Git repositories, so no capture is run.
"""

import hashlib
import typing as typ

import capture_identity as ci
import pytest
from git_helpers import IDENTITY, commit_files
from repo_files import git

if typ.TYPE_CHECKING:
    from pathlib import Path

MODULES = ("driver.py", "driver_part.py")
BODIES = {"scripts/driver.py": "A = 1\n", "scripts/driver_part.py": "B = 2\n"}


def sha(text: str) -> str:
    """Hash text as UTF-8.

    Returns
    -------
    str
        The SHA-256 in lower-case hexadecimal.
    """
    return hashlib.sha256(text.encode()).hexdigest()


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, str]:
    """Commit two modules under ``scripts/``.

    Returns
    -------
    tuple[pathlib.Path, str]
        The repository root and the commit.
    """
    root = tmp_path / "repo"
    root.mkdir()
    return root, commit_files(root, BODIES)


def record_of(root: Path) -> ci.Record:
    """Describe the two modules of the repository.

    Returns
    -------
    dict
        The identity record.
    """
    return ci.identity(MODULES, directory=root / "scripts")


class TestIdentity:
    """The record that a capture stores."""

    def test_a_committed_tree_is_clean_and_names_its_commit(
        self, repo: tuple[Path, str]
    ) -> None:
        """The commit is the head, nothing differs, and the schema is stated."""
        root, commit = repo
        record = record_of(root)
        assert record["schema_version"] == ci.SCHEMA_VERSION, record
        assert record["commit"] == commit, record
        assert record["dirty"] == [], record

    def test_each_file_is_listed_in_the_given_order_with_its_hash(
        self, repo: tuple[Path, str]
    ) -> None:
        """Paths run from the repository root, in the order of ``modules``."""
        root, _ = repo
        files = record_of(root)["files"]
        paths = [item["path"] for item in files]
        hashes = [item["sha256"] for item in files]
        assert paths == ["scripts/driver.py", "scripts/driver_part.py"], files
        assert hashes == [sha("A = 1\n"), sha("B = 2\n")], files

    def test_the_digest_is_what_sha256sum_of_the_files_gives(
        self, repo: tuple[Path, str]
    ) -> None:
        """The digest hashes the lines a ``sha256sum`` listing would print."""
        root, _ = repo
        listing = (
            f"{sha('A = 1\n')}  scripts/driver.py\n"
            f"{sha('B = 2\n')}  scripts/driver_part.py\n"
        )
        assert record_of(root)["digest"] == sha(listing), (
            "expected record_of(root)[digest] == sha(listing)"
        )

    def test_the_order_changes_the_digest(self, repo: tuple[Path, str]) -> None:
        """A different order is a different set identity."""
        root, _ = repo
        reverse = ci.identity(MODULES[::-1], directory=root / "scripts")
        assert reverse["digest"] != record_of(root)["digest"], reverse

    def test_a_changed_file_is_listed_as_dirty(self, repo: tuple[Path, str]) -> None:
        """A capture from edited scripts shows which file was edited."""
        root, commit = repo
        (root / "scripts/driver_part.py").write_text("B = 3\n")
        record = record_of(root)
        assert record["dirty"] == ["scripts/driver_part.py"], record
        assert record["commit"] == commit, record
        assert record["files"][1]["sha256"] == sha("B = 3\n"), record

    def test_an_untracked_file_is_listed_as_dirty(self, repo: tuple[Path, str]) -> None:
        """A module that no commit holds cannot be recovered, so it is dirty."""
        root, _ = repo
        (root / "scripts/new_part.py").write_text("C = 3\n")
        record = ci.identity(("driver.py", "new_part.py"), directory=root / "scripts")
        assert record["dirty"] == ["scripts/new_part.py"], record

    def test_a_file_that_differs_only_in_the_index_is_clean(
        self, repo: tuple[Path, str]
    ) -> None:
        """Dirty means the bytes differ from the commit, not that Git says so."""
        root, _ = repo
        git("-C", str(root), "add", "--all").run_sync()
        assert record_of(root)["dirty"] == [], "expected record_of(root)[dirty] == []"

    def test_without_a_repository_the_commit_is_absent_and_all_are_dirty(
        self, tmp_path: Path
    ) -> None:
        """A capture is never refused for want of Git, but it says so."""
        scripts = tmp_path / "plain" / "scripts"
        scripts.mkdir(parents=True)
        for name, body in BODIES.items():
            (scripts.parent / name).write_text(body)
        record = ci.identity(MODULES, directory=scripts)
        assert record["commit"] is None, record
        assert record["dirty"] == ["scripts/driver.py", "scripts/driver_part.py"], (
            "expected record[dirty] == [scripts/driver.py, scripts/driver_part.py]"
        )

    def test_no_modules_and_repeated_modules_are_refused(
        self, repo: tuple[Path, str]
    ) -> None:
        """An empty or repeating declaration is a programming error."""
        root, _ = repo
        with pytest.raises(ValueError, match="at least one"):
            ci.identity((), directory=root / "scripts")
        with pytest.raises(ValueError, match="more than once"):
            ci.identity(("driver.py", "driver.py"), directory=root / "scripts")

    def test_a_missing_module_is_a_file_not_found_error(
        self, repo: tuple[Path, str]
    ) -> None:
        """An undeclared file is not hidden by the record."""
        root, _ = repo
        with pytest.raises(FileNotFoundError):
            ci.identity(("absent.py",), directory=root / "scripts")


class TestCheck:
    """The comparison of a record with the live modules."""

    def test_the_same_files_match(self, repo: tuple[Path, str]) -> None:
        """A record matches the files it was made from."""
        root, _ = repo
        record = record_of(root)
        assert ci.check(record, MODULES, directory=root / "scripts"), (
            "expected ci.check(record, MODULES, directory=root / scripts)"
        )

    def test_a_changed_file_is_named(self, repo: tuple[Path, str]) -> None:
        """The difference names the file and both hashes."""
        root, _ = repo
        record = record_of(root)
        (root / "scripts/driver.py").write_text("A = 9\n")
        found = ci.differences(record, MODULES, directory=root / "scripts")
        assert "scripts/driver.py" in found[0], found
        assert "digest" in found[-1], found
        assert not ci.check(record, MODULES, directory=root / "scripts"), (
            "expected not ci.check(record, MODULES, directory=root / scripts)"
        )

    def test_another_order_or_set_is_a_difference(self, repo: tuple[Path, str]) -> None:
        """The list of files must be the recorded one."""
        root, _ = repo
        record = record_of(root)
        reverse = ci.differences(record, MODULES[::-1], directory=root / "scripts")
        fewer = ci.differences(record, MODULES[:1], directory=root / "scripts")
        assert reverse, reverse
        assert fewer, fewer

    def test_a_record_with_a_wrong_digest_does_not_match(
        self, repo: tuple[Path, str]
    ) -> None:
        """The recorded digest is compared too."""
        root, _ = repo
        record = record_of(root) | {"digest": "0" * 64}
        found = ci.differences(record, MODULES, directory=root / "scripts")
        assert any("digest" in line for line in found), found

    def test_the_commit_is_not_compared(self, repo: tuple[Path, str]) -> None:
        """A later commit of the same bytes still matches."""
        root, _ = repo
        record = record_of(root)
        (root / "unrelated.txt").write_text("x\n")
        git("-C", str(root), "add", "--all").run_sync()
        git("-C", str(root), *IDENTITY, "commit", "-m", "next").run_sync()
        assert ci.check(record, MODULES, directory=root / "scripts"), (
            "expected ci.check(record, MODULES, directory=root / scripts)"
        )


class TestProblems:
    """The soundness check that a verifier makes of a stored record."""

    def test_a_clean_record_of_a_known_commit_is_sound(
        self, repo: tuple[Path, str]
    ) -> None:
        """Nothing is reported for a faithful record."""
        root, _ = repo
        assert not ci.problems(record_of(root), root=root), "expected a sound record"

    @pytest.mark.parametrize(
        ("change", "word"),
        [
            ({"schema_version": 2}, "schema"),
            ({"commit": "abc"}, "commit"),
            ({"files": []}, "files"),
            ({"files": [{"path": "x", "sha256": "no"}]}, "sha256"),
            ({"dirty": "scripts/driver.py"}, "dirty"),
            ({"digest": "1" * 64}, "digest"),
        ],
    )
    def test_a_malformed_or_inconsistent_record_is_reported(
        self, repo: tuple[Path, str], change: dict[str, object], word: str
    ) -> None:
        """Each fault is named."""
        root, _ = repo
        found = ci.problems(record_of(root) | change, root=root)
        assert found, found
        assert word in found[0], found

    def test_a_record_that_is_not_a_mapping_is_reported(self) -> None:
        """Anything else in the field is one problem, not an exception."""
        assert ci.problems(["x"]) == ["the identity record is not a mapping"], (
            "expected ci.problems([x]) == [the identity record is not a mapping]"
        )

    def test_a_dirty_record_is_not_sound(self, repo: tuple[Path, str]) -> None:
        """Bytes that no commit holds cannot be recovered."""
        root, _ = repo
        (root / "scripts/driver.py").write_text("A = 9\n")
        found = ci.problems(record_of(root), root=root)
        assert any("uncommitted" in line for line in found), found

    def test_a_record_without_a_commit_is_not_sound(
        self, repo: tuple[Path, str]
    ) -> None:
        """No commit, nothing to compare with."""
        root, _ = repo
        record = record_of(root) | {"commit": None, "dirty": []}
        found = ci.problems(record, root=root)
        assert any("no commit" in line for line in found), found

    def test_a_commit_that_is_not_in_the_history_is_reported(
        self, repo: tuple[Path, str]
    ) -> None:
        """The record names a commit this clone lacks."""
        root, _ = repo
        record = record_of(root) | {"commit": "ab" * 20}
        found = ci.problems(record, root=root)
        assert any("not in the history" in line for line in found), found

    def test_a_file_that_differs_at_the_commit_is_reported(
        self, repo: tuple[Path, str]
    ) -> None:
        """The recorded hash must be the hash of the blob at the commit."""
        root, _ = repo
        record = record_of(root)
        record["files"][0] = {"path": "scripts/driver.py", "sha256": sha("other\n")}
        record["digest"] = ci.set_digest(record["files"])
        found = ci.problems(record, root=root)
        assert any("scripts/driver.py" in line for line in found), found

    def test_a_path_that_the_commit_lacks_is_reported(
        self, repo: tuple[Path, str]
    ) -> None:
        """The commit must hold every listed path."""
        root, _ = repo
        record = record_of(root)
        record["files"][0] = {"path": "scripts/gone.py", "sha256": sha("A = 1\n")}
        record["digest"] = ci.set_digest(record["files"])
        found = ci.problems(record, root=root)
        assert any("scripts/gone.py" in line for line in found), found
