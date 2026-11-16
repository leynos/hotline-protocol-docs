"""Test the two calls by which a verifier accepts a capture driver (decision D31).

``driver_in`` stands where a verifier wrote ``report["driver_sha256"] in known``
and ``driver_is`` where it wrote ``== expected``. Each keeps the earlier verdict
for a report of the earlier form and accepts a sound identity record for one
made after the decision. The reports here are synthetic; no capture is run.
"""

import typing as typ

import capture_acceptance as ca
import capture_identity as ci
import pytest
from git_helpers import commit_files

if typ.TYPE_CHECKING:
    from pathlib import Path

MODULES = ("driver.py", "driver_part.py")
BODIES = {"scripts/driver.py": "A = 1\n", "scripts/driver_part.py": "B = 2\n"}
OLD_HASH = "e" * 64


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """Commit two modules under ``scripts/``.

    Returns
    -------
    pathlib.Path
        The repository root.
    """
    root = tmp_path / "repo"
    root.mkdir()
    commit_files(root, BODIES)
    return root


def new_report(root: Path) -> dict[str, typ.Any]:
    """Build the report fields of a capture made after decision D31.

    Returns
    -------
    dict[str, typing.Any]
        ``driver_sha256`` and ``driver_identity``.
    """
    record = ci.identity(MODULES, directory=root / "scripts")
    return {"driver_sha256": record["digest"], "driver_identity": record}


class TestDriverIn:
    """A driver named in a corpus's list of source hashes."""

    def test_a_report_of_the_earlier_form_is_accepted_when_its_hash_is_listed(
        self,
    ) -> None:
        """The verdict is the verifier's earlier one."""
        assert ca.driver_in({"driver_sha256": OLD_HASH}, {OLD_HASH: "driver.py"}), (
            "expected a listed hash to be accepted"
        )

    def test_a_report_of_the_earlier_form_is_refused_when_its_hash_is_not_listed(
        self,
    ) -> None:
        """No record, no second chance."""
        assert not ca.driver_in({"driver_sha256": OLD_HASH}, {"0" * 64}), (
            "expected an unlisted hash to be refused"
        )

    def test_a_missing_hash_is_the_callers_key_error(self) -> None:
        """The lookup of the field is where it was."""
        with pytest.raises(KeyError, match="driver_sha256"):
            ca.driver_in({}, set())

    def test_a_sound_record_is_accepted_though_its_digest_is_not_listed(
        self, repo: Path
    ) -> None:
        """The set digest of a new capture is in no corpus list of files."""
        report = new_report(repo)
        assert ca.driver_in(report, {OLD_HASH}, root=repo), (
            "expected the sound record to be accepted"
        )

    def test_an_unsound_record_is_refused(self, repo: Path) -> None:
        """An edited file, uncommitted at capture, is refused."""
        (repo / "scripts/driver.py").write_text("A = 2\n")
        report = new_report(repo)
        assert not ca.driver_in(report, {OLD_HASH}, root=repo), (
            "expected the uncommitted record to be refused"
        )


class TestDriverIs:
    """A driver equal to a recorded hash."""

    def test_an_equal_hash_is_accepted_and_another_is_refused(self) -> None:
        """The verdict is the verifier's earlier one."""
        report = {"driver_sha256": OLD_HASH}
        assert ca.driver_is(report, OLD_HASH), "expected an equal hash"
        assert not ca.driver_is(report, "0" * 64), "expected another hash refused"

    def test_a_sound_record_is_accepted(self, repo: Path) -> None:
        """The digest need not equal the verifier's expected hash."""
        report = new_report(repo)
        assert ca.driver_is(report, OLD_HASH, root=repo), "expected the record"

    def test_a_digest_that_is_not_the_records_is_refused(self, repo: Path) -> None:
        """A report cannot name one set and carry another."""
        report = new_report(repo) | {"driver_sha256": "0" * 64}
        assert not ca.driver_is(report, OLD_HASH, root=repo), "expected a refusal"


class TestRoleIn:
    """A role other than the driver, as a manifest names its runner and fixture."""

    def manifest_of(self, repo: Path) -> dict[str, typ.Any]:
        """Build the manifest fields of a run made after decision D31.

        Returns
        -------
        dict[str, typing.Any]
            ``source_runner_sha256`` and ``source_runner_identity``.
        """
        record = ci.identity(MODULES, directory=repo / "scripts")
        return {
            "source_runner_sha256": record["digest"],
            "source_runner_identity": record,
        }

    def test_the_earlier_form_is_decided_by_the_listed_hashes(self) -> None:
        """A listed single-file hash is accepted, another is not."""
        manifest = {"source_runner_sha256": OLD_HASH}
        assert ca.role_in(manifest, "source_runner", {OLD_HASH}), "expected listed"
        assert not ca.role_in(manifest, "source_runner", set()), "expected unlisted"

    def test_a_sound_record_is_accepted_for_its_role_only(self, repo: Path) -> None:
        """The record under one role does not vouch for another."""
        manifest = self.manifest_of(repo)
        assert ca.role_in(manifest, "source_runner", set(), root=repo), "expected role"
        manifest["source_fixture_sha256"] = OLD_HASH
        assert not ca.role_in(manifest, "source_fixture", set(), root=repo), (
            "expected the other role to need its own record"
        )


class TestDriverAccepted:
    """The one call by which a verifier accepts either form."""

    def report_of(self, root: Path) -> dict[str, object]:
        """Build the report fields of a new-form capture.

        Returns
        -------
        dict[str, object]
            ``driver_sha256`` and ``driver_identity``.
        """
        record = ci.identity(MODULES, directory=root / "scripts")
        return {"driver_sha256": record["digest"], "driver_identity": record}

    def test_the_legacy_verdict_is_kept_when_it_is_true(self) -> None:
        """A report of the earlier form needs no record."""
        assert ca.driver_accepted({"driver_sha256": "x"}, legacy_ok=True), "kept"

    def test_a_report_of_the_earlier_form_that_failed_stays_failed(self) -> None:
        """Without a record there is nothing else to accept."""
        assert not ca.driver_accepted({"driver_sha256": "x"}, legacy_ok=False), (
            "no record"
        )
        assert not ca.driver_accepted({}, legacy_ok=False), "no fields"

    def test_a_sound_new_form_is_accepted_when_the_legacy_comparison_fails(
        self, repo: Path
    ) -> None:
        """The set digest is not in any corpus source list, the record is."""
        root = repo
        assert ca.driver_accepted(self.report_of(root), legacy_ok=False, root=root), (
            "sound"
        )

    def test_the_digest_field_must_equal_the_records_digest(self, repo: Path) -> None:
        """A report cannot name one set and carry another."""
        root = repo
        report = self.report_of(root) | {"driver_sha256": "0" * 64}
        assert not ca.driver_accepted(report, legacy_ok=False, root=root), report

    def test_an_unsound_record_is_not_accepted(self, repo: Path) -> None:
        """The record is checked against the commit."""
        root = repo
        (root / "scripts/driver.py").write_text("A = 9\n")
        report = self.report_of(root)
        assert not ca.driver_accepted(report, legacy_ok=False, root=root), report

    def test_a_report_without_the_digest_field_is_not_accepted(
        self, repo: Path
    ) -> None:
        """The digest field must be present as well as the record."""
        root = repo
        report = {"driver_identity": ci.identity(MODULES, directory=root / "scripts")}
        assert not ca.driver_accepted(report, legacy_ok=False, root=root), report
