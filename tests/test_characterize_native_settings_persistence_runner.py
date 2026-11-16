"""Characterize the persistence runner.

``native_settings_persistence`` hashed its own file and three siblings at capture
and recorded the hash of its own file in the report it wrote. These tests were
written on those bytes, and they hold for the runner after decision D31, which
checks the module set that the planner recorded and records the digest of the set
and the record of its files; the tests that read the records write both forms, and
a refusal is matched by what both messages begin with. They run only the offline
checks that precede a capture, in the order in which they run, and the command
line, with the recorder never created. No socket is opened and no capture is run.
"""

import copy
import json
import sys
import typing as typ
from pathlib import Path

import capture_identity
import native_settings_persistence as runner
import native_settings_persistence_cases as cases
import pytest

type Plan = dict[str, typ.Any]

RUNTIME = {"emulator_pid": 123, "source_a7_sha256": cases.A7_SHA}
# The set that the runner records for itself after decision D31; before it, none.
MODULES = getattr(
    runner,
    "CAPTURE_MODULES",
    ("native_settings_persistence.py", "native_settings_persistence_cases.py"),
)
REFUSED = r"^Source code differs"  # the earlier message names a file, the later a fault
USAGE_STATUS = 2
PLAN_NAMES = ["phase1", "phase2"]


def prepared(phase: str) -> Plan:
    """Prepare one phase's plan.

    Returns
    -------
    dict[str, typing.Any]
        The plan.
    """
    return cases.plans(RUNTIME, 15760)[phase]


@pytest.fixture
def as_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the runner believe it runs as root, as its first check requires."""
    monkeypatch.setattr(runner.os, "geteuid", lambda: 0)


class VerifyPlanTests:
    """``verify_plan`` accepts only the plan that the planner prepares."""

    @pytest.mark.parametrize("phase", PLAN_NAMES)
    def test_a_prepared_plan_gives_its_phase_number(self, phase: str) -> None:
        """The case name ends with the phase number."""
        assert runner.verify_plan(prepared(phase)) == int(phase[-1]), "phase"

    def test_another_case_is_refused_after_the_plan_is_validated(self) -> None:
        """A readiness plan is a valid plan of the wrong case."""
        with pytest.raises(ValueError, match=r"^Wrong case$"):
            runner.verify_plan(prepared("readiness"))

    def test_a_changed_step_is_refused_as_a_changed_plan(self) -> None:
        """The plan must equal the one the planner prepares for its environment."""
        plan = copy.deepcopy(prepared("phase1"))
        plan["steps"] = plan["steps"][:-1]
        with pytest.raises(ValueError, match=r"^Prepared plan changed$"):
            runner.verify_plan(plan)

    def test_a_malformed_plan_is_refused_by_the_generic_validation_first(self) -> None:
        """The generic plan validation runs before the case is read."""
        plan = copy.deepcopy(prepared("phase1"))
        plan["schema_version"] = 2
        with pytest.raises(ValueError, match="schema"):
            runner.verify_plan(plan)


class RunGatedTests:
    """The order of the checks before ``run_gated`` creates a recorder."""

    def paths(self, tmp_path: Path, plan: Plan) -> tuple[Path, Path, Path, Path, Path]:
        """Write a plan and name the other four paths.

        Returns
        -------
        tuple[pathlib.Path, ...]
            The plan, the readiness directory, the receipt, the binary and the
            output directory.
        """
        path = tmp_path / "plan.json"
        path.write_text(json.dumps(plan))
        return (
            path,
            tmp_path / "readiness",
            tmp_path / "receipt.json",
            tmp_path / "binary",
            tmp_path / "out",
        )

    def test_a_user_who_is_not_root_is_refused_before_anything_is_read(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The first check is the effective user."""
        monkeypatch.setattr(runner.os, "geteuid", lambda: 1000)
        with pytest.raises(PermissionError, match="root /proc identity checks"):
            runner.run_gated(*self.paths(tmp_path, {}))

    @pytest.mark.usefixtures("as_root")
    def test_a_missing_plan_is_a_file_error(self, tmp_path: Path) -> None:
        """The plan is read after the effective user is checked."""
        paths = self.paths(tmp_path, {})
        paths[0].unlink()
        with pytest.raises(FileNotFoundError):
            runner.run_gated(*paths)

    @pytest.mark.usefixtures("as_root")
    def test_a_plan_of_another_case_is_refused_before_the_hashes_are_read(
        self, tmp_path: Path
    ) -> None:
        """The plan is verified before ``source-hashes.json`` is opened."""
        paths = self.paths(tmp_path, prepared("readiness"))
        with pytest.raises(ValueError, match=r"^Wrong case$"):
            runner.run_gated(*paths)

    @pytest.mark.usefixtures("as_root")
    def test_missing_plan_hashes_are_a_file_error(self, tmp_path: Path) -> None:
        """A verified plan without its hash list."""
        paths = self.paths(tmp_path, prepared("phase1"))
        with pytest.raises(FileNotFoundError):
            runner.run_gated(*paths)

    @pytest.mark.usefixtures("as_root")
    def test_a_different_plan_hash_is_refused_before_the_sources_are_hashed(
        self, tmp_path: Path
    ) -> None:
        """The plan's hash is compared first; the source list is not yet read."""
        paths = self.paths(tmp_path, prepared("phase1"))
        (tmp_path / "source-hashes.json").write_text(json.dumps({"phase1": "0" * 64}))
        with pytest.raises(ValueError, match=r"^Plan source hash differs$"):
            runner.run_gated(*paths)

    @pytest.mark.usefixtures("as_root")
    def test_a_source_that_is_not_one_of_the_four_is_refused(
        self, tmp_path: Path
    ) -> None:
        """Only the planner, the runner and two siblings may be named."""
        paths = self.paths(tmp_path, prepared("phase1"))
        digest = runner.digest(paths[0].read_bytes())
        (tmp_path / "source-hashes.json").write_text(json.dumps({"phase1": digest}))
        (tmp_path / "source-code-sha256.json").write_text(json.dumps({"other.py": "x"}))
        other = {"files": [{"path": "scripts/other.py", "sha256": "0" * 64}]}
        (tmp_path / "source-code-identity.json").write_text(json.dumps(other))
        with pytest.raises(ValueError, match=REFUSED):
            runner.run_gated(*paths)

    @pytest.mark.usefixtures("as_root")
    def test_a_changed_sibling_source_digest_is_refused(self, tmp_path: Path) -> None:
        """A recorded digest that is not the live file's."""
        paths = self.paths(tmp_path, prepared("phase1"))
        digest = runner.digest(paths[0].read_bytes())
        (tmp_path / "source-hashes.json").write_text(json.dumps({"phase1": digest}))
        sources = {"native_ban_control_cases.py": "0" * 64}
        (tmp_path / "source-code-sha256.json").write_text(json.dumps(sources))
        files = capture_identity.identity(MODULES)["files"]
        files[0]["sha256"] = "0" * 64
        (tmp_path / "source-code-identity.json").write_text(
            json.dumps({"files": files})
        )
        with pytest.raises(ValueError, match=REFUSED):
            runner.run_gated(*paths)

    @pytest.mark.usefixtures("as_root")
    def test_the_live_digests_of_the_four_siblings_are_accepted_then_readiness_is_read(
        self, tmp_path: Path
    ) -> None:
        """With the live digests recorded, the next check is the readiness capture."""
        paths = self.paths(tmp_path, prepared("phase1"))
        digest = runner.digest(paths[0].read_bytes())
        (tmp_path / "source-hashes.json").write_text(json.dumps({"phase1": digest}))
        names = [
            "native_settings_persistence_cases.py",
            "native_settings_persistence.py",
            "native_control_readiness.py",
            "native_ban_control_cases.py",
        ]
        here = Path(runner.__file__).parent
        sources = {n: runner.digest((here / n).read_bytes()) for n in names}
        (tmp_path / "source-code-sha256.json").write_text(json.dumps(sources))
        files = capture_identity.identity(MODULES)["files"]
        (tmp_path / "source-code-identity.json").write_text(
            json.dumps({"files": files})
        )
        with pytest.raises(FileNotFoundError):
            runner.run_gated(*paths)
        assert not paths[4].exists(), "expected no output directory"


class CommandLineTests:
    """``main`` takes six required options and exits 1 for a failed run."""

    @pytest.mark.parametrize(
        "arguments",
        [
            [],
            ["--run"],
            ["--run", "--plan", "p"],
            ["stray"],
        ],
    )
    def test_a_command_line_that_cannot_be_used_exits_with_status_two(
        self, monkeypatch: pytest.MonkeyPatch, arguments: list[str]
    ) -> None:
        """A missing option, or a stray argument."""
        monkeypatch.setattr(sys, "argv", ["native_settings_persistence.py", *arguments])
        with pytest.raises(SystemExit) as caught:
            runner.main()
        assert caught.value.code == USAGE_STATUS, "expected the usage status"

    def test_a_failed_run_prints_its_status_and_exits_with_one(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
    ) -> None:
        """The report's status, gates and error are printed as one JSON line."""
        report = {"status": "failed", "gates": ["identity"], "error": "boom"}
        monkeypatch.setattr(runner, "run_gated", lambda *_args: report)
        options = ["--plan", "--readiness-dir", "--capture-receipt", "--binary"]
        arguments = ["--run", "--output", str(tmp_path / "out")]
        for name in options:
            arguments += [name, str(tmp_path / name.lstrip("-"))]
        monkeypatch.setattr(sys, "argv", ["native_settings_persistence.py", *arguments])
        with pytest.raises(SystemExit) as caught:
            runner.main()
        assert caught.value.code == 1, "expected the failure status"
        assert json.loads(capsys.readouterr().out) == report, "expected the summary"
