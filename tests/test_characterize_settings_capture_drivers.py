"""Characterize the two settings capture drivers, which stay at the old rules.

``verify_native_settings_transition`` and ``verify_native_121_default`` are capture
drivers despite their names, and each records the SHA-256 of its own file in the
report it writes (decision D31), so neither is refactored yet. These tests were
written on their current bytes. They run only the offline paths: the checks that
precede a capture, in the order in which they run, and the command lines, with
the recorder never created. No socket is opened and no capture is run.
"""

import copy
import json
import sys
import typing as typ
from pathlib import Path

import native_121_default_cases as default_cases
import native_settings_transition_cases as transition_cases
import pytest
import verify_native_121_default as default_driver
import verify_native_settings_transition as transition_driver

if typ.TYPE_CHECKING:
    import types

type Plan = dict[str, typ.Any]

ROOT = Path(__file__).resolve().parents[1]
BASELINE = (
    ROOT / "evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01"
    "/capture/plan.json"
)
USAGE_STATUS = 2


def prepared(module: types.ModuleType) -> Plan:
    """Prepare the observation plan of a planner.

    Returns
    -------
    dict[str, typing.Any]
        The plan.
    """
    raw = BASELINE.read_bytes()
    return module.plans(json.loads(raw)["environment"], raw)["observe"]


@pytest.fixture(scope="module")
def transition_plan() -> Plan:
    """Prepare the settings-transition plan.

    Returns
    -------
    dict[str, typing.Any]
        The plan.
    """
    return prepared(transition_cases)


@pytest.fixture(scope="module")
def default_plan() -> Plan:
    """Prepare the 121-default plan.

    Returns
    -------
    dict[str, typing.Any]
        The plan.
    """
    return prepared(default_cases)


def write_plan(path: Path, plan: Plan) -> Path:
    """Write a plan and return its path.

    Returns
    -------
    pathlib.Path
        The file.
    """
    path.write_text(json.dumps(plan))
    return path


class TransitionDriverTests:
    """The offline paths of the settings-transition driver."""

    def test_a_report_of_another_case_is_refused_first(
        self, transition_plan: Plan
    ) -> None:
        """The case is compared before the report's status is read."""
        plan = copy.deepcopy(transition_plan)
        plan["expectation"]["case"] = "other"
        with pytest.raises(ValueError, match=r"^Wrong settings case$"):
            transition_driver.semantic({}, plan)

    def test_an_unfinished_capture_is_refused_before_any_frame_is_read(
        self, transition_plan: Plan
    ) -> None:
        """A failed report ends with the completion message."""
        with pytest.raises(ValueError, match=r"^Transition capture did not complete$"):
            transition_driver.semantic({"status": "failed"}, transition_plan)

    def test_a_plan_of_another_case_is_refused_before_the_binary_is_read(
        self, tmp_path: Path, transition_plan: Plan
    ) -> None:
        """The plan is validated and its case compared before anything else."""
        plan = copy.deepcopy(transition_plan)
        plan["expectation"]["case"] = "other"
        path = write_plan(tmp_path / "plan.json", plan)
        with pytest.raises(ValueError, match=r"^Wrong run case$"):
            transition_driver.run_gated(path, tmp_path / "absent", tmp_path / "out")
        assert not (tmp_path / "out").exists(), "expected no output directory"

    def test_a_different_binary_is_refused_before_the_output_is_made(
        self, tmp_path: Path, transition_plan: Plan
    ) -> None:
        """The oracle binary's hash is compared before the directory is created."""
        path = write_plan(tmp_path / "plan.json", transition_plan)
        binary = tmp_path / "binary"
        binary.write_bytes(b"not the oracle")
        with pytest.raises(ValueError, match=r"^Oracle binary hash differs$"):
            transition_driver.run_gated(path, binary, tmp_path / "out")
        assert not (tmp_path / "out").exists(), "expected no output directory"

    def test_a_missing_binary_is_a_file_error(
        self, tmp_path: Path, transition_plan: Plan
    ) -> None:
        """The binary is read after the case is compared."""
        path = write_plan(tmp_path / "plan.json", transition_plan)
        with pytest.raises(FileNotFoundError):
            transition_driver.run_gated(path, tmp_path / "absent", tmp_path / "out")

    @pytest.mark.parametrize(
        "arguments",
        [
            [],
            ["--verify", "a", "--run", "b"],
            ["--run", "plan.json"],
            ["--run", "plan.json", "--binary", "b"],
        ],
    )
    def test_a_command_line_that_cannot_be_used_exits_with_status_two(
        self, monkeypatch: pytest.MonkeyPatch, arguments: list[str]
    ) -> None:
        """No mode, both modes, or a run without its binary and output."""
        monkeypatch.setattr(
            sys, "argv", ["verify_native_settings_transition.py", *arguments]
        )
        with pytest.raises(SystemExit) as caught:
            transition_driver.main()
        assert caught.value.code == USAGE_STATUS, "expected the usage status"


class DefaultDriverTests:
    """The offline paths of the 121-default driver."""

    def test_an_unfinished_capture_is_refused_before_the_plan_is_laid_out(
        self, default_plan: Plan
    ) -> None:
        """The status is compared before the layout."""
        with pytest.raises(ValueError, match=r"^121 capture did not complete$"):
            default_driver.semantic({"status": "failed"}, default_plan)

    def test_a_plan_of_another_case_is_refused_by_the_layout(
        self, default_plan: Plan
    ) -> None:
        """A completed report with a plan of another case."""
        plan = copy.deepcopy(default_plan)
        plan["expectation"]["case"] = "other"
        with pytest.raises(ValueError, match=r"^Wrong 121 case$"):
            default_driver.semantic({"status": "completed"}, plan)

    def test_the_baseline_pin_is_checked_after_the_steps(
        self, default_plan: Plan
    ) -> None:
        """A changed pin ends with the pin message; changed steps come first."""
        plan = copy.deepcopy(default_plan)
        plan["expectation"]["baseline_plan_sha256"] = "0" * 64
        with pytest.raises(ValueError, match=r"^A7 baseline pin differs$"):
            default_driver.layout(plan)
        plan["steps"] = plan["steps"][:-1]
        with pytest.raises(ValueError, match=r"^121 steps/cases differ$"):
            default_driver.layout(plan)

    def test_the_baseline_is_checked_before_the_binary(
        self, tmp_path: Path, default_plan: Plan
    ) -> None:
        """A baseline that is not the A7 plan is refused before the binary is read."""
        path = write_plan(tmp_path / "plan.json", default_plan)
        baseline = tmp_path / "baseline.json"
        baseline.write_bytes(BASELINE.read_bytes() + b" ")
        with pytest.raises(ValueError, match="SHA-256"):
            default_driver.run_gated(
                path, tmp_path / "absent", baseline, tmp_path / "out"
            )
        assert not (tmp_path / "out").exists(), "expected no output directory"

    def test_a_different_binary_is_refused_before_the_output_is_made(
        self, tmp_path: Path, default_plan: Plan
    ) -> None:
        """The oracle binary's hash is compared before the directory is created."""
        path = write_plan(tmp_path / "plan.json", default_plan)
        binary = tmp_path / "binary"
        binary.write_bytes(b"not the oracle")
        with pytest.raises(ValueError, match=r"^Oracle binary hash differs$"):
            default_driver.run_gated(path, binary, BASELINE, tmp_path / "out")
        assert not (tmp_path / "out").exists(), "expected no output directory"

    @pytest.mark.parametrize(
        "arguments",
        [
            [],
            ["--verify", "a", "--run", "b"],
            ["--run", "plan.json", "--binary", "b", "--output", "o"],
            ["--run", "plan.json", "--baseline-plan", "p", "--binary", "b"],
        ],
    )
    def test_a_command_line_that_cannot_be_used_exits_with_status_two(
        self, monkeypatch: pytest.MonkeyPatch, arguments: list[str]
    ) -> None:
        """No mode, both modes, or a run without its three paths."""
        monkeypatch.setattr(sys, "argv", ["verify_native_121_default.py", *arguments])
        with pytest.raises(SystemExit) as caught:
            default_driver.main()
        assert caught.value.code == USAGE_STATUS, "expected the usage status"
