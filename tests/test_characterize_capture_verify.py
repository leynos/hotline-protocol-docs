"""Characterize the saved-capture checks and command line of ``protocol_capture``.

``protocol_capture`` is not refactored in this pass (its self-hash needs a
decision), so these tests are the continuity for a later refactor: every
expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``). ``verify_capture`` is run on small synthetic
captures that break one rule at a time, with pairs of faults that pin which
error is raised first. The exit status of the command line is pinned, its usage
text is not. The plan validation and frame decoding are in
``test_characterize_capture_plans.py``.
"""

import json
import re
import runpy
import sys
import typing as typ
from pathlib import Path

import protocol_capture as pc
import pytest

CHARACTERIZES = "protocol_capture.py"
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / CHARACTERIZES
ORACLE = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
ZEROS = "0" * 64

type Json = dict[str, typ.Any]


def synthetic_plan() -> Json:
    """Build a plan that connects and reads two bytes.

    Returns
    -------
    dict[str, typing.Any]
        The plan.
    """
    return {
        "schema_version": 1,
        "profile": "synthetic-tool-test",
        "operator": "operator",
        "oracle_sha256": ORACLE,
        "gap_ids": ["GAP-001"],
        "endpoints": {"control": {"host": "127.0.0.1", "port": 15500}},
        "steps": [
            {"op": "connect", "connection": "main", "endpoint": "control"},
            {"op": "read", "connection": "main", "size": 2},
        ],
    }


def synthetic_report(plan_bytes: bytes) -> Json:
    """Build the report that a completed run of the synthetic plan would leave.

    Returns
    -------
    dict[str, typing.Any]
        The report.
    """
    connect = {"connection": "main", "event": "connect", "elapsed_ns": 1, "hex": ""}
    receive = {"connection": "main", "event": "receive", "elapsed_ns": 2, "hex": "4142"}
    return {
        "profile": "synthetic-tool-test",
        "native_conformance": False,
        "status": "completed",
        "oracle_sha256": ORACLE,
        "plan_sha256": pc.digest(plan_bytes),
        "completed_actions": 2,
        "error": "",
        "events": [{"action": 0, **connect}, {"action": 1, **receive}],
        "frames": [],
        "streams": {"main": {"sent_hex": "", "received_hex": "4142"}},
    }


class Capture:
    """A synthetic capture directory whose plan and report a test may alter."""

    def __init__(self, directory: Path) -> None:
        """Hold the directory and a consistent plan and report.

        Parameters
        ----------
        directory : pathlib.Path
            An empty directory.
        """
        self.directory = directory
        self.plan = synthetic_plan()
        self.report = synthetic_report(self.plan_bytes())
        self.checksum_edits: list[tuple[str, str]] = []

    def plan_bytes(self) -> bytes:
        """Serialise the plan.

        Returns
        -------
        bytes
            The plan's JSON bytes.
        """
        return json.dumps(self.plan).encode()

    def write(self, *, keep_plan_hash: bool = False) -> Path:
        """Write the plan, the report and the checksum list.

        Parameters
        ----------
        keep_plan_hash : bool
            Leave ``plan_sha256`` as it is instead of recomputing it.

        Returns
        -------
        pathlib.Path
            The directory.
        """
        data = self.plan_bytes()
        if not keep_plan_hash:
            self.report["plan_sha256"] = pc.digest(data)
        (self.directory / "plan.json").write_bytes(data)
        text = (json.dumps(self.report, indent=2) + "\n").encode()
        (self.directory / "report.json").write_bytes(text)
        lines = f"{pc.digest(data)}  plan.json\n{pc.digest(text)}  report.json\n"
        (self.directory / "checksums.sha256").write_text(lines)
        return self.directory


@pytest.fixture
def capture(tmp_path: Path) -> Capture:
    """Create a synthetic capture directory.

    Returns
    -------
    Capture
        The capture, not yet written.
    """
    return Capture(tmp_path)


def refused(capture: Capture, message: str, **options: bool) -> None:
    """Write the capture and require that its verification raises this message."""
    directory = capture.write(**options)
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        pc.verify_capture(directory)


class ChecksumTests:
    """The checksum list is checked before the plan or report is read."""

    def test_a_sound_capture_returns_its_report(self, capture: Capture) -> None:
        """The parsed report is returned unchanged."""
        directory = capture.write()
        assert pc.verify_capture(directory) == capture.report, "expected the report"

    def test_a_line_for_another_file_is_an_invalid_inventory(
        self, capture: Capture
    ) -> None:
        """Only the plan and the report may be listed."""
        directory = capture.write()
        listing = directory / "checksums.sha256"
        listing.write_text(listing.read_text() + f"{ZEROS}  other.json\n")
        with pytest.raises(ValueError, match=r"^Invalid checksum inventory$"):
            pc.verify_capture(directory)

    def test_a_repeated_line_is_an_invalid_inventory(self, capture: Capture) -> None:
        """A file may be listed once."""
        directory = capture.write()
        listing = directory / "checksums.sha256"
        first = listing.read_text().splitlines()[0]
        listing.write_text(listing.read_text() + first + "\n")
        with pytest.raises(ValueError, match=r"^Invalid checksum inventory$"):
            pc.verify_capture(directory)

    def test_a_changed_file_is_a_checksum_mismatch(self, capture: Capture) -> None:
        """The bytes must hash to the listed value."""
        directory = capture.write()
        (directory / "report.json").write_text("{}")
        with pytest.raises(ValueError, match=r"^Checksum mismatch: report.json$"):
            pc.verify_capture(directory)

    def test_a_short_list_is_an_incomplete_inventory(self, capture: Capture) -> None:
        """Both files must be listed."""
        directory = capture.write()
        listing = directory / "checksums.sha256"
        listing.write_text(listing.read_text().splitlines()[0] + "\n")
        with pytest.raises(ValueError, match=r"^Incomplete checksum inventory$"):
            pc.verify_capture(directory)

    def test_the_name_check_comes_before_the_hash_check_in_each_line(
        self, capture: Capture
    ) -> None:
        """A wrong name with a wrong hash is an inventory error."""
        directory = capture.write()
        (directory / "checksums.sha256").write_text(f"{ZEROS}  other.json\n")
        with pytest.raises(ValueError, match=r"^Invalid checksum inventory$"):
            pc.verify_capture(directory)

    def test_a_mismatch_comes_before_an_incomplete_list(self, capture: Capture) -> None:
        """Lines are checked as they are read; completeness is checked last."""
        directory = capture.write()
        (directory / "checksums.sha256").write_text(f"{ZEROS}  plan.json\n")
        with pytest.raises(ValueError, match=r"^Checksum mismatch: plan.json$"):
            pc.verify_capture(directory)

    def test_a_missing_list_is_a_file_not_found_error(self, tmp_path: Path) -> None:
        """An empty directory has no checksum list."""
        with pytest.raises(FileNotFoundError):
            pc.verify_capture(tmp_path)


class ReportTests:
    """The report is checked against the plan, in a fixed order."""

    def test_an_invalid_plan_is_refused_by_the_validator(
        self, capture: Capture
    ) -> None:
        """Checksums pass, then the plan is validated."""
        capture.plan["schema_version"] = 2
        refused(capture, "Unsupported capture schema")

    def test_another_profile_is_a_profile_mismatch(self, capture: Capture) -> None:
        """The report's profile must be the plan's."""
        capture.report["profile"] = "native-mac-oracle"
        refused(capture, "Evidence profile mismatch")

    def test_a_native_conformance_claim_is_a_profile_mismatch(
        self, capture: Capture
    ) -> None:
        """A capture never claims conformance."""
        capture.report["native_conformance"] = True
        refused(capture, "Evidence profile mismatch")

    def test_another_plan_hash_is_a_source_identity_mismatch(
        self, capture: Capture
    ) -> None:
        """The report must record the plan's hash."""
        capture.report["plan_sha256"] = ZEROS
        refused(capture, "Source identity mismatch", keep_plan_hash=True)

    def test_another_oracle_hash_is_a_source_identity_mismatch(
        self, capture: Capture
    ) -> None:
        """The report must record the plan's oracle hash."""
        capture.report["oracle_sha256"] = ZEROS
        refused(capture, "Source identity mismatch")

    def test_the_profile_check_comes_before_the_identity_check(
        self, capture: Capture
    ) -> None:
        """A report wrong in both is a profile error."""
        capture.report["profile"] = "native-mac-oracle"
        capture.report["oracle_sha256"] = ZEROS
        refused(capture, "Evidence profile mismatch")

    def test_an_unknown_status_is_refused(self, capture: Capture) -> None:
        """Completed or failed only."""
        capture.report["status"] = "running"
        refused(capture, "Unknown capture status")

    @pytest.mark.parametrize("change", [{"error": "boom"}, {"completed_actions": 1}])
    def test_a_completed_report_with_an_error_or_missing_actions_is_refused(
        self, capture: Capture, change: dict[str, object]
    ) -> None:
        """Completed means no error and every step."""
        capture.report.update(change)
        refused(capture, "Incomplete plan reported as completed")

    def test_a_failed_report_may_have_an_error_and_fewer_actions(
        self, capture: Capture
    ) -> None:
        """Failure is allowed to be partial."""
        capture.report.update(status="failed", error="boom", completed_actions=1)
        assert pc.verify_capture(capture.write())["status"] == "failed", (
            "expected: failure is allowed to be partial"
        )

    def test_streams_that_the_events_do_not_rebuild_are_refused(
        self, capture: Capture
    ) -> None:
        """The saved streams must equal the ones rebuilt from the events."""
        capture.report["streams"]["main"]["received_hex"] = "4143"
        refused(capture, "Stream reconstruction mismatch")

    def test_frames_that_the_events_do_not_rebuild_are_refused(
        self, capture: Capture
    ) -> None:
        """Frames are rebuilt from ``read_frame`` actions; others give none."""
        capture.report["frames"] = [{"action": 1}]
        refused(capture, "Decoded frame mismatch")

    def test_the_status_check_comes_before_the_completion_check(
        self, capture: Capture
    ) -> None:
        """An unknown status with an error is a status error."""
        capture.report.update(status="running", error="boom")
        refused(capture, "Unknown capture status")

    def test_the_completion_check_comes_before_the_stream_check(
        self, capture: Capture
    ) -> None:
        """A completed report with an error and wrong streams is a completion error."""
        capture.report["error"] = "boom"
        capture.report["streams"] = {}
        refused(capture, "Incomplete plan reported as completed")

    def test_the_stream_check_comes_before_the_frame_check(
        self, capture: Capture
    ) -> None:
        """Wrong streams and wrong frames are a stream error."""
        capture.report["streams"] = {}
        capture.report["frames"] = [{"action": 1}]
        refused(capture, "Stream reconstruction mismatch")


class CommandLineTests:
    """``main`` runs a subcommand chosen from ``sys.argv``."""

    @staticmethod
    def argv(monkeypatch: pytest.MonkeyPatch, *arguments: object) -> None:
        """Set the command line of a run."""
        arguments_text = [str(argument) for argument in arguments]
        monkeypatch.setattr(sys, "argv", [CHARACTERIZES, *arguments_text])

    def test_verify_prints_the_profile_status_and_action_count(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capture: Capture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """One line, and a normal return for a completed capture."""
        self.argv(monkeypatch, "verify", capture.write())
        pc.main()
        assert (
            capsys.readouterr().out == "synthetic-tool-test: completed; 2 actions\n"
        ), "expected: one line, and a normal return for a completed capture"

    def test_the_recipe_form_runs_the_script_as_a_program(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capture: Capture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """``python scripts/protocol_capture.py verify DIRECTORY`` prints the line."""
        self.argv(monkeypatch, "verify", capture.write())
        runpy.run_path(str(SCRIPT), run_name="__main__")
        assert (
            capsys.readouterr().out == "synthetic-tool-test: completed; 2 actions\n"
        ), "expected: the program form prints the line"

    def test_a_failed_capture_exits_with_status_one_after_printing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capture: Capture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The line is printed, then ``SystemExit(1)``."""
        capture.report.update(status="failed", error="boom", completed_actions=1)
        self.argv(monkeypatch, "verify", capture.write())
        with pytest.raises(SystemExit) as caught:
            pc.main()
        assert caught.value.code == 1, "expected status one"
        assert capsys.readouterr().out == "synthetic-tool-test: failed; 1 actions\n", (
            "expected: the line is printed, then ``SystemExit(1)``"
        )

    def test_a_refused_capture_raises_its_error(
        self, monkeypatch: pytest.MonkeyPatch, capture: Capture
    ) -> None:
        """The verification error propagates."""
        capture.report["status"] = "running"
        self.argv(monkeypatch, "verify", capture.write())
        with pytest.raises(ValueError, match="Unknown capture status"):
            pc.main()

    @pytest.mark.parametrize(
        "arguments",
        [[], ["verify"], ["bogus"], ["capture"], ["capture", "plan.json"]],
    )
    def test_an_unusable_command_line_exits_with_status_two(
        self, monkeypatch: pytest.MonkeyPatch, arguments: list[str]
    ) -> None:
        """A missing subcommand, directory or option, or an unknown subcommand."""
        self.argv(monkeypatch, *arguments)
        with pytest.raises(SystemExit) as caught:
            pc.main()
        assert caught.value.code == 2, "expected the usage status"

    def test_the_constants_of_the_command_line_are_unchanged(self) -> None:
        """The oracle hash and the capture limit."""
        assert pc.ORACLE_SHA256 == ORACLE, "expected the recorded oracle hash"
        assert pc.MAX_CAPTURE_BYTES == 8 * 1024 * 1024, "expected 8 MiB"
