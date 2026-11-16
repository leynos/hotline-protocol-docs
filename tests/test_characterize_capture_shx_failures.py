"""Characterize ``capture_shx_session.py``: its refusals, failures and command line."""

import json
import types
import typing as typ
from pathlib import Path

import pytest
from shx_session_fakes import EIO, FD, PID
from shx_session_rig import (
    BOUND,
    ORACLE_BYTES,
    PEER_BYTES,
    STEPS,
    Rig,
    build_rig,
    sha,
)

if typ.TYPE_CHECKING:
    import collections.abc as cabc


@pytest.fixture
def rig(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Rig:
    """Build the synthetic repository and load the script against fakes.

    Returns
    -------
    Rig
        The prepared rig.
    """
    return build_rig(tmp_path, monkeypatch)


class CaptureRefusalTests:
    """Pin the refusals made before any directory is created."""

    def refused(
        self, rig: Rig, message: str, kind: type[Exception] = ValueError
    ) -> None:
        """Expect a refusal that leaves no output behind.

        Parameters
        ----------
        rig : Rig
            The rig to run.
        message : str
            The message that the refusal must carry.
        kind : type[Exception]
            The exception type.
        """
        with pytest.raises(kind, match=message):
            rig.capture()
        assert not rig.output.exists(), "output was created"
        assert rig.terminal.written == [], "the child was driven"

    def test_a_binary_outside_the_checkout_is_refused(self, rig: Rig) -> None:
        """The peer binary must lie inside the mothra checkout."""
        outside = rig.output.parent.parent / "outside-hx"
        outside.write_bytes(PEER_BYTES)
        rig.binary = outside
        self.refused(rig, "Peer binary and capture output must be inside mothra")

    def test_an_output_outside_the_checkout_is_refused(self, rig: Rig) -> None:
        """The capture output must lie inside the mothra checkout."""
        rig.output = rig.root.parent / "elsewhere"
        self.refused(rig, "Peer binary and capture output must be inside mothra")

    def test_an_oracle_that_is_not_the_recorded_one_is_refused(self, rig: Rig) -> None:
        """An oracle with another hash is refused."""
        rig.oracle.write_bytes(b"another oracle")
        self.refused(rig, "Peer or oracle identity mismatch")

    def test_a_binary_that_the_profile_does_not_record_is_refused(
        self, rig: Rig
    ) -> None:
        """A binary whose hash is not the profile's is refused."""
        rig.binary.write_bytes(b"another peer")
        self.refused(rig, "Peer or oracle identity mismatch")

    def test_an_unknown_source_commit_is_refused(self, rig: Rig) -> None:
        """Only the one historical source profile is accepted."""
        rig.profile.write_text(
            json.dumps({"binary_sha256": sha(PEER_BYTES), "source_commit": "abc"})
        )
        self.refused(rig, "Unknown historical source profile")

    @pytest.mark.parametrize("bad", ["a\nb", "a\rb", "a\0b", "x" * 4097])
    def test_an_unbounded_command_is_refused(self, rig: Rig, bad: str) -> None:
        """A command with a control character, or over 4096 characters, is refused."""
        rig.write_plan([{"command": bad}, *STEPS])
        self.refused(rig, "Require bounded single-line peer commands")

    def test_a_command_of_4096_characters_is_allowed(self, rig: Rig) -> None:
        """The bound is exclusive of 4096."""
        rig.write_plan([{"command": "x" * 4096}, *STEPS])
        report = rig.capture()
        assert report["status"] == "completed", report
        assert report["completed_steps"] == len(STEPS) + 1, report

    @pytest.mark.parametrize(
        "steps",
        [[], [{"command": "help"}], [{"command": "quit", "expect_exit": 1}]],
    )
    def test_a_plan_without_a_successful_final_exit_is_refused(
        self, rig: Rig, steps: list[dict[str, typ.Any]]
    ) -> None:
        """The last step must expect exit code 0."""
        rig.write_plan(steps)
        self.refused(rig, "Require an explicit successful peer exit as the final step")

    def test_a_missing_tool_is_refused(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Both bwrap and strace must be found."""
        monkeypatch.setattr(
            rig.module,
            "shutil",
            types.SimpleNamespace(which=lambda n: None if n == "strace" else "/bin/x"),
        )
        self.refused(rig, "Require bwrap and strace")

    def test_an_existing_output_is_a_file_error(self, rig: Rig) -> None:
        """The output directory is created without ``exist_ok``."""
        rig.output.mkdir()
        with pytest.raises(FileExistsError):
            rig.capture()
        assert rig.terminal.written == [], "the child was driven"

    def test_checks_run_in_order_checkout_then_identity_then_commit_then_plan(
        self, rig: Rig
    ) -> None:
        """With every fault at once, the checkout refusal comes first."""
        rig.output = rig.root.parent / "elsewhere"
        rig.oracle.write_bytes(b"another oracle")
        rig.write_plan([])
        self.refused(rig, "must be inside mothra")
        rig.output = rig.root / "capture"
        self.refused(rig, "Peer or oracle identity mismatch")
        rig.oracle.write_bytes(ORACLE_BYTES)
        self.refused(rig, "Require an explicit successful peer exit")


class CaptureFailureTests:
    """Pin how a started session fails: the status, the error and the clean-up."""

    def failed(self, rig: Rig, error: str) -> dict[str, typ.Any]:
        """Run, expect a failed report with this error and every file written.

        Parameters
        ----------
        rig : Rig
            The rig to run.
        error : str
            The error text that the report must carry.

        Returns
        -------
        dict[str, typing.Any]
            The report.
        """
        report = rig.capture()
        assert report["status"] == "failed", report
        assert report["error"] == error, report
        assert report == rig.read_report(), "the report was not written"
        assert (rig.output / "SHA256SUMS").exists(), "sums were not written"
        assert rig.terminal.closed == [FD], rig.terminal.closed
        return report

    def test_a_peer_that_exits_before_a_step_fails_the_session(self, rig: Rig) -> None:
        """A child that is gone at the first step is reported with its code."""
        rig.terminal.initial = b"crash\r\n"
        rig.terminal.ended = 7
        report = self.failed(rig, "RuntimeError: Peer exited before step 0: 7")
        assert report["completed_steps"] == 0, report
        assert report["peer_exit_code"] == 7, report
        assert rig.terminal.killed == [], "an ended child was killed"

    def test_output_that_does_not_match_times_out_and_the_child_is_killed(
        self, rig: Rig
    ) -> None:
        """An unmatched expectation is a TimeoutError, and SIGTERM ends the child."""
        rig.write_plan([
            {"command": "help", "expect": "Never", "timeout": 1},
            *STEPS[1:],
        ])
        report = self.failed(rig, "TimeoutError: Step 0 output did not match 'Never'")
        assert rig.terminal.killed == [(PID, 15)], rig.terminal.killed
        assert report["peer_exit_code"] == -15, report
        assert rig.terminal.reaped, "the killed child was not reaped"

    def test_an_exit_code_that_differs_fails_the_session(self, rig: Rig) -> None:
        """A child that ends with another code than expected is reported."""
        rig.terminal.exits = {"quit": 3}
        report = self.failed(rig, "RuntimeError: Step 1 exit differs: 3")
        assert report["completed_steps"] == 1, report

    def test_a_child_that_does_not_exit_when_expected_is_reported_with_none(
        self, rig: Rig
    ) -> None:
        """No exit by the deadline reports ``None`` and the child is killed."""
        rig.terminal.exits = {}
        rig.write_plan([
            *STEPS[:1],
            {"command": "quit", "expect_exit": 0, "timeout": 1},
        ])
        self.failed(rig, "RuntimeError: Step 1 exit differs: None")
        assert rig.terminal.killed == [(PID, 15)], rig.terminal.killed

    def test_a_killed_child_that_is_already_gone_is_tolerated(self, rig: Rig) -> None:
        """A missing process group at the final kill is ignored."""
        rig.terminal.lookup_error = True
        rig.write_plan([
            {"command": "help", "expect": "Never", "timeout": 1},
            *STEPS[1:],
        ])
        self.failed(rig, "TimeoutError: Step 0 output did not match 'Never'")

    def test_output_beyond_eight_mebibytes_fails_the_session(self, rig: Rig) -> None:
        """The captured terminal output is bounded."""
        rig.terminal.queue = [b"x" * (BOUND + 1)]
        self.failed(rig, "ValueError: Terminal output exceeds capture bound")

    def test_a_terminal_read_error_other_than_eio_fails_the_session(
        self, rig: Rig
    ) -> None:
        """An OSError other than errno 5 is caught and reported."""
        rig.terminal.failing_read = OSError(9, "Bad file descriptor")
        self.failed(rig, "OSError: [Errno 9] Bad file descriptor")

    def test_the_eio_of_a_closed_terminal_is_not_an_error(self, rig: Rig) -> None:
        """EIO is read as no data, so the step times out instead of raising."""
        rig.terminal.failing_read = EIO
        rig.write_plan([
            {"command": "help", "expect": "Commands", "timeout": 1},
            *STEPS[1:],
        ])
        error = "TimeoutError: Step 0 output did not match 'Commands'"
        self.failed(rig, error)


class CaptureCommandLineTests:
    """Pin the command line, the verdict line and the exit status."""

    ARGS: typ.ClassVar[list[str]] = [
        "plan.json",
        "--binary",
        "b",
        "--peer-profile",
        "p",
        "--oracle-binary",
        "o",
        "--output",
        "out",
    ]

    def run_main(
        self,
        rig: Rig,
        monkeypatch: pytest.MonkeyPatch,
        report: dict[str, typ.Any],
        arguments: cabc.Sequence[str],
    ) -> tuple[list[tuple[Path, ...]], int | bool | str | None]:
        """Run ``main`` with a recording ``capture`` that returns ``report``.

        Returns
        -------
        tuple
            The arguments that ``capture`` received, and the exit code.
        """
        calls: list[tuple[Path, ...]] = []

        def fake(*given: Path) -> dict[str, typ.Any]:
            """Record the call and answer with the report.

            Returns
            -------
            dict[str, typing.Any]
                The canned report.
            """
            calls.append(given)
            return report

        monkeypatch.setattr(rig.module, "capture", fake)
        monkeypatch.setattr("sys.argv", ["capture_shx_session.py", *arguments])
        with pytest.raises(SystemExit) as caught:
            rig.module.main()
        return calls, caught.value.code

    def test_the_arguments_map_to_the_five_paths_in_order(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Plan, binary, profile, oracle and output reach ``capture`` as paths."""
        report = {"status": "completed", "completed_steps": 2, "error": ""}
        calls, _ = self.run_main(rig, monkeypatch, report, self.ARGS)
        expected = [tuple(Path(x) for x in ("plan.json", "b", "p", "o", "out"))]
        assert calls == expected, calls

    def test_a_completed_session_prints_its_verdict_and_exits_zero(
        self,
        rig: Rig,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The verdict line names status, steps and error; the exit status is 0."""
        report = {"status": "completed", "completed_steps": 2, "error": ""}
        _, code = self.run_main(rig, monkeypatch, report, self.ARGS)
        out = capsys.readouterr().out
        assert out == "Compiled peer: completed; 2 steps; \n", out
        assert code == 0, code

    def test_a_failed_session_exits_one(
        self,
        rig: Rig,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A failed report is printed with its error and the exit status is 1."""
        report = {"status": "failed", "completed_steps": 1, "error": "boom"}
        _, code = self.run_main(rig, monkeypatch, report, self.ARGS)
        out = capsys.readouterr().out
        assert out == "Compiled peer: failed; 1 steps; boom\n", out
        assert code == 1, code

    def test_a_missing_option_is_a_usage_error(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The four options are required; argparse exits with status 2."""
        report = {"status": "completed", "completed_steps": 0, "error": ""}
        _, code = self.run_main(rig, monkeypatch, report, ["plan.json"])
        assert code == 2, code
