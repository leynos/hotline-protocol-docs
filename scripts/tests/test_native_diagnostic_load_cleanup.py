"""Decision controls for the conditional cleanup and the command line of the planner.

The cleanup is run against a recorder that answers each read step from a table,
so no socket is opened.
"""

import hashlib
import json
import sys
import typing as typ
from unittest import mock

import capture_identity
import native_diagnostic_load_cases as planner
import protocol_capture
import pytest
from native_diagnostic_load_cases import NAME, CleanupPaths, conditional_cleanup
from native_plan import packet, payload
from protocol_capture import Recorder, decode_frame

BINARY = b"binary"
BINARY_SHA256 = hashlib.sha256(BINARY).hexdigest()
RUNTIME = {"fixture_profile": "control-only"}
ADMIN_ROW = bytes(8) + b"framing-fixture"
FILES = [(200, bytes(16) + len(b"other").to_bytes(4, "big") + b"other")]
ACCOUNTS = [(102, b"admin")]


def frame(identifier: int, fields: list[tuple[int, bytes]], error: int = 0) -> dict:
    """Decode a reply frame carrying the given fields.

    Returns
    -------
    dict
        The decoded frame.
    """
    return decode_frame(
        bytes.fromhex(packet(0, identifier, payload(fields), reply=1, error=error))
    )


def scripted(branch: str, *, leftover: bool = False) -> dict[int, dict]:
    """Build the replies that a cleanup run reads, by request identifier.

    Parameters
    ----------
    branch : str
        ``absent`` or ``present``.
    leftover : bool
        Whether the owned file is still there after the cleanup.

    Returns
    -------
    dict[int, dict]
        The reply frame of each identifier.
    """
    present = branch == "present"
    listing = (
        [(200, bytes(16) + len(NAME).to_bytes(4, "big") + NAME)] if present else []
    )
    replies = {
        10: frame(10, [(201, NAME)] if present else [], 0 if present else 1),
        11: frame(11, listing),
        12: frame(12, [(201, NAME)] if leftover else [], 0 if leftover else 1),
        13: frame(13, FILES),
        14: frame(14, ACCOUNTS),
        15: frame(15, [(300, ADMIN_ROW)]),
        16: frame(16, [(101, b"idle"), (102, b"quiet")]),
    }
    if present:
        replies[17] = frame(17, [])
    return replies


if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path


class FakeRecorder(Recorder):
    """Recorder that answers each frame read from a fixed table."""

    replies: typ.ClassVar[dict[int, dict]] = {}

    def execute(self, action: int, step: dict) -> None:
        """Record the effect of one step; a frame read gets its scripted reply."""
        wanted = step.get("match_frame", {}).get("id")
        if step["op"] == "read_frame" and wanted is not None:
            self.frames.append({
                "action": action,
                "connection": step["connection"],
                **self.replies.get(wanted, frame(wanted, [])),
            })
        else:
            self.event(action, step.get("connection", ""), step["op"])


def cleanup_module() -> typ.Any:  # ruff: ignore[any-type]  # the module that holds the cleanup, whichever it is
    """Find the module that defines ``conditional_cleanup``.

    Returns
    -------
    types.ModuleType
        The module whose globals the cleanup reads.
    """
    return sys.modules[conditional_cleanup.__module__]


def invoke(runtime: dict, binary: Path, output: Path, baseline: Path) -> None:
    """Run the conditional cleanup with the identity of the planner's modules."""
    conditional_cleanup(
        runtime,
        CleanupPaths(binary, output, baseline),
        capture_identity.identity(planner.CAPTURE_MODULES),
    )


@pytest.fixture
def staged(tmp_path: Path) -> cabc.Iterator[Path]:
    """Stage a binary and a baseline report, with the recorder and oracle faked.

    Yields
    ------
    pathlib.Path
        The directory that holds ``binary`` and ``baseline``.
    """
    (tmp_path / "binary").write_bytes(BINARY)
    (tmp_path / "baseline").mkdir()
    (tmp_path / "baseline/report.json").write_text(
        json.dumps({"frames": [frame(11, FILES), frame(10, ACCOUNTS)]})
    )
    module = cleanup_module()
    with (
        mock.patch.object(module, "Recorder", FakeRecorder),
        mock.patch.object(module, "ORACLE_SHA256", BINARY_SHA256),
        mock.patch.object(protocol_capture, "ORACLE_SHA256", BINARY_SHA256),
    ):
        yield tmp_path


def run(staged: Path, replies: dict[int, dict]) -> dict:
    """Run the cleanup on the replies and read back its report.

    Returns
    -------
    dict
        The report that the run wrote.
    """
    FakeRecorder.replies = replies
    invoke(RUNTIME, staged / "binary", staged / "out", staged / "baseline")
    return json.loads((staged / "out/report.json").read_text())


class CleanupTests:
    """Check the branches of the cleanup and what it writes."""

    def test_absent_file_runs_without_a_deletion(self, staged: Path) -> None:
        """An absent file completes the short plan and deletes nothing."""
        report = run(staged, scripted("absent"))
        assert report["status"] == "completed", report["error"]
        assert report["branch"] == "absent", "branch"
        assert report["completed_actions"] == len(
            json.loads((staged / "out/plan.json").read_text())["steps"]
        ), "the plan was not run to its end"

    def test_present_file_is_deleted_once(self, staged: Path) -> None:
        """A present file selects the plan with one deletion."""
        report = run(staged, scripted("present"))
        plan = json.loads((staged / "out/plan.json").read_text())
        assert report["status"] == "completed", report["error"]
        assert report["branch"] == "present", "branch"
        assert plan["expectation"]["branch"] == "present", "the plan was not swapped"
        assert any(
            step.get("op") == "send" and step["hex"][4:8] == "00cc"
            for step in plan["steps"]
        ), "the deletion request is absent"

    def test_the_output_is_the_plan_the_report_and_their_checksums(
        self, staged: Path
    ) -> None:
        """The checksums name the plan and the report, in that order."""
        run(staged, scripted("absent"))
        out = staged / "out"
        lines = (out / "checksums.sha256").read_text().splitlines()
        assert lines == [
            f"{hashlib.sha256((out / name).read_bytes()).hexdigest()}  {name}"
            for name in ("plan.json", "report.json")
        ], "the checksums differ"
        report = json.loads((out / "report.json").read_text())
        plan_bytes = (out / "plan.json").read_bytes()
        assert report["plan_sha256"] == hashlib.sha256(plan_bytes).hexdigest(), (
            "the report does not hash the plan"
        )

    def test_the_report_records_the_identity_of_the_declared_modules(
        self, staged: Path
    ) -> None:
        """The report holds the set digest and the record of each module."""
        report = run(staged, scripted("absent"))
        record = report["driver_identity"]
        assert report["driver_sha256"] == record["digest"], (
            "the driver hash is not the digest of the module set"
        )
        assert [item["path"] for item in record["files"]] == [
            f"scripts/{name}" for name in planner.CAPTURE_MODULES
        ], "the identity lists other modules than the declared set"
        assert capture_identity.check(record, planner.CAPTURE_MODULES), (
            "the identity does not describe the live modules"
        )

    def test_a_remaining_file_fails_the_run_and_still_writes_it(
        self, staged: Path
    ) -> None:
        """A file left after the cleanup fails the run with exit status 1."""
        FakeRecorder.replies = scripted("absent", leftover=True)
        with pytest.raises(SystemExit) as stopped:
            invoke(RUNTIME, staged / "binary", staged / "out", staged / "baseline")
        assert stopped.value.code == 1, "the exit status differs"
        report = json.loads((staged / "out/report.json").read_text())
        assert report["status"] == "failed", "status"
        assert report["error"] == "ValueError: Owned file remains after cleanup", (
            report["error"]
        )

    def test_a_wrong_binary_stops_before_any_output(self, staged: Path) -> None:
        """A binary with another hash is refused before the output is made."""
        (staged / "binary").write_bytes(b"other")
        with pytest.raises(ValueError, match="Oracle binary hash mismatch"):
            invoke(RUNTIME, staged / "binary", staged / "out", staged / "baseline")
        assert not (staged / "out").exists(), "the output was made"

    def test_an_ambiguous_file_is_never_deleted(self, staged: Path) -> None:
        """Replies that disagree fail the run before any deletion is sent."""
        replies = scripted("absent")
        replies[10] = frame(10, [(201, NAME)], 0)
        FakeRecorder.replies = replies
        with pytest.raises(SystemExit):
            invoke(RUNTIME, staged / "binary", staged / "out", staged / "baseline")
        report = json.loads((staged / "out/report.json").read_text())
        assert "ambiguous" in report["error"], report["error"]
        assert report["branch"] == "unresolved", "a branch was chosen"


class CommandTests:
    """Check the command line of the planner."""

    def command(self, tmp_path: Path, *args: str) -> None:
        """Run ``main`` with the given arguments and a runtime record."""
        (tmp_path / "runtime.json").write_text(json.dumps(RUNTIME))
        argv = [
            "native_diagnostic_load_cases.py",
            *args,
            "--runtime-record",
            str(tmp_path / "runtime.json"),
            "--output",
            str(tmp_path / "plan.json"),
        ]
        with mock.patch.object(sys, "argv", argv):
            planner.main()

    def test_a_case_plan_is_written_once(self, tmp_path: Path) -> None:
        """A case's plan is written to a new file and never over an old one."""
        self.command(tmp_path, "boundary")
        plan = json.loads((tmp_path / "plan.json").read_text())
        assert plan["expectation"] == {
            "case": "boundary",
            "owned_name_hex": NAME.hex(),
        }, "the expectation differs"
        assert plan["endpoints"]["data"]["port"] == 15501, "the data port differs"
        with pytest.raises(FileExistsError):
            self.command(tmp_path, "boundary")

    def test_cleanup_without_its_guards_is_refused(self, tmp_path: Path) -> None:
        """The cleanup case needs the guard, the binary and the baseline."""
        with pytest.raises(SystemExit) as stopped:
            self.command(tmp_path, "cleanup")
        assert stopped.value.code == 2, "the usage error differs"

    def test_the_guard_belongs_to_the_cleanup_case(self, tmp_path: Path) -> None:
        """A plan case refuses the cleanup guard."""
        with pytest.raises(SystemExit) as stopped:
            self.command(tmp_path, "boundary", "--conditional-cleanup")
        assert stopped.value.code == 2, "the usage error differs"

    def test_the_cleanup_command_passes_the_identity_of_its_modules(
        self, tmp_path: Path
    ) -> None:
        """The command records the identity of the declared set in the cleanup."""
        with mock.patch.object(planner, "conditional_cleanup") as cleanup:
            self.command(
                tmp_path,
                "cleanup",
                "--conditional-cleanup",
                "--oracle-binary",
                str(tmp_path / "binary"),
                "--baseline",
                str(tmp_path / "baseline"),
            )
        runtime, paths, identity = cleanup.call_args.args
        assert runtime == RUNTIME, "the runtime record differs"
        assert paths == CleanupPaths(
            tmp_path / "binary", tmp_path / "plan.json", tmp_path / "baseline"
        ), "the paths differ"
        assert (
            identity["digest"]
            == capture_identity.identity(planner.CAPTURE_MODULES)["digest"]
        ), "the identity is not that of the declared set"
