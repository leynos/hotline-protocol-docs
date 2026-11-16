"""Characterize the ban run of ``native_control_readiness``.

This is the state before it is refactored.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``) and must hold on the refactored module;
``tests/test_pin_equivalence.py`` runs these tests against both. No socket is
opened and no capture is run.
"""

import hashlib
import json
import os
import typing as typ
from pathlib import Path

import native_ban_control_cases as cases
import native_control_readiness as gates
import pytest
from native_ban_control_cases import A7_SHA
from native_control_support import home

if typ.TYPE_CHECKING:
    from native_control_support import Report
    from protocol_capture import Recorder

REPORT_KEYS = [
    "schema_version",
    "profile",
    "status",
    "native_conformance",
    "operator",
    "oracle_sha256",
    "controller_uid",
    "plan_sha256",
    "driver_sha256",
    "recorded_at_utc",
    "started_at_utc",
    "gap_ids",
    "completed_actions",
    "error",
    "events",
    "frames",
    "streams",
]
RUNTIME = {"source_a7_sha256": A7_SHA, "emulator_pid": 42}


def written(tmp_path: Path) -> Path:
    """Write the five plans and their digests.

    Returns
    -------
    pathlib.Path
        The plan directory.
    """
    directory = tmp_path / "plans"
    hashes = cases.write_plans(directory, RUNTIME, 15750)
    (directory / "source-hashes.json").write_text(json.dumps(hashes))
    return directory


class FakeSocket:
    """A connection that only records that it was closed."""

    def __init__(self) -> None:
        """Start open."""
        self.closed = False

    def close(self) -> None:
        """Record the close."""
        self.closed = True


class FakeRecorder:
    """A recorder that runs no step and keeps what a report reads."""

    failing_at: typ.ClassVar[int | None] = None
    created: typ.ClassVar[list[FakeRecorder]] = []

    def __init__(self, plan: Report) -> None:
        """Start empty, with one open connection.

        Parameters
        ----------
        plan : dict[str, typing.Any]
            The plan, which is not read.
        """
        del plan
        self.events: list[Report] = []
        self.frames: list[Report] = []
        self.variables = {"target_uid": b"\0\2"}
        self.sockets = {"main": FakeSocket()}
        self.started_at_utc = "offline"
        self.executed: list[int] = []
        self.created.append(self)

    def execute(self, index: int, step: Report) -> None:
        """Record the step, or fail at the chosen one.

        Raises
        ------
        ValueError
            At the step named by ``failing_at``.
        """
        del step
        if index == self.failing_at:
            message = "boom"
            raise ValueError(message)
        self.executed.append(index)

    def event(self, action: int, name: str, kind: str) -> None:
        """Record an event."""
        self.events.append({"action": action, "connection": name, "event": kind})

    def streams(self) -> Report:
        """Give no streams.

        Returns
        -------
        dict[str, typing.Any]
            An empty mapping.
        """
        return {}


@pytest.fixture
def ban_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path, Path]:
    """Prepare a ban plan, an oracle file and an output path, with the offline recorder.

    Returns
    -------
    tuple[pathlib.Path, pathlib.Path, pathlib.Path]
        The plan, the binary and the output directory.
    """
    plan = written(tmp_path) / "ban.json"
    binary = tmp_path / "binary"
    binary.write_bytes(b"offline oracle")
    run = home(gates.execute_ban_step)  # the module that holds the ban run
    oracle = hashlib.sha256(b"offline oracle").hexdigest()
    monkeypatch.setattr(run, "ORACLE_SHA256", oracle)
    monkeypatch.setattr(run, "Recorder", FakeRecorder)
    monkeypatch.setattr(run, "target_gate", lambda _frames: b"\0\2")
    FakeRecorder.failing_at = None
    FakeRecorder.created = []
    return plan, binary, tmp_path / "out"


class RunGuardedBanTests:
    """The ban run, with a recorder that executes nothing."""

    def test_a_completed_run_writes_the_plan_report_and_checksums(
        self, ban_run: tuple[Path, Path, Path]
    ) -> None:
        """Three files, and a report in the order that earlier ones have."""
        plan, binary, output = ban_run
        report = gates.run_guarded_ban(plan, binary, output)
        assert report["status"] == "completed", report
        assert report["completed_actions"] == 32, report
        assert (output / "plan.json").read_bytes() == plan.read_bytes(), "plan copy"
        written_report = json.loads((output / "report.json").read_text())
        assert written_report == json.loads(json.dumps(report)), "report file"
        keys = [key for key in report if key != "driver_identity"]
        assert keys == REPORT_KEYS, keys
        sums = (output / "checksums.sha256").read_text().splitlines()
        assert sums == [
            f"{hashlib.sha256((output / name).read_bytes()).hexdigest()}  {name}"
            for name in ("plan.json", "report.json")
        ], sums

    def test_the_fixed_fields_are_those_of_the_plan_and_the_run(
        self, ban_run: tuple[Path, Path, Path]
    ) -> None:
        """Profile, scope, user and the plan's digest."""
        plan, binary, output = ban_run
        report = gates.run_guarded_ban(plan, binary, output)
        planned = json.loads(plan.read_text())
        assert report["profile"] == planned["profile"], report
        assert report["native_conformance"] is False, report
        assert report["controller_uid"] == os.geteuid(), report
        digest = hashlib.sha256(plan.read_bytes()).hexdigest()
        assert report["plan_sha256"] == digest, report
        assert report["gap_ids"] == planned["gap_ids"], report
        assert not report["error"], report
        assert report["started_at_utc"] == "offline", report

    def test_the_driver_is_identified(self, ban_run: tuple[Path, Path, Path]) -> None:
        """One file before decision D31; the module set and its record after."""
        plan, binary, output = ban_run
        report = gates.run_guarded_ban(plan, binary, output)
        if "driver_identity" not in report:
            held = Path(gates.__file__).read_bytes()
            assert report["driver_sha256"] == hashlib.sha256(held).hexdigest(), report
            return
        record = report["driver_identity"]
        scripts = Path(gates.__file__).parent
        names = [Path(item["path"]).name for item in record["files"]]
        assert names[0] == "native_control_readiness.py", record
        for item in record["files"]:
            held = (scripts / Path(item["path"]).name).read_bytes()
            assert item["sha256"] == hashlib.sha256(held).hexdigest(), item
        assert report["driver_sha256"] == record["digest"], report

    def test_a_failed_step_ends_the_run_and_closes_the_connection(
        self, ban_run: tuple[Path, Path, Path]
    ) -> None:
        """Status, error text, completed count and the close event."""
        plan, binary, output = ban_run
        FakeRecorder.failing_at = 3
        report = gates.run_guarded_ban(plan, binary, output)
        assert report["status"] == "failed", report
        assert report["error"] == "ValueError: boom", report
        assert report["completed_actions"] == 3, report
        assert report["events"] == [
            {"action": 3, "connection": "main", "event": "close"}
        ], report
        assert FakeRecorder.created[0].sockets["main"].closed, "expected a close"
        assert (output / "report.json").exists(), "expected a report"

    def test_the_plan_is_validated_before_the_binary_is_read(
        self, ban_run: tuple[Path, Path, Path]
    ) -> None:
        """An invalid plan with a missing binary."""
        plan, binary, output = ban_run
        document = json.loads(plan.read_text())
        document["schema_version"] = 2
        plan.write_text(json.dumps(document))
        binary.unlink()
        with pytest.raises(ValueError, match="schema"):
            gates.run_guarded_ban(plan, binary, output)

    def test_another_binary_is_refused_before_the_output_is_made(
        self, ban_run: tuple[Path, Path, Path]
    ) -> None:
        """The oracle identity."""
        plan, binary, output = ban_run
        binary.write_bytes(b"another")
        with pytest.raises(ValueError, match=r"^Oracle identity differs$"):
            gates.run_guarded_ban(plan, binary, output)
        assert not output.exists(), "expected no output directory"
        assert not FakeRecorder.created, "expected no recorder"

    def test_an_existing_output_is_refused_before_the_recorder_is_made(
        self, ban_run: tuple[Path, Path, Path]
    ) -> None:
        """The directory is made without ``exist_ok``."""
        plan, binary, output = ban_run
        output.mkdir()
        with pytest.raises(FileExistsError):
            gates.run_guarded_ban(plan, binary, output)
        assert not FakeRecorder.created, "expected no recorder"


class ExecuteBanStepTests:
    """The gate on the 110 request."""

    def test_only_the_ban_request_is_gated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Another send passes without the target gate."""
        monkeypatch.setattr(home(gates.execute_ban_step), "target_gate", None)
        recorder = FakeRecorder({})
        step = {"op": "send", "hex": "00000067" + "00" * 8}
        gates.execute_ban_step(typ.cast("Recorder", recorder), 4, step)
        assert recorder.executed == [4], "expected the step to run"

    def test_a_read_step_is_not_gated_even_with_the_ban_prefix(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Only a send."""
        monkeypatch.setattr(home(gates.execute_ban_step), "target_gate", None)
        recorder = FakeRecorder({})
        step = {"op": "read", "hex": "0000006e00000021"}
        gates.execute_ban_step(typ.cast("Recorder", recorder), 5, step)
        assert recorder.executed == [5], "expected the step to run"
