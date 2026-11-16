"""Fault controls for the isolated settings persistence plan and gates."""

import json
import sys
import typing as typ
from pathlib import Path
from unittest import mock

import capture_identity
import native_settings_persistence as runner
import native_settings_persistence_cases as cases
import pytest
from protocol_capture import Recorder, digest, verify_capture

if typ.TYPE_CHECKING:
    import types

type Frame = dict[str, typ.Any]
type Plan = dict[str, typ.Any]

RUNTIME = {"emulator_pid": 123, "source_a7_sha256": cases.A7_SHA}
PORT = 15760
PHASE1_ACTIONS = 64
PHASE2_ACTIONS = 26
FIRST_PHASE_ACTIONS = 4
LOGIN_107 = "0000006b"
SET_CLIENT_INFO = "00000130"
# The set that a runner records for itself; the runner before decision D31 had none.
MODULES = getattr(
    runner,
    "CAPTURE_MODULES",
    ("native_settings_persistence.py", "native_settings_persistence_cases.py"),
)


def gates_module() -> types.ModuleType:
    """Find the module that holds the stage gates.

    Returns
    -------
    types.ModuleType
        The module that defines ``gate_identity``, so that a patch of the names
        it reads reaches the call, whether the gates are one file or many.
    """
    return sys.modules[runner.gate_identity.__module__]


def prepared(phase: str = "phase1") -> Plan:
    """Prepare one phase's plan.

    Returns
    -------
    dict[str, typing.Any]
        The plan.
    """
    return cases.plans(RUNTIME, PORT)[phase]


def sent(plan: Plan, prefix: str) -> list[Frame]:
    """List the steps that send a request that starts with a prefix.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps, in order.
    """
    return [
        step
        for step in plan["steps"]
        if step["op"] == "send" and step["hex"].startswith(prefix)
    ]


def frame(
    connection: str, kind: int, fields: dict[int, bytes], *, index: int = 0
) -> Frame:
    """Build a decoded notification of a connection.

    Returns
    -------
    dict[str, typing.Any]
        The frame, with its action.
    """
    return {
        "action": index,
        "connection": connection,
        "type": kind,
        "is_reply": int(kind == 0),
        "id": 1,
        "error": 0,
        "fields": [{"id": key, "hex": value.hex()} for key, value in fields.items()],
    }


class OfflineRecorder(Recorder):
    """A recorder that connects and waits for end of file without a socket."""

    def execute(self, action: int, step: Frame) -> None:
        """Run one offline step.

        Raises
        ------
        AssertionError
            If the step is not a connect or an end-of-file read.
        """
        name = step["connection"]
        match step["op"]:
            case "connect":
                self.sockets[name] = mock.Mock()
                self.event(action, name, "connect")
            case "read_eof":
                self.event(action, name, "eof")
            case _:
                message = "Unexpected offline action"
                raise AssertionError(message)


def write_inputs(tmp_path: Path, plan: Plan) -> tuple[bytes, Path, Path, Path]:
    """Write what a phase is run from: the plans, the readiness capture and the receipt.

    Both records of the scripts are written, the hashes of two files that the runner
    checked before decision D31 and the record of its module set after it.

    Parameters
    ----------
    tmp_path : pathlib.Path
        The directory that receives them.
    plan : dict[str, typing.Any]
        The phase's plan.

    Returns
    -------
    tuple[bytes, pathlib.Path, pathlib.Path, pathlib.Path]
        The plan file's bytes, the plan directory, the readiness directory and the
        capture-ready receipt.
    """
    plans = tmp_path / "plans"
    plans.mkdir()
    raw = (json.dumps(plan) + "\n").encode()
    (plans / "phase1.json").write_bytes(raw)
    (plans / "source-hashes.json").write_text(json.dumps({"phase1": digest(raw)}))
    scripts = Path(runner.__file__).parent
    legacy = {
        name: digest((scripts / name).read_bytes())
        for name in (
            "native_settings_persistence_cases.py",
            "native_settings_persistence.py",
        )
    }
    (plans / "source-code-sha256.json").write_text(json.dumps(legacy))
    files = capture_identity.identity(MODULES)["files"]
    (plans / "source-code-identity.json").write_text(json.dumps({"files": files}))
    ready = tmp_path / "readiness"
    ready.mkdir()
    (ready / "plan.json").write_text(json.dumps(plan))
    (ready / "report.json").write_text("{}")
    receipt = tmp_path / "capture-ready.json"
    receipt.write_text('{"emulator_pid": 123}')
    return raw, plans, ready, receipt


class PersistencePreparationTests:
    """Fault controls for the isolated settings persistence plan and gates."""

    def test_fixed_login_reused_and_three_bounded_transitions(self) -> None:
        """Both phases send the same two logins, and phase one changes three times."""
        plans = cases.plans(RUNTIME, PORT)
        before = plans["phase1"]["steps"]
        assert sent(plans["phase1"], LOGIN_107) == sent(plans["phase2"], LOGIN_107), (
            "expected the same fixed login"
        )
        assert len(sent(plans["phase1"], SET_CLIENT_INFO)) == 3, "three 304 requests"
        stages = plans["phase1"]["expectation"]["stages"]
        labels = [stage["label"] for stage in stages]
        assert labels == ["enable", "disable", "reenable"], labels
        assert stages[-1]["auto"], "expected the last stage to enable the response"
        assert not any(step["op"] == "close" for step in before), "expected no close"
        for plan, count in (
            (plans["phase1"], PHASE1_ACTIONS),
            (plans["phase2"], PHASE2_ACTIONS),
        ):
            assert plan["expectation"]["observation_actions"] == count, "actions"
            assert [(s["op"], s["connection"]) for s in plan["steps"][-2:]] == [
                ("read_eof", "subject"),
                ("read_eof", "main"),
            ], "expected the two end-of-file reads"
        profile = plans["phase1"]["environment"]["full_file_baseline"]
        assert profile == "not_exercised", "expected no full baseline"

    def test_bad_readiness_stops_before_recorder(self) -> None:
        """A failed readiness capture is refused before any socket is opened."""
        with (
            mock.patch.object(
                runner, "Recorder", side_effect=AssertionError("opened socket")
            ),
            pytest.raises(ValueError, match="readiness"),
        ):
            runner.gate_readiness({"status": "failed"}, {})

    def test_wrong_subject_identity_blocks_pm(self) -> None:
        """A subject announced under another name stops the message."""
        plan = prepared()
        action = plan["expectation"]["identity_action"]
        admin = gates_module().ADMIN
        report = {
            "frames": [
                frame("main", 0, {}),
                frame("main", 354, {}),
                frame("main", 109, {}),
                frame("main", 0, {}, index=8),
                frame("subject", 0, {}),
                frame("subject", 354, {110: admin}),
                frame("subject", 109, {}),
                frame(
                    "main",
                    301,
                    {103: b"\0\2", 102: b"wrong", 104: b"\0\3"},
                    index=action,
                ),
            ]
        }
        report["frames"][3]["id"] = 10
        observer = [{"name_hex": b"framing-fixture".hex(), "uid": 1}]
        with (
            mock.patch.object(gates_module(), "login_gate"),
            mock.patch.object(gates_module(), "roster", return_value=observer),
            pytest.raises(ValueError, match="identity"),
        ):
            runner.gate_identity(report, plan)

    def test_wrong_automatic_text_is_not_an_enabled_witness(self) -> None:
        """A response with another text does not count as the automatic response."""
        stage = prepared()["expectation"]["stages"][0]
        start = stage["pm_action"]

        def notice(action: int, connection: str, values: dict[int, bytes]) -> Frame:
            """Build a 104 of the stage's message.

            Returns
            -------
            dict[str, typing.Any]
                The frame.
            """
            built = frame(connection, 104, values, index=action)
            built["id"] = stage["pm_id"]
            return built

        acknowledgement = frame("main", 0, {}, index=start + 1)
        acknowledgement["is_reply"] = 1
        acknowledgement["id"] = stage["pm_id"]
        wrong = {103: b"\0\2", 102: cases.MARKER_NAME, 113: b"\0\4", 101: b"wrong"}
        original = {
            103: b"\0\1",
            102: b"framing-fixture",
            113: b"\0\1",
            101: bytes.fromhex(stage["pm_text_hex"]),
        }
        report = {
            "completed_actions": start + 4,
            "frames": [
                acknowledgement,
                notice(start + 2, "main", wrong),
                notice(start + 3, "subject", original),
            ],
        }
        with pytest.raises(ValueError, match="Automatic PM feedback"):
            runner.gate_pm(report, start, b"\0\2", b"\0\1", phase=1, stage=stage)

    def test_changed_301_blocks_dependent_pm(self) -> None:
        """An update that never arrived is refused."""
        with pytest.raises(ValueError, match="301"):
            runner.gate_update({"frames": []}, prepared(), b"\0\2")

    def test_runner_serialization_passes_generic_capture_gate(
        self, tmp_path: Path
    ) -> None:
        """A phase that the runner writes replays as a generic capture."""
        binary = tmp_path / "oracle-fixture.bin"
        binary.write_bytes(b"offline oracle identity fixture")
        oracle = digest(binary.read_bytes())
        plan = prepared()
        plan["profile"] = "synthetic-tool-test"
        plan["oracle_sha256"] = oracle
        plan["steps"] = [s for s in plan["steps"] if s["op"] == "connect"] + plan[
            "steps"
        ][-2:]
        plan["expectation"]["observation_actions"] = 2
        raw, plans, ready, receipt = write_inputs(tmp_path, plan)
        output = tmp_path / "phase"
        with (
            mock.patch.object(runner.os, "geteuid", return_value=0),
            mock.patch.object(runner, "ORACLE_SHA256", oracle),
            mock.patch.object(runner, "verify_plan", return_value=1),
            mock.patch.object(
                runner, "verify_capture", return_value={"oracle_sha256": oracle}
            ),
            mock.patch.object(runner, "gate_readiness"),
            mock.patch.object(runner, "capture_gate"),
            mock.patch.object(runner, "phase_gate", return_value=None),
            mock.patch.object(runner, "Recorder", OfflineRecorder),
        ):
            result = runner.run_gated(
                plans / "phase1.json", ready, receipt, binary, output
            )
        assert result["status"] == "completed", result["error"]
        assert result["completed_actions"] == FIRST_PHASE_ACTIONS, "actions"
        replayed = verify_capture(output)["completed_actions"]
        assert replayed == FIRST_PHASE_ACTIONS, "expected the capture to replay"
        self.replay(result, plan)
        self.shorten(output, raw, result)
        with pytest.raises(ValueError, match="Incomplete plan"):
            verify_capture(output)

    @staticmethod
    def shorten(output: Path, raw: bytes, result: Frame) -> None:
        """Rewrite the report with one action fewer, and its checksums to match."""
        report_path = output / "report.json"
        report_path.write_text(
            json.dumps({**result, "completed_actions": FIRST_PHASE_ACTIONS - 1}) + "\n"
        )
        lines = [
            f"{digest(raw)}  plan.json",
            f"{digest(report_path.read_bytes())}  report.json",
        ]
        (output / "checksums.sha256").write_text("\n".join(lines) + "\n")

    @staticmethod
    def replay(result: Frame, plan: Plan) -> None:
        """Replay a written phase, then drop one end-of-file event and replay again."""
        home = sys.modules[runner.semantic.__module__]
        with (
            mock.patch.object(home, "verify_plan", return_value=1),
            mock.patch.object(home, "phase_gate", return_value=None),
        ):
            status = runner.semantic(result, plan)["status"]
            assert status == "verified_phase_only", "expected a verified phase"
            kept = [
                e
                for e in result["events"]
                if not (e["event"] == "eof" and e["connection"] == "main")
            ]
            with pytest.raises(ValueError, match="Owned socket EOFs"):
                runner.semantic({**result, "events": kept}, plan)
