"""Offline contract tests for the bounded same-session 304 fixture."""

import copy
import json
import typing as typ
from pathlib import Path
from unittest import mock

import native_settings_transition_cases as cases
import pytest
import verify_native_settings_transition as verifier
from verify_native_settings_transition import check_stage

type Frame = dict[str, typ.Any]
type Plan = dict[str, typ.Any]

BASELINE = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01"
    "/capture/plan.json"
)
SUBJECT_UID = b"\0\x21"
MAIN_UID = b"\0\x20"
STALE_UID = b"\0\x22"


class RecordingRecorder:
    """A recorder that runs no step and keeps what a report reads."""

    executed: typ.ClassVar[list[int]] = []

    def __init__(self, plan: Plan) -> None:
        """Start empty.

        Parameters
        ----------
        plan : dict[str, typing.Any]
            The plan, which is not read.
        """
        del plan
        self.events: list[Frame] = []
        self.frames: list[Frame] = []
        self.sockets: dict[str, typ.Any] = {}
        self.started_at_utc = "offline"

    def execute(self, index: int, step: Frame) -> None:
        """Record the index of the step."""
        del step
        self.executed.append(index)

    def streams(self) -> dict[str, typ.Any]:
        """Give no streams.

        Returns
        -------
        dict[str, typing.Any]
            An empty mapping.
        """
        return {}


def frame(
    kind: int, action: int, connection: str, values: dict[int, bytes], **options: int
) -> Frame:
    """Build a decoded frame.

    Parameters
    ----------
    kind : int
        The transaction type.
    action : int
        The action at which the frame arrived.
    connection : str
        The connection that received it.
    values : dict[int, bytes]
        The fields of the frame.
    **options : int
        ``reply`` and ``identifier``, each zero when omitted.

    Returns
    -------
    dict[str, typing.Any]
        The frame, with its action and connection.
    """
    return {
        "type": kind,
        "action": action,
        "connection": connection,
        "is_reply": options.get("reply", 0),
        "id": options.get("identifier", 0),
        "error": 0,
        "fields": [{"id": key, "hex": value.hex()} for key, value in values.items()],
    }


def sample(stage: cases.Stage, window: Frame, uid: bytes = SUBJECT_UID) -> Frame:
    """Build the frames that an exact witness of one stage holds.

    Returns
    -------
    dict[str, typing.Any]
        A report with the stage's frames.
    """
    name, icon = stage.expected_name, stage.expected_icon
    first = window["first"]
    frames = [
        frame(301, first + 1, "main", {103: uid, 102: name, 104: icon}),
        frame(301, first + 2, "subject", {103: uid, 102: name, 104: icon}),
        frame(108, first + 4, "main", {}, reply=1, identifier=window["pm_id"]),
        frame(
            104,
            first + 5,
            "subject",
            {
                103: MAIN_UID,
                102: b"framing-fixture",
                113: b"\0\1",
                101: bytes.fromhex(window["pm_text_hex"]),
            },
        ),
    ]
    if stage.expected_auto is not None:
        automatic = {103: uid, 102: name, 113: b"\0\4", 101: stage.expected_auto}
        frames.append(frame(104, first + 6, "main", automatic))
    return {"frames": frames}


@pytest.fixture(scope="module")
def plan() -> Plan:
    """Prepare the observation plan from the retained baseline.

    Returns
    -------
    dict[str, typing.Any]
        The plan.
    """
    raw = BASELINE.read_bytes()
    baseline = cases.load_baseline(raw)
    return cases.plans(baseline["environment"], raw)["observe"]


class SettingsTransitionTests:
    """Offline contract tests for the bounded same-session 304 fixture."""

    def test_each_stage_accepts_exact_synthetic_witness(self, plan: Plan) -> None:
        """Every stage accepts the frames that it expects."""
        for stage, window in zip(
            cases.STAGES, plan["expectation"]["windows"], strict=True
        ):
            result = check_stage(sample(stage, window), plan, window, SUBJECT_UID)
            assert result["uid_hex"] == "0021", f"{stage.label}: expected the UID"

    def test_rejects_wrong_default_missing_feedback_and_wrong_301(
        self, plan: Plan
    ) -> None:
        """A stale text, a missing response and a wrong icon are each refused."""
        window = plan["expectation"]["windows"][1]
        report = sample(cases.STAGES[1], window)
        wrong = copy.deepcopy(report)
        wrong["frames"][-1]["fields"][-1]["hex"] = b"stale-explicit".hex()
        with pytest.raises(ValueError, match="automatic text"):
            check_stage(wrong, plan, window, SUBJECT_UID)
        with pytest.raises(ValueError, match="104 delivery"):
            check_stage({"frames": report["frames"][:-1]}, plan, window, SUBJECT_UID)
        wrong = copy.deepcopy(report)
        wrong["frames"][0]["fields"][2]["hex"] = b"\0\7".hex()
        with pytest.raises(ValueError, match="301 name/icon"):
            check_stage(wrong, plan, window, SUBJECT_UID)

    def test_rejects_extra_feedback_and_stale_uid(self, plan: Plan) -> None:
        """An extra notification and another subject UID are each refused."""
        window = plan["expectation"]["windows"][3]
        report = sample(cases.STAGES[3], window)
        wrong = copy.deepcopy(report)
        wrong["frames"].append(
            frame(104, window["first"] + 6, "main", {101: b"unexpected"})
        )
        with pytest.raises(ValueError, match="104 delivery"):
            check_stage(wrong, plan, window, SUBJECT_UID)
        with pytest.raises(ValueError, match="301 name/icon/UID"):
            check_stage(report, plan, window, STALE_UID)

    def test_runner_stops_before_304_or_pm_on_first_bad_gate(
        self, tmp_path: Path, plan: Plan
    ) -> None:
        """A bad identity or update gate stops the run at the step that it follows."""
        saved = next(i for i, s in enumerate(plan["steps"]) if s.get("save_fields"))
        first = plan["expectation"]["windows"][0]["first"]
        (tmp_path / "plan.json").write_text(json.dumps(plan))
        (tmp_path / "binary").write_bytes(b"offline")
        for gate, stop in (("current_uids", saved), ("check_update", first + 1)):
            RecordingRecorder.executed = []
            with (
                mock.patch.object(verifier, "Recorder", RecordingRecorder),
                mock.patch.object(verifier, "digest", return_value=cases.ORACLE_SHA256),
                mock.patch.object(
                    verifier, "current_uids", return_value=(SUBJECT_UID, MAIN_UID)
                ),
                mock.patch.object(verifier, gate, side_effect=ValueError("bad gate")),
            ):
                report = verifier.run_gated(
                    tmp_path / "plan.json", tmp_path / "binary", tmp_path / gate
                )
            assert report["status"] == "failed", f"{gate}: expected a failed run"
            assert RecordingRecorder.executed[-1] == stop, f"{gate}: expected a stop"
            assert (tmp_path / gate / "report.json").exists(), f"{gate}: report"
