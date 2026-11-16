"""Offline fault controls for delayed-121 default-response gates."""

import json
import typing as typ
from pathlib import Path
from unittest import mock

import native_121_default_cases as cases
import pytest
import verify_native_121_default as verifier

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Plan = dict[str, typ.Any]

BASELINE = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01"
    "/capture/plan.json"
)
SUBJECT_UID = b"\0\x32"
OBSERVER_UID = b"\0\x20"
FIRST_STOPS = (8, 19, 38)


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
        self.events: list[dict[str, typ.Any]] = []
        self.frames: list[dict[str, typ.Any]] = []
        self.sockets: dict[str, typ.Any] = {}
        self.started_at_utc = "offline"

    def execute(self, index: int, step: dict[str, typ.Any]) -> None:
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


def frame(values: dict[int, bytes]) -> dict[str, typ.Any]:
    """Build a frame that holds the given fields.

    Returns
    -------
    dict[str, typing.Any]
        The frame.
    """
    return {
        "fields": [{"id": key, "hex": value.hex()} for key, value in values.items()]
    }


def failing_at(cutoff: int) -> cabc.Callable[..., None]:
    """Make a gate that fails at one action and passes the others.

    Returns
    -------
    collections.abc.Callable[..., None]
        The gate, which names nothing when it passes.
    """

    def gate(report: Plan, plan: Plan, index: int) -> None:
        """Fail at the cutoff action.

        Raises
        ------
        ValueError
            At the cutoff.
        """
        del report, plan
        if index == cutoff:
            message = f"bad gate {cutoff}"
            raise ValueError(message)

    return gate


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


class Delayed121Tests:
    """Offline fault controls for delayed-121 default-response gates."""

    def test_wrong_default_text_and_subject_uid_rejected(self, plan: Plan) -> None:
        """A stale default text and a subject with the wrong name are refused."""
        name = b"A35-absent-215"
        good = {103: SUBJECT_UID, 102: name, 113: b"\0\4", 101: cases.DEFAULT}
        verifier.check_auto(frame(good), SUBJECT_UID, name)
        wrong = dict(good)
        wrong[101] = b"stale"
        with pytest.raises(ValueError, match="default text"):
            verifier.check_auto(frame(wrong), SUBJECT_UID, name)
        announcement = {
            "action": 19,
            "connection": "main",
            "type": 301,
            **frame({103: OBSERVER_UID, 102: name, 104: b"\0\7"}),
        }
        with pytest.raises(ValueError, match="301 identity"):
            verifier.subject_uid(
                {"frames": [announcement]},
                plan["expectation"]["cases"][0],
                OBSERVER_UID,
            )

    def test_first_bad_identity_and_case_stop_before_dependent_work(
        self, tmp_path: Path, plan: Plan
    ) -> None:
        """A failed gate stops the run at its action and still writes the report."""
        (tmp_path / "plan.json").write_text(json.dumps(plan))
        (tmp_path / "binary").write_bytes(b"offline")
        for stop in FIRST_STOPS:
            RecordingRecorder.executed = []
            output = tmp_path / f"stop-{stop}"
            with (
                mock.patch.object(verifier, "Recorder", RecordingRecorder),
                mock.patch.object(verifier, "digest", return_value=cases.ORACLE_SHA256),
                mock.patch.object(verifier, "gate", side_effect=failing_at(stop)),
            ):
                result = verifier.run_gated(
                    tmp_path / "plan.json", tmp_path / "binary", BASELINE, output
                )
            assert result["status"] == "failed", "expected a failed run"
            assert RecordingRecorder.executed[-1] == stop, "expected the run to stop"
            assert (output / "report.json").exists(), "expected a report"
            assert (output / "stage-gates.json").exists(), "expected stage gates"
