"""Reject incorrect native queue positions, owners and shortened timer evidence."""

import json
import typing as typ
from pathlib import Path

import pytest
from native_wire_names import FIELD_QUEUE_POSITION, TYPE_QUEUE_NOTIFICATION
from pcap_tcp import read_packets
from verify_native_queues import check_case, notices, references, verify

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-12/native-queue-01"
)
CASES = 4
MIN_PENDING_AGE = 490
LAST_MODE_NOTICES = [5, 4, 3, 2, 1, 0]
SHORT_WINDOW_NS = 1


def capture(name: str) -> tuple[dict[str, typ.Any], dict[str, typ.Any]]:
    """Read the report and plan of one retained queue case.

    Returns
    -------
    tuple[dict[str, typing.Any], dict[str, typing.Any]]
        The report and the plan.
    """
    case = BATCH / "transcripts" / name
    return json.loads((case / "report.json").read_text()), json.loads(
        (case / "plan.json").read_text()
    )


class QueueTests:
    """Reject queue evidence whose positions, owners or windows are wrong."""

    def test_native_queue_corpus(self) -> None:
        """The retained corpus verifies, with its timed and mode cases intact."""
        result = verify(BATCH)
        assert len(result["cases"]) == CASES, "expected the four retained cases"
        timed = next(c for c in result["cases"] if c["case"] == "queue-pending-timeout")
        assert timed["admission_after_initial_ack_host_seconds"] >= MIN_PENDING_AGE, (
            "expected the pending entry to age past the bound"
        )
        modes = next(c for c in result["cases"] if c["case"] == "queue-mode-matrix")
        assert modes["notification_positions"]["m16"] == LAST_MODE_NOTICES, (
            "expected the last mode to count down from five"
        )

    def test_wrong_queue_position_is_rejected(self) -> None:
        """A notification that reports the wrong position is refused."""
        report, plan = capture("queue-mode-matrix")
        first = next(
            f for f in report["frames"] if f["type"] == TYPE_QUEUE_NOTIFICATION
        )
        next(v for v in first["fields"] if v["id"] == FIELD_QUEUE_POSITION)["hex"] = (
            "0001"
        )
        with pytest.raises(ValueError, match="Queue notification sequence differs"):
            check_case("queue-mode-matrix", report, plan, {}, [])

    def test_notification_must_reach_the_reference_owner(self) -> None:
        """A notification delivered to another session is refused."""
        report, plan = capture("queue-two-owner-order")
        first = next(
            f
            for f in report["frames"]
            if f["type"] == TYPE_QUEUE_NOTIFICATION and f["connection"] == "b"
        )
        first["connection"] = "a"
        with pytest.raises(ValueError, match="different owner"):
            notices(report, references(report, plan))

    def test_nominal_timer_plan_requires_measured_pause_windows(self) -> None:
        """A pause shorter than the plan's window is refused."""
        report, plan = capture("queue-pending-timeout")
        pause = next(e for e in report["events"] if e["event"] == "pause")
        prior = [e for e in report["events"] if e["action"] < pause["action"]][-1]
        pause["elapsed_ns"] = prior["elapsed_ns"] + SHORT_WINDOW_NS
        with pytest.raises(ValueError, match="Shortened timed queue window"):
            check_case(
                "queue-pending-timeout",
                report,
                plan,
                {"expired": {"guest_server_initiated_close": True}},
                read_packets(BATCH / "guest.pcap"),
            )
