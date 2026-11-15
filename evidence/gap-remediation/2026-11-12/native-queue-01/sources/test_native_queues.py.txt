"""Reject incorrect native queue positions, owners and shortened timer evidence."""

import json
import unittest
from pathlib import Path

from pcap_tcp import read_packets
from verify_native_queues import check_case, notices, references, verify

BATCH = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-12/native-queue-01"
)


def capture(name: str) -> tuple[dict, dict]:
    case = BATCH / "transcripts" / name
    return json.loads((case / "report.json").read_text()), json.loads(
        (case / "plan.json").read_text()
    )


class QueueTests(unittest.TestCase):
    def test_native_queue_corpus(self) -> None:
        result = verify(BATCH)
        self.assertEqual(len(result["cases"]), 4)
        timed = next(c for c in result["cases"] if c["case"] == "queue-pending-timeout")
        self.assertGreaterEqual(timed["admission_after_initial_ack_host_seconds"], 490)
        modes = next(c for c in result["cases"] if c["case"] == "queue-mode-matrix")
        self.assertEqual(modes["notification_positions"]["m16"], [5, 4, 3, 2, 1, 0])

    def test_wrong_queue_position_is_rejected(self) -> None:
        report, plan = capture("queue-mode-matrix")
        first = next(f for f in report["frames"] if f["type"] == 211)
        next(v for v in first["fields"] if v["id"] == 116)["hex"] = "0001"
        with self.assertRaisesRegex(ValueError, "Queue notification sequence differs"):
            check_case("queue-mode-matrix", report, plan, {}, [])

    def test_notification_must_reach_the_reference_owner(self) -> None:
        report, plan = capture("queue-two-owner-order")
        first = next(
            f for f in report["frames"] if f["type"] == 211 and f["connection"] == "b"
        )
        first["connection"] = "a"
        with self.assertRaisesRegex(ValueError, "different owner"):
            notices(report, references(report, plan))

    def test_nominal_timer_plan_requires_measured_pause_windows(self) -> None:
        report, plan = capture("queue-pending-timeout")
        pause = next(e for e in report["events"] if e["event"] == "pause")
        prior = [e for e in report["events"] if e["action"] < pause["action"]][-1]
        pause["elapsed_ns"] = prior["elapsed_ns"] + 1
        with self.assertRaisesRegex(ValueError, "Shortened timed queue window"):
            check_case(
                "queue-pending-timeout",
                report,
                plan,
                {"expired": {"guest_server_initiated_close": True}},
                read_packets(BATCH / "guest.pcap"),
            )


if __name__ == "__main__":
    unittest.main()
