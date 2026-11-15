"""Keep ID reuse, queued collisions and envelope rejection evidence distinct."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from native_correlation_cases import correlation
from verify_native_correlation import check_outcome, verify, verify_oracle
from verify_native_framing import check_quiet

BATCH = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-12/native-correlation-01"
)


class CorrelationTests(unittest.TestCase):
    def data(self, name: str) -> tuple[dict, dict, dict]:
        report = json.loads((BATCH / "transcripts" / name / "report.json").read_text())
        packets = json.loads((BATCH / "packet-reconciliation.json").read_text())[name]
        return report, correlation()[name][1], packets

    def test_retained_native_id_and_envelope_corpus(self) -> None:
        self.assertEqual(len(verify(BATCH)["cases"]), 24)

    def test_client_zero_id_is_not_replaced_by_server_allocator(self) -> None:
        report, expected, packets = self.data("client-id-boundaries-and-reuse")
        report["frames"][3]["id"] = 1
        with self.assertRaisesRegex(ValueError, "Direct reply correlation differs"):
            check_outcome(report, expected, packets)

    def test_pipelined_duplicate_is_not_two_independent_acks(self) -> None:
        report, expected, packets = self.data("pipelined-duplicate-id")
        report["frames"].insert(4, copy.deepcopy(report["frames"][3]))
        with self.assertRaisesRegex(ValueError, "Direct reply count differs"):
            check_outcome(report, expected, packets)

    def test_late_reply_does_not_generate_another_ack(self) -> None:
        report, expected, packets = self.data("late-reply-255-completed-client-id")
        report["frames"].append(copy.deepcopy(report["frames"][-1]))
        with self.assertRaisesRegex(ValueError, "Direct reply count differs"):
            check_outcome(report, expected, packets)

    def test_notification_counter_is_separate_from_client_id(self) -> None:
        report, expected, packets = self.data("notification-and-direct-reply-id-spaces")
        report["frames"][4]["id"] = 1
        with self.assertRaisesRegex(ValueError, "Notification ID allocation differs"):
            check_outcome(report, expected, packets)

    def test_mixed_collision_preserves_the_first_payload_prefix(self) -> None:
        report, expected, packets = self.data("pipelined-id-collision-last-type")
        field = next(f for f in report["frames"][3]["fields"] if f["id"] == 102)
        field["hex"] = b"collision-name".hex()
        with self.assertRaisesRegex(
            ValueError, "Collision/notification settings differ"
        ):
            check_outcome(report, expected, packets)

    def test_unsupported_request_error_is_a_zero_type_direct_reply(self) -> None:
        report, expected, packets = self.data("unsupported-request-type-65535")
        report["frames"][3]["type"] = 65535
        with self.assertRaisesRegex(ValueError, "Unsupported error envelope differs"):
            check_outcome(report, expected, packets)

    def test_reply_size_failure_requires_native_close(self) -> None:
        report, expected, packets = self.data("reply-255-zero-size-rejection")
        packets["main"]["guest_server_initiated_close"] = False
        with self.assertRaisesRegex(ValueError, "Missing native reply-size close"):
            check_outcome(report, expected, packets)

    def test_partial_input_eof_is_a_response_to_client_half_close(self) -> None:
        report, expected, packets = self.data("underfilled-transaction-eof")
        packets["main"]["guest_server_initiated_close"] = True
        with self.assertRaisesRegex(ValueError, "Missing native reply-size close"):
            check_outcome(report, expected, packets)

    def test_late_reply_silence_has_an_observed_duration(self) -> None:
        name = "late-reply-255-completed-client-id"
        report, _, _ = self.data(name)
        plan = json.loads((BATCH / "transcripts" / name / "plan.json").read_text())
        event = next(e for e in report["events"] if e["event"] == "quiet")
        event["elapsed_ns"] -= 1_000_000_000
        with self.assertRaisesRegex(ValueError, "shorter than its plan"):
            check_quiet(report, plan)

    def test_wrap_rule_is_pinned_to_machine_instructions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(BATCH / "oracle-queries", root / "oracle-queries")
            for p in BATCH.glob("oracle-*.json"):
                shutil.copy2(p, root / p.name)
            file = root / "oracle-queries/ID-A-10058d70.json"
            record = json.loads(file.read_text())
            record["result"]["structuredContent"]["items"][1]["bytes"] = "34040002"
            file.write_text(json.dumps(record))
            with self.assertRaisesRegex(
                ValueError, "increment/zero-skip instructions differ"
            ):
                verify_oracle(root)


if __name__ == "__main__":
    unittest.main()
