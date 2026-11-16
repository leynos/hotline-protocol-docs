"""Keep ID reuse, queued collisions and envelope rejection evidence distinct."""

import copy
import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from native_correlation_cases import correlation
from verify_native_correlation import check_outcome, verify, verify_oracle
from verify_native_framing import check_quiet

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-12/native-correlation-01"
)
CASES = 24
SHORTENED_NS = 1_000_000_000
UNSUPPORTED_TYPE = 65535
BOOTSTRAP_FRAMES = 3  # the login ACK and its two notifications
WRONG_INCREMENT_HEX = "34040002"


class CorrelationTests:
    """Keep ID reuse, queued collisions and envelope rejection evidence distinct."""

    @staticmethod
    def data(name: str) -> tuple[Report, Report, Report]:
        """Load a retained case's report, its planned expectation and its packets.

        Returns
        -------
        tuple[dict[str, typing.Any], dict[str, typing.Any], dict[str, typing.Any]]
            The report, the expectation and the packet reconciliation.
        """
        report = json.loads((BATCH / "transcripts" / name / "report.json").read_text())
        packets = json.loads((BATCH / "packet-reconciliation.json").read_text())[name]
        return report, correlation()[name][1], packets

    def test_retained_native_id_and_envelope_corpus(self) -> None:
        """The retained corpus verifies with all of its cases."""
        assert len(verify(BATCH)["cases"]) == CASES, "the corpus has 24 cases"

    def test_client_zero_id_is_not_replaced_by_server_allocator(self) -> None:
        """A reply whose ID was replaced by the allocator's is refused."""
        report, expected, packets = self.data("client-id-boundaries-and-reuse")
        report["frames"][BOOTSTRAP_FRAMES]["id"] = 1
        with pytest.raises(ValueError, match="Direct reply correlation differs"):
            check_outcome(report, expected, packets)

    def test_pipelined_duplicate_is_not_two_independent_acks(self) -> None:
        """A third reply to a pipelined duplicate is refused."""
        report, expected, packets = self.data("pipelined-duplicate-id")
        report["frames"].insert(
            BOOTSTRAP_FRAMES + 1, copy.deepcopy(report["frames"][BOOTSTRAP_FRAMES])
        )
        with pytest.raises(ValueError, match="Direct reply count differs"):
            check_outcome(report, expected, packets)

    def test_late_reply_does_not_generate_another_ack(self) -> None:
        """An extra ACK after a late reply is refused."""
        report, expected, packets = self.data("late-reply-255-completed-client-id")
        report["frames"].append(copy.deepcopy(report["frames"][-1]))
        with pytest.raises(ValueError, match="Direct reply count differs"):
            check_outcome(report, expected, packets)

    def test_notification_counter_is_separate_from_client_id(self) -> None:
        """A notification that took the client's ID is refused."""
        report, expected, packets = self.data("notification-and-direct-reply-id-spaces")
        report["frames"][BOOTSTRAP_FRAMES + 1]["id"] = 1
        with pytest.raises(ValueError, match="Notification ID allocation differs"):
            check_outcome(report, expected, packets)

    def test_mixed_collision_preserves_the_first_payload_prefix(self) -> None:
        """A collision whose name was not replaced is refused."""
        report, expected, packets = self.data("pipelined-id-collision-last-type")
        field = next(
            f for f in report["frames"][BOOTSTRAP_FRAMES]["fields"] if f["id"] == 102
        )
        field["hex"] = b"collision-name".hex()
        with pytest.raises(ValueError, match="Collision/notification settings differ"):
            check_outcome(report, expected, packets)

    def test_unsupported_request_error_is_a_zero_type_direct_reply(self) -> None:
        """An error reply that carries the request's type is refused."""
        report, expected, packets = self.data("unsupported-request-type-65535")
        report["frames"][BOOTSTRAP_FRAMES]["type"] = UNSUPPORTED_TYPE
        with pytest.raises(ValueError, match="Unsupported error envelope differs"):
            check_outcome(report, expected, packets)

    def test_reply_size_failure_requires_native_close(self) -> None:
        """A reply-size rejection without a native close is refused."""
        report, expected, packets = self.data("reply-255-zero-size-rejection")
        packets["main"]["guest_server_initiated_close"] = False
        with pytest.raises(ValueError, match="Missing native reply-size close"):
            check_outcome(report, expected, packets)

    def test_partial_input_eof_is_a_response_to_client_half_close(self) -> None:
        """A native close in answer to a client half-close is refused."""
        report, expected, packets = self.data("underfilled-transaction-eof")
        packets["main"]["guest_server_initiated_close"] = True
        with pytest.raises(ValueError, match="Missing native reply-size close"):
            check_outcome(report, expected, packets)

    def test_late_reply_silence_has_an_observed_duration(self) -> None:
        """A quiet observation shorter than its plan is refused."""
        name = "late-reply-255-completed-client-id"
        report, _, _ = self.data(name)
        plan = json.loads((BATCH / "transcripts" / name / "plan.json").read_text())
        event = next(e for e in report["events"] if e["event"] == "quiet")
        event["elapsed_ns"] -= SHORTENED_NS
        with pytest.raises(ValueError, match="shorter than its plan"):
            check_quiet(report, plan)

    def test_wrap_rule_is_pinned_to_machine_instructions(self, tmp_path: Path) -> None:
        """Changed increment instructions are refused."""
        shutil.copytree(BATCH / "oracle-queries", tmp_path / "oracle-queries")
        for p in BATCH.glob("oracle-*.json"):
            shutil.copy2(p, tmp_path / p.name)
        file = tmp_path / "oracle-queries/ID-A-10058d70.json"
        record = json.loads(file.read_text())
        record["result"]["structuredContent"]["items"][1]["bytes"] = WRONG_INCREMENT_HEX
        file.write_text(json.dumps(record))
        with pytest.raises(ValueError, match="increment/zero-skip instructions differ"):
            verify_oracle(tmp_path)
