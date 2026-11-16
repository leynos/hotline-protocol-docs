"""Characterize ``native_pm_cases`` before it is refactored.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``) and must hold on the refactored module;
``tests/test_pin_equivalence.py`` runs these tests against both. The plan
builders are pinned by fingerprints of their exact output. This module covers
the step and plan builders; ``test_characterize_native_pm_baseline.py`` covers
the baseline checks, the order of faults and the command line, whose usage text
is not pinned, only its exit status.
"""

import hashlib
import json
from pathlib import Path

import native_pm_cases as cases
import pytest

CHARACTERIZES = "native_pm_cases.py"
ROOT = Path(__file__).resolve().parents[1]
BASELINE_PLAN = (
    ROOT / "evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01"
    "/capture/plan.json"
)
OBSERVE_STEPS = 151
OBSERVE_FINGERPRINT = "4cfc5a4723bb9be7791683766601b11280aa1ca379dda839f6d5899322a6717a"
PREFLIGHT_FINGERPRINT = (
    "40a55b07520215c8ce21a76ab6148fc430cea0cf9da44cdc8facad83afd3590a"
)
OBSERVE_PLAN_FINGERPRINT = (
    "44f7bcf7b0d2760a57921684e26cdd99f9f7dbd4e1e942ef9cca0ca922801564"
)
CASES_FINGERPRINT = "dd406e2073c5d701a0d43fe1103b43ecf9a361fb98fd7396c267a86657b6751f"
BARRIER_FINGERPRINT = "89d7a5594fb101df44539d2a23c39fecfd7b6c504a5f11a7cee7171b66484466"
AUTO_SETTINGS_FINGERPRINT = (
    "729968eb635a9c85a685230ddd92e830a4591bc4d973851d348ca87f9c3807a5"
)
MESSAGE_FINGERPRINT = "8b28b5a5705408318ccef1b233b56d8dbf426f8de2e2a0ea3354306981d4c86c"
SETTINGS_SENT = (
    "0000013000000014000000000000001d0000001d00030066000b504d2d4d61696e2d41323600"
    "6800020001007100020000"
)


def fingerprint(value: object) -> str:
    """Hash the JSON text of a value, keys in their existing order.

    Returns
    -------
    str
        The lower-case hexadecimal SHA-256.
    """
    return hashlib.sha256(json.dumps(value).encode()).hexdigest()


@pytest.fixture(scope="module")
def raw() -> bytes:
    """Read the retained baseline plan.

    Returns
    -------
    bytes
        The plan's bytes.
    """
    return BASELINE_PLAN.read_bytes()


class PlanBuilderTests:
    """The step builders and the plans they make, pinned by fingerprint."""

    def test_the_constants_are_unchanged(self) -> None:
        """Names, quote, baseline hash and stream size."""
        assert (cases.MAIN, cases.PEER, cases.QUOTE) == (
            b"PM-Main-A26",
            b"PM-Peer-A26",
            b"quote-a26",
        ), "expected the recorded names"
        assert cases.FULL_STREAM_BYTES == 1049073, "expected the stream size"
        assert cases.BASELINE_SHA256.startswith("5d0aa3dc"), "expected the hash"

    def test_the_case_table_is_unchanged(self) -> None:
        """Seven cases in order with their fields."""
        assert list(cases.CASES) == [
            "direct-quoted",
            "recipient-refuses",
            "auto-and-original",
            "sender-refuses",
            "option-two",
            "option-three",
            "empty",
        ], "expected the case order"
        table = {name: repr(case) for name, case in cases.CASES.items()}
        assert fingerprint(table) == CASES_FINGERPRINT, "expected the same fields"

    def test_a_variable_message_is_built_from_its_fields(self) -> None:
        """The hex packs the type, identifier, length, user id and each field."""
        fields = [(113, b"\0\1"), (101, b"hi")]
        step = cases.variable_message(108, 5, "main_uid", fields, "peer")
        assert step["connection"] == "peer", "expected the named connection"
        assert "{main_uid}" in step["hex"], "expected the saved variable"
        assert fingerprint(step) == MESSAGE_FINGERPRINT, "expected the exact step"

    def test_a_variable_message_defaults_to_the_main_connection(self) -> None:
        """No connection means ``main``."""
        step = cases.variable_message(108, 5, "peer_uid", [])
        assert step["connection"] == "main", "expected the main connection"

    @pytest.mark.parametrize("uid", ["", "uid", "main_UID", "main_uid "])
    def test_a_user_id_variable_other_than_the_two_is_refused(self, uid: str) -> None:
        """Only ``main_uid`` and ``peer_uid`` are accepted."""
        message = "^UID must come from the current observed connection$"
        with pytest.raises(ValueError, match=message):
            cases.variable_message(108, 5, uid, [])

    def test_settings_send_one_packet_then_a_barrier(self) -> None:
        """A 304 send, then two requests and two quiet checks."""
        steps = cases.settings("main", 20, cases.MAIN, 0)
        assert [s["op"] for s in steps] == [
            "send",
            "send",
            "read_frame",
            "send",
            "read_frame",
            "expect_quiet",
            "expect_quiet",
        ], "expected a send and a barrier"
        assert steps[0]["hex"] == SETTINGS_SENT, "expected the settings packet"
        assert steps[1:] == cases.barrier(120), "expected the barrier at id + 100"

    def test_settings_with_an_automatic_reply_add_a_field(self) -> None:
        """The reply text is a fourth field."""
        steps = cases.settings("peer", 21, cases.PEER, 4, b"auto")
        plain = cases.settings("peer", 21, cases.PEER, 4)
        assert len(steps[0]["hex"]) > len(plain[0]["hex"]), "expected a longer packet"
        assert fingerprint(steps) == AUTO_SETTINGS_FINGERPRINT, "expected the steps"

    def test_a_barrier_asks_both_connections_then_expects_quiet(self) -> None:
        """Main then peer for each stage."""
        steps = cases.barrier(5)
        assert [s["connection"] for s in steps] == [
            "main",
            "main",
            "peer",
            "peer",
            "main",
            "peer",
        ], "expected the connection order"
        assert fingerprint(steps) == BARRIER_FINGERPRINT, "expected the exact steps"

    def test_the_observation_is_the_pinned_step_list(self) -> None:
        """151 steps, bit for bit."""
        steps = cases.observe()
        assert len(steps) == OBSERVE_STEPS, "expected 151 steps"
        assert fingerprint(steps) == OBSERVE_FINGERPRINT, "expected the exact steps"

    def test_the_prepared_plans_are_the_pinned_documents(self, raw: bytes) -> None:
        """Preflight and postflight are the baseline; observe is the full plan."""
        baseline = json.loads(raw)
        prepared = cases.plans(baseline["environment"], raw)
        assert list(prepared) == ["preflight", "observe", "postflight"], "order"
        assert fingerprint(prepared["preflight"]) == PREFLIGHT_FINGERPRINT, (
            "expected: the pinned plan"
        )
        assert fingerprint(prepared["postflight"]) == PREFLIGHT_FINGERPRINT, (
            "expected: the pinned plan"
        )
        assert fingerprint(prepared["observe"]) == OBSERVE_PLAN_FINGERPRINT, (
            "expected: the pinned plan"
        )
        keys = [
            "schema_version",
            "profile",
            "operator",
            "oracle_sha256",
            "gap_ids",
            "environment",
            "endpoints",
            "steps",
            "expectation",
        ]
        assert list(prepared["observe"]) == keys, "expected the plan keys in order"
