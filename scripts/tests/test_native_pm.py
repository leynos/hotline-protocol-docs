"""Offline requirements for the bounded native PM preparation packet."""

import copy
import json
import sys
import typing as typ
from pathlib import Path
from unittest import mock

import native_pm_cases as cases
import pytest
from protocol_capture import validate_plan
from verify_native_pm import check_variant

BASELINE_PLAN = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01"
    / "capture/plan.json"
)
BASELINE_STEPS = 29
PM_REQUESTS = 7
MAX_PM_REQUESTS = 20
MIN_QUIET_BARRIERS = 14
TYPE_PRIVATE_MESSAGE = 108
FORBIDDEN_TYPES = {350, 351, 353, 203, 204}
SHORT_BASELINE_STEPS = 18
DOWNLOAD_READ_STEP = 21
SAMPLE_UID = b"\0\x02"
PM_OPTIONS = {1: b"\0\x01", 2: b"\0\x02"}
FIELD_USER_ID = 103
FIELD_NAME = 102
FIELD_OPTIONS = 113
FIELD_DATA = 101
FIELD_QUOTE = 214


class Baseline(typ.NamedTuple):
    """The A7 baseline plan as bytes and as parsed, with its runtime."""

    raw: bytes
    plan: dict[str, typ.Any]
    runtime: dict[str, typ.Any]


@pytest.fixture(scope="module")
def baseline() -> Baseline:
    """Load the retained A7 baseline plan through the planner's own checks.

    Returns
    -------
    Baseline
        The raw bytes, the parsed plan and the plan's environment.
    """
    raw = BASELINE_PLAN.read_bytes()
    plan = cases.load_baseline(raw)
    return Baseline(raw, plan, plan["environment"])


def message_types(steps: list[dict[str, typ.Any]]) -> list[int]:
    """List the transaction type of each sent packet.

    Returns
    -------
    list[int]
        One type per ``send`` step.
    """
    return [int(s["hex"][4:8], 16) for s in steps if s["op"] == "send"]


class NativePMPlanTests:
    """Check the plans, the baselines and the variant checker."""

    def test_bounded_plan_and_baselines(self, baseline: Baseline) -> None:
        """The three plans are valid, bounded and carry the baseline unchanged."""
        plans = cases.plans(baseline.runtime, baseline.raw)
        assert set(plans) == {"preflight", "observe", "postflight"}, "expected plans"
        for plan in plans.values():
            validate_plan(plan)
        assert plans["preflight"]["steps"] == plans["postflight"]["steps"], (
            "expected matching preflight and postflight"
        )
        assert plans["preflight"] == baseline.plan, "expected the baseline verbatim"
        assert len(plans["preflight"]["steps"]) == BASELINE_STEPS, "expected 29 steps"
        assert plans["preflight"]["endpoints"] == baseline.plan["endpoints"], (
            "expected the baseline endpoints"
        )
        observe = plans["observe"]
        expectation = observe["expectation"]
        assert expectation["baseline_plan_sha256"] == cases.BASELINE_SHA256, (
            "expected the baseline hash"
        )
        assert expectation["pm_request_count"] == PM_REQUESTS, "expected 7 requests"
        assert expectation["pm_request_count"] <= MAX_PM_REQUESTS, "expected a bound"
        assert expectation["cases"] == list(cases.CASES), "expected the case list"
        sent = message_types(observe["steps"])
        assert sent.count(TYPE_PRIVATE_MESSAGE) == PM_REQUESTS, "expected 7 sends"
        assert not FORBIDDEN_TYPES & set(sent), "expected no account or upload sends"
        assert observe["steps"][-2]["op"] == "close", "expected the peer to close"
        assert observe["steps"][-1]["op"] == "close", "expected the main to close"

    def test_uid_substitutions_are_current_session_only(
        self, baseline: Baseline
    ) -> None:
        """Target UIDs come from saved variables, never from a literal."""
        observe = cases.plans(baseline.runtime, baseline.raw)["observe"]
        sent = "".join(s["hex"] for s in observe["steps"] if s["op"] == "send")
        assert "{main_uid}" in sent, "expected the main UID variable"
        assert "{peer_uid}" in sent, "expected the peer UID variable"
        assert "00000067" not in sent, "expected no literal UID field header"

    def test_unique_case_texts_and_negative_barriers(self, baseline: Baseline) -> None:
        """Every case has its own text, and quiet barriers separate the cases."""
        texts = [case.text for case in cases.CASES.values() if case.text]
        assert len(texts) == len(set(texts)), "expected unique case texts"
        observe = cases.plans(baseline.runtime, baseline.raw)["observe"]
        quiet = sum(s["op"] == "expect_quiet" for s in observe["steps"])
        assert quiet >= MIN_QUIET_BARRIERS, "expected the negative barriers"

    def test_variant_rejects_wrong_option_and_missing_quote(self) -> None:
        """A wrong option or a missing quote field fails the 104 check."""
        fields = {
            FIELD_USER_ID: SAMPLE_UID,
            FIELD_NAME: cases.MAIN,
            FIELD_OPTIONS: PM_OPTIONS[1],
            FIELD_DATA: b"hello",
            FIELD_QUOTE: cases.QUOTE,
        }
        check_variant(fields, SAMPLE_UID, cases.MAIN, 1, b"hello", cases.QUOTE)
        with pytest.raises(ValueError, match="identity/option"):
            check_variant(fields, SAMPLE_UID, cases.MAIN, 2, b"hello", cases.QUOTE)
        with pytest.raises(ValueError, match="field set"):
            check_variant(
                {k: v for k, v in fields.items() if k != FIELD_QUOTE},
                SAMPLE_UID,
                cases.MAIN,
                1,
                b"hello",
                cases.QUOTE,
            )

    def test_variant_rejects_empty_generated_text(self) -> None:
        """A generated-text variant with empty text fails."""
        fields = {
            FIELD_USER_ID: SAMPLE_UID,
            FIELD_NAME: cases.PEER,
            FIELD_OPTIONS: PM_OPTIONS[2],
            FIELD_DATA: b"",
        }
        with pytest.raises(ValueError, match="Generated PM text"):
            check_variant(fields, SAMPLE_UID, cases.PEER, 2, None)

    def test_baseline_rejects_mutation_or_short_readback(
        self, baseline: Baseline
    ) -> None:
        """A changed byte, a short plan or another runtime is refused."""
        with pytest.raises(ValueError, match="SHA-256"):
            cases.load_baseline(baseline.raw + b" ")
        short = copy.deepcopy(baseline.plan)
        short["steps"] = short["steps"][:SHORT_BASELINE_STEPS]
        with pytest.raises(ValueError, match="29-step"):
            cases.check_baseline_structure(short)
        short = copy.deepcopy(baseline.plan)
        short["steps"][DOWNLOAD_READ_STEP]["size"] -= 1
        with pytest.raises(ValueError, match="download sequence"):
            cases.check_baseline_structure(short)
        wrong_runtime = dict(baseline.runtime, emulator_pid=-1)
        with pytest.raises(ValueError, match="Runtime identity"):
            cases.plans(wrong_runtime, baseline.raw)

    def test_export_preserves_full_baseline_bytes(
        self, baseline: Baseline, tmp_path: Path
    ) -> None:
        """The command line writes the baseline bytes and a full observe plan."""
        record = tmp_path / "runtime.json"
        record.write_text(json.dumps(baseline.runtime))
        output = tmp_path / "plans"
        argv = [
            "native_pm_cases.py",
            "--runtime-record",
            str(record),
            "--baseline-plan",
            str(BASELINE_PLAN),
            "--output",
            str(output),
        ]
        with mock.patch.object(sys, "argv", argv):
            cases.main()
        preflight = (output / "preflight.json").read_bytes()
        postflight = (output / "postflight.json").read_bytes()
        assert preflight == baseline.raw, "expected the preflight baseline bytes"
        assert postflight == baseline.raw, "expected the postflight baseline bytes"
        steps = json.loads((output / "observe.json").read_text())["steps"]
        assert len(steps) == len(cases.observe()), "expected every observe step"
