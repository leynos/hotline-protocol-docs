"""Offline contract test for the delayed-121 default-response planner.

This was the planner's test in ``test_native_121_default``, which keeps the tests
of the capture driver ``verify_native_121_default``; its class and method names are
unchanged. The test also checks the plan against the driver's ``layout`` function,
so that the plan and the driver cannot drift apart.
"""

import copy
import typing as typ
from pathlib import Path

import native_121_default_cases as cases
import pytest
import verify_native_121_default as verifier

type Plan = dict[str, typ.Any]

BASELINE = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01"
    / "capture/plan.json"
)
BASELINE_STEPS = 29
CASE_COUNT = 2
CHANGED_STEP = 17  # the 121 of the first case
CHANGED_IDENTIFIER = 20


@pytest.fixture(scope="module")
def raw() -> bytes:
    """Read the retained baseline plan.

    Returns
    -------
    bytes
        The plan's bytes.
    """
    return BASELINE.read_bytes()


@pytest.fixture(scope="module")
def baseline(raw: bytes) -> Plan:
    """Parse the retained baseline plan.

    Returns
    -------
    dict[str, typing.Any]
        The baseline, as the planner loads it.
    """
    return cases.load_baseline(raw)


class Delayed121Tests:
    """Offline contract test for the delayed-121 default-response planner."""

    def test_exact_two_case_plan_and_full_baseline(
        self, baseline: Plan, raw: bytes
    ) -> None:
        """Two cases between two copies of the baseline, as the driver lays them out."""
        plans = cases.plans(baseline["environment"], raw)
        plan = plans["observe"]
        assert plans["preflight"] == baseline, "expected the baseline first"
        assert plans["postflight"] == baseline, "expected the baseline last"
        assert len(baseline["steps"]) == BASELINE_STEPS, "expected 29 baseline steps"
        assert [c["label"] for c in verifier.layout(plan)] == [
            "absent",
            "empty",
        ], "expected two cases"
        assert plan["expectation"]["pm_request_count"] == CASE_COUNT, "two messages"
        wrong = copy.deepcopy(plan)
        wrong["steps"][CHANGED_STEP]["hex"] = cases.packet(121, CHANGED_IDENTIFIER)
        with pytest.raises(ValueError, match="steps/cases"):
            verifier.layout(wrong)
