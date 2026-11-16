"""Offline contract tests for the bounded same-session 304 fixture's planner.

These two tests were the planner's half of ``test_native_settings_transition``,
which keeps the tests of the capture driver ``verify_native_settings_transition``;
their class and method names are unchanged.
"""

import typing as typ
from pathlib import Path

import native_settings_transition_cases as cases
import pytest

type Plan = dict[str, typ.Any]

BASELINE = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01"
    / "capture/plan.json"
)
UNIQUE_MESSAGES = 8


@pytest.fixture(scope="module")
def baseline_raw() -> bytes:
    """Read the retained baseline plan.

    Returns
    -------
    bytes
        The plan's bytes.
    """
    return BASELINE.read_bytes()


@pytest.fixture(scope="module")
def baseline(baseline_raw: bytes) -> Plan:
    """Parse the retained baseline plan.

    Returns
    -------
    dict[str, typing.Any]
        The baseline, as the planner loads it.
    """
    return cases.load_baseline(baseline_raw)


@pytest.fixture(scope="module")
def plan(baseline: Plan, baseline_raw: bytes) -> Plan:
    """Prepare the observation plan.

    Returns
    -------
    dict[str, typing.Any]
        The observation.
    """
    return cases.plans(baseline["environment"], baseline_raw)["observe"]


class SettingsTransitionTests:
    """Offline contract tests for the bounded same-session 304 fixture."""

    def test_full_baseline_and_bounded_unique_sequence(
        self, baseline: Plan, baseline_raw: bytes, plan: Plan
    ) -> None:
        """The baseline frames the observation, whose eight messages are unique."""
        pair = cases.plans(baseline["environment"], baseline_raw)
        assert pair["preflight"] == pair["postflight"], "expected the same baseline"
        assert [w["label"] for w in plan["expectation"]["windows"]] == [
            s.label for s in cases.STAGES
        ], "expected one window per stage"
        sent = "".join(s["hex"] for s in plan["steps"] if s["op"] == "send")
        assert "{peer_uid}" in sent, "expected the saved peer variable"
        texts = {w["pm_text_hex"] for w in plan["expectation"]["windows"]}
        assert len(texts) == UNIQUE_MESSAGES, "expected eight unique messages"

    def test_identity_and_baseline_fail_closed(
        self, baseline: Plan, baseline_raw: bytes
    ) -> None:
        """A changed baseline hash or runtime identity is refused."""
        with pytest.raises(ValueError, match="SHA-256"):
            cases.load_baseline(baseline_raw + b" ")
        with pytest.raises(ValueError, match="Runtime identity"):
            cases.plans(dict(baseline["environment"], emulator_pid=-1), baseline_raw)
