"""Characterize ``native_settings_transition_cases`` before it is refactored.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``) and must hold on the refactored module;
``tests/test_pin_equivalence.py`` runs these tests against both. The stage table,
the step builders and the observation plan are pinned by fingerprints of their
exact output. The command line and the identity check, which the planner shares
with the 121-default planner, are covered by
``test_characterize_baseline_planners.py``.
"""

import hashlib
import json
from pathlib import Path

import native_settings_transition_cases as cases
import pytest

ROOT = Path(__file__).resolve().parents[1]
BASELINE_PLAN = (
    ROOT / "evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01"
    "/capture/plan.json"
)
STAGE_LABELS = [
    "explicit",
    "omitted",
    "empty",
    "unknown-only",
    "mixed-unknown",
    "disable-absent",
    "disable-zero",
    "reenable",
]
STAGES_FINGERPRINT = "5a0eedfc6ae742de54d34519a5bc9adbb8c0457b2c1e18ac421a67a9cd91b2e4"
OBSERVE_FINGERPRINT = "45870c8540ba378b49782a00b2cf017dab673561bcb6f253ff715571918170a3"
OBSERVE_STEPS = 129
SETTINGS_FINGERPRINT = (
    "9456d8ef2660bf2942183151664816a9a40e867cdbf5c7332f01fb304eadea12"
)
BARRIER_FINGERPRINT = "09678cd0d40a03d526a2692e29ac0a31794ca9d871859c9308521d0cb4e1c226"
PLAN_FINGERPRINT = "65b629b212ebebe5f1b874cc22bfdde9ac52fd17f4ff4af3bc8d697de96dfd69"
DEFAULT_TEXT = b"I'm not able to respond right now. Please try later!"


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


class StageTableTests:
    """The constants and the eight stages."""

    def test_the_names_and_the_default_text_are_unchanged(self) -> None:
        """The two session names and the default automatic response."""
        assert cases.SUBJECT == b"A32-Subject", "expected the subject name"
        assert cases.EXPLICIT == b"A32-Explicit", "expected the explicit name"
        assert cases.DEFAULT == DEFAULT_TEXT, "expected the default text"

    def test_the_eight_stages_are_unchanged(self) -> None:
        """Labels in order, and every field of every stage."""
        assert [stage.label for stage in cases.STAGES] == STAGE_LABELS, "labels"
        table = [repr(stage) for stage in cases.STAGES]
        assert fingerprint(table) == STAGES_FINGERPRINT, "expected the same fields"

    def test_a_stage_is_frozen(self) -> None:
        """A stage cannot be reassigned."""
        with pytest.raises(AttributeError):
            cases.STAGES[0].label = "other"  # ty: ignore[invalid-assignment]  # the frozen stage is the subject of the test


class StepBuilderTests:
    """The step builders and the observation they make."""

    def test_the_settings_of_each_stage_are_one_304_send_on_the_subject(self) -> None:
        """Absent fields are left out of the request."""
        built = [cases.settings(s, 20 + i) for i, s in enumerate(cases.STAGES)]
        assert {step["connection"] for step in built} == {"subject"}, "connection"
        assert fingerprint(built) == SETTINGS_FINGERPRINT, "expected the same steps"

    def test_a_barrier_checks_both_connections(self) -> None:
        """A 500 request, its reply and two quiet seconds, main then subject."""
        steps = cases.barrier(100)
        assert [step["op"] for step in steps] == [
            "send",
            "read_frame",
            "expect_quiet",
            "send",
            "read_frame",
            "expect_quiet",
        ], "expected the op order"
        assert [step["connection"] for step in steps[::3]] == [
            "main",
            "subject",
        ], "expected main then subject"
        assert fingerprint(steps) == BARRIER_FINGERPRINT, "expected the same steps"

    def test_the_observation_is_unchanged(self) -> None:
        """The steps and the eight windows, byte for byte."""
        steps, windows = cases.observe()
        assert len(steps) == OBSERVE_STEPS, "expected the step count"
        assert [w["label"] for w in windows] == STAGE_LABELS, "window labels"
        assert fingerprint([steps, windows]) == OBSERVE_FINGERPRINT, "expected same"

    def test_each_window_names_its_unique_message(self) -> None:
        """The windows partition the stages and carry distinct texts."""
        _steps, windows = cases.observe()
        assert [w["pm_id"] for w in windows] == list(range(60, 68)), "message ids"
        texts = {bytes.fromhex(w["pm_text_hex"]) for w in windows}
        assert len(texts) == len(STAGE_LABELS), "expected distinct texts"
        assert windows[0]["pm_text_hex"] == b"a32-pm-0-explicit".hex(), "first text"

    def test_the_observation_plan_is_unchanged(self, raw: bytes) -> None:
        """The plan, its expectation and its operator text."""
        runtime = json.loads(raw)["environment"]
        observed = cases.plans(runtime, raw)["observe"]
        assert fingerprint(observed) == PLAN_FINGERPRINT, "expected the same plan"
        assert observed["expectation"]["pm_count"] == len(STAGE_LABELS), "count"
        assert observed["gap_ids"] == ["GAP-029", "GAP-030"], "expected the gaps"
        assert observed["operator"].startswith("A32 offline preparation"), "operator"
