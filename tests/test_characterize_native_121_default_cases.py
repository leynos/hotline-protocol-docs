"""Characterize ``native_121_default_cases`` before it is refactored.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``) and must hold on the refactored module;
``tests/test_pin_equivalence.py`` runs these tests against both. The step
builders and the observation plan are pinned by fingerprints of their exact
output. The command line and the identity check, which the planner shares with
the settings-transition planner, are covered by
``test_characterize_baseline_planners.py``.
"""

import hashlib
import json
from pathlib import Path

import native_121_default_cases as cases
import pytest

ROOT = Path(__file__).resolve().parents[1]
BASELINE_PLAN = (
    ROOT / "evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01"
    "/capture/plan.json"
)
DEFAULT_TEXT = b"I'm not able to respond right now. Please try later!"
ABSENT_FINGERPRINT = "4616b06c6ab681a23ad27db44eef854632470aee99f6dd75415ce04d1afc2425"
EMPTY_FINGERPRINT = "5b52e96e3687389b0e3e6ce8467db5bd6e253b87c672d93d9020421c48e4c54f"
OBSERVE_FINGERPRINT = "2fad767f16aa6309800917f16ddc399a5e892b6f2fa743abb8816ce19a517f3b"
OBSERVE_STEPS = 70
ROSTER_FINGERPRINT = "b89898b87299eb221011696bae1ecd8f9af20573aede63c2d6733ae510602b22"
BARRIER_FINGERPRINT = "40bd3f254a45603b523fc1ef1f904af4c28b66fb2b7c050dbbe3b032bd895b71"
PLAN_FINGERPRINT = "cfe2772fb48a4a04b1d1bf886db91629fb4bc342720fbf67ecd39f86b9325583"


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


class StepBuilderTests:
    """The roster, barrier and delayed-case builders."""

    def test_the_default_text_is_unchanged(self) -> None:
        """The automatic response that the server is expected to substitute."""
        assert cases.DEFAULT == DEFAULT_TEXT, "expected the default text"

    def test_a_roster_request_is_a_300_and_its_reply(self) -> None:
        """One send and one matched read on the main connection."""
        steps = cases.roster(10)
        assert [step["op"] for step in steps] == ["send", "read_frame"], "op order"
        assert fingerprint(steps) == ROSTER_FINGERPRINT, "expected the same steps"

    def test_a_barrier_checks_the_main_and_the_named_subject_connection(self) -> None:
        """A 500 request, its reply and two quiet seconds on each."""
        steps = cases.barrier(31, "subject_absent")
        assert [step["connection"] for step in steps[::3]] == [
            "main",
            "subject_absent",
        ], "expected the two connections"
        assert fingerprint(steps) == BARRIER_FINGERPRINT, "expected the same steps"

    def test_the_absent_case_is_unchanged(self) -> None:
        """Steps and detail of the case that omits field 215."""
        built = cases.delayed_case("absent", 0)
        assert built[1]["subject_connection"] == "subject_absent", "connection"
        assert built[1]["name_hex"] == b"A35-absent-215".hex(), "expected the name"
        assert fingerprint(built) == ABSENT_FINGERPRINT, "expected the same case"

    def test_the_empty_case_sends_an_empty_215(self) -> None:
        """Steps and detail of the case that sends field 215 empty."""
        built = cases.delayed_case("empty", 1)
        assert built[1]["icon_hex"] == "0008", "expected the second icon"
        assert (built[1]["agreement_id"], built[1]["pm_id"]) == (40, 50), "ids"
        assert fingerprint(built) == EMPTY_FINGERPRINT, "expected the same case"

    def test_the_observation_is_unchanged(self) -> None:
        """Both cases, with their first and last step indices."""
        steps, details = cases.observe()
        assert len(steps) == OBSERVE_STEPS, "expected the step count"
        assert [d["label"] for d in details] == ["absent", "empty"], "case labels"
        assert fingerprint([steps, details]) == OBSERVE_FINGERPRINT, "expected same"

    def test_the_observation_plan_is_unchanged(self, raw: bytes) -> None:
        """The plan, its expectation and its operator text."""
        runtime = json.loads(raw)["environment"]
        observed = cases.plans(runtime, raw)["observe"]
        assert fingerprint(observed) == PLAN_FINGERPRINT, "expected the same plan"
        assert observed["expectation"]["pm_request_count"] == 2, "expected two"
        assert observed["gap_ids"] == ["GAP-029", "GAP-030"], "expected the gaps"
        assert observed["operator"].startswith("A35 offline 121"), "operator"
