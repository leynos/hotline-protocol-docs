"""Checks for bounded 303 diagnostic plan construction and semantic validation."""

import copy
import json
import re
from pathlib import Path

import native_diagnostic_cases as cases
import pytest
from protocol_capture import decode_frame
from verify_native_diagnostics import semantic, verify

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-diagnostics-01"
)


class DiagnosticPlanTests:
    """Check the bounded 303 diagnostic plan and its UID substitution."""

    def test_uid_substitution_is_two_bytes(self) -> None:
        """A substituted UID is carried as a two-byte field 103."""
        step = cases.diagnostic_request("main", 11, "target_uid")
        frame = decode_frame(bytes.fromhex(step["hex"].replace("{target_uid}", "1234")))
        assert frame["data_size"] == 8, "data size"
        assert frame["fields"] == [{"id": 103, "hex": "1234"}], "UID field"

    def test_unknown_uid_substitution_rejected(self) -> None:
        """Only the current-session UID placeholder may be substituted."""
        with pytest.raises(
            ValueError, match=re.escape("Only current-session UIDs may be substituted")
        ):
            cases.diagnostic_request("main", 11, "other")

    def test_self_case_saves_uid_from_current_roster(self) -> None:
        """The self case saves the UID from the current roster and uses it."""
        steps, _ = cases.suites()["self"]
        roster = next(
            step for step in steps if step.get("save", {}).get("name") == "admin_uid"
        )
        assert roster["save"] == {
            "name": "admin_uid",
            "offset": 26,
            "size": 2,
        }, "saved roster UID"
        assert "{admin_uid}" in next(
            step["hex"] for step in steps if "{admin_uid}" in step.get("hex", "")
        ), "UID placeholder"

    def test_owned_account_is_unique_and_zero_privilege(self) -> None:
        """The owned account has zero access and a bounded unique key."""
        assert bytes(8) == cases.ACCESS, "zero access"
        assert cases.KEY.startswith(b"m-diag31-"), "key prefix"
        assert len(cases.KEY) <= 31, "key length"


class DiagnosticEvidenceTests:
    """Check the retained 303 diagnostic corpus and its semantic rejections."""

    def reports(self) -> dict:
        """Load the reports of the retained diagnostic corpus.

        Returns
        -------
        dict
            The parsed ``report.json`` of each scenario, keyed by name.
        """
        return {
            name: json.loads((CORPUS / name / "report.json").read_text())
            for name in ("preflight", "seed", "observe", "self", "cleanup")
        }

    def test_complete_corpus(self) -> None:
        """The retained corpus verifies with all five completed reports."""
        assert verify(CORPUS)["completed_reports"] == 5, "completed reports"

    def test_wrong_field_is_rejected(self) -> None:
        """A changed reply field is rejected by the semantic check."""
        reports = self.reports()
        reply = next(
            f for f in reports["observe"]["frames"] if f["id"] == 10 and f["is_reply"]
        )
        reply["fields"][0]["id"] = 100
        with pytest.raises(
            ValueError, match=re.escape("303 success fields/bytes differ")
        ):
            semantic(reports)

    def test_wrong_error_is_rejected(self) -> None:
        """A changed reply error is rejected by the semantic check."""
        reports = self.reports()
        reply = next(
            f
            for f in reports["observe"]["frames"]
            if f["id"] == 11 and f["is_reply"] and f["connection"] == "zero"
        )
        reply["error"] = 0
        with pytest.raises(
            ValueError, match=re.escape("303 failure fields/status differ")
        ):
            semantic(reports)

    def test_stale_uid_cannot_be_relabelled_self(self) -> None:
        """A stale UID in the self send cannot be relabelled as the self UID."""
        reports = self.reports()
        send = next(
            e
            for e in reports["self"]["events"]
            if e["event"] == "send" and e["action"] == 9
        )
        send["hex"] = send["hex"][:-4] + "008d"
        with pytest.raises(ValueError, match=re.escape("Self 303 UID differs")):
            semantic(reports)

    def test_multiple_self_roster_candidates_are_rejected(self) -> None:
        """More than one roster UID candidate is rejected by the semantic check."""
        reports = self.reports()
        roster = next(
            f for f in reports["self"]["frames"] if f["id"] == 10 and f["is_reply"]
        )
        roster["fields"].append(copy.deepcopy(roster["fields"][0]))
        with pytest.raises(ValueError, match=re.escape("Duplicate roster UID")):
            semantic(reports)

    def test_diagnostic_reply_reordering_is_rejected(self) -> None:
        """Swapped diagnostic replies are rejected for their order."""
        reports = self.reports()
        frames = reports["observe"]["frames"]
        left = next(
            i
            for i, frame in enumerate(frames)
            if frame["id"] == 10 and frame["is_reply"]
        )
        right = next(
            i
            for i, frame in enumerate(frames)
            if frame["id"] == 12 and frame["is_reply"]
        )
        frames[left], frames[right] = frames[right], frames[left]
        with pytest.raises(ValueError, match="order"):
            semantic(reports)
