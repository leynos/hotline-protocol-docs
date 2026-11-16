"""Reject agreement configuration, content and partial-login substitutions."""

import json
import typing as typ
from pathlib import Path

import pytest
from native_agreement_cases import TEXT, phase
from native_wire_names import TYPE_LOGIN_AGREEMENT
from verify_native_agreements import check_overflow, native_file, verify
from verify_native_auth import check_state

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-agreement-01"
)
CASES = 42  # the agreement cases in the retained matrix
PHASE_COUNT = 11  # the agreement phases in the retained matrix


class AgreementTests:
    """Reject agreement configuration, content and partial-login substitutions."""

    def report(self, name: str) -> dict[str, typ.Any]:
        """Load the report of one retained agreement capture.

        Returns
        -------
        dict[str, typing.Any]
            The parsed ``report.json`` of the capture.
        """
        return json.loads((BATCH / "captures" / name / "report.json").read_text())

    def test_full_retained_agreement_matrix(self) -> None:
        """The retained agreement matrix verifies with all of its cases."""
        result = verify(BATCH)
        assert (result["cases"], result["phases"]) == (
            CASES,
            PHASE_COUNT,
        ), "the agreement case or phase count differs"

    def test_installed_finder_type_overrides_intended_upload_type(self) -> None:
        """The installed Finder type of an agreement overrides the intended one."""
        with pytest.raises(ValueError, match="Finder type differs"):
            native_file(BATCH / "native-text-staged", b"BMP ", TEXT)

    def test_nontext_notice_does_not_normalize_crlf(self) -> None:
        """A non-text agreement notice keeps the agreement's CRLF bytes."""
        name = "nontext-early-admin"
        with pytest.raises(ValueError, match="bypass contents differ"):
            check_state(
                name,
                self.report(name),
                phase("nontext")[name][1],
                TEXT.replace(b"\r\n", b"\r"),
            )

    def test_oversized_early_login_cannot_claim_an_agreement_frame(self) -> None:
        """An oversized early login cannot claim an agreement frame."""
        name = "nontext-field-over-limit-early"
        report = self.report(name)
        report["frames"].append({
            "connection": "subject",
            "type": TYPE_LOGIN_AGREEMENT,
            "is_reply": 0,
            "error": 0,
        })
        with pytest.raises(ValueError, match="partial login sequence differs"):
            check_overflow(report, phase("nontext-field-over-limit")[name][1])

    def test_omitted_configuration_cannot_shrink_the_required_matrix(
        self, tmp_path: Path
    ) -> None:
        """A manifest that omits a required phase is refused."""
        manifest = json.loads((BATCH / "manifest.json").read_text())
        del manifest["phases"]["directory"]
        (tmp_path / "manifest.json").write_text(json.dumps(manifest))
        with pytest.raises(ValueError, match="phase inventory differs"):
            verify(tmp_path)
