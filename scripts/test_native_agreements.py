"""Reject agreement configuration, content and partial-login substitutions."""

import json
import tempfile
import unittest
from pathlib import Path

from native_agreement_cases import TEXT, phase
from verify_native_agreements import check_overflow, native_file, verify
from verify_native_auth import check_state

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-agreement-01"
)


class AgreementTests(unittest.TestCase):
    def report(self, name: str) -> dict:
        return json.loads((BATCH / "captures" / name / "report.json").read_text())

    def test_full_retained_agreement_matrix(self) -> None:
        result = verify(BATCH)
        self.assertEqual((result["cases"], result["phases"]), (42, 11))

    def test_installed_finder_type_overrides_intended_upload_type(self) -> None:
        with self.assertRaisesRegex(ValueError, "Finder type differs"):
            native_file(BATCH / "native-text-staged", b"BMP ", TEXT)

    def test_nontext_notice_does_not_normalize_crlf(self) -> None:
        name = "nontext-early-admin"
        with self.assertRaisesRegex(ValueError, "bypass contents differ"):
            check_state(
                name,
                self.report(name),
                phase("nontext")[name][1],
                TEXT.replace(b"\r\n", b"\r"),
            )

    def test_oversized_early_login_cannot_claim_an_agreement_frame(self) -> None:
        name = "nontext-field-over-limit-early"
        report = self.report(name)
        report["frames"].append(
            {"connection": "subject", "type": 109, "is_reply": 0, "error": 0}
        )
        with self.assertRaisesRegex(ValueError, "partial login sequence differs"):
            check_overflow(report, phase("nontext-field-over-limit")[name][1])

    def test_omitted_configuration_cannot_shrink_the_required_matrix(self) -> None:
        manifest = json.loads((BATCH / "manifest.json").read_text())
        del manifest["phases"]["directory"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "phase inventory differs"):
                verify(root)


if __name__ == "__main__":
    unittest.main()
