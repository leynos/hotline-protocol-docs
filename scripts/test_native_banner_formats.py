"""Keep native banner loading distinct from metadata, file storage and reset scope."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from native_banner_formats import content
from verify_native_banner_formats import (
    check_format,
    check_recovery,
    verify,
    verify_native_files,
)

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-12/native-banner-02"
)


class BannerFormatTests(unittest.TestCase):
    def report(self, name: str) -> dict:
        return json.loads((BATCH / "transcripts" / name / "report.json").read_text())

    def test_native_format_recovery_and_reset_corpus(self) -> None:
        result = verify(BATCH)
        self.assertEqual(len(result["formats"]), 8)
        text = next(c for c in result["formats"] if c["format"] == "text-conversion")
        self.assertEqual((text["native_file_bytes"], text["received_bytes"]), (43, 42))
        self.assertEqual(result["recovery"]["received_bytes"], 58)
        self.assertTrue(
            result["packet_reconciliation"]["format-empty"]["observer"][
                "guest_server_initiated_close"
            ]
        )

    def test_text_loader_output_is_not_the_original_native_fork(self) -> None:
        report = self.report("format-text-conversion")
        report["streams"]["banner"]["received_hex"] = content("text-conversion").hex()
        with self.assertRaisesRegex(ValueError, "payload differs"):
            check_format("text-conversion", report)

    def test_zero_type_can_transfer_without_a_metadata_notification(self) -> None:
        report = self.report("format-zero-type")
        jpeg = self.report("format-jpeg")
        report["frames"].extend(f for f in jpeg["frames"] if f["type"] == 122)
        with self.assertRaisesRegex(ValueError, "metadata eligibility differs"):
            check_format("zero-type", report)

    def test_present_empty_buffer_still_has_metadata(self) -> None:
        report = self.report("format-empty")
        report["frames"] = [f for f in report["frames"] if f["type"] != 122]
        with self.assertRaisesRegex(ValueError, "metadata eligibility differs"):
            check_format("empty", report)

    def test_restoration_requires_a_positive_protocol_phase(self) -> None:
        report = self.report("phase-checked-recovery")
        report["frames"] = [
            f
            for f in report["frames"]
            if not (f["connection"] == "restored" and f["type"] == 122)
        ]
        plan = json.loads(
            (BATCH / "transcripts/phase-checked-recovery/plan.json").read_text()
        )
        with self.assertRaisesRegex(ValueError, "Restored phase lacks GIF metadata"):
            check_recovery(report, plan)

    def test_recovery_pause_duration_is_observed(self) -> None:
        report = self.report("phase-checked-recovery")
        plan = json.loads(
            (BATCH / "transcripts/phase-checked-recovery/plan.json").read_text()
        )
        event = next(
            e
            for e in report["events"]
            if e["event"] == "pause" and plan["steps"][e["action"]]["seconds"] == 30
        )
        event["elapsed_ns"] -= 1_000_000_000
        with self.assertRaisesRegex(ValueError, "Shortened recovery phase pause"):
            check_recovery(report, plan)

    def test_disappearance_is_after_the_owner_banner_advertisement(self) -> None:
        report = self.report("phase-checked-recovery")
        plan = json.loads(
            (BATCH / "transcripts/phase-checked-recovery/plan.json").read_text()
        )
        self.assertEqual(plan["expectation"]["initial_completion"], "delayed")
        report["frames"] = [
            f
            for f in report["frames"]
            if not (f["connection"] == "main" and f["type"] == 122)
        ]
        with self.assertRaisesRegex(
            ValueError, "Initial delayed banner metadata differs"
        ):
            check_recovery(report, plan)

    def test_native_finder_type_is_checked_separately(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            for name in [
                "native-format-files",
                "native-text-file",
                "native-empty-file",
            ]:
                shutil.copytree(BATCH / name, target / name)
            file = target / "native-text-file/catalog-11259.stat.txt"
            file.write_text(
                file.read_text().replace("54455854  TEXT", "47494666  GIFf")
            )
            with self.assertRaisesRegex(ValueError, "native Finder type differs"):
                verify_native_files(target)


if __name__ == "__main__":
    unittest.main()
