"""Reject overclaims about native HTXF ownership, routing and stored upload bytes."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_native_htxf import check_case, verify, verify_native_uploads

BATCH = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-12/native-htxf-01"
)


class HtxfTests(unittest.TestCase):
    def check(self, name: str, mutate) -> None:
        report = json.loads((BATCH / "transcripts" / name / "report.json").read_text())
        packets = json.loads((BATCH / "packet-reconciliation.json").read_text())[name]
        mutate(report, packets)
        check_case(name, report, packets)

    def test_retained_native_header_and_reference_corpus(self) -> None:
        self.assertEqual(len(verify(BATCH)["cases"]), 18)

    def test_reserved_words_are_checked_as_sent(self) -> None:
        def mutate(report, packets):
            report["streams"]["data"]["sent_hex"] = (
                report["streams"]["data"]["sent_hex"][:-4] + "0000"
            )

        with self.assertRaisesRegex(ValueError, "physical HTXF header differs"):
            self.check("banner-size-one-reserved-1234", mutate)

    def test_duplicate_transport_must_not_repeat_the_banner(self) -> None:
        def mutate(report, packets):
            report["streams"]["second"]["received_hex"] = report["streams"]["first"][
                "received_hex"
            ]

        with self.assertRaisesRegex(
            ValueError, "Rejected/duplicate connection delivered bytes"
        ):
            self.check("banner-duplicate-after-send", mutate)

    def test_owner_departure_must_precede_stale_attachment(self) -> None:
        def mutate(report, packets):
            event = next(
                e
                for e in report["events"]
                if e["connection"] == "a" and e["event"] == "close"
            )
            event["action"] = 1000

        with self.assertRaisesRegex(
            ValueError, "Owner was not closed before attachment"
        ):
            self.check("download-owner-gone", mutate)

    def test_quiet_window_is_bounded_by_actual_events(self) -> None:
        def mutate(report, packets):
            event = next(e for e in report["events"] if e["event"] == "quiet")
            event["elapsed_ns"] -= 1_000_000_000

        with self.assertRaisesRegex(ValueError, "Short HTXF quiet observation"):
            self.check("banner-size-one-reserved-1234", mutate)

    def test_upload_data_must_match_the_native_fork(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(BATCH / "native-uploads", root / "native-uploads")
            (root / "native-uploads/catalog-11282.data").write_bytes(b"wrong")
            with self.assertRaisesRegex(ValueError, "Native upload data differs"):
                verify_native_uploads(root)

    def test_absent_resource_attribute_is_not_successful_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(BATCH / "native-uploads", root / "native-uploads")
            path = root / "native-uploads/extraction.json"
            extraction = json.loads(path.read_text())
            extraction["records"][0]["attributes"]["rsrc"]["exit_code"] = 0
            path.write_text(json.dumps(extraction))
            with self.assertRaisesRegex(
                ValueError, "Absent resource attribute was not retained"
            ):
                verify_native_uploads(root)


if __name__ == "__main__":
    unittest.main()
