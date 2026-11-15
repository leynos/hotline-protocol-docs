"""Reject banner evidence that confuses raw payload, advertisement and completion."""

import copy
import json
import unittest
from pathlib import Path

from verify_native_banners import check_case, verify

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-12/native-banner-01"
)


class BannerTests(unittest.TestCase):
    def test_native_banner_corpus(self) -> None:
        result = verify(BATCH)
        self.assertEqual(len(result["cases"]), 24)
        changed = next(c for c in result["cases"] if c["case"] == "changed-buffer")
        self.assertEqual(
            (changed["advertised_bytes"], changed["delivered_bytes"]), (43, 58)
        )

    def fixture(self, name: str) -> tuple[dict, dict, dict]:
        directory = BATCH / "transcripts" / name
        return (
            json.loads((directory / "report.json").read_text()),
            json.loads((directory / "plan.json").read_text()),
            {"banner": {"guest_server_initiated_close": False}},
        )

    def test_filp_wrapping_is_not_raw_banner_delivery(self) -> None:
        report, plan, packets = self.fixture("local-a-raw")
        report["streams"]["banner"]["received_hex"] = (
            b"FILP".hex() + report["streams"]["banner"]["received_hex"]
        )
        with self.assertRaisesRegex(ValueError, "raw banner bytes differ"):
            check_case("local-a-raw", report, plan, packets)

    def test_changed_buffer_must_not_be_pinned_to_advertised_size(self) -> None:
        report, plan, packets = self.fixture("changed-buffer")
        report["streams"]["banner"]["received_hex"] = report["streams"]["banner"][
            "received_hex"
        ][:86]
        with self.assertRaisesRegex(ValueError, "raw banner bytes differ"):
            check_case("changed-buffer", report, plan, packets)

    def test_early_completion_does_not_inherit_delayed_banner(self) -> None:
        report, plan, packets = self.fixture("local-a-early")
        delayed, _, _ = self.fixture("local-a-metadata-190")
        report["frames"].extend(
            copy.deepcopy(f) for f in delayed["frames"] if f["type"] == 122
        )
        with self.assertRaisesRegex(ValueError, "unexpected122"):
            check_case("local-a-early", report, plan, packets)

    def test_wrong_selector_requires_the_original_reference(self) -> None:
        report, plan, packets = self.fixture("local-a-selector1")
        sent = report["streams"]["banner"]["sent_hex"]
        report["streams"]["banner"]["sent_hex"] = sent[:8] + "ffffffff" + sent[16:]
        packets["banner"]["guest_server_initiated_close"] = True
        with self.assertRaisesRegex(ValueError, "negative HTXF control differs"):
            check_case("local-a-selector1", report, plan, packets)

    def test_missing_banner_silence_is_not_a_successful_empty_ack(self) -> None:
        report, plan, packets = self.fixture("none-request212")
        report["frames"].append({"type": 0, "is_reply": 1, "id": 10})
        with self.assertRaisesRegex(ValueError, "unexpected212 reply"):
            check_case("none-request212", report, plan, packets)


if __name__ == "__main__":
    unittest.main()
