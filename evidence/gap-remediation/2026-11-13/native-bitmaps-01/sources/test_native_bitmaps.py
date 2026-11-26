"""Check bounded, owned 64-bit native account bitmap plans."""

import copy
import json
import unittest
from pathlib import Path

import native_bitmap_cases as cases
from verify_native_bitmaps import semantic, verify

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/native-bitmaps-01"
)


class BitmapPlanTests(unittest.TestCase):
    """Tests of the bitmap plan builders."""
    def test_all_64_msb_first_single_bits(self) -> None:
        """Check that the 64 walking bits are distinct, eight bytes long and most significant bit first."""
        values = [cases.walking_bit(bit) for bit in range(64)]
        self.assertEqual(len(set(values)), 64)
        self.assertTrue(all(len(value) == 8 for value in values))
        self.assertEqual(values[0], bytes.fromhex("8000000000000000"))
        self.assertEqual(values[7], bytes.fromhex("0100000000000000"))
        self.assertEqual(values[8], bytes.fromhex("0080000000000000"))
        self.assertEqual(values[63], bytes.fromhex("0000000000000001"))

    def test_width_controls_are_distinguishable(self) -> None:
        """Check that the bitmap width controls have distinct lengths and contents."""
        values = cases.WIDTHS
        self.assertEqual(
            [len(value) if value is not None else None for value in values.values()],
            [None, 0, 1, 7, 8, 9],
        )
        self.assertNotEqual(values["short-one"], values["short-seven"])
        over, exact = values["over-nine"], values["exact-eight"]
        assert over is not None and exact is not None
        self.assertEqual(over[:8], exact)

    def test_one_owned_account_and_bounded_suite_inventory(self) -> None:
        """Check that the suite has thirteen plans and a single bounded account key."""
        plans = cases.suites()
        self.assertEqual(len(plans), 13)
        self.assertEqual(sum(label.startswith("walk-") for label in plans), 8)
        self.assertTrue(cases.KEY.startswith(b"m-bit32-"))
        self.assertLessEqual(len(cases.KEY), 31)


class BitmapEvidenceTests(unittest.TestCase):
    """Tests of the retained bitmap evidence."""
    def reports(self) -> dict:
        """Load the report of every bitmap suite from the corpus."""
        return {
            name: json.loads((CORPUS / name / "report.json").read_text())
            for name in cases.suites()
        }

    def test_complete_corpus(self) -> None:
        """Check that the retained corpus verifies with all 64 walking bits."""
        self.assertEqual(verify(CORPUS)["walking_bits_verified"], 64)

    def test_wrong_readback_bit_is_rejected(self) -> None:
        """Check that a wrong bitmap in a readback reply is rejected."""
        reports = self.reports()
        reply = next(
            f for f in reports["walk-04"]["frames"] if f["is_reply"] and f["id"] == 21
        )
        next(field for field in reply["fields"] if field["id"] == 110)["hex"] = (
            "8000000000000000"
        )
        with self.assertRaisesRegex(ValueError, "readback"):
            semantic(reports)

    def test_wrong_sent_bit_is_rejected(self) -> None:
        """Check that a wrong bitmap in a sent request is rejected."""
        reports = self.reports()
        event = next(
            e
            for e in reports["walk-07"]["events"]
            if e["event"] == "send" and e["hex"].startswith("00000161")
        )
        before = event["hex"]
        event["hex"] = before.replace("0000000000000080", "8000000000000000")
        self.assertNotEqual(event["hex"], before)
        with self.assertRaisesRegex(ValueError, "submitted"):
            semantic(reports)

    def test_wrong_owned_identity_is_rejected(self) -> None:
        """Check that a readback of the wrong account identity is rejected."""
        reports = self.reports()
        reply = next(
            f for f in reports["walk-02"]["frames"] if f["is_reply"] and f["id"] == 21
        )
        next(field for field in reply["fields"] if field["id"] == 105)["hex"] = "00"
        with self.assertRaisesRegex(ValueError, "identity"):
            semantic(reports)

    def test_reordered_readbacks_are_rejected(self) -> None:
        """Check that readback replies in the wrong order are rejected."""
        reports = self.reports()
        frames = reports["walk-00"]["frames"]
        a = next(i for i, f in enumerate(frames) if f["is_reply"] and f["id"] == 21)
        b = next(i for i, f in enumerate(frames) if f["is_reply"] and f["id"] == 23)
        frames[a], frames[b] = frames[b], frames[a]
        with self.assertRaisesRegex(ValueError, "order"):
            semantic(reports)

    def test_ambiguous_all_ones_privilege_push_is_rejected(self) -> None:
        """Check that a duplicated privilege push in the all-ones suite is rejected."""
        reports = self.reports()
        push = next(
            f
            for f in reports["all-ones"]["frames"]
            if f["connection"] == "owned" and f["type"] == 354
        )
        reports["all-ones"]["frames"].append(copy.deepcopy(push))
        with self.assertRaisesRegex(ValueError, "effective session"):
            semantic(reports)


if __name__ == "__main__":
    unittest.main()
