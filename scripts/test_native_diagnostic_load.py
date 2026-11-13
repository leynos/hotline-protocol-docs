"""Decision controls for the single owned diagnostic-load cleanup capture."""

import copy
import unittest
from pathlib import Path

from native_diagnostic_load_cases import NAME, choose_owned_branch
from native_plan import packet, payload
from protocol_capture import decode_frame, verify_capture
from verify_native_diagnostic_load import CASES, semantic


def frame(identifier: int, fields: list[tuple[int, bytes]], error: int = 0) -> dict:
    return decode_frame(
        bytes.fromhex(packet(0, identifier, payload(fields), reply=1, error=error))
    )


def info(name: bytes | None, error: int = 0) -> dict:
    fields = [] if name is None else [(201, name)]
    return frame(10, fields, error)


def listing(*names: bytes) -> dict:
    entries = [(200, bytes(16) + len(name).to_bytes(4, "big") + name) for name in names]
    return frame(11, entries)


class BranchTests(unittest.TestCase):
    def test_positive_exact_owned_file_can_be_deleted(self) -> None:
        self.assertEqual(choose_owned_branch(info(NAME), listing(NAME)), "present")

    def test_absent_file_skips_delete(self) -> None:
        self.assertEqual(choose_owned_branch(info(None, 1), listing()), "absent")

    def test_wrong_name_never_deletes(self) -> None:
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            choose_owned_branch(info(b"other"), listing(NAME))

    def test_disagreement_never_deletes(self) -> None:
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            choose_owned_branch(info(NAME), listing())
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            choose_owned_branch(info(None, 1), listing(NAME))

    def test_duplicate_name_never_deletes(self) -> None:
        with self.assertRaises(ValueError):
            choose_owned_branch(info(NAME), listing(NAME, NAME))


BATCH = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/native-diagnostic-load-01"
)


class SemanticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reports = {name: verify_capture(BATCH / name) for name in CASES}
        for name, report in cls.reports.items():
            report["_plan_path"] = BATCH / name / "plan.json"

    def test_corpus_has_failed_seed_and_complete_cleanup(self) -> None:
        result = semantic(copy.deepcopy(self.reports))
        self.assertEqual(
            result["seed_error"],
            "ConnectionResetError: [Errno 104] Connection reset by peer",
        )

    def test_failed_seed_cannot_be_relabelled_success(self) -> None:
        reports = copy.deepcopy(self.reports)
        reports["seed"]["status"] = "completed"
        with self.assertRaisesRegex(ValueError, "Seed failure"):
            semantic(reports)

    def test_cleanup_cannot_target_other_file(self) -> None:
        reports = copy.deepcopy(self.reports)
        frame = next(
            f for f in reports["cleanup"]["frames"] if f["is_reply"] and f["id"] == 10
        )
        next(field for field in frame["fields"] if field["id"] == 201)["hex"] = (
            b"other".hex()
        )
        with self.assertRaisesRegex(ValueError, "partial file identity"):
            semantic(reports)

    def test_cleanup_cannot_hide_remaining_file(self) -> None:
        reports = copy.deepcopy(self.reports)
        frame = next(
            f for f in reports["cleanup"]["frames"] if f["is_reply"] and f["id"] == 12
        )
        frame["error"] = 0
        with self.assertRaisesRegex(ValueError, "remains"):
            semantic(reports)

    def test_cleanup_cannot_change_account_baseline(self) -> None:
        reports = copy.deepcopy(self.reports)
        frame = next(
            f for f in reports["cleanup"]["frames"] if f["is_reply"] and f["id"] == 14
        )
        frame["fields"].pop()
        with self.assertRaisesRegex(ValueError, "account enumeration"):
            semantic(reports)


if __name__ == "__main__":
    unittest.main()
