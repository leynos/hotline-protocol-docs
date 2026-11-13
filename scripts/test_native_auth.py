"""Prevent guest fallback, visibility and native account-boundary overclaims."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_native_auth import cases, check_lookup, check_state, verify, verify_accounts

BATCH = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/native-auth-01"
)


class AuthTests(unittest.TestCase):
    def report(self, name: str) -> dict:
        return json.loads((BATCH / "transcripts" / name / "report.json").read_text())

    def test_complete_retained_authentication_corpus(self) -> None:
        self.assertEqual(verify(BATCH)["cases"], 33)

    def test_nul_is_not_equivalent_to_empty_guest_login(self) -> None:
        report = self.report("configured-guest-empty")
        with self.assertRaisesRegex(ValueError, "failure/fallback differs"):
            check_lookup(report, cases()["nul-only"][1], verify_accounts(BATCH))

    def test_guest_privileges_come_from_its_account(self) -> None:
        report = self.report("configured-guest-absent")
        report["frames"][1]["fields"][0]["hex"] = "fff3cfefff800000"
        with self.assertRaisesRegex(ValueError, "effective privileges differ"):
            check_lookup(
                report, cases()["configured-guest-absent"][1], verify_accounts(BATCH)
            )

    def test_bad_filename_is_not_ordinary_bad_password(self) -> None:
        report = self.report("name-length32")
        report["frames"][0]["fields"][0]["hex"] = b"Incorrect login.".hex()
        with self.assertRaisesRegex(ValueError, "failure/fallback differs"):
            check_lookup(report, cases()["name-length32"][1], verify_accounts(BATCH))

    def test_bypass_flag_is_not_configured_agreement_text(self) -> None:
        report = self.report("delayed-bypass")
        frame = next(
            f
            for f in report["frames"]
            if f["connection"] == "subject" and f["type"] == 109
        )
        frame["fields"] = [{"id": 101, "hex": verify_accounts(BATCH).hex()}]
        with self.assertRaisesRegex(ValueError, "bypass contents differ"):
            check_state(
                "delayed-bypass",
                report,
                cases()["delayed-bypass"][1],
                verify_accounts(BATCH),
            )

    def test_delayed_authenticated_session_is_not_yet_roster_visible(self) -> None:
        report = self.report("delayed-admin")
        frames = [
            f
            for f in report["frames"]
            if f["connection"] == "observer" and f["is_reply"]
        ]
        before = next(f for f in frames if f["id"] == 12)
        after = next(f for f in frames if f["id"] == 13)
        before["fields"] = copy.deepcopy(after["fields"])
        with self.assertRaisesRegex(ValueError, "visibility transition differs"):
            check_state(
                "delayed-admin",
                report,
                cases()["delayed-admin"][1],
                verify_accounts(BATCH),
            )

    def test_missing_agreement_field_is_distinct_from_empty_value(self) -> None:
        report = self.report("early-admin")
        frame = next(
            f
            for f in report["frames"]
            if f["connection"] == "subject" and f["type"] == 109
        )
        frame["fields"] = []
        check_state("early-admin", report, cases()["early-admin"][1], None)
        with self.assertRaisesRegex(ValueError, "bypass contents differ"):
            check_state("early-admin", report, cases()["early-admin"][1], b"")
        frame["fields"] = [{"id": 101, "hex": ""}]
        with self.assertRaisesRegex(ValueError, "bypass contents differ"):
            check_state("early-admin", report, cases()["early-admin"][1], None)

    def test_native_canonical_key_is_checked_separately_from_login_ack(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(BATCH / "native-accounts", root / "native-accounts")
            file = root / "native-accounts/catalog-11284.data"
            value = bytearray(file.read_bytes())
            value[0x29A] ^= 1
            file.write_bytes(value)
            with self.assertRaisesRegex(ValueError, "canonical account keys differ"):
                verify_accounts(root)


if __name__ == "__main__":
    unittest.main()
