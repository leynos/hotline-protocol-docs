"""Prevent guest fallback, visibility and native account-boundary overclaims."""

import copy
import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from verify_native_auth import cases, check_lookup, check_state, verify, verify_accounts

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-auth-01"
)
CASES = 33
FLIPPED_BYTE = 0x29A  # the first stored byte of an account's canonical login


class AuthTests:
    """Prevent guest fallback, visibility and native account-boundary overclaims."""

    @staticmethod
    def report(name: str) -> dict[str, typ.Any]:
        """Load the report of one retained authentication case.

        Returns
        -------
        dict[str, typing.Any]
            The parsed ``report.json`` of the case.
        """
        return json.loads((BATCH / "transcripts" / name / "report.json").read_text())

    def test_complete_retained_authentication_corpus(self) -> None:
        """The retained corpus verifies, with all of its cases."""
        assert verify(BATCH)["cases"] == CASES, "expected the 33 retained cases"

    def test_nul_is_not_equivalent_to_empty_guest_login(self) -> None:
        """A NUL-only login is not mistaken for the empty guest login."""
        report = self.report("configured-guest-empty")
        with pytest.raises(ValueError, match="failure/fallback differs"):
            check_lookup(report, cases()["nul-only"][1], verify_accounts(BATCH))

    def test_guest_privileges_come_from_its_account(self) -> None:
        """Administrator privileges on a guest login are refused."""
        report = self.report("configured-guest-absent")
        report["frames"][1]["fields"][0]["hex"] = "fff3cfefff800000"
        with pytest.raises(ValueError, match="effective privileges differ"):
            check_lookup(
                report, cases()["configured-guest-absent"][1], verify_accounts(BATCH)
            )

    def test_bad_filename_is_not_ordinary_bad_password(self) -> None:
        """A bad-password text for an over-long key is refused."""
        report = self.report("name-length32")
        report["frames"][0]["fields"][0]["hex"] = b"Incorrect login.".hex()
        with pytest.raises(ValueError, match="failure/fallback differs"):
            check_lookup(report, cases()["name-length32"][1], verify_accounts(BATCH))

    def test_bypass_flag_is_not_configured_agreement_text(self) -> None:
        """Agreement text in place of the bypass flag is refused."""
        report = self.report("delayed-bypass")
        frame = next(
            f
            for f in report["frames"]
            if f["connection"] == "subject" and f["type"] == 109
        )
        frame["fields"] = [{"id": 101, "hex": verify_accounts(BATCH).hex()}]
        with pytest.raises(ValueError, match="bypass contents differ"):
            check_state(
                "delayed-bypass",
                report,
                cases()["delayed-bypass"][1],
                verify_accounts(BATCH),
            )

    def test_delayed_authenticated_session_is_not_yet_roster_visible(self) -> None:
        """A delayed session that is already listed is refused."""
        report = self.report("delayed-admin")
        frames = [
            f
            for f in report["frames"]
            if f["connection"] == "observer" and f["is_reply"]
        ]
        before = next(f for f in frames if f["id"] == 12)
        after = next(f for f in frames if f["id"] == 13)
        before["fields"] = copy.deepcopy(after["fields"])
        with pytest.raises(ValueError, match="visibility transition differs"):
            check_state(
                "delayed-admin",
                report,
                cases()["delayed-admin"][1],
                verify_accounts(BATCH),
            )

    def test_missing_agreement_field_is_distinct_from_empty_value(self) -> None:
        """A missing agreement field is not the same as an empty agreement."""
        report = self.report("early-admin")
        frame = next(
            f
            for f in report["frames"]
            if f["connection"] == "subject" and f["type"] == 109
        )
        frame["fields"] = []
        check_state("early-admin", report, cases()["early-admin"][1], None)
        with pytest.raises(ValueError, match="bypass contents differ"):
            check_state("early-admin", report, cases()["early-admin"][1], b"")
        frame["fields"] = [{"id": 101, "hex": ""}]
        with pytest.raises(ValueError, match="bypass contents differ"):
            check_state("early-admin", report, cases()["early-admin"][1], None)

    def test_native_canonical_key_is_checked_separately_from_login_ack(
        self, tmp_path: Path
    ) -> None:
        """A changed stored canonical key is refused by the account verifier."""
        shutil.copytree(BATCH / "native-accounts", tmp_path / "native-accounts")
        file = tmp_path / "native-accounts/catalog-11284.data"
        value = bytearray(file.read_bytes())
        value[FLIPPED_BYTE] ^= 1
        file.write_bytes(value)
        with pytest.raises(ValueError, match="canonical account keys differ"):
            verify_accounts(tmp_path)
