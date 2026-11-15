"""Reject login-extra omission, decoding and refresh overclaims."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from native_login_extras_cases import NAMES, configured
from verify_native_login_extras import (
    check_configured,
    check_lifetime,
    login_ack,
    preferences,
    verify,
)

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-login-extras-01"
)


class LoginExtraTests(unittest.TestCase):
    def report(self, name: str) -> dict:
        return json.loads((BATCH / "captures" / name / "report.json").read_text())

    def agreement(self) -> bytes:
        return (BATCH / "original-agreement.data").read_bytes().replace(b"\r\n", b"\r")

    def test_full_retained_login_extra_corpus(self) -> None:
        self.assertEqual(verify(BATCH)["cases"], 34)

    def test_absent_client_version_does_not_omit_configured_server_name(self) -> None:
        frame = self.report("name-a-absent-early")["frames"][0]
        frame["fields"] = [f for f in frame["fields"] if f["id"] != 162]
        with self.assertRaisesRegex(ValueError, "login-extra values differ"):
            login_ack(frame, NAMES["name-a"])

    def test_native_high_byte_is_not_reencoded_as_utf8(self) -> None:
        frame = self.report("macroman-190-early")["frames"][0]
        next(f for f in frame["fields"] if f["id"] == 162)["hex"] = (
            "mothra-ö".encode().hex()
        )
        with self.assertRaisesRegex(ValueError, "login-extra values differ"):
            login_ack(frame, NAMES["macroman"])

    def test_old_client_version_does_not_receive_configured_banner(self) -> None:
        report = self.report("name-a-150-delayed")
        notice = next(
            f for f in self.report("name-a-190-delayed")["frames"] if f["type"] == 122
        )
        report["frames"].insert(-1, copy.deepcopy(notice))
        name = "name-a-150-delayed"
        with self.assertRaisesRegex(ValueError, "login/banner sequence differs"):
            check_configured(report, configured("name-a")[name][1], self.agreement())

    def test_acceptance_does_not_refresh_the_old_login_name(self) -> None:
        report = self.report("name-change-with-existing-sessions")
        ack = next(
            f
            for f in report["frames"]
            if f["connection"] == "waiting" and f["is_reply"] and f["id"] == 2
        )
        ack["fields"] = [{"id": 162, "hex": NAMES["name-b"].hex()}]
        with self.assertRaisesRegex(ValueError, "login extras were refreshed"):
            check_lifetime(report, self.agreement())

    def test_truncated_live_preference_snapshot_is_not_accepted(self) -> None:
        with self.assertRaisesRegex(ValueError, "Truncated native Pascal content"):
            preferences(BATCH / "native-url")

    def test_required_configurations_cannot_be_removed_from_the_manifest(self) -> None:
        manifest = json.loads((BATCH / "manifest.json").read_text())
        del manifest["configurations"]["none"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "configuration inventory differs"):
                verify(root)


if __name__ == "__main__":
    unittest.main()
