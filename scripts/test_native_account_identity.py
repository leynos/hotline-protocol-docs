"""Guard the distinctions between kick protection, deletion and identity echo."""

import json
import unittest
from pathlib import Path

import native_account_identity_cases as cases
from native_auth_cases import complement
from verify_native_account_identity import deletion, duplicate, verify
from verify_native_auth import reply

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/native-account-identity-01"
)


class IdentityTests(unittest.TestCase):
    def report(self, name: str) -> dict:
        return json.loads((CORPUS / name / "report.json").read_text())

    def evidence(self, name: str) -> tuple[dict, bytes]:
        observations = json.loads((CORPUS / "packet-observations.json").read_text())
        tails = json.loads((CORPUS / "unread-tails.json").read_text())
        return observations[name], bytes.fromhex(tails[name]["main"])

    def test_complete_retained_corpus(self) -> None:
        result = verify(CORPUS)
        self.assertEqual(result["completed_reports"], 14)
        self.assertEqual(result["paired_connections"], 16)

    def test_uppercase_lookup_echo_is_not_stored_login_case(self) -> None:
        report = self.report("duplicate-uppercase")
        next(f for f in reply(report, 21)["fields"] if f["id"] == 105)["hex"] = (
            complement(cases.KEYS["duplicate"]).hex()
        )
        with self.assertRaisesRegex(ValueError, "account record"):
            duplicate(report, True)

    def test_duplicate_create_does_not_replace_display_name(self) -> None:
        report = self.report("duplicate-exact")
        next(f for f in reply(report, 20)["fields"] if f["id"] == 102)["hex"] = (
            b"Changed29-duplicate".hex()
        )
        with self.assertRaisesRegex(ValueError, "account record"):
            duplicate(report, False)

    def test_kick_protection_is_observed_before_deletion(self) -> None:
        report = self.report("protected")
        reply(report, 11)["error"] = 0
        observation, tail = self.evidence("protected")
        with self.assertRaisesRegex(ValueError, "Kick protection"):
            deletion(report, "protected", observation, tail)

    def test_self_delete_ack_precedes_its_notice(self) -> None:
        report = self.report("self")
        ack = reply(report, 12, "target")
        report["frames"].remove(ack)
        report["frames"].append(ack)
        observation, tail = self.evidence("self")
        with self.assertRaisesRegex(ValueError, "notice precedes ACK"):
            deletion(report, "self", observation, tail)

    def test_client_close_is_not_evidence_of_server_first_fin(self) -> None:
        observation, tail = self.evidence("self")
        observation["target"]["guest_server_initiated_close"] = False
        with self.assertRaisesRegex(ValueError, "guest close"):
            deletion(self.report("self"), "self", observation, tail)

    def test_unread_removal_must_name_the_deleted_subject(self) -> None:
        observation, tail = self.evidence("self")
        with self.assertRaisesRegex(ValueError, "removal identity"):
            deletion(self.report("self"), "self", observation, tail[:-2] + b"\0\1")

    def test_mask_is_bit_23_and_not_a_generic_admin_role(self) -> None:
        report = self.report("protected")
        access = next(
            f
            for f in report["frames"]
            if f["type"] == 354 and f["connection"] == "target"
        )
        access["fields"][0]["hex"] = "fff3cfefff800000"
        observation, tail = self.evidence("protected")
        with self.assertRaisesRegex(ValueError, "Protection mask"):
            deletion(report, "protected", observation, tail)

    def test_target_factory_rejects_unowned_identity(self) -> None:
        with self.assertRaises(ValueError):
            cases.target_case("admin")


if __name__ == "__main__":
    unittest.main()
