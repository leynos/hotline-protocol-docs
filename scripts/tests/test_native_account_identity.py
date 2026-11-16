"""Guard the distinctions between kick protection, deletion and identity echo."""

import json
import typing as typ
from pathlib import Path

import native_account_identity_cases as cases
import pytest
from native_auth_cases import complement
from native_wire_names import FIELD_LOGIN, FIELD_NAME, TYPE_PRIVILEGES_NOTIFICATION
from verify_native_account_identity import deletion, duplicate, verify
from verify_native_auth import reply

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-account-identity-01"
)
COMPLETED_REPORTS = 14
PAIRED_CONNECTIONS = 16
UPPERCASE_LOOKUP_ID = 21
DUPLICATE_LOOKUP_ID = 20
KICK_ID = 11
DELETE_ID = 12
REWRITTEN_TAIL_BYTES = 2


class IdentityTests:
    """Guard the distinctions between kick protection, deletion and identity echo."""

    @staticmethod
    def report(name: str) -> dict[str, typ.Any]:
        """Load the report of one retained identity case.

        Returns
        -------
        dict[str, typing.Any]
            The parsed ``report.json`` of the case.
        """
        return json.loads((CORPUS / name / "report.json").read_text())

    @staticmethod
    def evidence(name: str) -> tuple[dict[str, typ.Any], bytes]:
        """Load the packet observation and the unread main tail of one case.

        Returns
        -------
        tuple[dict[str, typing.Any], bytes]
            The observation of the case and its unread bytes on the main connection.
        """
        observations = json.loads((CORPUS / "packet-observations.json").read_text())
        tails = json.loads((CORPUS / "unread-tails.json").read_text())
        return observations[name], bytes.fromhex(tails[name]["main"])

    def test_complete_retained_corpus(self) -> None:
        """The retained corpus verifies with all of its reports and connections."""
        result = verify(CORPUS)
        assert result["completed_reports"] == COMPLETED_REPORTS, (
            "the completed report count differs"
        )
        assert result["paired_connections"] == PAIRED_CONNECTIONS, (
            "the paired connection count differs"
        )

    def test_uppercase_lookup_echo_is_not_stored_login_case(self) -> None:
        """An uppercase lookup echo is not accepted as the stored login case."""
        report = self.report("duplicate-uppercase")
        next(
            f
            for f in reply(report, UPPERCASE_LOOKUP_ID)["fields"]
            if f["id"] == FIELD_LOGIN
        )["hex"] = complement(cases.KEYS["duplicate"]).hex()
        with pytest.raises(ValueError, match="account record"):
            duplicate(report, uppercase=True)

    def test_duplicate_create_does_not_replace_display_name(self) -> None:
        """A duplicate create does not replace the stored display name."""
        report = self.report("duplicate-exact")
        next(
            f
            for f in reply(report, DUPLICATE_LOOKUP_ID)["fields"]
            if f["id"] == FIELD_NAME
        )["hex"] = b"Changed29-duplicate".hex()
        with pytest.raises(ValueError, match="account record"):
            duplicate(report, uppercase=False)

    def test_kick_protection_is_observed_before_deletion(self) -> None:
        """A kick refused by protection is observed before any deletion."""
        report = self.report("protected")
        reply(report, KICK_ID)["error"] = 0
        observation, tail = self.evidence("protected")
        with pytest.raises(ValueError, match="Kick protection"):
            deletion(report, "protected", observation, tail)

    def test_self_delete_ack_precedes_its_notice(self) -> None:
        """The self-delete acknowledgement precedes its notice."""
        report = self.report("self")
        ack = reply(report, DELETE_ID, "target")
        report["frames"].remove(ack)
        report["frames"].append(ack)
        observation, tail = self.evidence("self")
        with pytest.raises(ValueError, match="notice precedes ACK"):
            deletion(report, "self", observation, tail)

    def test_client_close_is_not_evidence_of_server_first_fin(self) -> None:
        """A client close is not evidence of a server-first FIN."""
        observation, tail = self.evidence("self")
        observation["target"]["guest_server_initiated_close"] = False
        with pytest.raises(ValueError, match="guest close"):
            deletion(self.report("self"), "self", observation, tail)

    def test_unread_removal_must_name_the_deleted_subject(self) -> None:
        """An unread removal must name the deleted subject."""
        observation, tail = self.evidence("self")
        with pytest.raises(ValueError, match="removal identity"):
            deletion(
                self.report("self"),
                "self",
                observation,
                tail[:-REWRITTEN_TAIL_BYTES] + b"\0\1",
            )

    def test_mask_is_bit_23_and_not_a_generic_admin_role(self) -> None:
        """The protection mask is bit 23 and not a generic administrator role."""
        report = self.report("protected")
        access = next(
            f
            for f in report["frames"]
            if f["type"] == TYPE_PRIVILEGES_NOTIFICATION and f["connection"] == "target"
        )
        access["fields"][0]["hex"] = "fff3cfefff800000"
        observation, tail = self.evidence("protected")
        with pytest.raises(ValueError, match="Protection mask"):
            deletion(report, "protected", observation, tail)

    def test_target_factory_rejects_unowned_identity(self) -> None:
        """The target factory refuses an identity that the case does not own."""
        with pytest.raises(ValueError):  # ruff: ignore[pytest-raises-too-broad]  # the original asserted the exception type only
            cases.target_case("admin")
