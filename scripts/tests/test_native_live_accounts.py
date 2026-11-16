"""Guard live update ordering, orderly close, late removal and restart records."""

import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from pcap_tcp import read_packets
from verify_native_auth import reply, selected
from verify_native_live_accounts import (
    check_delete,
    check_edit,
    stopped,
    storage,
    verify,
    waits,
)

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-live-accounts-01"
)
GUEST_CONNECTIONS = 24
LATE_REMOVALS = 2
PRIVILEGES = 354
NOTICE = 104
ACCESS_FIELD = 110
INITIAL_ACCESS = "2000000000000000"
REVOKED_ID = 91
EDIT_ACK_ID = 11
STALE_ID = 12
SHORTENED_NS = 1_000_000_000
REMOVAL_BYTES = 28  # one removal notice of the two that were left unread
POLITE_QUIT_TYPE = 111
SERVER_PORT = 5500
RST = 4
PASSWORD_BYTE = 702  # a byte of the stored password in the account record
ERROR_FIELD = 100


class LiveAccountTests:
    """Guard live update ordering, orderly close, late removal and restart records."""

    @staticmethod
    def report(name: str) -> Report:
        """Load the report of one retained step.

        Returns
        -------
        dict[str, typing.Any]
            The parsed ``report.json``.
        """
        return json.loads((BATCH / name / "report.json").read_text())

    def deletion(self) -> tuple[Report, bytes, Report]:
        """Load the deletion case with its unread tail and native close facts.

        Returns
        -------
        tuple[dict, bytes, dict]
            The report, the unread tail and the guest's observations.
        """
        report = self.report("delete")
        tail = bytes.fromhex(
            json.loads((BATCH / "delete-unread-tails.json").read_text())["main"]
        )
        observations = {
            c: {"guest_server_initiated_close": True, "guest_server_close_kind": "FIN"}
            for c in ["one", "two"]
        }
        return report, tail, observations

    def test_complete_live_and_application_restart_corpus(self) -> None:
        """The retained corpus verifies with its connection counts."""
        result = verify(BATCH)
        assert (
            result["established_guest_connections"],
            result["late_unread_removals"],
        ) == (GUEST_CONNECTIONS, LATE_REMOVALS), "the live corpus counts differ"

    def test_new_access_mask_is_delivered_to_both_matching_sessions(self) -> None:
        """An access update that kept the old mask is refused."""
        report = self.report("edit")
        updated = [f for f in selected(report, "one") if f["type"] == PRIVILEGES][1]
        next(f for f in updated["fields"] if f["id"] == ACCESS_FIELD)["hex"] = (
            INITIAL_ACCESS
        )
        with pytest.raises(ValueError, match="354"):
            check_edit(report)

    def test_own_rename_cannot_precede_own_access_update(self) -> None:
        """A rename that came before the session's own access update is refused."""
        report = self.report("edit")
        updated = [f for f in selected(report, "one") if f["type"] == PRIVILEGES][1]
        report["frames"].remove(updated)
        report["frames"].append(updated)
        with pytest.raises(ValueError, match="354 must precede"):
            check_edit(report)

    def test_effective_revocation_applies_on_existing_connection(self) -> None:
        """A download that succeeded after the revocation is refused."""
        report = self.report("edit")
        reply(report, REVOKED_ID, "two")["error"] = 0
        with pytest.raises(ValueError, match="revocation"):
            check_edit(report)

    def test_caller_ack_precedes_its_roster_notifications(self) -> None:
        """An ACK that came after the roster notifications is refused."""
        report = self.report("edit")
        ack = reply(report, EDIT_ACK_ID)
        report["frames"].remove(ack)
        report["frames"].append(ack)
        with pytest.raises(ValueError, match="ACK/rename/roster"):
            check_edit(report)

    def test_password_only_change_does_not_emit_a_second_privilege_update(
        self,
    ) -> None:
        """A third access update after a password-only change is refused."""
        report = self.report("edit")
        updated = [f for f in selected(report, "one") if f["type"] == PRIVILEGES][1]
        report["frames"].append(dict(updated))
        with pytest.raises(ValueError, match="354"):
            check_edit(report)

    def test_deletion_notice_is_data101_not_an_error100(self) -> None:
        """A deletion notice carried in the error field is refused."""
        report, tail, observations = self.deletion()
        notice = next(f for f in selected(report, "one") if f["type"] == NOTICE)
        notice["fields"][0]["id"] = ERROR_FIELD
        with pytest.raises(ValueError, match="notice"):
            check_delete(report, tail, observations)

    def test_client_close_is_not_promoted_to_native_initiated_close(self) -> None:
        """A close that the client began is not accepted as the native close."""
        report, tail, observations = self.deletion()
        observations["two"]["guest_server_initiated_close"] = False
        with pytest.raises(ValueError, match="first FIN"):
            check_delete(report, tail, observations)

    def test_stale_snapshot_is_not_rewritten_to_immediate_removal(self) -> None:
        """A roster that dropped the stale subject is refused."""
        report, tail, observations = self.deletion()
        reply(report, STALE_ID)["fields"] = reply(report, STALE_ID)["fields"][:1]
        with pytest.raises(ValueError, match="stale roster"):
            check_delete(report, tail, observations)

    def test_both_unread_removal_messages_are_required(self) -> None:
        """A tail with one removal notice only is refused."""
        report, tail, observations = self.deletion()
        with pytest.raises(ValueError, match="Late removal UIDs"):
            check_delete(report, tail[:REMOVAL_BYTES], observations)

    def test_late_removal_is_not_an_undocumented_politequit(self) -> None:
        """A late removal of another type is refused."""
        report, tail, observations = self.deletion()
        changed = tail[:2] + POLITE_QUIT_TYPE.to_bytes(2, "big") + tail[4:]
        with pytest.raises(ValueError, match="Unexpected unread"):
            check_delete(report, changed, observations)

    def test_quiet_intervals_are_measured_for_each_socket(self) -> None:
        """A quiet interval shorter than planned is refused."""
        report = self.report("edit")
        event = next(e for e in report["events"] if e["event"] == "quiet")
        event["elapsed_ns"] -= SHORTENED_NS
        plan = json.loads((BATCH / "edit/plan.json").read_text())
        with pytest.raises(ValueError, match="Short live"):
            waits(report, plan["steps"])

    def test_stopped_listener_failure_cannot_be_reported_as_success(self) -> None:
        """A stopped witness that completed is refused."""
        report = self.report("stopped")
        report["status"] = "completed"
        with pytest.raises(ValueError, match="must remain a reset failure"):
            stopped(report, [], [])

    def test_rst_diagnostic_bytes_are_not_a_protocol_reply(self) -> None:
        """The reset's bytes are the listener's text, and no frame was received."""
        report = self.report("stopped")
        guest = read_packets(BATCH / "guest.pcap")
        source = report["events"][0]["local_address"][1]
        diagnostic = next(
            p
            for p in guest
            if p["src_port"] == SERVER_PORT
            and p["dst_port"] == source
            and p["flags"] & RST
        )
        assert bytes.fromhex(diagnostic["payload_hex"]) == b"No listener", (
            "the reset carries the listener's text"
        )
        assert report["frames"] == [], "the stopped witness received no frame"

    def test_restart_does_not_restore_the_old_password(self, tmp_path: Path) -> None:
        """A changed stored password fork after the restart is refused."""
        for name in [
            "native-before-restart",
            "native-after-restart",
            "native-cleanup",
            "native-published",
            "native-application-before",
            "native-application-after",
        ]:
            shutil.copytree(BATCH / name, tmp_path / name)
        shutil.copy2(
            BATCH / "restart-application-identities.json",
            tmp_path / "restart-application-identities.json",
        )
        rows = json.loads(
            (tmp_path / "native-after-restart/extraction.json").read_text()
        )["records"]
        row = next(r for r in rows if r["path"].endswith("/m-live27/UserData"))
        path = tmp_path / "native-after-restart" / (row["key"] + ".data")
        value = bytearray(path.read_bytes())
        value[PASSWORD_BYTE] ^= 1
        path.write_bytes(value)
        with pytest.raises(ValueError, match="changed stored fork"):
            storage(tmp_path)
