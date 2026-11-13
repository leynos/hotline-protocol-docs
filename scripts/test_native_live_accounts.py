"""Guard live update ordering, orderly close, late removal and restart records."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

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

BATCH = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/native-live-accounts-01"
)


class LiveAccountTests(unittest.TestCase):
    def report(self, name: str) -> dict:
        return json.loads((BATCH / name / "report.json").read_text())

    def deletion(self) -> tuple[dict, bytes, dict]:
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
        result = verify(BATCH)
        self.assertEqual(
            (result["established_guest_connections"], result["late_unread_removals"]),
            (24, 2),
        )

    def test_new_access_mask_is_delivered_to_both_matching_sessions(self) -> None:
        report = self.report("edit")
        updated = [f for f in selected(report, "one") if f["type"] == 354][1]
        next(f for f in updated["fields"] if f["id"] == 110)["hex"] = "2000000000000000"
        with self.assertRaisesRegex(ValueError, "354"):
            check_edit(report)

    def test_own_rename_cannot_precede_own_access_update(self) -> None:
        report = self.report("edit")
        updated = [f for f in selected(report, "one") if f["type"] == 354][1]
        report["frames"].remove(updated)
        report["frames"].append(updated)
        with self.assertRaisesRegex(ValueError, "354 must precede"):
            check_edit(report)

    def test_effective_revocation_applies_on_existing_connection(self) -> None:
        report = self.report("edit")
        reply(report, 91, "two")["error"] = 0
        with self.assertRaisesRegex(ValueError, "revocation"):
            check_edit(report)

    def test_caller_ack_precedes_its_roster_notifications(self) -> None:
        report = self.report("edit")
        ack = reply(report, 11)
        report["frames"].remove(ack)
        report["frames"].append(ack)
        with self.assertRaisesRegex(ValueError, "ACK/rename/roster"):
            check_edit(report)

    def test_password_only_change_does_not_emit_a_second_privilege_update(self) -> None:
        report = self.report("edit")
        updated = [f for f in selected(report, "one") if f["type"] == 354][1]
        report["frames"].append(dict(updated))
        with self.assertRaisesRegex(ValueError, "354"):
            check_edit(report)

    def test_deletion_notice_is_data101_not_an_error100(self) -> None:
        report, tail, observations = self.deletion()
        notice = next(f for f in selected(report, "one") if f["type"] == 104)
        notice["fields"][0]["id"] = 100
        with self.assertRaisesRegex(ValueError, "notice"):
            check_delete(report, tail, observations)

    def test_client_close_is_not_promoted_to_native_initiated_close(self) -> None:
        report, tail, observations = self.deletion()
        observations["two"]["guest_server_initiated_close"] = False
        with self.assertRaisesRegex(ValueError, "first FIN"):
            check_delete(report, tail, observations)

    def test_stale_snapshot_is_not_rewritten_to_immediate_removal(self) -> None:
        report, tail, observations = self.deletion()
        reply(report, 12)["fields"] = reply(report, 12)["fields"][:1]
        with self.assertRaisesRegex(ValueError, "stale roster"):
            check_delete(report, tail, observations)

    def test_both_unread_removal_messages_are_required(self) -> None:
        report, tail, observations = self.deletion()
        with self.assertRaisesRegex(ValueError, "Late removal UIDs"):
            check_delete(report, tail[:28], observations)

    def test_late_removal_is_not_an_undocumented_politequit(self) -> None:
        report, tail, observations = self.deletion()
        changed = tail[:2] + (111).to_bytes(2, "big") + tail[4:]
        with self.assertRaisesRegex(ValueError, "Unexpected unread"):
            check_delete(report, changed, observations)

    def test_quiet_intervals_are_measured_for_each_socket(self) -> None:
        report = self.report("edit")
        event = next(e for e in report["events"] if e["event"] == "quiet")
        event["elapsed_ns"] -= 1_000_000_000
        plan = json.loads((BATCH / "edit/plan.json").read_text())
        with self.assertRaisesRegex(ValueError, "Short live"):
            waits(report, plan["steps"])

    def test_stopped_listener_failure_cannot_be_reported_as_success(self) -> None:
        report = self.report("stopped")
        report["status"] = "completed"
        with self.assertRaisesRegex(ValueError, "must remain a reset failure"):
            stopped(report, [], [])

    def test_rst_diagnostic_bytes_are_not_a_protocol_reply(self) -> None:
        report = self.report("stopped")
        guest = read_packets(BATCH / "guest.pcap")
        source = report["events"][0]["local_address"][1]
        diagnostic = next(
            p
            for p in guest
            if p["src_port"] == 5500 and p["dst_port"] == source and p["flags"] & 4
        )
        self.assertEqual(bytes.fromhex(diagnostic["payload_hex"]), b"No listener")
        self.assertEqual(report["frames"], [])

    def test_restart_does_not_restore_the_old_password(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            for name in [
                "native-before-restart",
                "native-after-restart",
                "native-cleanup",
                "native-published",
                "native-application-before",
                "native-application-after",
            ]:
                shutil.copytree(BATCH / name, target / name)
            shutil.copy2(
                BATCH / "restart-application-identities.json",
                target / "restart-application-identities.json",
            )
            rows = json.loads(
                (target / "native-after-restart/extraction.json").read_text()
            )["records"]
            row = next(r for r in rows if r["path"].endswith("/m-live27/UserData"))
            path = target / "native-after-restart" / (row["key"] + ".data")
            value = bytearray(path.read_bytes())
            value[702] ^= 1
            path.write_bytes(value)
            with self.assertRaisesRegex(ValueError, "changed stored fork"):
                storage(target)


if __name__ == "__main__":
    unittest.main()
