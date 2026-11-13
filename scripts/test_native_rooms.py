"""Reject guessed room admission, atomic invitations and text normalization."""

import copy
import json
import unittest
from pathlib import Path

import native_room_cases as cases
from protocol_capture import decode_frame
from verify_native_auth import reply
from verify_native_rooms import identities, semantic, validate_tail, verify

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/native-rooms-01"
)


class RoomTests(unittest.TestCase):
    def report(self, name: str) -> dict:
        return json.loads((CORPUS / name / "report.json").read_text())

    def reject(self, name: str, change, message: str) -> None:
        report = self.report(name)
        change(report)
        with self.assertRaisesRegex(ValueError, message):
            semantic(name, report)

    def test_complete_corpus_retains_failed_expectations(self) -> None:
        result = verify(CORPUS)
        self.assertEqual(
            (
                result["completed_reports"],
                result["retained_failed_expectations"],
                result["paired_connections"],
            ),
            (13, 2, 45),
        )

    def test_room_substitution_is_four_bytes_even_for_id_14(self) -> None:
        step = cases.message("zero", 115, 14, [(114, "room")])
        raw = bytes.fromhex(step["hex"].replace("{room}", "12345678"))
        frame = decode_frame(raw)
        self.assertEqual(len(raw), frame["data_size"] + 20)
        self.assertEqual(frame["fields"], [{"id": 114, "hex": "12345678"}])

    def test_uid_substitution_remains_two_bytes(self) -> None:
        step = cases.message("zero", 113, 14, [(114, "room"), (103, "reader_uid")])
        raw = bytes.fromhex(
            step["hex"].replace("{room}", "12345678").replace("{reader_uid}", "0012")
        )
        frame = decode_frame(raw)
        self.assertEqual(len(raw), frame["data_size"] + 20)
        self.assertEqual(frame["fields"][1], {"id": 103, "hex": "0012"})

    def test_unknown_substitution_rejected_before_io(self) -> None:
        with self.assertRaises(ValueError):
            cases.message("zero", 115, 14, [(114, "arbitrary")])

    def test_nonmember_topic_change_is_delivered(self) -> None:
        def change(report):
            report["frames"] = [f for f in report["frames"] if f["type"] != 119]

        self.reject("basics", change, "topic permissions")

    def test_uninvited_join_roster_includes_self(self) -> None:
        def change(report):
            frame = reply(report, 13, "reader")
            frame["fields"] = [f for f in frame["fields"] if f["id"] != 300][:1]

        self.reject("basics", change, "roster inclusion")

    def test_zero_access_member_does_not_receive_chat(self) -> None:
        def change(report):
            frame = copy.deepcopy(next(f for f in report["frames"] if f["type"] == 106))
            frame["connection"] = "zero"
            report["frames"].append(frame)

        self.reject("basics", change, "Zero-access")

    def test_empty_topic_is_omitted_not_empty_tlv(self) -> None:
        def change(report):
            next(f for f in report["frames"] if f["type"] == 119)["fields"].append(
                {"id": 115, "hex": ""}
            )

        self.reject("topics", change, "Topic cap/default")

    def test_topic_256_is_clipped_to_255(self) -> None:
        def change(report):
            for f in report["frames"]:
                if f["type"] == 119:
                    for field in f["fields"]:
                        if field["id"] == 115 and field["hex"] == "59" * 255:
                            field["hex"] += "59"
                            return

        self.reject("topics", change, "Topic cap/default")

    def test_repeated_join_emits_no_duplicate_notification(self) -> None:
        def change(report):
            report["frames"].append(
                copy.deepcopy(next(f for f in report["frames"] if f["type"] == 117))
            )

        self.reject("lifecycle", change, "Repeated join")

    def test_concurrent_join_does_not_return_two_final_snapshots(self) -> None:
        def change(report):
            reply(report, 11, "reader")["fields"] = copy.deepcopy(
                reply(report, 12, "zero")["fields"]
            )

        self.reject("concurrent", change, "Concurrent join snapshots")

    def test_duplicate_invitation_targets_are_not_deduplicated(self) -> None:
        def change(report):
            report["frames"].remove(
                next(
                    f
                    for f in report["frames"]
                    if f["type"] == 113 and f["connection"] == "reader"
                )
            )

        self.reject("create_invites", change, "mixed-target")

    def test_auto_response_feedback_is_not_refusal_code(self) -> None:
        def change(report):
            notices = [f for f in report["frames"] if f["type"] == 104]
            next(f for f in notices[1]["fields"] if f["id"] == 113)["hex"] = "0003"

        self.reject("refusals", change, "refusal/automatic")

    def test_lf_and_nul_bytes_are_not_normalized_away(self) -> None:
        def change(report):
            frame = next(
                f
                for f in report["frames"]
                if f["type"] == 106
                and any(
                    "00" in item["hex"] for item in f["fields"] if item["id"] == 101
                )
            )
            text = next(f for f in frame["fields"] if f["id"] == 101)
            text["hex"] = text["hex"].replace("00", "", 1)

        self.reject("formatting", change, "format/newline/NUL")

    def test_guest_unread_tail_must_name_known_participant(self) -> None:
        report = self.report("basics")
        room, ids = identities(report)
        tails = json.loads((CORPUS / "unread-tails.json").read_text())
        raw = bytes.fromhex(tails["basics"]["guest"]["main"])
        with self.assertRaisesRegex(ValueError, "identity"):
            validate_tail(raw[:-2] + b"\xff\xff", room, ids)

    def test_host_and_guest_late_tails_are_preserved_separately(self) -> None:
        tails = json.loads((CORPUS / "unread-tails.json").read_text())["basics"]
        self.assertEqual(len(bytes.fromhex(tails["host"]["main"])), 36)
        self.assertEqual(len(bytes.fromhex(tails["guest"]["main"])), 64)


if __name__ == "__main__":
    unittest.main()
