"""Reject guessed room admission, atomic invitations and text normalization."""

import copy
import json
import typing as typ
from pathlib import Path

import native_room_cases as cases
import pytest
from native_wire_names import (
    FIELD_DATA,
    FRAME_HEADER_BYTES,
    TYPE_CHAT_NOTIFICATION,
    TYPE_MESSAGE_NOTIFICATION,
)
from protocol_capture import decode_frame
from verify_native_auth import reply
from verify_native_rooms import identities, semantic, validate_tail, verify
from verify_native_rooms_wire import (
    INVITE,
    ROOM_JOIN_NOTICE,
    ROOM_TOPIC_NOTICE,
    TOPIC_LIMIT,
)

if typ.TYPE_CHECKING:
    import collections.abc as cabc

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-rooms-01"
)
COMPLETED_REPORTS = 13  # the completed reports of the retained corpus
RETAINED_FAILURES = 2  # the failed expectations that the corpus keeps
PAIRED_CONNECTIONS = 45  # the connections of the paired recording
HOST_MAIN_TAIL_BYTES = 36  # the retained host tail of the basics main view
GUEST_MAIN_TAIL_BYTES = 64  # the retained guest tail of the basics main view
ROOM_ID_HEX = "12345678"  # a four-byte room identifier, as substituted
READER_UID_HEX = "0012"  # a two-byte user identifier, as substituted


class RoomTests:
    """Reject guessed room admission, atomic invitations and text normalization."""

    def report(self, name: str) -> dict:
        """Load the report of one retained room scenario.

        Returns
        -------
        dict
            The parsed ``report.json`` of the scenario.
        """
        return json.loads((CORPUS / name / "report.json").read_text())

    def reject(
        self, name: str, change: cabc.Callable[[dict], None], message: str
    ) -> None:
        """Apply ``change`` to a report and check that the semantics then reject it.

        Parameters
        ----------
        name : str
            The name of the scenario whose report is changed.
        change : collections.abc.Callable[[dict], None]
            The change that makes the report wrong.
        message : str
            A regular expression that the rejection message must match.
        """
        report = self.report(name)
        change(report)
        with pytest.raises(ValueError, match=message):
            semantic(name, report)

    def test_complete_corpus_retains_failed_expectations(self) -> None:
        """The retained corpus verifies with its completed and failed reports."""
        result = verify(CORPUS)
        assert (
            result["completed_reports"],
            result["retained_failed_expectations"],
            result["paired_connections"],
        ) == (
            COMPLETED_REPORTS,
            RETAINED_FAILURES,
            PAIRED_CONNECTIONS,
        ), "the corpus summary differs"

    def test_room_substitution_is_four_bytes_even_for_id_14(self) -> None:
        """A room placeholder is substituted with four bytes, even for ID 14."""
        step = cases.message("zero", 115, 14, [(114, "room")])
        raw = bytes.fromhex(step["hex"].replace("{room}", ROOM_ID_HEX))
        frame = decode_frame(raw)
        assert len(raw) == frame["data_size"] + FRAME_HEADER_BYTES, (
            "the substituted length differs"
        )
        assert frame["fields"] == [{"id": 114, "hex": ROOM_ID_HEX}], (
            "the room field differs"
        )

    def test_uid_substitution_remains_two_bytes(self) -> None:
        """A user placeholder is substituted with two bytes."""
        step = cases.message("zero", 113, 14, [(114, "room"), (103, "reader_uid")])
        raw = bytes.fromhex(
            step["hex"]
            .replace("{room}", ROOM_ID_HEX)
            .replace("{reader_uid}", READER_UID_HEX)
        )
        frame = decode_frame(raw)
        assert len(raw) == frame["data_size"] + FRAME_HEADER_BYTES, (
            "the substituted length differs"
        )
        assert frame["fields"][1] == {"id": 103, "hex": READER_UID_HEX}, (
            "the user field differs"
        )

    def test_unknown_substitution_rejected_before_io(self) -> None:
        """An unknown placeholder is refused when the message is built."""
        with pytest.raises(ValueError, match="Unknown room fixture substitution"):
            cases.message("zero", 115, 14, [(114, "arbitrary")])

    def test_nonmember_topic_change_is_delivered(self) -> None:
        """A topic change that a non-member should not receive is rejected."""

        def change(report: dict) -> None:
            """Remove the topic notifications from the basic scenario."""
            report["frames"] = [
                f for f in report["frames"] if f["type"] != ROOM_TOPIC_NOTICE
            ]

        self.reject("basics", change, "topic permissions")

    def test_uninvited_join_roster_includes_self(self) -> None:
        """A join reply without the roster row of its own member is rejected."""

        def change(report: dict) -> None:
            """Keep only the first field of the reader's join reply."""
            frame = reply(report, 13, "reader")
            frame["fields"] = [f for f in frame["fields"] if f["id"] != 300][:1]

        self.reject("basics", change, "roster inclusion")

    def test_zero_access_member_does_not_receive_chat(self) -> None:
        """A zero-access member that receives chat is rejected."""

        def change(report: dict) -> None:
            """Copy a chat notification to the zero-access connection."""
            frame = copy.deepcopy(
                next(f for f in report["frames"] if f["type"] == TYPE_CHAT_NOTIFICATION)
            )
            frame["connection"] = "zero"
            report["frames"].append(frame)

        self.reject("basics", change, "Zero-access")

    def test_empty_topic_is_omitted_not_empty_tlv(self) -> None:
        """An empty topic is omitted from the change, not sent as an empty field."""

        def change(report: dict) -> None:
            """Add an empty topic field to the first topic notification."""
            next(f for f in report["frames"] if f["type"] == ROOM_TOPIC_NOTICE)[
                "fields"
            ].append({"id": 115, "hex": ""})

        self.reject("topics", change, "Topic cap/default")

    def test_topic_256_is_clipped_to_255(self) -> None:
        """A topic of 256 bytes that is kept at 256 is rejected."""

        def change(report: dict) -> None:
            """Lengthen the 255-byte topic that the server keeps by one byte."""
            for f in report["frames"]:
                if f["type"] == ROOM_TOPIC_NOTICE:
                    for field in f["fields"]:
                        if field["id"] == 115 and field["hex"] == "59" * TOPIC_LIMIT:
                            field["hex"] += "59"
                            return

        self.reject("topics", change, "Topic cap/default")

    def test_repeated_join_emits_no_duplicate_notification(self) -> None:
        """A repeated join that emits a second notification is rejected."""

        def change(report: dict) -> None:
            """Repeat the first join notification."""
            report["frames"].append(
                copy.deepcopy(
                    next(f for f in report["frames"] if f["type"] == ROOM_JOIN_NOTICE)
                )
            )

        self.reject("lifecycle", change, "Repeated join")

    def test_concurrent_join_does_not_return_two_final_snapshots(self) -> None:
        """Two concurrent joins that return the same final snapshot are rejected."""

        def change(report: dict) -> None:
            """Give the reader the zero connection's roster."""
            reply(report, 11, "reader")["fields"] = copy.deepcopy(
                reply(report, 12, "zero")["fields"]
            )

        self.reject("concurrent", change, "Concurrent join snapshots")

    def test_duplicate_invitation_targets_are_not_deduplicated(self) -> None:
        """A missing invitation to a duplicated target is rejected."""

        def change(report: dict) -> None:
            """Remove one of the invitations that the reader received."""
            report["frames"].remove(
                next(
                    f
                    for f in report["frames"]
                    if f["type"] == INVITE and f["connection"] == "reader"
                )
            )

        self.reject("create_invites", change, "mixed-target")

    def test_auto_response_feedback_is_not_refusal_code(self) -> None:
        """An automatic-response notice with the wrong refusal code is rejected."""

        def change(report: dict) -> None:
            """Replace the refusal code of the second notice with another value."""
            notices = [
                f for f in report["frames"] if f["type"] == TYPE_MESSAGE_NOTIFICATION
            ]
            next(f for f in notices[1]["fields"] if f["id"] == 113)["hex"] = "0003"

        self.reject("refusals", change, "refusal/automatic")

    def test_lf_and_nul_bytes_are_not_normalized_away(self) -> None:
        """A chat text whose NUL byte is removed is rejected."""

        def change(report: dict) -> None:
            """Remove the first NUL byte from a chat text that contains one."""
            frame = next(
                f
                for f in report["frames"]
                if f["type"] == TYPE_CHAT_NOTIFICATION
                and any(
                    "00" in item["hex"]
                    for item in f["fields"]
                    if item["id"] == FIELD_DATA
                )
            )
            text = next(f for f in frame["fields"] if f["id"] == FIELD_DATA)
            text["hex"] = text["hex"].replace("00", "", 1)

        self.reject("formatting", change, "format/newline/NUL")

    def test_guest_unread_tail_must_name_known_participant(self) -> None:
        """An unread guest frame that names an unknown participant is rejected."""
        report = self.report("basics")
        room, ids = identities(report)
        tails = json.loads((CORPUS / "unread-tails.json").read_text())
        raw = bytes.fromhex(tails["basics"]["guest"]["main"])
        with pytest.raises(ValueError, match="identity"):
            validate_tail(raw[:-2] + b"\xff\xff", room, ids)

    def test_host_and_guest_late_tails_are_preserved_separately(self) -> None:
        """The host and guest late tails keep their own retained lengths."""
        tails = json.loads((CORPUS / "unread-tails.json").read_text())["basics"]
        assert len(bytes.fromhex(tails["host"]["main"])) == HOST_MAIN_TAIL_BYTES, (
            "the host tail length differs"
        )
        assert len(bytes.fromhex(tails["guest"]["main"])) == GUEST_MAIN_TAIL_BYTES, (
            "the guest tail length differs"
        )
