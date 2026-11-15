#!/usr/bin/env python3
"""Check bounded 108/104 PM routing without asserting unknown generated text."""

import dataclasses as dc
import json
import typing as typ
from pathlib import Path

import native_pm_cases as cases
from native_wire_names import (
    FIELD_DATA,
    FIELD_NAME,
    FIELD_OPTIONS,
    FIELD_QUOTE,
    FIELD_USER_ID,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
    TYPE_SEND_PRIVATE_MESSAGE,
)
from protocol_capture import decode_frame, verify_capture
from script_cli import UsageError, run
from verify_native_auth import reply, roster
from verify_native_core import require
from verify_native_shx import fields

type Report = dict[str, typ.Any]

# native-pm-witness.md: option 1 is an original message, 2 and 3 are generated
# refusals of a message and of a chat, and 4 is an automatic response.
OPTION_ORIGINAL = 1
OPTION_REFUSES_MESSAGES = 2
OPTION_AUTO_RESPONSE = 4
ROSTER_REQUEST_ID = 10  # the first 300 request of native_pm_cases.observe
FIRST_PM_REQUEST_ID = 60  # the PM requests count up from here
UID_BYTES = 2
TYPE_HEX_START = 4  # a packet's type is hex digits 4 to 8 of its encoding
TYPE_HEX_END = 8
INITIAL_ROSTER_NAME = b"framing-fixture"
AUTO_RESPONSE_TEXT = b"pm-a26-auto"
PEER_UID_SAVE = {"peer_uid": FIELD_USER_ID}


def check_variant(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # the callers' shape
    actual: dict[int, bytes],
    uid: bytes,
    name: bytes,
    option: int,
    text: bytes | None,
    quote: bytes | None = None,
) -> None:
    """Check the field set, identity, option and text of one 104 variant."""
    expected = {FIELD_USER_ID, FIELD_NAME, FIELD_OPTIONS, FIELD_DATA}
    if quote is not None:
        expected.add(FIELD_QUOTE)
    require(set(actual) == expected, "PM 104 field set differs")
    require(
        actual[FIELD_USER_ID] == uid
        and actual[FIELD_NAME] == name
        and actual[FIELD_OPTIONS] == option.to_bytes(2, "big"),
        "PM 104 identity/option differs",
    )
    if text is None:
        require(bool(actual[FIELD_DATA]), "Generated PM text absent")
    else:
        require(actual[FIELD_DATA] == text, "PM 104 text differs")
    if quote is not None:
        require(actual[FIELD_QUOTE] == quote, "PM quoted field differs")


@dc.dataclass(frozen=True, slots=True)
class Session:
    """The report of a capture and the two session UIDs it observed.

    Attributes
    ----------
    report : dict[str, typing.Any]
        The retained capture report.
    main_uid : bytes
        The main connection's UID.
    peer_uid : bytes
        The peer connection's UID.
    """

    report: Report
    main_uid: bytes
    peer_uid: bytes

    def uid(self, side: str) -> bytes:
        """Return a side's UID.

        Returns
        -------
        bytes
            The UID of ``"main"`` or ``"peer"``.
        """
        return self.main_uid if side == "main" else self.peer_uid


def name_of(side: str) -> bytes:
    """Return the session name that a side registered.

    Returns
    -------
    bytes
        The name of ``"main"`` or ``"peer"``.
    """
    return cases.MAIN if side == "main" else cases.PEER


def main_uid_of(report: Report) -> bytes:
    """Read the main session's UID from the initial roster reply.

    Returns
    -------
    bytes
        The UID, as the two bytes it travels in.
    """
    first = roster(reply(report, ROSTER_REQUEST_ID))
    require(
        len(first) == 1 and bytes.fromhex(first[0]["name_hex"]) == INITIAL_ROSTER_NAME,
        "Initial admin roster is ambiguous",
    )
    return first[0]["uid"].to_bytes(UID_BYTES, "big")


def peer_uid_of(report: Report, plan: Report) -> bytes:
    """Read the peer session's UID from the presence announcement the main saw.

    Returns
    -------
    bytes
        The peer's UID.
    """
    saved = [
        index
        for index, step in enumerate(plan["steps"])
        if step.get("save_fields") == PEER_UID_SAVE
    ]
    require(len(saved) == 1, "Peer UID save step differs")
    announced = [
        f
        for f in report["frames"]
        if f["action"] == saved[0]
        and f["type"] == TYPE_PRESENCE_UPDATE
        and f["connection"] == "main"
    ]
    require(len(announced) == 1, "Peer announcement missing/ambiguous")
    peer_fields = fields(announced[0])
    require(
        peer_fields.get(FIELD_NAME) == cases.PEER
        and len(peer_fields.get(FIELD_USER_ID, b"")) == UID_BYTES,
        "Peer identity announcement differs",
    )
    return peer_fields[FIELD_USER_ID]


def pm_actions(plan: Report) -> list[tuple[int, Report]]:
    """List the plan's send-private-message steps with their action indexes.

    Returns
    -------
    list[tuple[int, dict[str, typing.Any]]]
        Each ``(action, step)`` whose packet type is 108.
    """
    return [
        (index, step)
        for index, step in enumerate(plan["steps"])
        if step["op"] == "send"
        and int(step["hex"][TYPE_HEX_START:TYPE_HEX_END], 16)
        == TYPE_SEND_PRIVATE_MESSAGE
    ]


def check_case_variants(
    label: str,
    case: cases.Case,
    session: Session,
    events: tuple[list[dict[int, bytes]], list[dict[int, bytes]]],
) -> None:
    """Check the 104 variants a named case must have produced.

    ``events`` holds the sender's and the recipient's 104 fields. A case with
    no variant to check (the suppressed and empty ones) checks nothing here.
    """
    sender_events, recipient_events = events
    sender = case.sender
    recipient = "peer" if sender == "main" else "main"
    sender_uid, sender_name = session.uid(sender), name_of(sender)
    recipient_uid, recipient_name = session.uid(recipient), name_of(recipient)
    match label:
        case "direct-quoted":
            check_variant(
                recipient_events[0],
                sender_uid,
                sender_name,
                OPTION_ORIGINAL,
                case.text,
                cases.QUOTE,
            )
        case "recipient-refuses":
            check_variant(
                sender_events[0],
                recipient_uid,
                recipient_name,
                OPTION_REFUSES_MESSAGES,
                None,
            )
        case "auto-and-original":
            check_variant(
                sender_events[0],
                recipient_uid,
                recipient_name,
                OPTION_AUTO_RESPONSE,
                AUTO_RESPONSE_TEXT,
            )
            check_variant(
                recipient_events[0], sender_uid, sender_name, OPTION_ORIGINAL, case.text
            )
        case "option-two" | "option-three":
            check_variant(
                recipient_events[0], sender_uid, sender_name, case.option, None
            )


def sent_bytes(report: Report, action: int) -> bytes:
    """Join the bytes that one action sent.

    Returns
    -------
    bytes
        The concatenated ``send`` events of ``action``.
    """
    return bytes.fromhex(
        "".join(
            event["hex"]
            for event in report["events"]
            if event["action"] == action and event["event"] == "send"
        )
    )


def routed_frames(report: Report, window: tuple[int, int]) -> list[Report]:
    """List the 104 notifications received strictly inside an action window.

    Returns
    -------
    list[dict[str, typing.Any]]
        The decoded frames of type 104 that are not replies.
    """
    start, end = window
    return [
        f
        for f in report["frames"]
        if start < f["action"] < end
        and f["type"] == TYPE_MESSAGE_NOTIFICATION
        and not f["is_reply"]
    ]


def split_fields(
    pushed: list[Report], sender: str, recipient: str
) -> tuple[list[dict[int, bytes]], list[dict[int, bytes]]]:
    """Split notifications into the sender's and the recipient's field maps.

    Returns
    -------
    tuple[list[dict[int, bytes]], list[dict[int, bytes]]]
        The fields of each frame that the sender received, then those that the
        recipient received.
    """
    return (
        [fields(f) for f in pushed if f["connection"] == sender],
        [fields(f) for f in pushed if f["connection"] == recipient],
    )


def check_case(
    session: Session, index: int, label: str, window: tuple[int, int]
) -> None:
    """Check one PM request: its target, its ACK, its routing and its variants.

    ``window`` is the half-open range of actions from this send up to the next.
    """
    case = cases.CASES[label]
    recipient = "peer" if case.sender == "main" else "main"
    sent = sent_bytes(session.report, window[0])
    require(
        fields(decode_frame(sent))[FIELD_USER_ID] == session.uid(recipient),
        f"{label}: target UID differs",
    )
    ack = reply(session.report, FIRST_PM_REQUEST_ID + index, case.sender)
    require(ack["error"] == 0 and not ack["fields"], "PM ACK is not empty success")
    pushed = routed_frames(session.report, window)
    require(
        all(
            ack["action"] < frame["action"]
            for frame in pushed
            if frame["connection"] == case.sender
        ),
        f"{label}: sender feedback preceded ACK in recorded stream",
    )
    events = split_fields(pushed, case.sender, recipient)
    require(
        len(events[0]) == case.sender_push and len(events[1]) == case.recipient_push,
        f"{label}: PM routing count differs",
    )
    check_case_variants(label, case, session, events)


def check_cases(session: Session, plan: Report) -> None:
    """Check each PM request of the plan against the frames it produced."""
    actions = pm_actions(plan)
    require(len(actions) == len(cases.CASES), "PM action count differs")
    ends = [start for start, _ in actions[1:]] + [len(plan["steps"])]
    for index, (label, (start, _), end) in enumerate(
        zip(cases.CASES, actions, ends, strict=True)
    ):
        check_case(session, index, label, (start, end))


def check_no_stray_pushes(report: Report) -> None:
    """Require every 104 of the capture to belong to a PM case window."""
    expected = sum(c.sender_push + c.recipient_push for c in cases.CASES.values())
    require(
        sum(
            f["type"] == TYPE_MESSAGE_NOTIFICATION and not f["is_reply"]
            for f in report["frames"]
        )
        == expected,
        "Unexpected 104 outside PM case windows",
    )


def semantic(report: Report, plan: Report) -> dict[str, typ.Any]:
    """Check every PM case of a completed observation.

    Returns
    -------
    dict[str, typing.Any]
        The two UIDs in hexadecimal and the names of the verified cases.
    """
    require(report["status"] == "completed", "PM capture did not complete")
    require(plan["expectation"]["case"] == "observe", "Wrong PM case")
    main_uid = main_uid_of(report)
    peer_uid = peer_uid_of(report, plan)
    require(main_uid != peer_uid, "PM session UIDs collide")
    session = Session(report, main_uid, peer_uid)
    check_cases(session, plan)
    check_no_stray_pushes(report)
    return {
        "main_uid_hex": session.main_uid.hex(),
        "peer_uid_hex": peer_uid.hex(),
        "verified_cases": list(cases.CASES),
    }


def record(capture: str, *, output: str) -> None:
    """Verify an observe capture and write its PM routing summary to a new file.

    Raises
    ------
    UsageError
        If the output file already exists.
    """
    directory = Path(capture)
    report = verify_capture(directory)
    plan = json.loads((directory / "plan.json").read_text())
    result = semantic(report, plan)
    target = Path(output)
    if target.exists():
        message = "Refusing existing output"
        raise UsageError(message)
    target.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    """Verify an observe capture from the command line."""
    run(record, __doc__)


if __name__ == "__main__":
    main()
