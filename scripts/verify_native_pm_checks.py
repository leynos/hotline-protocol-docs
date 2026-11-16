"""Check the private-message semantics and the exact 104 notifications."""

import json
import typing as typ

from native_pm_cases import MAIN, PEER
from native_wire_names import (
    FIELD_DATA,
    FIELD_NAME,
    FIELD_OPTIONS,
    FIELD_QUOTE,
    FIELD_USER_ID,
    HANDSHAKE_REPLY_BYTES,
    HANDSHAKE_REPLY_HEX,
    TYPE_MESSAGE_NOTIFICATION,
)
from protocol_capture import verify_capture
from verify_native_core import require
from verify_native_pm import semantic
from verify_native_shx import fields, frames

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

OBSERVE_ACTIONS = 151
OPTION_WORD_1 = b"\0\1"
OPTION_WORD_2 = b"\0\2"
OPTION_WORD_3 = b"\0\3"
OPTION_WORD_4 = b"\0\4"
REFUSAL_REQUEST_ID = 61
AUTOMATIC_REQUEST_ID = 62
PM_REFUSED = b" does not accept private messages."
CHAT_REFUSED = b" does not accept private chats."


def expected_notifications(
    main_uid: bytes, peer_uid: bytes
) -> list[tuple[str, dict[int, bytes]]]:
    """List the 104 notifications that the observation must produce, in order.

    Parameters
    ----------
    main_uid : bytes
        The main session's user id.
    peer_uid : bytes
        The peer session's user id.

    Returns
    -------
    list[tuple[str, dict[int, bytes]]]
        The receiving connection and the exact fields of each notification.
    """
    return [
        (
            "peer",
            {
                FIELD_USER_ID: main_uid,
                FIELD_NAME: MAIN,
                FIELD_OPTIONS: OPTION_WORD_1,
                FIELD_DATA: b"pm-a26-direct",
                FIELD_QUOTE: b"quote-a26",
            },
        ),
        (
            "main",
            {
                FIELD_USER_ID: peer_uid,
                FIELD_NAME: PEER,
                FIELD_OPTIONS: OPTION_WORD_2,
                FIELD_DATA: PEER + PM_REFUSED,
            },
        ),
        (
            "main",
            {
                FIELD_USER_ID: peer_uid,
                FIELD_NAME: PEER,
                FIELD_OPTIONS: OPTION_WORD_4,
                FIELD_DATA: b"pm-a26-auto",
            },
        ),
        (
            "peer",
            {
                FIELD_USER_ID: main_uid,
                FIELD_NAME: MAIN,
                FIELD_OPTIONS: OPTION_WORD_1,
                FIELD_DATA: b"pm-a26-with-auto",
            },
        ),
        (
            "peer",
            {
                FIELD_USER_ID: main_uid,
                FIELD_NAME: MAIN,
                FIELD_OPTIONS: OPTION_WORD_2,
                FIELD_DATA: MAIN + PM_REFUSED,
            },
        ),
        (
            "main",
            {
                FIELD_USER_ID: peer_uid,
                FIELD_NAME: PEER,
                FIELD_OPTIONS: OPTION_WORD_3,
                FIELD_DATA: PEER + CHAT_REFUSED,
            },
        ),
    ]


def check_same_flow(report: Report) -> None:
    """Check that each acknowledgement preceded its refusal or automatic reply.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The observation's report.
    """
    received = bytes.fromhex(report["streams"]["main"]["received_hex"])
    require(
        received[:HANDSHAKE_REPLY_BYTES] == bytes.fromhex(HANDSHAKE_REPLY_HEX),
        "PM handshake reply differs",
    )
    main = frames(received[HANDSHAKE_REPLY_BYTES:])
    refusal = next(
        i
        for i, f in enumerate(main)
        if f["type"] == TYPE_MESSAGE_NOTIFICATION
        and fields(f).get(FIELD_OPTIONS) == OPTION_WORD_2
    )
    automatic = next(
        i
        for i, f in enumerate(main)
        if f["type"] == TYPE_MESSAGE_NOTIFICATION
        and fields(f).get(FIELD_OPTIONS) == OPTION_WORD_4
    )
    require(
        any(f["is_reply"] and f["id"] == REFUSAL_REQUEST_ID for f in main[:refusal]),
        "Same-flow refusal preceded 108 ACK",
    )
    require(
        any(
            f["is_reply"] and f["id"] == AUTOMATIC_REQUEST_ID for f in main[:automatic]
        ),
        "Same-flow auto preceded 108 ACK",
    )


def check_pm(root: Path) -> tuple[Report, Report]:
    """Check the observation's semantics, notifications and delivery order.

    The checks run in a fixed order, so the first failure decides the error:
    the capture's own verification, the action count, the semantic receipt, the
    exact notifications and the same-flow ordering.

    Parameters
    ----------
    root : pathlib.Path
        The corpus root.

    Returns
    -------
    tuple[dict[str, typing.Any], dict[str, typing.Any]]
        The observation's report and its semantic result.
    """
    report = verify_capture(root / "observe")
    plan = json.loads((root / "observe/plan.json").read_text())
    require(report["completed_actions"] == OBSERVE_ACTIONS, "PM action count differs")
    result = semantic(report, plan)
    require(
        result == json.loads((root / "observe-semantic.json").read_text()),
        "PM semantic receipt differs",
    )
    main_uid, peer_uid = (
        bytes.fromhex(result[key]) for key in ("main_uid_hex", "peer_uid_hex")
    )
    actual = [
        (f["connection"], fields(f))
        for f in report["frames"]
        if f["type"] == TYPE_MESSAGE_NOTIFICATION and not f["is_reply"]
    ]
    require(
        actual == expected_notifications(main_uid, peer_uid),
        "PM 104 exact variant bytes/order differ",
    )
    check_same_flow(report)
    return report, result
