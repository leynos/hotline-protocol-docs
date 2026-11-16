"""Check the outcome of each room scenario, beyond its notifications."""

import native_room_cases as cases
from native_wire_names import (
    FIELD_DATA,
    FIELD_ERROR_TEXT,
    FIELD_NAME,
    FIELD_OPTIONS,
    FIELD_ROSTER_SUBJECT,
    FIELD_USER_ID,
    TYPE_CHAT_NOTIFICATION,
    TYPE_MESSAGE_NOTIFICATION,
)
from verify_native_auth import reply, roster
from verify_native_core import require
from verify_native_rooms_reports import formatted, members, missing, pushes
from verify_native_rooms_wire import (
    FIELD_CHAT_OPTION,
    FIELD_ROOM,
    INVITE,
    PAIR,
    ROOM_JOIN_NOTICE,
    ROOM_LEAVE_NOTICE,
    ROOM_TOPIC_NOTICE,
    TOPIC_LIMIT,
)
from verify_native_shx import fields


def check_basics(report: dict, room: bytes, ids: dict[str, bytes]) -> None:
    """Check the permissions, fan-out and denials of the basic scenario.

    Parameters
    ----------
    report : dict
        The retained report of the scenario.
    room : bytes
        The room identifier.
    ids : dict[str, bytes]
        The identifier of the owner and of each role.
    """
    main, reader, zero = ids["main"], ids["reader"], ids["zero"]
    require(
        reply(report, 11, "zero")["error"] == 1
        and fields(reply(report, 11, "zero"))
        == {FIELD_ERROR_TEXT: b"You are not allowed to create a new chat."},
        "Create-chat denial differs",
    )
    require(
        pushes(report, "main", ROOM_TOPIC_NOTICE)
        == [{FIELD_ROOM: room, FIELD_ROSTER_SUBJECT: b"outsider-topic30"}]
        and not pushes(report, "zero", ROOM_TOPIC_NOTICE),
        "Non-member topic permissions differ",
    )
    members(report, "reader", 13, {main, reader}, b"outsider-topic30")
    members(report, "zero", 14, {main, reader, zero}, b"outsider-topic30")
    for connection in ["main", "reader"]:
        expected = [
            {
                FIELD_DATA: formatted(b"Room30-speaker", b"room-message30-speaker"),
                FIELD_ROOM: room,
            }
        ]
        expected += [
            {FIELD_DATA: formatted(b"Room30-speaker", text)}
            for text in [b"main-implicit30", b"main-zero30"]
        ]
        require(
            pushes(report, connection, TYPE_CHAT_NOTIFICATION) == expected,
            "Room/main-chat fanout differs",
        )
    require(
        pushes(report, "speaker", TYPE_CHAT_NOTIFICATION)
        == [
            {FIELD_DATA: formatted(b"Room30-speaker", text)}
            for text in [b"main-implicit30", b"main-zero30"]
        ],
        "Non-member sender eligibility differs",
    )
    require(
        not pushes(report, "zero", TYPE_CHAT_NOTIFICATION),
        "Zero-access subject received chat",
    )
    for connection in ["zero", "reader"]:
        require(
            pushes(report, connection, TYPE_MESSAGE_NOTIFICATION)
            == [
                {
                    FIELD_CHAT_OPTION: b"\0\1",
                    FIELD_DATA: b"You are not allowed to participate in chat.",
                }
            ],
            "Denied-chat notice differs",
        )
    missing(report, "zero", 20)
    missing(report, "zero", 21)


def check_topics(report: dict, room: bytes, ids: dict[str, bytes]) -> None:
    """Check the topic cap, the empty default and the byte preservation.

    Parameters
    ----------
    report : dict
        The retained report of the scenario.
    room : bytes
        The room identifier.
    ids : dict[str, bytes]
        The identifier of the owner and of each role.
    """
    main, reader = ids["main"], ids["reader"]
    values = [
        b"",
        b"",
        b"topic30",
        b"A\0B\rC\nD\x80\xff",
        b"X" * TOPIC_LIMIT,
        b"Y" * TOPIC_LIMIT,
        b"Z" * TOPIC_LIMIT,
        b"",
    ]
    expected = [
        {FIELD_ROOM: room, **({FIELD_ROSTER_SUBJECT: value} if value else {})}
        for value in values
    ]
    for connection in ["main", "reader"]:
        require(
            pushes(report, connection, ROOM_TOPIC_NOTICE) == expected,
            "Topic cap/default/byte preservation differs",
        )
    for connection in ["zero", "speaker"]:
        require(
            not pushes(report, connection, ROOM_TOPIC_NOTICE),
            "Non-member received topic update",
        )
    members(report, "reader", 11, {main, reader})
    for identifier, value in enumerate(values, 220):
        members(report, "reader", identifier, {main, reader}, value)
    require(
        len(pushes(report, "main", ROOM_JOIN_NOTICE)) == 1,
        "Repeated topic read joined twice",
    )


def check_lifecycle(report: dict, room: bytes, ids: dict[str, bytes]) -> None:
    """Check the repeated join, the leave order and the departure notices.

    Parameters
    ----------
    report : dict
        The retained report of the scenario.
    room : bytes
        The room identifier.
    ids : dict[str, bytes]
        The identifier of the owner and of each role.
    """
    main, reader, zero = ids["main"], ids["reader"], ids["zero"]
    members(report, "reader", 11, {main, reader})
    members(report, "reader", 12, {main, reader})
    members(report, "zero", 13, {main, reader, zero})
    require(
        [e[FIELD_USER_ID] for e in pushes(report, "main", ROOM_JOIN_NOTICE)]
        == [reader, zero],
        "Repeated join emitted extra event",
    )
    require(
        pushes(report, "main", ROOM_LEAVE_NOTICE)
        == [{FIELD_ROOM: room, FIELD_USER_ID: zero}],
        "Non-member leave or last leave emitted extra event",
    )
    require(
        pushes(report, "reader", ROOM_LEAVE_NOTICE)
        == [
            {FIELD_ROOM: room, FIELD_USER_ID: zero},
            {FIELD_ROOM: room, FIELD_USER_ID: main},
        ],
        "Leave recipient order differs",
    )
    missing(report, "zero", 18)


def check_concurrent_snapshots(report: dict, ids: dict[str, bytes]) -> None:
    """Check that each concurrent join returns a self-containing roster.

    Parameters
    ----------
    report : dict
        The retained report of the scenario.
    ids : dict[str, bytes]
        The identifier of the owner and of each role.
    """
    main, reader, zero = ids["main"], ids["reader"], ids["zero"]
    snapshots = []
    for connection, identifier in [("reader", 11), ("zero", 12)]:
        frame = reply(report, identifier, connection)
        rows = {r["uid"] for r in roster(frame)}
        require(
            {int.from_bytes(main, "big"), int.from_bytes(ids[connection], "big")}
            <= rows,
            "Concurrent join omitted self/creator",
        )
        snapshots.append(rows)
    require(
        sorted(map(len, snapshots)) == [2, 3]
        and set.union(*snapshots)
        == {int.from_bytes(i, "big") for i in [main, reader, zero]},
        "Concurrent join snapshots are inconsistent",
    )


def check_concurrent(report: dict, ids: dict[str, bytes]) -> None:
    """Check the fan-out and the recipient cut of the concurrent joins and leaves.

    Parameters
    ----------
    report : dict
        The retained report of the scenario.
    ids : dict[str, bytes]
        The identifier of the owner and of each role.
    """
    reader, zero = ids["reader"], ids["zero"]
    require(
        {e[FIELD_USER_ID] for e in pushes(report, "main", ROOM_JOIN_NOTICE)}
        == {reader, zero}
        and len(pushes(report, "main", ROOM_JOIN_NOTICE)) == PAIR,
        "Concurrent join fanout differs",
    )
    require(
        sum(len(pushes(report, c, ROOM_JOIN_NOTICE)) for c in ["reader", "zero"]) == 1,
        "Concurrent join recipient cut differs",
    )
    require(
        {e[FIELD_USER_ID] for e in pushes(report, "main", ROOM_LEAVE_NOTICE)}
        == {reader, zero}
        and len(pushes(report, "main", ROOM_LEAVE_NOTICE)) == PAIR,
        "Concurrent leave lost/duplicated membership",
    )
    require(
        sum(len(pushes(report, c, ROOM_LEAVE_NOTICE)) for c in ["reader", "zero"]) == 1,
        "Concurrent leave recipient cut differs",
    )
    missing(report, "zero", 16)


def check_create_invites(report: dict, room: bytes, ids: dict[str, bytes]) -> None:
    """Check the mixed-target invitations and the repeated rejection.

    Parameters
    ----------
    report : dict
        The retained report of the scenario.
    room : bytes
        The room identifier.
    ids : dict[str, bytes]
        The identifier of the owner and of each role.
    """
    main, reader = ids["main"], ids["reader"]
    invitation = {FIELD_ROOM: room, FIELD_USER_ID: main, FIELD_NAME: b"framing-fixture"}
    for connection, count in [
        ("reader", 2),
        ("speaker", 1),
        ("zero", 1),
        ("main", 0),
    ]:
        require(
            pushes(report, connection, INVITE) == [invitation] * count,
            "Create mixed-target invitation differs",
        )
    rejection = {
        FIELD_ROOM: room,
        FIELD_DATA: b'\r<<< "Room30-reader" declined invitation to chat >>>',
    }
    require(
        pushes(report, "main", TYPE_CHAT_NOTIFICATION) == [rejection, rejection],
        "Repeated rejection fanout differs",
    )
    require(
        all(not pushes(report, c, TYPE_CHAT_NOTIFICATION) for c in cases.ROLES),
        "Unjoined invitee received room rejection",
    )
    members(report, "reader", 13, {main, reader})


def check_invites(report: dict, room: bytes, ids: dict[str, bytes]) -> None:
    """Check the retried, disconnected and mixed-target invitations.

    Parameters
    ----------
    report : dict
        The retained report of the scenario.
    room : bytes
        The room identifier.
    ids : dict[str, bytes]
        The identifier of the owner and of each role.
    """
    main, reader, zero = ids["main"], ids["reader"], ids["zero"]
    invitation = {FIELD_ROOM: room, FIELD_USER_ID: zero, FIELD_NAME: b"Room30-zero"}
    require(
        pushes(report, "reader", INVITE) == [invitation] * 3
        and pushes(report, "speaker", INVITE) == [invitation],
        "Retry/disconnected/mixed invitation differs",
    )
    require(
        not pushes(report, "zero", INVITE) and not pushes(report, "main", INVITE),
        "Self/member invitation filter differs",
    )
    members(report, "reader", 13, {main, reader})
    members(report, "zero", 15, {main, reader, zero})


def check_refusals(report: dict, room: bytes, ids: dict[str, bytes]) -> None:
    """Check the refusal and automatic-response feedback of the invitations.

    Parameters
    ----------
    report : dict
        The retained report of the scenario.
    room : bytes
        The room identifier.
    ids : dict[str, bytes]
        The identifier of the owner and of each role.
    """
    main, reader, zero = ids["main"], ids["reader"], ids["zero"]
    base = {FIELD_USER_ID: reader, FIELD_NAME: b"Room30-reader"}
    require(
        pushes(report, "zero", TYPE_MESSAGE_NOTIFICATION)
        == [
            {
                **base,
                FIELD_OPTIONS: b"\0\3",
                FIELD_DATA: b"Room30-reader does not accept private chats.",
            },
            {**base, FIELD_OPTIONS: b"\0\4", FIELD_DATA: b"automatic30"},
        ],
        "Invitation refusal/automatic/sender-suppression feedback differs",
    )
    require(
        not pushes(report, "reader", INVITE), "Refusing invitee received invitation"
    )
    require(
        pushes(report, "speaker", INVITE)
        == [{FIELD_ROOM: room, FIELD_USER_ID: zero, FIELD_NAME: b"Room30-zero"}] * 3,
        "Refusal stopped other target delivery",
    )
    members(report, "reader", 14, {main, reader})


def check_formatting(report: dict, room: bytes) -> None:
    """Check the chat option, formatting, newline and NUL byte preservation.

    Parameters
    ----------
    report : dict
        The retained report of the scenario.
    room : bytes
        The room identifier.
    """
    expected = [
        {
            FIELD_ROOM: room,
            FIELD_DATA: formatted(b"Room30-speaker", text or b"", option == 1),
        }
        for option, text in cases.format_values()
    ]
    expected.append({FIELD_ROOM: room, FIELD_DATA: b"\r       Talk30:  short-name30"})
    for connection in ["main", "reader"]:
        require(
            pushes(report, connection, TYPE_CHAT_NOTIFICATION) == expected,
            "Chat option/format/newline/NUL bytes differ",
        )
    require(
        not pushes(report, "zero", TYPE_CHAT_NOTIFICATION)
        and not pushes(report, "speaker", TYPE_CHAT_NOTIFICATION),
        "Chat recipient membership/receive gate differs",
    )
