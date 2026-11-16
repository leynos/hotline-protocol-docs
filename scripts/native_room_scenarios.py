"""Build the room scenarios: permissions, topics, lifecycle and invitations."""

from native_live_account_cases import account_values, request
from native_mkdir_cases import exchange
from native_plan import close, quiet, read
from native_room_data import PASSWORD, ROLES, format_values, key
from native_room_steps import barrier, create, finish, message, setup


def basics() -> tuple[list[dict], dict]:
    """Build the basic permission and chat scenario.

    Returns
    -------
    tuple[list[dict], dict]
        The steps and the expectation of the scenario.
    """
    steps = setup() + create()
    steps += request("zero", 112, 11)
    steps += [message("zero", 120, 12, [(114, "room"), (115, b"outsider-topic30")])]
    steps += barrier(["zero", "main"], 100)
    for identifier, label in [(13, "reader"), (14, "zero")]:
        steps += [
            message(label, 115, identifier, [(114, "room")]),
            read(label, match_frame={"is_reply": 1, "id": identifier}),
        ]
        steps += barrier(["main", "reader", "zero"], identifier + 100)
    for identifier, label in [(15, "speaker"), (16, "zero"), (17, "reader")]:
        steps += [
            message(
                label,
                105,
                identifier,
                [(114, "room"), (101, b"room-message30-" + label.encode())],
            )
        ]
        steps += barrier(
            [label] + [c for c in ["main", *ROLES] if c != label], identifier + 100
        )
    for identifier, values in [
        (18, [(101, b"main-implicit30")]),
        (19, [(114, b"\0\0"), (101, b"main-zero30")]),
    ]:
        steps += [message("speaker", 105, identifier, values)]
        steps += barrier(["speaker", "main", "reader", "zero"], identifier + 100)
    for identifier, values in [(20, []), (21, [(114, b"\xff\xff")])]:
        steps += [
            message("zero", 115, identifier, values),
            read("zero", match_frame={"is_reply": 1, "id": identifier}),
        ]
    return steps + finish(), {"kind": "room-basics"}


def topics() -> tuple[list[dict], dict]:
    """Build the topic length, default and byte-preservation scenario.

    Returns
    -------
    tuple[list[dict], dict]
        The steps and the expectation of the scenario.
    """
    steps = setup() + create()
    steps += [
        message("reader", 115, 11, [(114, "room")]),
        read("reader", match_frame={"is_reply": 1, "id": 11}),
    ]
    steps += barrier(["reader", "main", "zero", "speaker"], 100)
    values = [
        None,
        b"",
        b"topic30",
        b"A\0B\rC\nD\x80\xff",
        b"X" * 255,
        b"Y" * 256,
        b"Z" * 65535,
        None,
    ]
    for identifier, value in enumerate(values, 20):
        fields = [(114, "room")] + ([] if value is None else [(115, value)])
        steps += [message("zero", 120, identifier, fields)]
        steps += barrier(["zero", "main", "reader", "speaker"], identifier + 100)
        steps += [
            message("reader", 115, identifier + 200, [(114, "room")]),
            read("reader", match_frame={"is_reply": 1, "id": identifier + 200}),
        ]
    steps += [message("zero", 120, 40, [(114, b"\xff\xff"), (115, b"missing30")])]
    steps += barrier(["zero", "main", "reader", "speaker"], 140)
    return steps + finish(), {"kind": "room-topics"}


def lifecycle() -> tuple[list[dict], dict]:
    """Build the join, repeated join, leave and deletion scenario.

    Returns
    -------
    tuple[list[dict], dict]
        The steps and the expectation of the scenario.
    """
    steps = setup() + create()
    for identifier, label in [(11, "reader"), (12, "reader"), (13, "zero")]:
        steps += [
            message(label, 115, identifier, [(114, "room")]),
            read(label, match_frame={"is_reply": 1, "id": identifier}),
        ]
        steps += barrier(
            [label] + [c for c in ["main", *ROLES] if c != label], identifier + 100
        )
    for identifier, label in [(14, "zero"), (15, "zero"), (16, "main"), (17, "reader")]:
        steps += [message(label, 116, identifier, [(114, "room")])]
        steps += barrier(
            [label] + [c for c in ["main", *ROLES] if c != label], identifier + 100
        )
    steps += [
        message("zero", 115, 18, [(114, "room")]),
        read("zero", match_frame={"is_reply": 1, "id": 18}),
    ]
    steps += [message("zero", 120, 19, [(114, "room"), (115, b"deleted30")])]
    steps += barrier(["zero", "main", "reader", "speaker"], 119)
    return steps + finish(), {"kind": "room-lifecycle"}


def concurrent() -> tuple[list[dict], dict]:
    """Build the concurrent join and leave scenario.

    Returns
    -------
    tuple[list[dict], dict]
        The steps and the expectation of the scenario.
    """
    steps = setup() + create()
    for identifier, label in [(11, "reader"), (12, "zero")]:
        steps += [message(label, 115, identifier, [(114, "room")])]
    for identifier, label in [(11, "reader"), (12, "zero")]:
        steps += [read(label, match_frame={"is_reply": 1, "id": identifier})]
    steps += barrier(["reader", "zero", "main", "speaker"], 100)
    for identifier, label in [(13, "reader"), (14, "zero")]:
        steps += [message(label, 116, identifier, [(114, "room")])]
    steps += barrier(["reader", "zero", "main", "speaker"], 101)
    steps += [message("main", 116, 15, [(114, "room")])]
    steps += barrier(["main", "zero", "reader", "speaker"], 102)
    steps += [
        message("zero", 115, 16, [(114, "room")]),
        read("zero", match_frame={"is_reply": 1, "id": 16}),
    ]
    return steps + finish(), {"kind": "room-concurrent"}


def create_invites() -> tuple[list[dict], dict]:
    """Build the mixed-target invitation creation scenario.

    Returns
    -------
    tuple[list[dict], dict]
        The steps and the expectation of the scenario.
    """
    steps = setup()
    steps += [
        message(
            "main",
            112,
            10,
            [
                (103, "reader_uid"),
                (103, b"\xff\xff"),
                (103, "reader_uid"),
                (103, "speaker_uid"),
                (103, "zero_uid"),
            ],
        ),
        read(match_frame={"is_reply": 1, "id": 10}, save_fields={"room": 114}),
    ]
    steps += barrier(["main", *ROLES], 100)
    for identifier in [11, 12]:
        steps += [message("reader", 114, identifier, [(114, "room")])]
        steps += barrier(["reader", "main", "zero", "speaker"], identifier + 100)
    steps += [
        message("reader", 115, 13, [(114, "room")]),
        read("reader", match_frame={"is_reply": 1, "id": 13}),
    ]
    return steps + finish(), {"kind": "room-create-invites"}


def invites() -> tuple[list[dict], dict]:
    """Build the invitation delivery, retry and disconnection scenario.

    Returns
    -------
    tuple[list[dict], dict]
        The steps and the expectation of the scenario.
    """
    steps = setup() + create()
    steps += [
        message(
            "zero",
            113,
            11,
            [
                (114, "room"),
                (103, "reader_uid"),
                (103, b"\xff\xff"),
                (103, "reader_uid"),
                (103, "speaker_uid"),
                (103, "zero_uid"),
            ],
        )
    ]
    steps += barrier(["zero", "main", "reader", "speaker"], 100)
    steps += [close("speaker"), {"op": "pause", "seconds": 3}]
    steps += [
        message(
            "zero", 113, 12, [(114, "room"), (103, "speaker_uid"), (103, "reader_uid")]
        )
    ]
    steps += barrier(["zero", "main", "reader"], 101)
    steps += [
        message("reader", 115, 13, [(114, "room")]),
        read("reader", match_frame={"is_reply": 1, "id": 13}),
    ]
    steps += [
        message(
            "zero",
            113,
            14,
            [(114, "room"), (103, "reader_uid"), (103, "zero_uid"), (103, b"\xff\xff")],
        )
    ]
    steps += barrier(["zero", "main", "reader"], 102)
    steps += [
        message("zero", 115, 15, [(114, "room")]),
        read("zero", match_frame={"is_reply": 1, "id": 15}),
    ]
    steps += [message("zero", 113, 16, [(114, b"\xff\xff"), (103, "reader_uid")])]
    steps += barrier(["zero", "main", "reader"], 999)
    return [*steps, quiet(), close("zero"), close("reader"), close()], {
        "kind": "room-invites"
    }


def refusals() -> tuple[list[dict], dict]:
    """Build the invitation refusal and automatic-response scenario.

    Returns
    -------
    tuple[list[dict], dict]
        The steps and the expectation of the scenario.
    """
    steps = setup() + create()
    for identifier, options, automatic in [(11, 2, None), (12, 6, b"automatic30")]:
        values = [(104, b"\0\x1f"), (113, options.to_bytes(2, "big"))]
        if automatic is not None:
            values.append((215, automatic))
        steps += [message("reader", 304, identifier, values)]
        steps += barrier(["reader", "main", "zero", "speaker"], identifier + 200)
        steps += [
            message(
                "zero",
                113,
                identifier + 10,
                [(114, "room"), (103, "reader_uid"), (103, "speaker_uid")],
            )
        ]
        steps += barrier(["zero", "main", "reader", "speaker"], identifier + 100)
    steps += [message("zero", 304, 13, [(104, b"\0\x1e"), (113, b"\0\1")])]
    steps += barrier(["zero", "main", "reader", "speaker"], 213)
    steps += [
        message(
            "zero", 113, 23, [(114, "room"), (103, "reader_uid"), (103, "speaker_uid")]
        )
    ]
    steps += barrier(["zero", "main", "reader", "speaker"], 113)
    steps += [
        message("reader", 115, 14, [(114, "room")]),
        read("reader", match_frame={"is_reply": 1, "id": 14}),
    ]
    return steps + finish(), {"kind": "room-refusals"}


def formatting() -> tuple[list[dict], dict]:
    """Build the chat option, formatting and byte-preservation scenario.

    Returns
    -------
    tuple[list[dict], dict]
        The steps and the expectation of the scenario.
    """
    steps = setup() + create()
    for identifier, label in [(11, "reader"), (12, "zero")]:
        steps += [
            message(label, 115, identifier, [(114, "room")]),
            read(label, match_frame={"is_reply": 1, "id": identifier}),
        ]
    for identifier, (option, text) in enumerate(format_values(), 20):
        values: list[tuple[int, bytes | str]] = [(114, "room")]
        if option is not None:
            values.append((109, option.to_bytes(2, "big")))
        if text is not None:
            values.append((101, text))
        steps += [message("speaker", 105, identifier, values)]
        steps += barrier(["speaker", "main", "reader", "zero"], identifier + 100)
    steps += exchange(
        353,
        40,
        account_values(
            key("speaker"), PASSWORD, b"Talk30", ROLES["speaker"], b"room30"
        ),
    )
    steps += barrier(["main", *ROLES], 140)
    steps += [message("speaker", 105, 41, [(114, "room"), (101, b"short-name30")])]
    steps += barrier(["speaker", "main", "reader", "zero"], 141)
    steps += exchange(
        353,
        42,
        account_values(
            key("speaker"), PASSWORD, b"Room30-speaker", ROLES["speaker"], b"room30"
        ),
    )
    return steps + finish(), {"kind": "room-formatting"}
