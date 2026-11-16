"""Prepare native transaction-ID, collision and reply-envelope observations."""

from native_plan import Action, close, login, packet, payload, quiet, read, send
from native_queue_cases import Case
from native_wire_names import (
    FIELD_ICON,
    FIELD_NAME,
    TYPE_EMPTY_ACK,
    TYPE_PRESENCE_UPDATE,
    TYPE_SET_CLIENT_INFO,
)

# prepare_native_cases, verify_native_correlation and test_native_correlation
# import correlation; probe is kept because the original module defined it
# publicly.
__all__ = ["correlation", "probe"]

type Cases = dict[str, Case]

REQUEST_ID = 10
FOLLOWUP_ID = 11
PAUSE_SECONDS = 3
READ_SECONDS = 30
BOUNDARY_IDS = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF, 0, 1]
MAX_TYPE = 65535  # the largest request type, which no server handles
ALL_FLAGS = 255
ALL_ERROR_BITS = 0xFFFFFFFF
REPLY_FLAGS = [1, 2, 255]  # reply words that a client should never send
REQUEST_FLAGS = [1, 128]
ZERO_SIZE_REPLY_WORDS = [1, 255]
UNSUPPORTED_TYPES = [0, MAX_TYPE]
PARTIAL_TOTAL = 4  # the declared total of a two-byte payload that is incomplete
INCOMPLETE_TOTAL = 100
ICON_SEVEN = b"\0\x07"
HEADER_PREFIX_BYTES = 18  # fewer than the 20 bytes of a header
BODY_CUT_BYTES = 2  # the frame body is cut short by this many bytes


def probe(identifier: int) -> list[Action]:
    """Plan an empty request with ``identifier`` and the read of its ACK.

    Returns
    -------
    list[native_plan.Action]
        The send and the matching reply read.
    """
    return [
        send(packet(TYPE_EMPTY_ACK, identifier)),
        read(match_frame={"is_reply": 1, "id": identifier}),
    ]


def case(steps: list[Action], expectation: dict[str, object]) -> Case:
    """Wrap steps in a login at the start and a close at the end.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The case's steps and its expectation.
    """
    return ([*login(), *steps, close()], expectation)


def acks(steps: list[Action], ids: list[int]) -> Case:
    """Plan a case that expects one direct ACK for each of ``ids``.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The case's steps and its expectation.
    """
    return case(steps, {"kind": "acks", "ids": ids})


def collision_cases() -> Cases:
    """Plan the reuse, pipelining and collision of request IDs.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The five cases, in plan order.
    """
    renamed = payload([(FIELD_NAME, b"collision-name"), (FIELD_ICON, ICON_SEVEN)])
    pause = {"op": "pause", "seconds": PAUSE_SECONDS}
    return {
        "client-id-boundaries-and-reuse": acks(
            [step for identifier in BOUNDARY_IDS for step in probe(identifier)],
            BOUNDARY_IDS,
        ),
        "pipelined-duplicate-id": acks(
            [
                send(packet(TYPE_EMPTY_ACK, REQUEST_ID) * 2),
                read(),
                quiet(),
                *probe(FOLLOWUP_ID),
            ],
            [REQUEST_ID, FOLLOWUP_ID],
        ),
        "pipelined-distinct-ids": acks(
            [
                send(
                    packet(TYPE_EMPTY_ACK, REQUEST_ID)
                    + packet(TYPE_EMPTY_ACK, FOLLOWUP_ID)
                ),
                read(),
                read(),
                quiet(),
            ],
            [REQUEST_ID, FOLLOWUP_ID],
        ),
        "duplicate-id-after-dispatch-pause": acks(
            [
                send(packet(TYPE_EMPTY_ACK, REQUEST_ID)),
                pause,
                send(packet(TYPE_EMPTY_ACK, REQUEST_ID)),
                read(),
                read(),
                quiet(),
            ],
            [REQUEST_ID, REQUEST_ID],
        ),
        "pipelined-id-collision-last-type": case(
            [
                send(
                    packet(TYPE_EMPTY_ACK, REQUEST_ID)
                    + packet(TYPE_SET_CLIENT_INFO, REQUEST_ID, renamed)
                ),
                read(match_frame={"type": TYPE_PRESENCE_UPDATE, "is_reply": 0}),
                quiet(),
                *probe(FOLLOWUP_ID),
            ],
            {
                "kind": "collision-notification",
                "ids": [FOLLOWUP_ID],
                "name_hex": b"***".hex(),
                "icon": 0,
            },
        ),
    }


def late_reply_cases() -> Cases:
    """Plan the replies that a client sends for IDs the server has used.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        Two cases for each reply word, in plan order.
    """
    cases = {}
    for reply in REPLY_FLAGS:
        wide = packet(
            MAX_TYPE, REQUEST_ID, flags=ALL_FLAGS, reply=reply, error=ALL_ERROR_BITS
        )
        cases[f"late-reply-{reply}-completed-client-id"] = acks(
            [*probe(REQUEST_ID), send(wide), quiet(), *probe(REQUEST_ID)],
            [REQUEST_ID, REQUEST_ID],
        )
        notice = packet(MAX_TYPE, 1, flags=ALL_FLAGS, reply=reply, error=ALL_ERROR_BITS)
        cases[f"reply-{reply}-server-notification-id"] = acks(
            [send(notice), quiet(), *probe(1)], [1]
        )
    return cases


def id_space_cases() -> Cases:
    """Plan the separation of notification and reply IDs, and partial frames.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The three cases, in plan order.
    """
    name = b"correlation-name"
    renamed = payload([(FIELD_NAME, name), (FIELD_ICON, ICON_SEVEN)])
    partial = packet(TYPE_EMPTY_ACK, REQUEST_ID, b"\0\0", total=PARTIAL_TOTAL)
    wide = packet(
        MAX_TYPE, REQUEST_ID, reply=ALL_FLAGS, flags=ALL_FLAGS, error=ALL_ERROR_BITS
    )
    return {
        "notification-and-direct-reply-id-spaces": case(
            [
                *probe(1),
                send(packet(TYPE_SET_CLIENT_INFO, 1, renamed)),
                read(match_frame={"type": TYPE_PRESENCE_UPDATE, "is_reply": 0}),
                *probe(1),
            ],
            {"kind": "notification", "ids": [1, 1], "name_hex": name.hex(), "icon": 7},
        ),
        "partial-request-and-wide-reply-same-id": acks(
            [send(partial), quiet(), send(wide), quiet(), send(partial), read()],
            [REQUEST_ID],
        ),
        "incomplete-request-id-reused-with-smaller-total": acks(
            [
                send(packet(TYPE_EMPTY_ACK, REQUEST_ID, b"\0", total=INCOMPLETE_TOTAL)),
                quiet(),
                send(packet(TYPE_EMPTY_ACK, REQUEST_ID)),
                read(),
                *probe(REQUEST_ID),
            ],
            [REQUEST_ID, REQUEST_ID],
        ),
    }


def request_word_cases() -> Cases:
    """Plan requests with unsupported types and unexpected flag words.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The unsupported-type cases and then the flag cases, in plan order.
    """
    cases = {}
    for kind in UNSUPPORTED_TYPES:
        cases[f"unsupported-request-type-{kind}"] = case(
            [
                send(packet(kind, REQUEST_ID, flags=ALL_FLAGS, error=ALL_ERROR_BITS)),
                read(),
                *probe(FOLLOWUP_ID),
            ],
            {"kind": "unsupported", "request_type": kind},
        )
    for flags in REQUEST_FLAGS:
        cases[f"request-flags-{flags}-error-ffffffff"] = acks(
            [
                send(
                    packet(
                        TYPE_EMPTY_ACK, REQUEST_ID, flags=flags, error=ALL_ERROR_BITS
                    )
                ),
                read(),
            ],
            [REQUEST_ID],
        )
    return cases


def eof_read() -> Action:
    """Plan the wait for the server to close with nothing more to say.

    Returns
    -------
    native_plan.Action
        The ``read_eof`` action.
    """
    return {
        "op": "read_eof",
        "connection": "main",
        "timeout": READ_SECONDS,
        "expect_hex": "",
    }


def close_cases() -> Cases:
    """Plan the inputs that make the server close the connection.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The zero-size reply cases and then the truncated-input cases.
    """
    cases = {}
    for reply in ZERO_SIZE_REPLY_WORDS:
        cases[f"reply-{reply}-zero-size-rejection"] = case(
            [
                send(packet(MAX_TYPE, 1, b"", reply=reply, total=0, size=0)),
                eof_read(),
            ],
            {"kind": "close"},
        )
    whole = packet(TYPE_EMPTY_ACK, REQUEST_ID)
    underfilled = packet(TYPE_EMPTY_ACK, REQUEST_ID, b"\0\0", total=PARTIAL_TOTAL)
    second = packet(TYPE_EMPTY_ACK, FOLLOWUP_ID, b"\0\0", total=PARTIAL_TOTAL)
    for name, raw in [
        ("partial-header-eof", whole[:HEADER_PREFIX_BYTES]),
        ("partial-frame-body-eof", whole[:-BODY_CUT_BYTES]),
        ("underfilled-transaction-eof", underfilled),
        ("interleaved-underfilled-transactions-eof", underfilled + second),
    ]:
        cases[name] = case(
            [
                send(raw),
                quiet(),
                {"op": "shutdown_write", "connection": "main"},
                eof_read(),
            ],
            {"kind": "close"},
        )
    return cases


def correlation() -> Cases:
    """Plan every ID and envelope observation.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The cases, in the order that the plans have always had.
    """
    return {
        **collision_cases(),
        **late_reply_cases(),
        **id_space_cases(),
        **request_word_cases(),
        **close_cases(),
    }
