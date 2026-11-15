"""Prepare controlled queues with global limit2 and per-session limit1."""

import typing as typ

from native_plan import Action, close, connect, eof, login, packet, payload, read, send
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_TRANSFER_OPTION,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    TYPE_DOWNLOAD_FILE,
    TYPE_EMPTY_ACK,
    TYPE_REFERENCE_CLEANUP,
)

type Case = tuple[list[Action], dict[str, typ.Any]]

# A cleanup request carries the four reference bytes (transfer-contracts.md,
# "Reference allocation and request 214"). The plan writes a marker of that width
# and replaces it with the recorder's saved variable.
REFERENCE_MARKER = b"REF!"
EMPTY_FIXTURE = b"mothra-empty-fixture"
FORK_FIXTURE = b"mothra-fork-fixture"
MODE_BYTES = 2
PUMP_SECONDS = 3
TIMER_PUMP_SECONDS = 45
TIMER_PUMPS = 12
TIMER_WAIT_SECONDS = 540
QUIET_SECONDS = 3
DATA_READ_SECONDS = 30
HTXF_MAGIC_HEX = "48545846"  # `HTXF`, then the reference (transfer-contracts.md)
HTXF_TAIL_HEX = "0000000000000000"  # eight zero bytes after the reference
MODE_MATRIX_FIRST_ID = 11  # request IDs 11 to 16 take the six queued modes
MODE_MATRIX_ZERO_PREVIEW_ID = 17
MODE_MATRIX_COUNT = 6
MODE_SPECS = [
    (0, False),
    (1, False),
    (3, False),
    (65535, False),
    (2, False),
    (None, True),
]
REFUSED_REFERENCES = [(32, bytes(4)), (33, bytes.fromhex("ffffffff"))]


class RequestOptions(typ.TypedDict, total=False):
    """The choices of a download request; each defaults to off.

    ``mode`` is the transfer option; ``empty`` asks for the empty fixture; and
    ``empty_preview`` leaves the reference unsaved because none is returned.
    """

    mode: int | None
    empty: bool
    empty_preview: bool


def session(name: str) -> list[Action]:
    """Plan a login on a connection with the given name.

    Returns
    -------
    list[native_plan.Action]
        The login steps, each moved to the named connection.
    """
    return [{**s, "connection": name} for s in login()]


def request(
    owner: str,
    identifier: int,
    variable: str,
    **options: typ.Unpack[RequestOptions],
) -> list[Action]:
    """Plan a download request and the read of its ACK.

    Returns
    -------
    list[native_plan.Action]
        The send and the reply read; a reply that carries a reference saves it
        and the transfer size under ``variable``.
    """
    empty = options.get("empty", False)
    filename = EMPTY_FIXTURE if empty else FORK_FIXTURE
    values = [(FIELD_FILE_NAME, filename)]
    mode = options.get("mode")
    if mode is not None:
        values.append((FIELD_TRANSFER_OPTION, mode.to_bytes(MODE_BYTES, "big")))
    read_options: dict[str, typ.Any] = {
        "match_frame": {"is_reply": 1, "id": identifier}
    }
    if not options.get("empty_preview"):
        read_options["save_fields"] = {
            variable: FIELD_TRANSFER_REFERENCE,
            variable + "_size": FIELD_TRANSFER_SIZE,
        }
    return [
        send(packet(TYPE_DOWNLOAD_FILE, identifier, payload(values)), owner),
        read(owner, **read_options),
    ]


def cancel(owner: str, identifier: int, variable: str | None) -> list[Action]:
    """Plan a reference cleanup and the read of its ACK.

    Returns
    -------
    list[native_plan.Action]
        The send, whose reference is the saved ``variable`` when one is named,
        and the reply read.
    """
    value = (
        payload([(FIELD_TRANSFER_REFERENCE, REFERENCE_MARKER)]) if variable else b"\0\0"
    )
    encoded = packet(TYPE_REFERENCE_CLEANUP, identifier, value)
    if variable:
        encoded = encoded.replace(REFERENCE_MARKER.hex(), "{" + variable + "}")
    return [
        send(encoded, owner),
        read(owner, match_frame={"is_reply": 1, "id": identifier}),
    ]


def pump(owner: str, identifier: int, seconds: int = PUMP_SECONDS) -> list[Action]:
    """Plan a pause and an empty ACK request that flushes queue notices.

    Returns
    -------
    list[native_plan.Action]
        The pause, the send and the reply read.
    """
    return [
        {"op": "pause", "seconds": seconds},
        send(packet(TYPE_EMPTY_ACK, identifier), owner),
        read(owner, match_frame={"is_reply": 1, "id": identifier}),
    ]


def attach(variable: str) -> list[Action]:
    """Plan opening a data connection for a saved reference.

    Returns
    -------
    list[native_plan.Action]
        The connect and the greeting that names the reference.
    """
    return [
        connect(variable, "data"),
        send(HTXF_MAGIC_HEX + "{" + variable + "}" + HTXF_TAIL_HEX, variable),
    ]


def read_data(variable: str) -> Action:
    """Plan reading the whole transfer that ``variable`` advertised.

    Returns
    -------
    native_plan.Action
        The sized ``read`` action.
    """
    return {
        "op": "read",
        "connection": variable,
        "size_from": variable + "_size",
        "timeout": DATA_READ_SECONDS,
    }


def quiet_on(connection: str) -> Action:
    """Plan a bounded silence on a data connection.

    Returns
    -------
    native_plan.Action
        The ``expect_quiet`` action.
    """
    return {"op": "expect_quiet", "connection": connection, "timeout": QUIET_SECONDS}


def take(owner: str, variable: str, identifier: int) -> list[Action]:
    """Plan attaching, reading and cleaning up one queued transfer.

    Returns
    -------
    list[native_plan.Action]
        The attach, the read, the cleanup, then end of stream and close.
    """
    return [
        *attach(variable),
        read_data(variable),
        *cancel(owner, identifier, variable),
        eof(variable),
        close(variable),
    ]


def mode_matrix() -> Case:
    """Plan the six queued modes behind one blocker.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the expectation of ``queue-modes``.
    """
    steps = session("a") + request("a", 10, "blocker")
    for index, (mode, empty) in enumerate(MODE_SPECS, MODE_MATRIX_FIRST_ID):
        steps += request("a", index, f"m{index}", mode=mode, empty=empty)
    steps += request(
        "a", MODE_MATRIX_ZERO_PREVIEW_ID, "zero", mode=2, empty=True, empty_preview=True
    )
    steps += cancel("a", 20, "blocker") + pump("a", 21)
    last = MODE_MATRIX_FIRST_ID + MODE_MATRIX_COUNT
    for index in range(MODE_MATRIX_FIRST_ID, last):
        steps += take("a", f"m{index}", index + 20) + pump("a", index + 40)
    steps += [close("a")]
    return steps, {"kind": "queue-modes"}


def cancel_position() -> Case:
    """Plan cancelling a queued transfer in the middle of the queue.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the expectation of ``queue-cancel-position``.
    """
    steps = session("a")
    for index in range(1, 5):
        steps += request("a", 9 + index, f"a{index}")
    steps += [*attach("a3"), quiet_on("a3")]
    steps += [*cancel("a", 20, "a3"), eof("a3"), close("a3"), *pump("a", 21)]
    steps += cancel("a", 22, "a2") + pump("a", 23)
    steps += cancel("a", 24, "a1") + pump("a", 25)
    steps += take("a", "a4", 26) + cancel("a", 27, "a4") + [close("a")]
    return steps, {"kind": "queue-cancel-position"}


def two_owner_order() -> Case:
    """Plan two sessions queueing so that eligibility decides the order.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the expectation of ``queue-two-owner-order``.
    """
    steps = session("a")
    for index in range(1, 4):
        steps += request("a", 9 + index, f"a{index}")
    steps += session("b") + request("b", 10, "b1") + request("b", 11, "b2")
    steps += cancel("b", 20, "b1") + pump("b", 21) + pump("a", 22)
    steps += take("b", "b2", 23)
    steps += cancel("a", 24, "a1") + pump("a", 25)
    steps += [*attach("a3"), quiet_on("a3")]
    steps += [*cancel("b", 26, "a2"), quiet_on("a3")]
    steps += cancel("a", 27, "a2") + pump("a", 28)
    steps += [read_data("a3")]
    steps += [*cancel("a", 29, "a3"), eof("a3"), close("a3")]
    steps += cancel("a", 30, "a1") + cancel("a", 31, None)
    for identifier, encoded in REFUSED_REFERENCES:
        steps += [
            send(
                packet(
                    TYPE_REFERENCE_CLEANUP,
                    identifier,
                    payload([(FIELD_TRANSFER_REFERENCE, encoded)]),
                ),
                "a",
            ),
            read("a", match_frame={"is_reply": 1, "id": identifier}),
        ]
    steps += [close("b"), close("a")]
    return steps, {"kind": "queue-two-owner-order"}


def queues() -> dict[str, Case]:
    """Plan the three ordering cases.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The steps and expectation of each case, by name.
    """
    return {
        "queue-mode-matrix": mode_matrix(),
        "queue-cancel-position": cancel_position(),
        "queue-two-owner-order": two_owner_order(),
    }


def timer() -> dict[str, Case]:
    """Plan the pending-timeout case.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The steps and expectation of ``queue-pending-timeout``.
    """
    steps = session("a") + request("a", 10, "expired") + request("a", 11, "waiting")
    for index in range(TIMER_PUMPS):
        steps += pump("a", 100 + index, TIMER_PUMP_SECONDS)
    steps += [*attach("expired"), eof("expired"), close("expired")]
    steps += [*take("a", "waiting", 120), close("a")]
    return {
        "queue-pending-timeout": (
            steps,
            {"kind": "queue-pending-timeout", "wait_seconds": TIMER_WAIT_SECONDS},
        )
    }
