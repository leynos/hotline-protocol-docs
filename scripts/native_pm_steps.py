"""Build the send steps of the private-message observation."""

import typing as typ

from native_live_account_cases import request
from native_plan import packet, payload, send
from native_wire_names import (
    FIELD_AUTO_RESPONSE,
    FIELD_ICON,
    FIELD_NAME,
    FIELD_OPTIONS,
    FIELD_USER_ID,
    TYPE_EMPTY_ACK,
    TYPE_SET_CLIENT_INFO,
)

type Json = dict[str, typ.Any]

FRAME_HEADER_HEX_CHARS = 40  # the 20-byte frame header of a built packet
UID_FIELD_BYTES = 8  # count word, field header and a two-byte user id
UID_BYTES = 2
FIELD_ID_BYTES = 2
FIELD_SIZE_BYTES = 2
BARRIER_OFFSET = 100  # a settings barrier uses the settings id plus this
QUIET_SECONDS = 2


def variable_message(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # the planners call it positionally  # pylint: disable=too-many-arguments,too-many-positional-arguments  # as above
    kind: int,
    identifier: int,
    uid: str,
    fields: list[tuple[int, bytes]],
    connection: str = "main",
) -> Json:
    """Build a send step whose target user id is a saved variable.

    Parameters
    ----------
    kind : int
        The transaction type.
    identifier : int
        The request identifier.
    uid : str
        ``main_uid`` or ``peer_uid``, the variable that holds the target.
    fields : list[tuple[int, bytes]]
        The fields after the user id.
    connection : str
        The sending connection.

    Returns
    -------
    dict[str, typing.Any]
        The send step.

    Raises
    ------
    ValueError
        If ``uid`` is not one of the two saved variables.
    """
    if uid not in {"main_uid", "peer_uid"}:
        message = "UID must come from the current observed connection"
        raise ValueError(message)
    body = (
        (1 + len(fields)).to_bytes(2, "big").hex()
        + FIELD_USER_ID.to_bytes(FIELD_ID_BYTES, "big").hex()
        + UID_BYTES.to_bytes(FIELD_SIZE_BYTES, "big").hex()
        + "{"
        + uid
        + "}"
    )
    length = UID_FIELD_BYTES
    for field, value in fields:
        body += (
            field.to_bytes(FIELD_ID_BYTES, "big").hex()
            + len(value).to_bytes(FIELD_SIZE_BYTES, "big").hex()
            + value.hex()
        )
        length += FIELD_ID_BYTES + FIELD_SIZE_BYTES + len(value)
    header = packet(kind, identifier, bytes(length))[:FRAME_HEADER_HEX_CHARS]
    return send(header + body, connection)


def barrier(identifier: int) -> list[Json]:
    """Ask both sessions a question, then expect both to be quiet.

    Parameters
    ----------
    identifier : int
        The request identifier of the question.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps.
    """
    steps: list[Json] = []
    for connection in ("main", "peer"):
        steps += request(connection, TYPE_EMPTY_ACK, identifier)
    quiet = [
        {"op": "expect_quiet", "connection": connection, "timeout": QUIET_SECONDS}
        for connection in ("main", "peer")
    ]
    return [*steps, *quiet]


def settings(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # the planners call it positionally  # pylint: disable=too-many-arguments,too-many-positional-arguments  # as above
    connection: str, identifier: int, name: bytes, options: int, auto: bytes = b""
) -> list[Json]:
    """Set a session's name and options, then run a barrier.

    Parameters
    ----------
    connection : str
        The session to configure.
    identifier : int
        The request identifier; the barrier uses it plus 100.
    name : bytes
        The session's name.
    options : int
        The PM options word.
    auto : bytes
        The automatic reply text; absent when empty.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps.
    """
    values = [
        (FIELD_NAME, name),
        (FIELD_ICON, b"\0\x01"),
        (FIELD_OPTIONS, options.to_bytes(2, "big")),
    ]
    if auto:
        values.append((FIELD_AUTO_RESPONSE, auto))
    request_step = send(
        packet(TYPE_SET_CLIENT_INFO, identifier, payload(values)), connection
    )
    return [request_step, *barrier(identifier + BARRIER_OFFSET)]
