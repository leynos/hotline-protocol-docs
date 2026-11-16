"""Build the steps that the room scenarios share: messages, barriers and setup."""

import typing as typ

from native_live_account_cases import request, subject
from native_plan import close, login, packet, quiet, read, send
from native_room_data import PASSWORD, ROLES, key

if typ.TYPE_CHECKING:
    import collections.abc as cabc

ROOM_ID_BYTES = 4  # the room identifier substituted for "{room}"
UID_BYTES = 2  # a user identifier substituted for "{<label>_uid}"
WORD_BYTES = 2  # a field identifier, a field size or a field count
FIELD_HEADER_BYTES = 4  # a field identifier followed by its size
PACKET_HEADER_BYTES = 40  # the fixed header kept from the packet builder
UNKNOWN_SUBSTITUTION = "Unknown room fixture substitution"


def message(
    connection: str,
    kind: int,
    identifier: int,
    values: cabc.Sequence[tuple[int, bytes | str]],
) -> dict:
    """Encode four-byte room and two-byte UID substitutions with exact lengths.

    Parameters
    ----------
    connection : str
        The connection that sends the message.
    kind : int
        The transaction type.
    identifier : int
        The request identifier.
    values : collections.abc.Sequence[tuple[int, bytes | str]]
        Each pair is a field identifier and its bytes, or the name of a
        substitution: ``"room"`` or ``"<label>_uid"`` for an owned role.

    Returns
    -------
    dict
        The send step for the encoded message.

    Raises
    ------
    ValueError
        When a substitution name is not a known room fixture substitution.
    """
    encoded = []
    physical_size = WORD_BYTES
    for field, value in values:
        if isinstance(value, str):
            if value == "room":
                size = ROOM_ID_BYTES
            elif value in {label + "_uid" for label in ROLES}:
                size = UID_BYTES
            else:
                raise ValueError(UNKNOWN_SUBSTITUTION)
        else:
            size = len(value)
        content = "{" + value + "}" if isinstance(value, str) else value.hex()
        encoded.append(
            field.to_bytes(WORD_BYTES, "big").hex()
            + size.to_bytes(WORD_BYTES, "big").hex()
            + content
        )
        physical_size += FIELD_HEADER_BYTES + size
    header = packet(kind, identifier, bytes(physical_size))[:PACKET_HEADER_BYTES]
    return send(
        header + len(values).to_bytes(WORD_BYTES, "big").hex() + "".join(encoded),
        connection,
    )


def barrier(connections: list[str], identifier: int) -> list[dict]:
    """Return the empty-acknowledgement request of each connection in turn.

    Parameters
    ----------
    connections : list[str]
        The connections that take part in the barrier.
    identifier : int
        The request identifier shared by every connection.

    Returns
    -------
    list[dict]
        The steps, in the order of ``connections``.
    """
    steps = []
    for connection in connections:
        steps += request(connection, 500, identifier)
    return steps


def setup() -> list[dict]:
    """Log in, subject each owned role and record its user identifier.

    Returns
    -------
    list[dict]
        The steps that establish the owned roles.
    """
    steps = login()
    for icon, label in enumerate(ROLES, 30):
        steps += subject(label, key(label), PASSWORD, icon)
        steps += [read(match_frame={"type": 301}, save_fields={label + "_uid": 103})]
    return steps


def create() -> list[dict]:
    """Create the owned room from the main connection.

    Returns
    -------
    list[dict]
        The create request and the read of its reply, which saves the room.
    """
    return [
        message("main", 112, 10, []),
        read(match_frame={"is_reply": 1, "id": 10}, save_fields={"room": 114}),
    ]


def finish() -> list[dict]:
    """Drain every connection, close them and end the scenario.

    Returns
    -------
    list[dict]
        The barrier, the quiet step and the closes of the scenario.
    """
    return (
        barrier(["main", *ROLES], 999)
        + [quiet()]
        + [close(label) for label in ROLES]
        + [close()]
    )
