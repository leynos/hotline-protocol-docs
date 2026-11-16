"""Plan the account fields, logins, requests and quiet windows of the live cases.

These helpers are re-exported by ``native_live_account_cases``, which the bitmap,
diagnostic, PM, room and identity planners import by name.
"""

from native_auth_cases import authentication, complement
from native_plan import (
    QUIET_WINDOW_SECONDS,
    Action,
    login,
    packet,
    payload,
    read,
    send,
)
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_ACCOUNT_ATTRIBUTE,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
)

# The steps of login() before its login request: connect, handshake and its read.
LOGIN_PREFIX_STEPS = 3
# The icon of a login is a two-byte big-endian word.
ICON_BYTES = 2


def account_values(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # the callers' shape
    key: bytes,
    password: bytes,
    name: bytes,
    access: bytes,
    attribute: bytes = b"live27",
) -> list[tuple[int, bytes]]:
    """Plan the complemented login and password with the name and access fields.

    Returns
    -------
    list[tuple[int, bytes]]
        The login, password, name, access and attribute fields, in that order.
    """
    return [
        (FIELD_LOGIN, complement(key)),
        (FIELD_PASSWORD, complement(password)),
        (FIELD_NAME, name),
        (FIELD_ACCESS_BITMAP, access),
        (FIELD_ACCOUNT_ATTRIBUTE, attribute),
    ]


def subject(name: str, key: bytes, password: bytes, icon: int) -> list[Action]:
    """Plan the login of one named connection as the given account.

    Returns
    -------
    list[native_plan.Action]
        The handshake, the login with its icon, and three reply reads.
    """
    steps = [{**s, "connection": name} for s in login()[:LOGIN_PREFIX_STEPS]]
    return [
        *steps,
        authentication(
            key,
            password,
            name=b"requested-" + name.encode(),
            icon=icon.to_bytes(ICON_BYTES, "big"),
            connection=name,
        ),
        read(name),
        read(name),
        read(name),
    ]


def request(
    connection: str,
    kind: int,
    identifier: int,
    values: list[tuple[int, bytes]] | None = None,
) -> list[Action]:
    """Plan one request on a connection and the read of its reply.

    Returns
    -------
    list[native_plan.Action]
        The send of the request and the read of the reply with ``identifier``.
    """
    return [
        send(packet(kind, identifier, payload(values or [])), connection),
        read(connection, match_frame={"is_reply": 1, "id": identifier}),
    ]


def settled() -> list[Action]:
    """Plan a quiet window on each of the three connections.

    Returns
    -------
    list[native_plan.Action]
        One ``expect_quiet`` action for each of the connections one, two and main.
    """
    return [
        {"op": "expect_quiet", "connection": name, "timeout": QUIET_WINDOW_SECONDS}
        for name in ["one", "two", "main"]
    ]
