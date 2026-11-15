"""Prepare native account lookup and login/agreement transition observations."""

from native_auth_states import reauthentication, states
from native_auth_steps import (
    ACCOUNTS,
    ADMIN_PASSWORD,
    FIRST_ID,
    HANDSHAKE_STEPS,
    KEY31,
    KEY32,
    PAIR_OFFSET,
    PASSWORD,
    Cases,
    answer,
    authentication,
    complement,
    pause,
    roster,
)
from native_plan import close, login, packet, payload, quiet, read, send
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    TYPE_CREATE_ACCOUNT,
    TYPE_DELETE_ACCOUNT,
    TYPE_GET_ACCOUNT,
)

# prepare_native_cases and native_agreement_cases import the planners and the
# shared steps from this module; verify_native_auth imports ACCOUNTS, KEY32 and
# PASSWORD; and many cases modules import authentication and complement.
__all__ = [
    "ACCOUNTS",
    "KEY31",
    "KEY32",
    "PASSWORD",
    "authentication",
    "cleanup",
    "complement",
    "guest_create",
    "lookup",
    "reauthentication",
    "roster",
    "seed",
    "states",
]

GUEST_ABSENT_ID = 9
LOGIN_SUCCESSES = {
    "admin-mixed-case",
    "admin-upper-case",
    "carriage-return-maps-to-hyphen",
    "high-byte-80-maps-to-8a",
    "name-length31",
}
# Each tuple is the case name, the login key and the password it sends.
LOOKUPS: list[tuple[str, bytes | None, bytes]] = [
    ("admin-mixed-case", b"AdMiN", ADMIN_PASSWORD),
    ("admin-upper-case", b"ADMIN", ADMIN_PASSWORD),
    ("guest-absent", None, b""),
    ("guest-empty", b"", b""),
    ("guest-explicit", b"guest", b""),
    ("unknown-nonempty", b"m-auth-no-such-account", b""),
    ("carriage-return-maps-to-hyphen", b"m-auth\rcr", PASSWORD),
    ("high-byte-80-maps-to-8a", b"m-auth-\x80", PASSWORD),
    ("nul-leading", b"\0admin", ADMIN_PASSWORD),
    ("nul-trailing", b"admin\0", ADMIN_PASSWORD),
    ("nul-interior", b"ad\0min", ADMIN_PASSWORD),
    ("nul-only", b"\0", b""),
    ("name-length31", KEY31, PASSWORD),
    ("name-length32", KEY32, PASSWORD),
    ("name-over32-clipped", KEY32 + b"-ignored", PASSWORD),
]


def seed() -> Cases:
    """Plan the creation and readback of the owned accounts.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The one seeding case.
    """
    steps = login()
    steps += [
        send(
            packet(
                TYPE_GET_ACCOUNT, GUEST_ABSENT_ID, payload([(FIELD_LOGIN, b"guest")])
            )
        ),
        read(),
    ]
    for identifier, (key, name, privileges) in enumerate(ACCOUNTS, FIRST_ID):
        create = payload([
            (FIELD_LOGIN, complement(key)),
            (FIELD_PASSWORD, complement(PASSWORD)),
            (FIELD_NAME, name),
            (FIELD_ACCESS_BITMAP, privileges),
        ])
        readback = identifier + PAIR_OFFSET
        steps += [
            send(packet(TYPE_CREATE_ACCOUNT, identifier, create)),
            answer(identifier),
            send(packet(TYPE_GET_ACCOUNT, readback, payload([(FIELD_LOGIN, key)]))),
            answer(readback),
        ]
    steps += [pause(), close()]
    return {"seed-owned-auth-accounts": (steps, {"kind": "account-seed"})}


def lookup_label(name: str, *, missing_guest: bool) -> str:
    """Name a lookup case, marking the guest phase it belongs to.

    Returns
    -------
    str
        The case name, prefixed for a guest lookup.
    """
    if not name.startswith("guest-"):
        return name
    return ("missing-" if missing_guest else "configured-") + name


def lookup(*, missing_guest: bool = False) -> Cases:
    """Plan each login-key lookup, in the guest phase that is asked for.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The lookup cases; with ``missing_guest`` only the guest cases.
    """
    cases = {}
    for name, key, password in LOOKUPS:
        if missing_guest and not name.startswith("guest-"):
            continue
        success = name in LOGIN_SUCCESSES or (
            name.startswith("guest-") and not missing_guest
        )
        steps = [*login()[:HANDSHAKE_STEPS], authentication(key, password), read()]
        if success:
            steps += [read(), read()]
        steps += [quiet(), close()]
        cases[lookup_label(name, missing_guest=missing_guest)] = (
            steps,
            {
                "kind": "lookup",
                "key_hex": None if key is None else key.hex(),
                "success": success,
            },
        )
    return cases


def guest_create() -> Cases:
    """Plan the creation and readback of a temporary guest account.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The one guest-creation case.
    """
    create = payload([
        (FIELD_LOGIN, complement(b"guest")),
        (FIELD_PASSWORD, b""),
        (FIELD_NAME, b"Auth guest"),
        (FIELD_ACCESS_BITMAP, bytes(8)),
    ])
    readback = FIRST_ID + 1
    steps = [
        *login(),
        send(packet(TYPE_CREATE_ACCOUNT, FIRST_ID, create)),
        answer(FIRST_ID),
        send(packet(TYPE_GET_ACCOUNT, readback, payload([(FIELD_LOGIN, b"guest")]))),
        answer(readback),
        pause(),
        close(),
    ]
    return {"create-temporary-guest": (steps, {"kind": "guest-create"})}


def cleanup() -> Cases:
    """Plan the removal of the owned accounts and their readbacks.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The one cleanup case.
    """
    steps = login()
    keys = [b"guest"] + [key for key, _, _ in ACCOUNTS if key != KEY32]
    for identifier, key in enumerate(keys, FIRST_ID):
        readback = identifier + PAIR_OFFSET
        steps += [
            send(
                packet(
                    TYPE_DELETE_ACCOUNT,
                    identifier,
                    payload([(FIELD_LOGIN, complement(key))]),
                )
            ),
            answer(identifier),
        ]
        steps += [
            send(packet(TYPE_GET_ACCOUNT, readback, payload([(FIELD_LOGIN, key)]))),
            answer(readback),
        ]
    steps += [pause(), close()]
    return {"remove-owned-auth-accounts": (steps, {"kind": "account-cleanup"})}
