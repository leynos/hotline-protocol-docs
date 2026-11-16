"""Prepare owned account identity, kick-protection and self-delete contrasts."""

import typing as typ

from native_auth_cases import authentication, complement
from native_live_account_cases import account_values, request, subject
from native_mkdir_cases import exchange
from native_plan import Action, close, login, packet, payload, quiet, read, send
from native_wire_names import (
    ACCESS_BITMAP_BYTES,
    FIELD_FILE_PATH,
    FIELD_LOGIN,
    FIELD_USER_ID,
    TYPE_CREATE_ACCOUNT,
    TYPE_DELETE_ACCOUNT,
    TYPE_EMPTY_ACK,
    TYPE_ENUMERATE_ACCOUNTS,
    TYPE_GET_ACCOUNT,
    TYPE_GET_USER_ROSTER,
    TYPE_LIST_FILES,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
)

type Case = tuple[list[Action], dict[str, typ.Any]]

# The request that the target case sends with the subject's user ID; no document
# given here fixes its name, so it keeps this neutral one.
TARGET_REQUEST_TYPE = 110
# The steps of login() before its login request: connect, handshake and its read.
LOGIN_PREFIX_STEPS = 3
PAUSE_SECONDS = 3
# The hex digits of the two zero bytes of the user ID that the target UID replaces.
PLACEHOLDER_HEX_LENGTH = 4

PASSWORD = b"identity-pass29"
CHANGED = b"identity-changed29"
KEYS = {
    "protected": b"m-id29-protected",
    "self": b"m-id29-self",
    "duplicate": b"m-id29-duplicate",
}
ACCESS = {
    "protected": bytes.fromhex("0000010000000000"),
    "self": bytes.fromhex("0001010000000000"),
    "duplicate": bytes(ACCESS_BITMAP_BYTES),
}


def values(label: str, *, changed: bool = False) -> list[tuple[int, bytes]]:
    """Plan the account fields of one owned identity.

    Returns
    -------
    list[tuple[int, bytes]]
        The login, password, name, access and attribute fields of the account.
    """
    return account_values(
        KEYS[label],
        CHANGED if changed else PASSWORD,
        (b"Changed29-" if changed else b"Identity29-") + label.encode(),
        ACCESS[label],
        b"identity29",
    )


def inspect() -> Case:
    """Plan the read of the account list and of each owned account record.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the inspection.
    """
    steps = (
        login()
        + exchange(TYPE_ENUMERATE_ACCOUNTS, 10, [])
        + exchange(TYPE_LIST_FILES, 11, [(FIELD_FILE_PATH, b"\0\0")])
    )
    for identifier, key in enumerate(KEYS.values(), 20):
        steps += exchange(TYPE_GET_ACCOUNT, identifier, [(FIELD_LOGIN, key)])
    return [*steps, close()], {"kind": "account-identity-inspect"}


def seed() -> Case:
    """Plan the creation of each owned account and its readback.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the seeding.
    """
    steps = login()
    for identifier, label in enumerate(KEYS, 10):
        steps += exchange(TYPE_CREATE_ACCOUNT, identifier, values(label))
        steps += exchange(
            TYPE_GET_ACCOUNT, identifier + 10, [(FIELD_LOGIN, KEYS[label])]
        )
    return [*steps, close()], {"kind": "account-identity-seed"}


def duplicate(
    uppercase: bool = False,  # ruff: ignore[boolean-type-hint-positional-argument, boolean-default-value-positional-argument]  # the public signature takes the flag positionally
) -> Case:
    """Plan a create of the duplicate identity and its lookups, optionally uppercase.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the duplicate case.
    """
    fields = values("duplicate", changed=True)
    if uppercase:
        fields = [
            (k, complement(KEYS["duplicate"].upper()) if k == FIELD_LOGIN else v)
            for k, v in fields
        ]
    steps = login() + exchange(TYPE_CREATE_ACCOUNT, 10, fields)
    steps += exchange(TYPE_GET_ACCOUNT, 20, [(FIELD_LOGIN, KEYS["duplicate"])])
    steps += exchange(TYPE_GET_ACCOUNT, 21, [(FIELD_LOGIN, KEYS["duplicate"].upper())])
    steps += exchange(TYPE_ENUMERATE_ACCOUNTS, 30, [])
    steps += exchange(TYPE_EMPTY_ACK, 90, [])
    return [*steps, quiet(), close()], {
        "kind": "account-identity-duplicate",
        "uppercase": uppercase,
    }


def target_case(label: str) -> Case:
    """Plan the kick of one owned protected or self-delete account and its readbacks.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the target case.

    Raises
    ------
    ValueError
        If the label is neither the protected nor the self-delete identity.
    """
    if label not in {"protected", "self"}:
        message = "Owned protected or self-delete target required"
        raise ValueError(message)
    steps = login() + subject("target", KEYS[label], PASSWORD, 29)
    steps += [
        read(
            match_frame={"type": TYPE_PRESENCE_UPDATE},
            save_fields={"target_uid": FIELD_USER_ID},
        )
    ]
    kick = packet(TARGET_REQUEST_TYPE, 11, payload([(FIELD_USER_ID, b"\0\0")]))
    steps += [
        send(kick[:-PLACEHOLDER_HEX_LENGTH] + "{target_uid}"),
        read(match_frame={"is_reply": 1, "id": 11}),
    ]
    steps += request("target", TYPE_EMPTY_ACK, 80)
    if label == "protected":
        steps += exchange(
            TYPE_DELETE_ACCOUNT, 12, [(FIELD_LOGIN, complement(KEYS[label]))]
        )
    else:
        steps += request(
            "target",
            TYPE_DELETE_ACCOUNT,
            12,
            [(FIELD_LOGIN, complement(KEYS[label]))],
        )
    steps += [read("target", match_frame={"type": TYPE_MESSAGE_NOTIFICATION})]
    steps += [{"op": "pause", "seconds": PAUSE_SECONDS}]
    steps += exchange(TYPE_GET_ACCOUNT, 20, [(FIELD_LOGIN, KEYS[label])])
    steps += exchange(TYPE_GET_USER_ROSTER, 30, []) + exchange(TYPE_EMPTY_ACK, 90, [])
    return [*steps, close("target"), close()], {
        "kind": "account-identity-target",
        "case": label,
    }


def probe(password: bytes, key: bytes, *, success: bool = False) -> Case:
    """Plan a login attempt with one owned key and password.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the login attempt.

    Raises
    ------
    ValueError
        If the key is not one of the owned account keys.
    """
    if key not in KEYS.values():
        message = "Owned account required"
        raise ValueError(message)
    steps = [
        *login()[:LOGIN_PREFIX_STEPS],
        authentication(key, password),
        read(),
    ]
    if success:
        steps += [read(), read(), *exchange(TYPE_EMPTY_ACK, 90, [])]
    return [*steps, quiet(), close()], {
        "kind": "account-identity-login",
        "key_hex": key.hex(),
        "password_hex": password.hex(),
        "success": success,
    }


def cleanup() -> Case:
    """Plan the removal of the duplicate identity and the readback of the list.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the cleanup.
    """
    steps = login() + exchange(
        TYPE_DELETE_ACCOUNT, 10, [(FIELD_LOGIN, complement(KEYS["duplicate"]))]
    )
    steps += exchange(TYPE_ENUMERATE_ACCOUNTS, 20, [])
    steps += exchange(TYPE_LIST_FILES, 21, [(FIELD_FILE_PATH, b"\0\0")])
    return [*steps, close()], {"kind": "account-identity-cleanup"}


def suites() -> dict[str, Case]:
    """Return preparation templates; execution must enforce the preflight guard.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The templates of the identity suites, by their labels, in order.
    """
    return {
        "preflight": inspect(),
        "seed": seed(),
        "duplicate-exact": duplicate(),
        "duplicate-uppercase": duplicate(uppercase=True),
        "duplicate-original-login": probe(PASSWORD, KEYS["duplicate"], success=True),
        "duplicate-changed-login": probe(CHANGED, KEYS["duplicate"]),
        "protected": target_case("protected"),
        "protected-login": probe(PASSWORD, KEYS["protected"]),
        "after-protected": inspect(),
        "self": target_case("self"),
        "self-login": probe(PASSWORD, KEYS["self"]),
        "after-self": inspect(),
        "cleanup": cleanup(),
        "final": inspect(),
    }
