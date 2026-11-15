"""Prepare isolated account replacement, sentinel and password-width fixtures."""

import typing as typ

from native_auth_cases import authentication, complement
from native_metadata_cases import upload
from native_mkdir_cases import exchange
from native_plan import close, login, quiet, read
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_ACCOUNT_ATTRIBUTE,
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    TYPE_CREATE_ACCOUNT,
    TYPE_DELETE_ACCOUNT,
    TYPE_DELETE_FILE,
    TYPE_EMPTY_ACK,
    TYPE_ENUMERATE_ACCOUNTS,
    TYPE_GET_ACCOUNT,
    TYPE_LIST_FILES,
    TYPE_UPDATE_ACCOUNT,
)

type Report = dict[str, typ.Any]
type Plan = tuple[list[Report], Report]

ACCESS = bytes.fromhex("2000000000000000")
PASSWORD = b"account-base-26"
LABELS = [
    "preserve",
    "absent",
    "empty",
    "literal-x",
    "replace32",
    "preserve32",
    "sparse",
    "attribute65",
]


def key(label: str) -> bytes:
    """Return the login of the owned account of ``label``.

    Returns
    -------
    bytes
        The login, ``m-au26-`` followed by the label.

    Raises
    ------
    ValueError
        If ``label`` is not one of the owned account cases.
    """
    if label not in LABELS:
        message = "Unknown owned account case"
        raise ValueError(message)
    return ("m-au26-" + label).encode()


def initial_password(label: str) -> bytes:
    """Return the password that the seed gives the account of ``label``.

    Returns
    -------
    bytes
        Thirty-two ``q`` bytes for ``preserve32``, otherwise the base password.
    """
    return b"q" * 32 if label == "preserve32" else PASSWORD


def result_password(label: str) -> bytes:
    """Return the password that the account of ``label`` holds after the update.

    Returns
    -------
    bytes
        The password that the replacement leaves in place.
    """
    match label:
        case "absent" | "empty":
            return b""
        case "literal-x":
            return b"\x87"
        case "replace32":
            return b"p" * 32
        case "preserve32":
            return b"q" * 31
        case _:
            return PASSWORD


def values(label: str) -> list[tuple[int, bytes]]:
    """Return the fields that create the account of ``label``.

    Returns
    -------
    list[tuple[int, bytes]]
        The field ID and the value of each field, in request order.
    """
    return [
        (FIELD_LOGIN, complement(key(label))),
        (FIELD_PASSWORD, complement(initial_password(label))),
        (FIELD_NAME, b"Account26-" + label.encode()),
        (FIELD_ACCOUNT_ATTRIBUTE, b"opaque26"),
        (FIELD_ACCESS_BITMAP, ACCESS),
    ]


def preflight() -> Plan:
    """Plan the check that every owned account is initially absent.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation.
    """
    steps = (
        login()
        + exchange(TYPE_ENUMERATE_ACCOUNTS, 10, [])
        + exchange(TYPE_LIST_FILES, 11, [(FIELD_FILE_PATH, b"\0\0")])
    )
    for identifier, label in enumerate(LABELS, 100):
        steps += exchange(TYPE_GET_ACCOUNT, identifier, [(FIELD_LOGIN, key(label))])
    return [*steps, close()], {"kind": "account-update-preflight"}


def seed() -> Plan:
    """Plan the creation of every owned account and the flush that follows it.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation.
    """
    steps = login()
    for identifier, label in enumerate(LABELS, 100):
        steps += exchange(TYPE_CREATE_ACCOUNT, identifier, values(label))
        steps += exchange(
            TYPE_GET_ACCOUNT, identifier + 100, [(FIELD_LOGIN, key(label))]
        )
    steps += upload(80, b"m-au26-seed-flush", b"\0\0")
    return [*steps, {"op": "pause", "seconds": 3}, close()], {
        "kind": "account-update-seed"
    }


def mutated_password(label: str) -> bytes | None:
    """Return the password field that the update of ``label`` sends.

    Returns
    -------
    bytes | None
        The encoded password, or ``None`` when the update omits the field.
    """
    match label:
        case "absent":
            return None
        case "empty":
            return b""
        case "literal-x":
            return b"x"
        case "replace32":
            return complement(b"p" * 32)
        case _:
            return b"\0"


def mutate(label: str) -> Plan:
    """Plan the update of the account of ``label`` and the read-back of it.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation.
    """
    fields = values(label)
    fields = [(k, v) for k, v in fields if k != FIELD_PASSWORD]
    encoded = mutated_password(label)
    if label == "sparse":
        fields = [(FIELD_LOGIN, complement(key(label)))]
    if label == "attribute65":
        fields = [
            (k, b"X" * 65 if k == FIELD_ACCOUNT_ATTRIBUTE else v) for k, v in fields
        ]
    if encoded is not None:
        fields.append((FIELD_PASSWORD, encoded))
    steps = login() + exchange(TYPE_GET_ACCOUNT, 10, [(FIELD_LOGIN, key(label))])
    steps += exchange(TYPE_UPDATE_ACCOUNT, 11, fields)
    steps += exchange(TYPE_GET_ACCOUNT, 12, [(FIELD_LOGIN, key(label))])
    steps += exchange(TYPE_EMPTY_ACK, 90, [])
    return [*steps, quiet(), close()], {
        "kind": "account-update-mutation",
        "case": label,
    }


def probe(
    label: str,
    password: bytes,
    success: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers pass success positionally
) -> Plan:
    """Plan a login of the account of ``label`` with ``password``.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation.
    """
    steps = [*login()[:3], authentication(key(label), password), read()]
    if success:
        steps += [read(), read(), *exchange(TYPE_EMPTY_ACK, 90, [])]
    return [*steps, quiet(), close()], {
        "kind": "account-update-login",
        "case": label,
        "password_hex": password.hex(),
        "success": success,
    }


def finalization() -> Plan:
    """Plan the read-back of every owned account after the update.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation.
    """
    steps = login() + upload(80, b"m-au26-final-flush", b"\0\0")
    for identifier, label in enumerate(LABELS, 100):
        steps += exchange(TYPE_GET_ACCOUNT, identifier, [(FIELD_LOGIN, key(label))])
    return [*steps, close()], {"kind": "account-update-final"}


def cleanup() -> Plan:
    """Plan the deletion of the owned accounts and files.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation.
    """
    steps = login()
    for identifier, label in enumerate(LABELS, 100):
        steps += exchange(
            TYPE_DELETE_ACCOUNT, identifier, [(FIELD_LOGIN, complement(key(label)))]
        )
    for identifier, name in [(20, b"m-au26-seed-flush"), (21, b"m-au26-final-flush")]:
        steps += exchange(TYPE_DELETE_FILE, identifier, [(FIELD_FILE_NAME, name)])
    steps += exchange(TYPE_ENUMERATE_ACCOUNTS, 90, [])
    steps += exchange(TYPE_LIST_FILES, 91, [(FIELD_FILE_PATH, b"\0\0")])
    return [*steps, close()], {"kind": "account-update-cleanup"}


def publish_cleanup() -> Plan:
    """Plan the publication of a separate file and the listings that follow it.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation.
    """
    steps = login() + upload(80, b"m-au26-publish", b"\0\0")
    steps += exchange(TYPE_ENUMERATE_ACCOUNTS, 90, [])
    steps += exchange(TYPE_LIST_FILES, 91, [(FIELD_FILE_PATH, b"\0\0")])
    return [*steps, close()], {"kind": "account-update-publish"}


def remove_publisher() -> Plan:
    """Plan the removal of the separate published file and the listings after it.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation.
    """
    steps = login() + exchange(
        TYPE_DELETE_FILE, 10, [(FIELD_FILE_NAME, b"m-au26-publish")]
    )
    steps += exchange(TYPE_ENUMERATE_ACCOUNTS, 90, [])
    steps += exchange(TYPE_LIST_FILES, 91, [(FIELD_FILE_PATH, b"\0\0")])
    return [*steps, close()], {"kind": "account-update-remove"}
