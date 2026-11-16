"""Prepare live account propagation/deletion and server restart observations."""

import typing as typ

from native_auth_cases import authentication, complement
from native_live_account_steps import (
    LOGIN_PREFIX_STEPS,
    account_values,
    request,
    settled,
    subject,
)
from native_metadata_cases import upload
from native_mkdir_cases import exchange
from native_plan import Action, close, login, quiet, read
from native_wire_names import (
    ACCESS_BITMAP_BYTES,
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    FIELD_LOGIN,
    FIELD_PASSWORD,
    TYPE_CREATE_ACCOUNT,
    TYPE_DELETE_ACCOUNT,
    TYPE_DELETE_FILE,
    TYPE_DOWNLOAD_FILE,
    TYPE_EMPTY_ACK,
    TYPE_ENUMERATE_ACCOUNTS,
    TYPE_GET_ACCOUNT,
    TYPE_GET_USER_ROSTER,
    TYPE_LIST_FILES,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_UPDATE_ACCOUNT,
)

# The helpers are re-exported for the consumers: the bitmap, diagnostic, PM and room
# planners and the identity planner import account_values, subject and request; the
# live verifier, prepare_native_cases and run-live.py import the planners below.
__all__ = [
    "ACCESS",
    "ALPHA",
    "BETA",
    "CHANGED",
    "DELETED",
    "DELETE_NAME",
    "DELETE_PASSWORD",
    "FINAL",
    "LIVE",
    "OLD",
    "account_values",
    "cleanup",
    "delete",
    "edit",
    "finalize",
    "inspect",
    "preflight",
    "probe",
    "publish_cleanup",
    "remove_publisher",
    "request",
    "seed",
    "settled",
    "stopped",
    "subject",
]

type Case = tuple[list[Action], dict[str, typ.Any]]

PAUSE_SECONDS = 3
STOPPED_TIMEOUT_SECONDS = 3

LIVE = b"m-live27"
DELETED = b"m-delete27"
OLD = b"live-old27"
CHANGED = b"live-changed27"
FINAL = b"live-final27"
DELETE_PASSWORD = b"delete-pass27"
ACCESS = bytes.fromhex("2000000000000000")
ALPHA = b"Stored Alpha27"
BETA = b"Stored Beta27"
DELETE_NAME = b"Delete Target27"


def preflight() -> Case:
    """Plan the read of the account list and of the two live identities.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the preflight.
    """
    steps = (
        login()
        + exchange(TYPE_ENUMERATE_ACCOUNTS, 10, [])
        + exchange(TYPE_LIST_FILES, 11, [(FIELD_FILE_PATH, b"\0\0")])
    )
    for identifier, key in [(20, LIVE), (21, DELETED)]:
        steps += exchange(TYPE_GET_ACCOUNT, identifier, [(FIELD_LOGIN, key)])
    return [*steps, close()], {"kind": "live-account-preflight"}


def seed() -> Case:
    """Plan the creation of the two live accounts and their readbacks.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the seeding.
    """
    steps = login()
    for identifier, key, password, name in [
        (10, LIVE, OLD, ALPHA),
        (11, DELETED, DELETE_PASSWORD, DELETE_NAME),
    ]:
        steps += exchange(
            TYPE_CREATE_ACCOUNT,
            identifier,
            account_values(key, password, name, ACCESS),
        )
        steps += exchange(TYPE_GET_ACCOUNT, identifier + 10, [(FIELD_LOGIN, key)])
    return [*steps, close()], {"kind": "live-account-seed"}


def edit() -> Case:
    """Plan the live edits of the account and the readbacks on two sessions.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the edit case.
    """
    steps = login() + subject("one", LIVE, OLD, 7) + subject("two", LIVE, OLD, 8)
    steps += (
        exchange(TYPE_GET_USER_ROSTER, 10, [])
        + request("one", TYPE_EMPTY_ACK, 80)
        + request("two", TYPE_EMPTY_ACK, 80)
    )
    steps += exchange(
        TYPE_UPDATE_ACCOUNT,
        11,
        account_values(LIVE, CHANGED, BETA, bytes(ACCESS_BITMAP_BYTES)),
    )
    steps += (
        exchange(TYPE_GET_USER_ROSTER, 12, [])
        + request("one", TYPE_EMPTY_ACK, 90)
        + request("two", TYPE_EMPTY_ACK, 90)
    )
    for name in ["one", "two"]:
        steps += request(
            name,
            TYPE_DOWNLOAD_FILE,
            91,
            [(FIELD_FILE_NAME, b"m-live27-denied")],
        )
    steps += settled()
    steps += exchange(
        TYPE_UPDATE_ACCOUNT,
        21,
        account_values(LIVE, FINAL, BETA, bytes(ACCESS_BITMAP_BYTES)),
    )
    steps += (
        exchange(TYPE_GET_USER_ROSTER, 22, [])
        + request("one", TYPE_EMPTY_ACK, 92)
        + request("two", TYPE_EMPTY_ACK, 92)
        + settled()
    )
    attribute = account_values(
        LIVE, FINAL, BETA, bytes(ACCESS_BITMAP_BYTES), b"attribute-only27"
    )
    attribute = [(k, b"\0" if k == FIELD_PASSWORD else v) for k, v in attribute]
    steps += exchange(TYPE_UPDATE_ACCOUNT, 31, attribute)
    steps += (
        exchange(TYPE_GET_USER_ROSTER, 32, [])
        + request("one", TYPE_EMPTY_ACK, 93)
        + request("two", TYPE_EMPTY_ACK, 93)
        + settled()
    )
    steps += [close("one"), close("two"), {"op": "pause", "seconds": PAUSE_SECONDS}]
    steps += [
        *exchange(TYPE_GET_USER_ROSTER, 40, []),
        {"op": "pause", "seconds": PAUSE_SECONDS},
        *exchange(TYPE_GET_USER_ROSTER, 41, []),
    ]
    return [*steps, close()], {"kind": "live-account-edit"}


def delete() -> Case:
    """Plan the deletion of the deleted live account seen by two sessions.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the delete case.
    """
    steps = (
        login()
        + subject("one", DELETED, DELETE_PASSWORD, 7)
        + subject("two", DELETED, DELETE_PASSWORD, 8)
    )
    steps += (
        exchange(TYPE_GET_USER_ROSTER, 10, [])
        + request("one", TYPE_EMPTY_ACK, 80)
        + request("two", TYPE_EMPTY_ACK, 80)
    )
    steps += exchange(TYPE_DELETE_ACCOUNT, 11, [(FIELD_LOGIN, complement(DELETED))])
    steps += [
        read("one", match_frame={"type": TYPE_MESSAGE_NOTIFICATION}),
        read("two", match_frame={"type": TYPE_MESSAGE_NOTIFICATION}),
        {"op": "pause", "seconds": PAUSE_SECONDS},
    ]
    steps += [
        *exchange(TYPE_GET_USER_ROSTER, 12, []),
        {"op": "pause", "seconds": PAUSE_SECONDS},
        *exchange(TYPE_GET_USER_ROSTER, 13, []),
    ]
    steps += exchange(TYPE_GET_ACCOUNT, 14, [(FIELD_LOGIN, DELETED)])
    return [*steps, close("one"), close("two"), close()], {
        "kind": "live-account-delete"
    }


def probe(label: str) -> Case:
    """Plan a reconnect with one of the four live identities.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the reconnect.
    """
    values = {
        "old": (LIVE, OLD, False),
        "intermediate": (LIVE, CHANGED, False),
        "final": (LIVE, FINAL, True),
        "deleted": (DELETED, DELETE_PASSWORD, False),
    }
    key, password, success = values[label]
    steps = [
        *login()[:LOGIN_PREFIX_STEPS],
        authentication(key, password),
        read(),
    ]
    if success:
        steps += [read(), read(), *exchange(TYPE_EMPTY_ACK, 90, [])]
    return [*steps, quiet(), close()], {
        "kind": "live-account-reconnect",
        "case": label,
        "success": success,
    }


def finalize() -> Case:
    """Plan the flush upload and the final read of both live accounts.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the finalization.
    """
    steps = login() + upload(80, b"m-live27-flush", b"\0\0")
    steps += exchange(TYPE_GET_ACCOUNT, 10, [(FIELD_LOGIN, LIVE)])
    steps += exchange(TYPE_GET_ACCOUNT, 11, [(FIELD_LOGIN, DELETED)])
    steps += exchange(TYPE_ENUMERATE_ACCOUNTS, 20, [])
    return [*steps, close()], {"kind": "live-account-final"}


def inspect() -> Case:
    """Plan the read of the account list and of the two live account records.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the inspection.
    """
    steps = (
        login()
        + exchange(TYPE_GET_ACCOUNT, 10, [(FIELD_LOGIN, LIVE)])
        + exchange(TYPE_GET_ACCOUNT, 11, [(FIELD_LOGIN, DELETED)])
    )
    steps += exchange(TYPE_ENUMERATE_ACCOUNTS, 20, [])
    steps += exchange(TYPE_LIST_FILES, 21, [(FIELD_FILE_PATH, b"\0\0")])
    return [*steps, close()], {"kind": "live-account-inspect"}


def stopped() -> Case:
    """Plan a handshake attempt against the application while it is stopped.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the stopped listener.
    """
    steps = [
        {**s, "timeout": STOPPED_TIMEOUT_SECONDS} for s in login()[:LOGIN_PREFIX_STEPS]
    ]
    return [*steps, close()], {
        "kind": "live-account-stopped-listener",
        "expected": "No successful native handshake while application is stopped",
    }


def cleanup() -> Case:
    """Plan the removal of the live account and the flush file.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the cleanup.
    """
    steps = login() + exchange(
        TYPE_DELETE_ACCOUNT, 10, [(FIELD_LOGIN, complement(LIVE))]
    )
    steps += exchange(TYPE_DELETE_FILE, 11, [(FIELD_FILE_NAME, b"m-live27-flush")])
    steps += exchange(TYPE_ENUMERATE_ACCOUNTS, 20, [])
    steps += exchange(TYPE_LIST_FILES, 21, [(FIELD_FILE_PATH, b"\0\0")])
    return [*steps, close()], {"kind": "live-account-cleanup"}


def publish_cleanup() -> Case:
    """Plan the upload of the publish marker and the final account readbacks.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the publish cleanup.
    """
    steps = login() + upload(80, b"m-live27-publish", b"\0\0")
    steps += exchange(TYPE_ENUMERATE_ACCOUNTS, 20, [])
    steps += exchange(TYPE_LIST_FILES, 21, [(FIELD_FILE_PATH, b"\0\0")])
    return [*steps, close()], {"kind": "live-account-publish"}


def remove_publisher() -> Case:
    """Plan the removal of the publish marker and the final account readbacks.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the marker removal.
    """
    steps = login() + exchange(
        TYPE_DELETE_FILE, 10, [(FIELD_FILE_NAME, b"m-live27-publish")]
    )
    steps += exchange(TYPE_ENUMERATE_ACCOUNTS, 20, [])
    steps += exchange(TYPE_LIST_FILES, 21, [(FIELD_FILE_PATH, b"\0\0")])
    return [*steps, close()], {"kind": "live-account-remove"}
