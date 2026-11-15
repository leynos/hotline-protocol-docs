"""Plan the fixtures and steps that the native metadata cases share.

The owned root, password and accounts, the upload of one file with its data
connection, the removal of the owned accounts, and the wire fields that the
metadata planners name. Nothing here plans a whole case.
"""

import typing as typ

from native_alias_cases import body
from native_auth_cases import complement
from native_folder_cases import path
from native_mkdir_cases import exchange
from native_plan import (
    Action,
    close,
    connect,
    eof,
    packet,
    payload,
    read,
    send,
)
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    FIELD_LOGIN,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    HTXF_MAGIC_HEX,
    TYPE_DELETE_ACCOUNT,
    TYPE_GET_ACCOUNT,
    TYPE_UPLOAD_FILE,
)

type Cases = dict[str, tuple[list[Action], dict[str, typ.Any]]]

# The field and type numbers below that native_wire_names does not hold.
FIELD_COMMENT = 210  # operation-contracts.md: "207 field 210 comment and 211 rename"
FIELD_NEW_NAME = 211  # operation-contracts.md: the rename that a 207 request carries
EMPTY_PATH = b"\0\0"  # a structured path of zero components: a count word of zero

ROOT = b"mothra-meta21"
BASE = path((ROOT,))
PASSWORD = b"meta-pass"
# Each entry is the login and the privilege bitmap of one owned account.
ACCOUNTS: dict[str, tuple[bytes, bytes]] = {
    "comment": (
        b"m-meta21-comment",
        ((1 << (63 - 28)) | (1 << (63 - 29))).to_bytes(8, "big"),
    ),
    "rename": (
        b"m-meta21-rename",
        ((1 << (63 - 3)) | (1 << (63 - 7))).to_bytes(8, "big"),
    ),
    "neither": (b"m-meta21-neither", bytes(8)),
}


def main_silence() -> Action:
    """Plan a bounded silence on the main connection.

    Returns
    -------
    dict[str, typing.Any]
        The ``expect_quiet`` action with a one-second timeout.
    """
    return {"op": "expect_quiet", "connection": "main", "timeout": 1}


def account_removal() -> list[Action]:
    """Plan the deletion of each owned account, and the readback of its absence.

    Returns
    -------
    list[dict[str, typing.Any]]
        The delete and readback exchanges of the owned accounts, in order.
    """
    steps: list[Action] = []
    for identifier, (name, _) in enumerate(ACCOUNTS.values(), 30):
        steps += exchange(
            TYPE_DELETE_ACCOUNT, identifier, [(FIELD_LOGIN, complement(name))]
        )
        steps += exchange(TYPE_GET_ACCOUNT, identifier + 10, [(FIELD_LOGIN, name)])
    return steps


def upload(
    identifier: int, name: bytes, parent: bytes = BASE, value: bytes | None = None
) -> list[dict[str, typ.Any]]:
    """Plan an upload request, its data connection and the body it sends.

    The request names the file and its parent path and gives the body size in
    field 108. The reply's reference is saved as ``reference`` for the greeting
    on the data connection, which sends the body and then ends.

    Returns
    -------
    list[dict[str, typing.Any]]
        The request, the reply read, the data connection, its greeting and body,
        the end of the stream, and the close of the data connection.
    """
    if value is None:
        value = body(b"metadata-data", b"", b"TEXT", b"MOTH", b"base-comment")
    channel, reference = f"up{identifier}", f"ref{identifier}"
    return [
        send(
            packet(
                TYPE_UPLOAD_FILE,
                identifier,
                payload([
                    (FIELD_FILE_NAME, name),
                    (FIELD_FILE_PATH, parent),
                    (FIELD_TRANSFER_SIZE, len(value).to_bytes(4, "big")),
                ]),
            )
        ),
        read(
            match_frame={"is_reply": 1, "id": identifier},
            save_field={"name": reference, "id": FIELD_TRANSFER_REFERENCE},
        ),
        connect(channel, "data"),
        send(
            HTXF_MAGIC_HEX
            + "{"
            + reference
            + "}"
            + len(value).to_bytes(4, "big").hex()
            + "00000000"
            + value.hex(),
            channel,
        ),
        eof(channel),
        close(channel),
    ]
