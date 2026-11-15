"""Plan the requests and the upload that the native directory cases share.

The owned root and its base path, the request and reply exchange, and the
upload of a file body. The request types and field IDs are the names in
``native_wire_names``; the list, create, info and delete requests carry the
folder name in field 201 and an optional structured path in field 202
(``operation-contracts.md``, "Request inventory").
"""

import typing as typ

from native_folder_cases import path
from native_plan import Action, close, connect, eof, packet, payload, read, send
from native_wire_names import (
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    HTXF_MAGIC_HEX,
    TYPE_UPLOAD_FILE,
)

type Case = tuple[list[Action], dict[str, typ.Any]]
type Cases = dict[str, Case]

ROOT = b"mothra-fs19"
BASE = path((ROOT,))
# A structured path with no components: the count word alone.
EMPTY_PATH = b"\0\0"
# The four zero bytes that follow the size word in the upload greeting.
UPLOAD_TAIL_HEX = "00000000"
SIZE_BYTES = 4


def exchange(
    kind: int, identifier: int, values: list[tuple[int, bytes]]
) -> list[Action]:
    """Plan one request and the read of its reply.

    Returns
    -------
    list[native_plan.Action]
        The send of the request and the read of the reply with ``identifier``.
    """
    return [
        send(packet(kind, identifier, payload(values))),
        read(match_frame={"is_reply": 1, "id": identifier}),
    ]


def upload(
    identifier: int, fields: list[tuple[int, bytes]], body: bytes
) -> list[Action]:
    """Plan an upload request, its data connection and the body it sends.

    The request carries the given fields and then the body size in field 108.
    The reply's reference is saved as ``reference`` for the greeting.

    Returns
    -------
    list[native_plan.Action]
        The request, the read that saves the reference, the data greeting with
        the body, the end of stream and the close.
    """
    size = len(body).to_bytes(SIZE_BYTES, "big")
    request = [*fields, (FIELD_TRANSFER_SIZE, size)]
    return [
        send(packet(TYPE_UPLOAD_FILE, identifier, payload(request))),
        read(
            match_frame={"is_reply": 1, "id": identifier},
            save_field={"name": "reference", "id": FIELD_TRANSFER_REFERENCE},
        ),
        connect("upload", "data"),
        send(
            HTXF_MAGIC_HEX + "{reference}" + size.hex() + UPLOAD_TAIL_HEX + body.hex(),
            "upload",
        ),
        eof("upload"),
        close("upload"),
    ]
