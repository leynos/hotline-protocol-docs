"""Plan the folder requests, descriptors and control words that the folder cases share.

The fixture tree, the request and descriptor encodings, the data-connection
header, and the upload and download request sequences. The folder planners
build their plans from these steps.
"""

import struct
import typing as typ

from native_plan import Action, close, connect, packet, payload, read, send
from native_queue_cases import session
from native_transfer_cases import resource_fork
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_ITEM_COUNT,
    FIELD_TRANSFER_OPTION,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    FOLDER_CONTROL_NEXT,
    FOLDER_DIRECTORY_FLAG,
    HTXF_MAGIC_HEX,
    RESUME_OPTION,
    SELECTOR_FOLDER,
    TYPE_DOWNLOAD_FOLDER,
    TYPE_UPLOAD_FOLDER,
)

type Case = tuple[list[Action], dict[str, typ.Any]]
type Cases = dict[str, Case]

ROOT = b"mothra-folder-source"
PARTIAL = b"mothra-folder-partial"
FILES: dict[tuple[bytes, ...], tuple[bytes, bytes]] = {
    (b"alpha",): (b"data-fork\r\n\x00\xff", resource_fork()),
    (b"zero",): (b"", b""),
    (b"inner", b"leaf"): (b"leaf\n", resource_fork()),
}
ORDER: list[tuple[bool, tuple[bytes, ...]]] = [
    (False, (b"alpha",)),
    (True, (b"empty",)),
    (True, (b"inner",)),
    (False, (b"inner", b"leaf")),
    (False, (b"zero",)),
]

FOLDER_REQUEST_ID = 10  # the folder request and its reply share this identifier
WORD_BYTES = 2  # control words, item counts and transfer options are 16-bit
SIZE_BYTES = 4  # the transfer size and the header's size word are 32-bit
STREAM_LENGTH_BYTES = 4  # a streamed file begins with its 32-bit length
READ_SECONDS = 30  # timeout of each read on the folder connection
QUIET_SECONDS = 3  # bounded silence on the folder connection
# The data connection: HTXF, the reference that the recorder fills in, a zero size
# word, the folder selector and a zero reserved word.
FOLDER_CONNECTION_HEX = (
    HTXF_MAGIC_HEX
    + "{reference}"
    + bytes(SIZE_BYTES).hex()
    + SELECTOR_FOLDER.to_bytes(WORD_BYTES, "big").hex()
    + bytes(WORD_BYTES).hex()
)


def path(parts: tuple[bytes, ...]) -> bytes:
    """Encode a structured path from its name parts.

    Returns
    -------
    bytes
        A big-endian count of the parts, then each part as two zero bytes, a
        length byte and the name.
    """
    return struct.pack(">H", len(parts)) + b"".join(
        b"\0\0" + bytes([len(p)]) + p for p in parts
    )


def descriptor(
    parts: tuple[bytes, ...],
    directory: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers' shape
) -> bytes:
    """Encode a folder item descriptor, with its flag word and path.

    Returns
    -------
    bytes
        The length word and then the flag word and the encoded path.
    """
    value = struct.pack(">H", FOLDER_DIRECTORY_FLAG if directory else 0) + path(parts)
    return struct.pack(">H", len(value)) + value


def control_word(value: int) -> bytes:
    """Encode a folder control word as a big-endian 16-bit value.

    Returns
    -------
    bytes
        The two-byte word.
    """
    return value.to_bytes(WORD_BYTES, "big")


def control(value: int) -> Action:
    """Plan the send of a folder control word on the folder connection.

    Returns
    -------
    dict[str, typing.Any]
        The ``send`` action for the word.
    """
    return send(control_word(value).hex(), "folder")


def silence_folder() -> Action:
    """Plan a bounded silence on the folder connection.

    Returns
    -------
    dict[str, typing.Any]
        The ``expect_quiet`` action.
    """
    return {"op": "expect_quiet", "connection": "folder", "timeout": QUIET_SECONDS}


def word(value: int) -> Action:
    """Plan the read of a folder control word on the folder connection.

    Returns
    -------
    dict[str, typing.Any]
        The ``read`` action that expects the word.
    """
    return {
        "op": "read",
        "connection": "folder",
        "size": WORD_BYTES,
        "expect_hex": control_word(value).hex(),
        "timeout": READ_SECONDS,
    }


def framed_hex(body: bytes) -> str:
    """Encode a streamed body as its 32-bit length followed by the body.

    Returns
    -------
    str
        The hexadecimal form of the framed body.
    """
    return (len(body).to_bytes(STREAM_LENGTH_BYTES, "big") + body).hex()


def reply_match() -> dict[str, int]:
    """Name the reply to the folder request.

    Returns
    -------
    dict[str, int]
        The frame match that selects the reply by its identifier.
    """
    return {"is_reply": 1, "id": FOLDER_REQUEST_ID}


def length_read(name: str, width: int) -> list[Action]:
    """Plan a read of a length word, saved as ``name``, and the value it sizes.

    Returns
    -------
    list[dict[str, typing.Any]]
        The read that saves the length, then the read of that many bytes.
    """
    return [
        {
            "op": "read",
            "connection": "folder",
            "size": width,
            "save": {"name": name, "offset": 0, "size": width},
            "timeout": READ_SECONDS,
        },
        {
            "op": "read",
            "connection": "folder",
            "size_from": name,
            "timeout": READ_SECONDS,
        },
    ]


def read_descriptor(index: int) -> list[Action]:
    """Plan the skip of one folder item descriptor on the folder connection.

    Returns
    -------
    list[dict[str, typing.Any]]
        The next-item control word and the descriptor's length reads.
    """
    return [
        control(FOLDER_CONTROL_NEXT),
        *length_read(f"descriptor{index}", WORD_BYTES),
    ]


def upload_start(
    root: bytes,
    count: int,
    size: int,
    resume: bool = False,  # ruff: ignore[boolean-type-hint-positional-argument, boolean-default-value-positional-argument]  # the callers' shape
) -> list[Action]:
    """Plan the folder upload request and, for a non-empty upload, its data connection.

    Returns
    -------
    list[dict[str, typing.Any]]
        The login, the request, and the reply read. A zero count closes the
        control connection there; otherwise the data connection is opened and
        the first item word is read.
    """
    values = [
        (FIELD_FILE_NAME, root),
        (FIELD_ITEM_COUNT, count.to_bytes(WORD_BYTES, "big")),
        (FIELD_TRANSFER_SIZE, size.to_bytes(SIZE_BYTES, "big")),
    ]
    if resume:
        values.append((
            FIELD_TRANSFER_OPTION,
            RESUME_OPTION.to_bytes(WORD_BYTES, "big"),
        ))
    steps = [
        *session("a"),
        send(packet(TYPE_UPLOAD_FOLDER, FOLDER_REQUEST_ID, payload(values)), "a"),
    ]
    if count == 0:
        return [*steps, read("a", match_frame=reply_match()), close("a")]
    return [
        *steps,
        read(
            "a",
            match_frame=reply_match(),
            save_field={"name": "reference", "id": FIELD_TRANSFER_REFERENCE},
        ),
        connect("folder", "data"),
        send(FOLDER_CONNECTION_HEX, "folder"),
        word(FOLDER_CONTROL_NEXT),
    ]


def download_start(
    root: bytes,
    empty: bool = False,  # ruff: ignore[boolean-type-hint-positional-argument, boolean-default-value-positional-argument]  # the callers' shape
) -> list[Action]:
    """Plan the folder download request and its data connection, if any.

    Returns
    -------
    list[dict[str, typing.Any]]
        The login, the request, and the reply read. An empty folder closes the
        control connection there; otherwise the reply's reference, item count
        and size are saved and the data connection is opened.
    """
    steps = [
        *session("a"),
        send(
            packet(
                TYPE_DOWNLOAD_FOLDER,
                FOLDER_REQUEST_ID,
                payload([(FIELD_FILE_NAME, root)]),
            ),
            "a",
        ),
    ]
    if empty:
        return [*steps, read("a", match_frame=reply_match()), close("a")]
    return [
        *steps,
        read(
            "a",
            match_frame=reply_match(),
            save_fields={
                "reference": FIELD_TRANSFER_REFERENCE,
                "items": FIELD_ITEM_COUNT,
                "size": FIELD_TRANSFER_SIZE,
            },
        ),
        connect("folder", "data"),
        send(FOLDER_CONNECTION_HEX, "folder"),
    ]
