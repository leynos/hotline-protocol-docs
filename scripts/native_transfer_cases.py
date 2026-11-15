"""Prepare ordinary-fork upload and download observation cases."""

import struct
import typing as typ

from native_plan import Action, close, connect, eof, login, packet, payload, read, send
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_TRANSFER_OPTION,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    FILP_FILE_HEADER,
    FORK_HEADER_PADDING,
    FORK_LENGTH_BYTES,
    HANDSHAKE_HANDOVER_REQUEST_HEX,
    HANDSHAKE_REPLY_BYTES,
    HANDSHAKE_REPLY_HEX,
    HTXF_MAGIC_HEX,
    INFO_FIXED_BYTES,
    INFO_FLAGS_OFFSET,
    INFO_NAME_LENGTH_OFFSET,
    INFO_NAME_OFFSET,
    INFO_TYPE_CREATOR,
    PREVIEW_OPTION,
    SELECTOR_BANNER,
    SELECTOR_FOLDER,
    TYPE_DOWNLOAD_FILE,
    TYPE_GET_FILE_INFO,
    TYPE_REFERENCE_CLEANUP,
    TYPE_UPLOAD_FILE,
)

type Case = tuple[list[Action], dict[str, typ.Any]]

# The classic Mac OS resource-fork layout of the 317-byte MACR fixture
# (transfer-contracts.md, "Captured ordinary-file round trips"): a 16-byte
# header, padding to offset 256, the data, then a 50-byte map that repeats the
# header.
RESOURCE_VALUE = b"native!"
RESOURCE_DATA_OFFSET = 256
RESOURCE_PADDING = 240
RESOURCE_MAP_BYTES = 50
RESOURCE_MAP_RESERVED = 8
RESOURCE_MAP_FIELDS = (28, 50, 0, b"TEST", 0, 10, 128, 65535, 0, 0)

# The INFO value of the uploaded fixtures deliberately carries a name that
# differs from the file name, so that INFO is shown not to rename the file, a
# comment, flags `00008100` and zero dates (transfer-contracts.md).
EMBEDDED_NAME = b"metadata-only-name"
EMBEDDED_COMMENT = b"fixture-comment"
INFO_FLAGS = 0x8100
INFO_FLAGS_BYTES = 4
LENGTH_WORD_BYTES = 2
FORK_TAGS = (b"INFO", b"DATA", b"MACR")

FORK_NAME = b"mothra-fork-fixture"
EMPTY_NAME = b"mothra-empty-fixture"
FORK_DATA = b"data-fork\r\n\x00\xff"
HANDOVER_TIMEOUT_SECONDS = 10
DOWNLOAD_READ_SECONDS = 30
QUIET_SECONDS = 3
REQUEST_ID = 10
FOLLOWUP_ID = 11
HTXF_RESERVED_HEX = "00000000"  # the selector and the unexamined word, as zero
SELECTOR_BYTES = 2
OPTION_BYTES = 2
SIZE_BYTES = 4
REFERENCE_MARKER = b"REF!"
NO_FOLLOWUP_SELECTORS = {SELECTOR_FOLDER, SELECTOR_BANNER}


def resource_fork() -> bytes:
    """Build the resource-fork fixture.

    Returns
    -------
    bytes
        The 317-byte resource fork that every fixture file carries.
    """
    data = struct.pack(">I", len(RESOURCE_VALUE)) + RESOURCE_VALUE
    header = struct.pack(
        ">IIII",
        RESOURCE_DATA_OFFSET,
        RESOURCE_DATA_OFFSET + len(data),
        len(data),
        RESOURCE_MAP_BYTES,
    )
    resource_map = (
        header
        + bytes(RESOURCE_MAP_RESERVED)
        + struct.pack(">HHH4sHHHHII", *RESOURCE_MAP_FIELDS)
    )
    return header + bytes(RESOURCE_PADDING) + data + resource_map


def info_value() -> bytes:
    """Build the INFO value of an uploaded fixture.

    Returns
    -------
    bytes
        The type, creator, flags, embedded name and comment, with zero dates.
    """
    embedded, comment = EMBEDDED_NAME, EMBEDDED_COMMENT
    info = bytearray(INFO_FIXED_BYTES + len(embedded) + len(comment))
    info[: len(INFO_TYPE_CREATOR)] = INFO_TYPE_CREATOR
    info[INFO_FLAGS_OFFSET : INFO_FLAGS_OFFSET + INFO_FLAGS_BYTES] = (
        INFO_FLAGS.to_bytes(INFO_FLAGS_BYTES, "big")
    )
    info[INFO_NAME_LENGTH_OFFSET:INFO_NAME_OFFSET] = len(embedded).to_bytes(
        LENGTH_WORD_BYTES, "big"
    )
    info[INFO_NAME_OFFSET : INFO_NAME_OFFSET + len(embedded)] = embedded
    comment_at = INFO_NAME_OFFSET + len(embedded)
    info[comment_at : comment_at + LENGTH_WORD_BYTES] = len(comment).to_bytes(
        LENGTH_WORD_BYTES, "big"
    )
    info[comment_at + LENGTH_WORD_BYTES :] = comment
    return bytes(info)


def file_stream(data: bytes, resource: bytes) -> bytes:
    """Use a different embedded name to test that INFO does not rename files.

    Returns
    -------
    bytes
        The flattened file: its header, then the INFO, DATA and MACR forks.
    """
    values = {b"INFO": info_value(), b"DATA": data, b"MACR": resource}
    return FILP_FILE_HEADER + b"".join(
        tag
        + bytes(FORK_HEADER_PADDING)
        + len(values[tag]).to_bytes(FORK_LENGTH_BYTES, "big")
        + values[tag]
        for tag in FORK_TAGS
    )


def handover() -> list[Action]:
    """Plan the control-handover greeting and its eight-byte reply.

    Returns
    -------
    list[native_plan.Action]
        The ``TRTP HOTL 0001 0003`` send and the read of the success bytes, on
        the connection named ``upload``.
    """
    return [
        {
            "op": "send",
            "connection": "upload",
            "hex": HANDSHAKE_HANDOVER_REQUEST_HEX,
        },
        {
            "op": "read",
            "connection": "upload",
            "size": HANDSHAKE_REPLY_BYTES,
            "expect_hex": HANDSHAKE_REPLY_HEX,
            "timeout": HANDOVER_TIMEOUT_SECONDS,
        },
    ]


def upload_case(name: bytes, data: bytes, resource: bytes) -> tuple[str, Case]:
    """Plan the upload of one fixture and the file-info read that follows.

    Returns
    -------
    tuple[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The case name, its steps and its expectation.
    """
    body = file_stream(data, resource)
    by_control = name == EMPTY_NAME
    size = len(body).to_bytes(SIZE_BYTES, "big")
    request = payload([(FIELD_FILE_NAME, name), (FIELD_TRANSFER_SIZE, size)])
    steps = [
        *login(),
        send(packet(TYPE_UPLOAD_FILE, REQUEST_ID, request)),
        read(save_field={"name": "upload_ref", "id": FIELD_TRANSFER_REFERENCE}),
        connect("upload", "control" if by_control else "data"),
    ]
    if by_control:
        steps += handover()
    steps += [
        send(
            HTXF_MAGIC_HEX
            + "{upload_ref}"
            + size.hex()
            + HTXF_RESERVED_HEX
            + body.hex(),
            "upload",
        ),
        eof("upload"),
        close("upload"),
        send(
            packet(TYPE_GET_FILE_INFO, FOLLOWUP_ID, payload([(FIELD_FILE_NAME, name)]))
        ),
        read(),
        close(),
    ]
    expectation: dict[str, typ.Any] = {
        "kind": "upload",
        "name_hex": name.hex(),
        "data_hex": data.hex(),
        "resource_hex": resource.hex(),
        "stream_hex": body.hex(),
    }
    if by_control:
        expectation["handover"] = True
    return "upload-empty-handover" if by_control else "upload-" + name.decode(), (
        steps,
        expectation,
    )


def transfers() -> dict[str, Case]:
    """Plan the ordinary-file uploads.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The steps and expectation of each case, by name.
    """
    cases: dict[str, Case] = {}
    for name, data, resource in [
        (FORK_NAME, FORK_DATA, resource_fork()),
        (EMPTY_NAME, b"", b""),
    ]:
        key, case = upload_case(name, data, resource)
        cases[key] = case
    return cases


class DownloadCase(typ.NamedTuple):
    """One download observation.

    Attributes
    ----------
    case : str
        The suffix of the case name.
    name : bytes
        The file to request.
    preview : bool
        Whether to ask for the raw preview.
    by_control : bool
        Whether the data connection is made through the control port.
    selector : int
        The selector word that the data connection sends.
    """

    case: str
    name: bytes
    preview: bool
    by_control: bool
    selector: int


DOWNLOAD_CASES = [
    DownloadCase("raw", FORK_NAME, preview=False, by_control=False, selector=0),
    DownloadCase("handover", FORK_NAME, preview=False, by_control=True, selector=0),
    DownloadCase("selector7", FORK_NAME, preview=False, by_control=False, selector=7),
    DownloadCase("preview", FORK_NAME, preview=True, by_control=False, selector=0),
    DownloadCase("empty", EMPTY_NAME, preview=False, by_control=False, selector=0),
    DownloadCase(
        "empty-preview", EMPTY_NAME, preview=True, by_control=False, selector=0
    ),
    DownloadCase(
        "wrong-folder-selector",
        FORK_NAME,
        preview=False,
        by_control=False,
        selector=SELECTOR_FOLDER,
    ),
    DownloadCase(
        "wrong-banner-selector",
        FORK_NAME,
        preview=False,
        by_control=False,
        selector=SELECTOR_BANNER,
    ),
]


def cleanup_steps() -> list[Action]:
    """Plan an owner cleanup of the download reference and the end of the stream.

    Returns
    -------
    list[native_plan.Action]
        The 214 send, its reply and the end of the data stream.
    """
    cleanup = packet(
        TYPE_REFERENCE_CLEANUP,
        FOLLOWUP_ID,
        payload([(FIELD_TRANSFER_REFERENCE, REFERENCE_MARKER)]),
    ).replace(REFERENCE_MARKER.hex(), "{download_ref}")
    return [send(cleanup), read(), eof("download")]


def download_stream(case: DownloadCase) -> list[Action]:
    """Plan the data connection of one download after its request is answered.

    Returns
    -------
    list[native_plan.Action]
        The connect, optional handover, greeting and the reads that follow.
    """
    steps: list[Action] = [
        read(
            save_fields={
                "download_ref": FIELD_TRANSFER_REFERENCE,
                "download_size": FIELD_TRANSFER_SIZE,
            }
        ),
        connect("download", "control" if case.by_control else "data"),
    ]
    if case.by_control:
        steps += [
            send(HANDSHAKE_HANDOVER_REQUEST_HEX, "download"),
            {
                "op": "read",
                "connection": "download",
                "size": HANDSHAKE_REPLY_BYTES,
                "expect_hex": HANDSHAKE_REPLY_HEX,
                "timeout": HANDOVER_TIMEOUT_SECONDS,
            },
        ]
    greeting = (
        HTXF_MAGIC_HEX
        + "{download_ref}00000000"
        + case.selector.to_bytes(SELECTOR_BYTES, "big").hex()
        + "0000"
    )
    steps += [send(greeting, "download")]
    if case.selector in NO_FOLLOWUP_SELECTORS:
        return [*steps, eof("download")]
    steps += [
        {
            "op": "read",
            "connection": "download",
            "size_from": "download_size",
            "timeout": DOWNLOAD_READ_SECONDS,
        },
        {"op": "expect_quiet", "connection": "download", "timeout": QUIET_SECONDS},
    ]
    if case.case == "raw":
        steps += cleanup_steps()
    return steps


def download_case(case: DownloadCase) -> Case:
    """Plan one download observation.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and expectation of the case.
    """
    fields = [(FIELD_FILE_NAME, case.name)]
    if case.preview:
        fields.append((
            FIELD_TRANSFER_OPTION,
            PREVIEW_OPTION.to_bytes(OPTION_BYTES, "big"),
        ))
    steps = [*login(), send(packet(TYPE_DOWNLOAD_FILE, REQUEST_ID, payload(fields)))]
    if case.case == "empty-preview":
        steps += [read(), close()]
    else:
        steps += [*download_stream(case), close("download"), close()]
    return steps, {
        "kind": "download",
        "name_hex": case.name.hex(),
        "preview": case.preview,
        "handover": case.by_control,
        "selector": case.selector,
    }


def downloads() -> dict[str, Case]:
    """Plan the ordinary-file downloads.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The steps and expectation of each case, by name.
    """
    return {"download-" + case.case: download_case(case) for case in DOWNLOAD_CASES}
