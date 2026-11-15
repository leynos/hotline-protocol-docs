"""Read the control ACKs, INFO metadata and transfer bytes of the fork corpus."""

import typing as typ

from native_filp import metadata
from native_wire_names import (
    FIELD_FILE_CREATOR,
    FIELD_FILE_NAME,
    FIELD_FILE_SIZE,
    FIELD_FILE_TYPE,
    HANDSHAKE_HANDOVER_REQUEST_HEX,
    HANDSHAKE_REPLY_HEX,
    HTXF_MAGIC_HEX,
)
from verify_native_core import require

type Report = dict[str, typ.Any]

HANDOVER = bytes.fromhex(HANDSHAKE_HANDOVER_REQUEST_HEX)
SUCCESS = bytes.fromhex(HANDSHAKE_REPLY_HEX)
HTXF = bytes.fromhex(HTXF_MAGIC_HEX)
HTXF_HEADER_BYTES = 16  # magic, reference, size word, selector and reserved word
FIELD_FILE_COMMENT = 210  # operation-contracts.md: 207 field 210 is the comment
# date-contracts.md: file-info replies carry two eight-byte dates, 208 and 209.
FILE_DATE_FIELDS = (208, 209)
FIXTURE_COMMENT = b"fixture-comment"
UPLOADED_NAME = b"metadata-only-name"
UPLOADED_FLAGS = 0x8100
DATE_BYTES = 8


def fields(frame: Report) -> dict[int, bytes]:
    """Map the fields of a transfer control ACK by ID.

    Returns
    -------
    dict[int, bytes]
        The value of each field.
    """
    require(
        frame["is_reply"] == 1 and frame["type"] == 0 and frame["error"] == 0,
        "Transfer control ACK changed",
    )
    result = {f["id"]: bytes.fromhex(f["hex"]) for f in frame["fields"]}
    require(len(result) == len(frame["fields"]), "Duplicate output field")
    return result


def check_metadata(
    info: bytes,
    name: bytes,
    uploaded: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers' shape
) -> Report:
    """Check the type, creator, comment, name, flags and dates of an INFO value.

    Returns
    -------
    dict[str, typing.Any]
        The decoded values, in hexadecimal.
    """
    values = metadata(info)
    require(
        values["type"] == b"TEXT" and values["creator"] == b"MOTH",
        "Type/creator differ",
    )
    require(values["comment"] == FIXTURE_COMMENT, "Comment round trip differs")
    require(
        values["name"] == (UPLOADED_NAME if uploaded else name),
        "INFO name differs",
    )
    require(
        int.from_bytes(values["flags"], "big") == (UPLOADED_FLAGS if uploaded else 0),
        "Metadata flags differ",
    )
    for field in ["created", "modified"]:
        require(
            (values[field] == bytes(DATE_BYTES)) == uploaded,
            "Transmitted zero dates unexpectedly restored",
        )
    return {key: value.hex() for key, value in values.items()}


def check_file_info(frame: Report, name: bytes, logical_size: int) -> Report:
    """Check a file-info reply for the uploaded file.

    Returns
    -------
    dict[str, typing.Any]
        The fields of the reply, in hexadecimal, by decimal ID.
    """
    values = fields(frame)
    require(values[FIELD_FILE_NAME] == name, "Request name did not survive upload")
    require(
        values[FIELD_FILE_TYPE] == b"TEXT" and values[FIELD_FILE_CREATOR] == b"MOTH",
        "File-info type/creator differ",
    )
    require(
        int.from_bytes(values[FIELD_FILE_SIZE], "big") == logical_size,
        "File-info size differs",
    )
    require(values[FIELD_FILE_COMMENT] == FIXTURE_COMMENT, "File-info comment differs")
    first, second = FILE_DATE_FIELDS
    require(
        values[first] != bytes(DATE_BYTES) and values[second] != bytes(DATE_BYTES),
        "File-info dates stayed zero",
    )
    return {str(k): v.hex() for k, v in values.items()}


def transfer_bytes(
    report: Report, connection: str, *, handover: bool
) -> tuple[bytes, bytes]:
    """Return what a data connection sent and received, after any handover.

    Returns
    -------
    tuple[bytes, bytes]
        The bytes sent and the bytes received, from the HTXF header on.
    """
    received = bytes.fromhex(report["streams"][connection]["received_hex"])
    sent = bytes.fromhex(report["streams"][connection]["sent_hex"])
    if handover:
        require(
            sent.startswith(HANDOVER) and received.startswith(SUCCESS),
            "Handover failed",
        )
        sent, received = sent[len(HANDOVER) :], received[len(SUCCESS) :]
    require(
        sent[: len(HTXF)] == HTXF and len(sent) >= HTXF_HEADER_BYTES,
        "Missing HTXF header",
    )
    return sent, received
