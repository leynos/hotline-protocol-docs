"""Describe a physical frame for ``protocol_capture`` without inferring more.

Part of the capture driver's module set (``protocol_capture.CAPTURE_MODULES``).
:func:`decode_frame` is re-exported by ``protocol_capture``, which every other
script imports it from.
"""

import struct
import typing as typ

HEADER_SIZE = 20
COUNT_SIZE = 2
FIELD_HEAD_SIZE = 4

type Frame = dict[str, typ.Any]


def _walk_fields(payload: bytes, count: int) -> tuple[list[Frame], int]:
    """Read the declared fields while they fit in the payload.

    Parameters
    ----------
    payload : bytes
        The payload, whose first two bytes are the count word.
    count : int
        The number of fields the count word declares.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], int]
        The fields read, each with ``id`` and ``hex``, and the offset where
        reading stopped.
    """
    fields: list[Frame] = []
    offset = COUNT_SIZE
    for _ in range(count):
        if offset + FIELD_HEAD_SIZE > len(payload):
            break
        field, length = struct.unpack(">HH", payload[offset : offset + FIELD_HEAD_SIZE])
        if offset + FIELD_HEAD_SIZE + length > len(payload):
            break
        start = offset + FIELD_HEAD_SIZE
        fields.append({"id": field, "hex": payload[start : start + length].hex()})
        offset += FIELD_HEAD_SIZE + length
    return fields, offset


def _header(data: bytes) -> tuple[Frame, int, int]:
    """Unpack the 20-byte header.

    Returns
    -------
    tuple[dict[str, typing.Any], int, int]
        The header fields with the payload as hexadecimal, then the total size
        and the data size that the header declares.
    """
    flags, reply, kind, identifier, error, total, size = struct.unpack(
        ">BBHIIII", data[:HEADER_SIZE]
    )
    result: Frame = {
        "flags": flags,
        "is_reply": reply,
        "type": kind,
        "id": identifier,
        "error": error,
        "total_size": total,
        "data_size": size,
        "payload_hex": data[HEADER_SIZE:].hex(),
    }
    return result, total, size


def decode_frame(data: bytes) -> Frame:
    """Describe a physical frame; preserve malformed/fragmented payloads as bytes.

    A ``struct.error`` from the header unpacking is raised if ``data`` is shorter
    than the 20-byte header.

    Parameters
    ----------
    data : bytes
        At least the 20-byte header.

    Returns
    -------
    dict[str, typing.Any]
        The header fields and the payload as hexadecimal. A frame whose total
        size equals its data size also lists the fields it declares and any
        bytes left over; a fragment, or a payload without a count word, carries
        a ``decode_note`` instead.
    """
    result, total, size = _header(data)
    if total != size:
        result["decode_note"] = "Physical fragment only; no logical TLV inference"
        return result
    payload = data[HEADER_SIZE:]
    if len(payload) < COUNT_SIZE:
        result["decode_note"] = "Payload lacks a complete count word"
        return result
    count = int.from_bytes(payload[:COUNT_SIZE], "big")
    fields, offset = _walk_fields(payload, count)
    result["fields"] = fields
    result["declared_field_count"] = count
    result["unconsumed_hex"] = payload[offset:].hex()
    return result
