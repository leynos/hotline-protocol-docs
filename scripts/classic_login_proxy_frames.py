"""Decode, check and transform the control frames that the proxy relays."""

import struct
import typing as typ

from classic_login_proxy_constants import MAX_FRAME, MIN_FRAME_BYTES, VARIANTS
from classic_login_proxy_errors import fail
from native_plan import packet, payload
from native_wire_names import FIELD_SERVER_NAME, FIELD_UNNAMED_WORD, FRAME_HEADER_BYTES
from protocol_capture import decode_frame

MALFORMED_FRAME = "Fragmented, oversized or malformed control frame"


def parse_frame(raw: bytes) -> dict[str, typ.Any]:
    """Decode one control frame and refuse a malformed header or field sequence.

    Parameters
    ----------
    raw : bytes
        One whole control frame, header included.

    Returns
    -------
    dict[str, typing.Any]
        The decoded frame, with each field as an ``(id, value)`` pair.
    """
    if len(raw) < MIN_FRAME_BYTES:
        fail(ValueError, "Short control frame")
    _, reply, _, _, _, total, size = struct.unpack(">BBHIIII", raw[:FRAME_HEADER_BYTES])
    if reply not in {0, 1} or total != size:
        fail(ValueError, MALFORMED_FRAME)
    if size > MAX_FRAME or len(raw) != FRAME_HEADER_BYTES + size:
        fail(ValueError, MALFORMED_FRAME)
    frame = decode_frame(raw)
    fields = frame.get("fields", [])
    if frame.get("declared_field_count") != len(fields) or frame.get("unconsumed_hex"):
        fail(ValueError, "Malformed control TLV sequence")
    frame["fields"] = [(item["id"], bytes.fromhex(item["hex"])) for item in fields]
    return frame


def transform_ack(raw: bytes, login_id: int, variant: str) -> bytes:
    """Rebuild the first server ACK as the named variant requires.

    Parameters
    ----------
    raw : bytes
        The native successful Login107 ACK, as the server sent it.
    login_id : int
        The ID of the observed Login107 request that the ACK must answer.
    variant : str
        One of the names in ``VARIANTS``.

    Returns
    -------
    bytes
        The ACK to forward to the client.
    """
    if variant not in VARIANTS:
        fail(ValueError, "Unknown variant")
    frame = parse_frame(raw)
    if (frame["is_reply"], frame["type"], frame["id"], frame["error"]) != (
        1,
        0,
        login_id,
        0,
    ):
        fail(ValueError, "First server frame is not successful Login107 ACK")
    values = [value for key, value in frame["fields"] if key == FIELD_UNNAMED_WORD]
    if values != [b"\x00\x00"]:
        fail(ValueError, "Native 161 source is not exactly two zero bytes")
    _rewrite_fields(frame, variant)
    result = bytes.fromhex(
        packet(
            frame["type"],
            frame["id"],
            payload(frame["fields"]),
            flags=frame["flags"],
            reply=frame["is_reply"],
            error=frame["error"],
        )
    )
    if variant in {"baseline", "roster-subject-115"} and result != raw:
        fail(ValueError, "Baseline ACK reconstruction differs")
    return result


def _rewrite_fields(frame: dict[str, typ.Any], variant: str) -> None:
    """Apply the field edit of one variant to a decoded ACK in place.

    Parameters
    ----------
    frame : dict[str, typing.Any]
        The decoded ACK, whose ``fields`` list is replaced or extended.
    variant : str
        One of the names in ``VARIANTS``.
    """
    if variant == "server-name-162":
        if any(key == FIELD_SERVER_NAME for key, _ in frame["fields"]):
            fail(ValueError, "Native ACK already contains field 162")
        frame["fields"].append((FIELD_SERVER_NAME, b"fixture-native"))
        return
    replacement = {
        "baseline": b"\x00\x00",
        "roster-subject-115": b"\x00\x00",
        "omit-161": None,
        "one-byte-161": b"\x00",
        "four-byte-161": b"\x00" * 4,
    }[variant]
    if replacement is None:
        frame["fields"] = [
            (key, value) for key, value in frame["fields"] if key != FIELD_UNNAMED_WORD
        ]
    else:
        frame["fields"] = [
            (key, replacement if key == FIELD_UNNAMED_WORD else value)
            for key, value in frame["fields"]
        ]
