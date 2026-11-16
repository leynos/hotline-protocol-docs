"""Check the unread room frames that a client retained after its last read."""

import native_wire_names as names
import verify_native_rooms_wire as wire
from native_wire_names import (
    FIELD_ICON,
    FIELD_NAME,
    FIELD_USER_ID,
    FRAME_HEADER_BYTES,
    FRAME_SIZE_START,
    TYPE_PRESENCE_UPDATE,
    TYPE_USER_LEFT,
)
from protocol_capture import decode_frame
from verify_native_core import require
from verify_native_rooms_wire import FIELD_ROOM, FIELD_STATUS, ROOM_LEAVE_NOTICE
from verify_native_shx import fields


def tail_frames(raw: bytes) -> list[dict]:
    """Split a retained tail into its frames, each decoded.

    Parameters
    ----------
    raw : bytes
        The bytes of the tail, one frame after another.

    Returns
    -------
    list[dict]
        The decoded frames, in order.
    """
    result = []
    while raw:
        require(len(raw) >= FRAME_HEADER_BYTES, "Incomplete room tail header")
        size = FRAME_HEADER_BYTES + int.from_bytes(
            raw[FRAME_SIZE_START:FRAME_HEADER_BYTES], "big"
        )
        require(len(raw) >= size, "Incomplete room tail payload")
        result.append(decode_frame(raw[:size]))
        raw = raw[size:]
    return result


def validate_tail(raw: bytes, room: bytes, ids: dict[str, bytes]) -> None:
    """Check that every unread frame of a tail names a known participant.

    Parameters
    ----------
    raw : bytes
        The bytes of the tail.
    room : bytes
        The room identifier.
    ids : dict[str, bytes]
        The identifier of the owner and of each role.
    """
    for frame in tail_frames(raw):
        values = fields(frame)
        require(
            frame["type"] in {ROOM_LEAVE_NOTICE, TYPE_PRESENCE_UPDATE, TYPE_USER_LEFT}
            and not frame["is_reply"]
            and frame["error"] == 0
            and values.get(FIELD_USER_ID) in ids.values(),
            "Unread room message identity differs",
        )
        match frame["type"]:
            case wire.ROOM_LEAVE_NOTICE:
                require(
                    values == {FIELD_ROOM: room, FIELD_USER_ID: values[FIELD_USER_ID]},
                    "Unread room departure differs",
                )
            case names.TYPE_USER_LEFT:
                require(set(values) == {FIELD_USER_ID}, "Unread roster removal differs")
            case _:
                require(
                    set(values)
                    == {FIELD_USER_ID, FIELD_ICON, FIELD_STATUS, FIELD_NAME},
                    "Unread profile schema differs",
                )
