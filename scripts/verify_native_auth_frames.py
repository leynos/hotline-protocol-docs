"""Read the frames and roster views of a retained native authentication capture."""

import typing as typ

from native_wire_names import (
    FIELD_USER_RECORD,
    ROSTER_HEADER_BYTES,
    ROSTER_ICON_START,
    ROSTER_NAME_LENGTH_START,
    ROSTER_STATUS_START,
)
from verify_native_core import require

type Report = dict[str, typ.Any]

ADMIN = bytes.fromhex("fff3cfefff800000")  # the administrator's access bitmap
BYPASS = bytes.fromhex("0000003000000000")  # the bitmap of the bypass account


def selected(report: Report, connection: str) -> list[Report]:
    """Select the frames that were received on a connection.

    Returns
    -------
    list[dict[str, typing.Any]]
        The frames of ``connection``, in order.
    """
    return [f for f in report["frames"] if f["connection"] == connection]


def reply(report: Report, identifier: int, connection: str = "main") -> Report:
    """Find the one reply to the request with ``identifier``.

    Returns
    -------
    dict[str, typing.Any]
        The reply frame.
    """
    matches = [
        f
        for f in selected(report, connection)
        if f["is_reply"] and f["id"] == identifier
    ]
    require(len(matches) == 1, "Missing/duplicate auth reply")
    return matches[0]


def roster(frame: Report) -> list[Report]:
    """Decode the packed user records of a roster reply.

    Returns
    -------
    list[dict[str, typing.Any]]
        The UID, icon and name (hexadecimal) of each record.
    """
    records = []
    for item in frame["fields"]:
        require(item["id"] == FIELD_USER_RECORD, "Unexpected roster parameter")
        raw = bytes.fromhex(item["hex"])
        name_length = int.from_bytes(
            raw[ROSTER_NAME_LENGTH_START:ROSTER_HEADER_BYTES], "big"
        )
        require(
            len(raw) >= ROSTER_HEADER_BYTES
            and len(raw) == ROSTER_HEADER_BYTES + name_length,
            "Roster record boundary differs",
        )
        records.append({
            "uid": int.from_bytes(raw[:ROSTER_ICON_START], "big"),
            "icon": int.from_bytes(raw[ROSTER_ICON_START:ROSTER_STATUS_START], "big"),
            "name_hex": raw[ROSTER_HEADER_BYTES:].hex(),
        })
    require(len({r["uid"] for r in records}) == len(records), "Duplicate roster UID")
    return records
