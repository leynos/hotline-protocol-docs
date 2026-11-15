"""Read queue references, notifications and timing out of a native queue capture.

These are the building blocks of ``verify_native_queues``. That module
re-exports them, because ``verify_native_cleanup``, ``native_folder_clock_checks``
and ``verify_native_banner_formats`` import ``frame_time`` from it by name, and
the queue tests import the rest.
"""

import datetime as dt
import struct
import typing as typ

from native_filp import decode
from native_transfer_cases import resource_fork
from native_wire_names import (
    FIELD_FILE_SIZE,
    FIELD_QUEUE_POSITION,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    FRAME_HEADER_FORMAT,
    TYPE_QUEUE_NOTIFICATION,
)
from pcap_tcp import direction, lifetime, stream
from verify_native_core import require
from verify_native_forks import check_metadata, fields

type Report = dict[str, typ.Any]
type Frame = dict[str, typ.Any]
type Reference = dict[str, typ.Any]

# The guest runs a user-mode network: the host side of the capture is 10.0.2.2
# and the Hotline Server listens on 10.0.2.15, port 5500.
HOST_ADDRESS = "10.0.2.2"
GUEST_ADDRESS = "10.0.2.15"
SERVER_PORT = 5500
MICROSECONDS_PER_SECOND = 1_000_000
NANOSECONDS_PER_MICROSECOND = 1000
MAX_TIMED_FRAME_BYTES = 4096
TCP_SYN = 2
TCP_RST = 4
SEQUENCE_MASK = 0xFFFFFFFF
REFERENCE_BYTES = 4
QUEUE_NOTICE_FIELDS = 2  # reference 107 and position 116
HTXF_TAIL = bytes(8)
FORK_DATA = b"data-fork\r\n\x00\xff"
EMPTY_FIXTURE = b"mothra-empty-fixture"
FORK_FIXTURE = b"mothra-fork-fixture"


def reply(report: Report, owner: str, identifier: int) -> Frame:
    """Find the one reply to a request of an owner.

    Returns
    -------
    dict[str, typing.Any]
        The reply frame, whose output fields have been checked.
    """
    selected = [
        f
        for f in report["frames"]
        if f["connection"] == owner and f["is_reply"] == 1 and f["id"] == identifier
    ]
    require(len(selected) == 1, "Missing or duplicate queue reply")
    fields(selected[0])
    return selected[0]


def _frame_bytes(frame: Frame) -> bytes:
    """Rebuild the wire bytes of a decoded frame.

    Returns
    -------
    bytes
        The header and the data.
    """
    return struct.pack(
        FRAME_HEADER_FORMAT,
        frame["flags"],
        frame["is_reply"],
        frame["type"],
        frame["id"],
        frame["error"],
        frame["total_size"],
        frame["data_size"],
    ) + bytes.fromhex(frame["payload_hex"])


def _first_seen(selected: list[dict[str, typ.Any]], start: int, end: int) -> dict:
    """Map each byte offset of a frame to the first packet that carried it.

    Returns
    -------
    dict[int, int]
        The earliest timestamp, in microseconds, by stream offset.
    """
    base = (
        next(p["sequence"] for p in selected if p["flags"] & TCP_SYN) + 1
    ) & SEQUENCE_MASK
    seen: dict[int, int] = {}
    for packet in selected:
        if packet["flags"] & TCP_RST:
            continue
        offset = (
            packet["sequence"] + bool(packet["flags"] & TCP_SYN) - base
        ) & SEQUENCE_MASK
        count = len(bytes.fromhex(packet["payload_hex"]))
        for index in range(max(start, offset), min(end, offset + count)):
            seen[index] = min(
                seen.get(index, packet["timestamp_us"]), packet["timestamp_us"]
            )
    return seen


def frame_time(report: Report, frame: Frame, guest: list[dict[str, typ.Any]]) -> int:
    """Return complete-frame first observation in guest PCAP host UTC units.

    Returns
    -------
    int
        The time, in microseconds, at which the last byte of the frame was seen
        for the first time.
    """
    event = next(
        e
        for e in report["events"]
        if e["event"] == "connect" and e["connection"] == frame["connection"]
    )
    client = (HOST_ADDRESS, event["local_address"][1])
    server = (GUEST_ADDRESS, SERVER_PORT)
    when = int(
        dt.datetime.fromisoformat(report["started_at_utc"]).timestamp()
        * MICROSECONDS_PER_SECOND
        + event["elapsed_ns"] / NANOSECONDS_PER_MICROSECOND
    )
    packets = lifetime(guest, client, server, when)
    data = _frame_bytes(frame)
    require(
        len(data) <= MAX_TIMED_FRAME_BYTES,
        "Control timing frame exceeds analysis bound",
    )
    raw = stream(packets, server, client)
    require(raw.count(data) == 1, "Control timing frame is not unique")
    start = raw.index(data)
    seen = _first_seen(direction(packets, server, client), start, start + len(data))
    require(len(seen) == len(data), "Missing timed frame bytes")
    return max(seen.values())


def references(report: Report, plan: Report) -> dict[str, Reference]:
    """Collect the saved transfer references of a capture, by variable name.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        The reference in hexadecimal, its frame and its fields, per variable.
    """
    result: dict[str, Reference] = {}
    for action, step in enumerate(plan["steps"]):
        saves = step.get("save_fields", {})
        names = [
            name for name, field in saves.items() if field == FIELD_TRANSFER_REFERENCE
        ]
        if not names:
            continue
        require(len(names) == 1, "Ambiguous saved queue reference")
        frame = next(f for f in reversed(report["frames"]) if f["action"] == action)
        values = fields(frame)
        reference = values[FIELD_TRANSFER_REFERENCE]
        require(
            len(reference) == REFERENCE_BYTES
            and int.from_bytes(reference, "big") & 1 != 0,
            "Queue reference is not four-byte odd",
        )
        result[names[0]] = {
            "reference": reference.hex(),
            "frame": frame,
            "values": values,
        }
    require(
        len({r["reference"] for r in result.values()}) == len(result),
        "Duplicate live references",
    )
    return result


def _check_notice(
    frame: Frame, by_reference: dict[str, str], refs: dict
) -> tuple[str, int]:
    """Check one queue notification and name the transfer it advances.

    Returns
    -------
    tuple[str, int]
        The variable of the transfer that the notification names, and the queue
        position that it reports.
    """
    require(
        frame["is_reply"] == 0 and frame["error"] == 0,
        "Queue notification envelope differs",
    )
    values = {f["id"]: f["hex"] for f in frame["fields"]}
    require(
        set(values) == {FIELD_TRANSFER_REFERENCE, FIELD_QUEUE_POSITION}
        and len(frame["fields"]) == QUEUE_NOTICE_FIELDS,
        "Queue notification field set differs",
    )
    reference = values[FIELD_TRANSFER_REFERENCE]
    require(
        len(bytes.fromhex(reference)) == REFERENCE_BYTES,
        "Queue notification reference width differs",
    )
    require(reference in by_reference, "Queue notification has unknown reference")
    name = by_reference[reference]
    require(
        frame["connection"] == refs[name]["frame"]["connection"],
        "Queue notice went to a different owner",
    )
    return name, int(values[FIELD_QUEUE_POSITION], 16)


def notices(report: Report, refs: dict[str, Reference]) -> dict[str, list[Frame]]:
    """Group the queue notifications of a capture by the transfer they name.

    Returns
    -------
    dict[str, list[dict[str, typing.Any]]]
        A position and frame for each notification, per variable.
    """
    by_reference = {r["reference"]: name for name, r in refs.items()}
    result: dict[str, list[Frame]] = {name: [] for name in refs}
    for frame in report["frames"]:
        if frame["type"] != TYPE_QUEUE_NOTIFICATION:
            continue
        name, position = _check_notice(frame, by_reference, refs)
        result[name].append({"position": position, "frame": frame})
    return result


class Delivery(typ.TypedDict, total=False):
    """What a queued download is expected to deliver; each defaults to false.

    ``preview`` means a raw preview and not forks, and ``empty`` means that the
    fixture file is empty.
    """

    preview: bool
    empty: bool


def check_download(
    report: Report,
    refs: dict[str, Reference],
    name: str,
    **delivery: typ.Unpack[Delivery],
) -> None:
    """Check that a queued transfer attached with its reference and delivered."""
    recorded = report["streams"][name]
    require(
        bytes.fromhex(recorded["sent_hex"])
        == b"HTXF" + bytes.fromhex(refs[name]["reference"]) + HTXF_TAIL,
        "Queued HTXF differs",
    )
    received = bytes.fromhex(recorded["received_hex"])
    require(
        len(received)
        == int.from_bytes(refs[name]["values"][FIELD_TRANSFER_SIZE], "big"),
        "Queued delivery count differs",
    )
    empty = delivery.get("empty", False)
    data = b"" if empty else FORK_DATA
    if delivery.get("preview"):
        require(received == data, "Queued preview is not raw DATA")
        return
    forks = decode(received)
    require(
        forks["DATA"] == data and forks["MACR"] == (b"" if empty else resource_fork()),
        "Queued fork bytes differ",
    )
    check_metadata(
        forks["INFO"], EMPTY_FIXTURE if empty else FORK_FIXTURE, uploaded=False
    )


def logical_size(values: dict[int, bytes]) -> int:
    """Read the logical file size of a transfer ACK.

    Returns
    -------
    int
        The size in field 207.
    """
    return int.from_bytes(values[FIELD_FILE_SIZE], "big")
