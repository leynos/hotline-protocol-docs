"""Check bounded folder clock observations independently of declared pauses."""

import typing as typ

from native_folder_stream import HTXF_HEADER_BYTES, upload
from native_wire_names import FIELD_TRANSFER_REFERENCE
from pcap_tcp import direction
from verify_native_cleanup import flow
from verify_native_core import require
from verify_native_folder_support import (
    FOLDER_REQUEST_ID,
    ODD_REFERENCE_MASK,
    REFERENCE_BYTES,
    Packets,
    Report,
)
from verify_native_forks import fields
from verify_native_queues import frame_time

# TCP flag bits as the captures record them (RFC 793): SYN marks the start of a
# direction and RST marks a reset.
FLAG_SYN = 2
FLAG_RST = 4
# The mask that selects a closing segment in the original check: bit zero and
# RST. Bit zero is kept unnamed because no retained document fixes its meaning.
CLOSE_FLAG_MASK = 5
SEQUENCE_MASK = 0xFFFFFFFF  # the 32-bit TCP sequence space

# Declared pauses (the planners in native_folder_timing.py) and the bounded
# host windows that the measured closes must fall in.
LATE_ATTACHMENT_CASE = "folder-upload-late-attachment"
LATE_ATTACHMENT_PAUSE_SECONDS = 125
TIMED_PAUSE_SECONDS = 130
UPLOAD_CLOSE_MIN_SECONDS = 115
UPLOAD_CLOSE_MAX_SECONDS = 165
DELAYED_CLOSE_MIN_SECONDS = 125
DELAYED_CLOSE_MAX_SECONDS = 175
DIRECTORY_REPLY_BOUND_SECONDS = 90


def pauses(report: Report, plan: Report, total: int) -> None:
    """Check that every declared pause lasted at least its declared seconds."""
    measured: list[typ.Any] = []
    for action, step in enumerate(plan["steps"]):
        if step["op"] != "pause":
            continue
        event = next(
            e
            for e in report["events"]
            if e["event"] == "pause" and e["action"] == action
        )
        previous = [e for e in report["events"] if e["action"] < action][-1]
        require(
            event["elapsed_ns"] - previous["elapsed_ns"] >= step["seconds"] * 1e9,
            "Shortened folder timing pause",
        )
        measured.append(step["seconds"])
    require(sum(measured) == total, "Folder pause total differs")


def payload_times(selected: Packets, start: int, size: int) -> dict[int, int]:
    """Earliest capture time of each stream byte in ``[start, start + size)``.

    Returns
    -------
    dict[int, int]
        The capture time in microseconds, by stream offset.
    """
    base = (
        next(p["sequence"] for p in selected if p["flags"] & FLAG_SYN) + 1
    ) & SEQUENCE_MASK
    seen: dict[int, int] = {}
    for packet in selected:
        if packet["flags"] & FLAG_RST:
            continue
        offset = (
            packet["sequence"] + bool(packet["flags"] & FLAG_SYN) - base
        ) & SEQUENCE_MASK
        end = offset + len(bytes.fromhex(packet["payload_hex"]))
        for index in range(max(start, offset), min(start + size, end)):
            seen[index] = min(
                seen.get(index, packet["timestamp_us"]), packet["timestamp_us"]
            )
    return seen


def span_time(report: Report, guest: Packets, start: int, size: int) -> int:
    """Return the capture time at which the last byte of a span was seen.

    Returns
    -------
    int
        The latest of the earliest capture times, in microseconds.
    """
    packets, client, server = flow(report, "folder", guest)
    seen = payload_times(direction(packets, server, client), start, size)
    require(len(seen) == size, "Missing timed folder span bytes")
    return max(seen.values())


def timed_request(report: Report, ack: Report) -> bytes:
    """Check the reference of a timed upload ACK and the HTXF header it names.

    Returns
    -------
    bytes
        The folder request bytes that the client sent.
    """
    values = fields(ack)
    require(
        set(values) == {FIELD_TRANSFER_REFERENCE}
        and len(values[FIELD_TRANSFER_REFERENCE]) == REFERENCE_BYTES
        and not int.from_bytes(values[FIELD_TRANSFER_REFERENCE], "big")
        & ODD_REFERENCE_MASK,
        "Timed upload reference differs",
    )
    sent = bytes.fromhex(report["streams"]["folder"]["sent_hex"])
    require(
        sent[:HTXF_HEADER_BYTES]
        == b"HTXF" + values[FIELD_TRANSFER_REFERENCE] + bytes(4) + b"\0\1\0\0",
        "Timed upload HTXF differs",
    )
    return sent


def close_time(report: Report, guest: Packets) -> int:
    """Return the capture time of the first closing segment of the folder flow.

    Returns
    -------
    int
        The capture time in microseconds.
    """
    packets, client, server = flow(report, "folder", guest)
    closes = [
        p for p in direction(packets, server, client) if p["flags"] & CLOSE_FLAG_MASK
    ]
    require(bool(closes), "Missing native timed-folder close")
    return closes[0]["timestamp_us"]


def directory_reply_time(
    report: Report, guest: Packets, sent: bytes, received: bytes
) -> int:
    """Check the directory exchange of a timed upload and return its reply time.

    Returns
    -------
    int
        The capture time of the directory reply.
    """
    parsed = upload(sent, received)
    require(
        parsed["completed"] == 1
        and len(parsed["items"]) == 1
        and parsed["items"][0]["path"] == (b"wait",)
        and parsed["items"][0]["directory"],
        "Timed directory exchange differs",
    )
    return span_time(report, guest, 2, 2)


def directory_gap(closed_at: int, reply: int) -> float:
    """Return the seconds from the directory reply to the close, bounded.

    Returns
    -------
    float
        The seconds between the two capture times.
    """
    since_directory = (closed_at - reply) / 1e6
    require(
        0 <= since_directory < DIRECTORY_REPLY_BOUND_SECONDS,
        "Descriptor exchange may have reset a full connected timer",
    )
    return since_directory


def upload_clock(name: str, report: Report, plan: Report, guest: Packets) -> Report:
    """Check the host-measured close of a timed folder upload.

    Returns
    -------
    dict[str, typing.Any]
        The seconds from the request ACK and, unless late, from the directory reply.
    """
    late = name == LATE_ATTACHMENT_CASE
    pause = LATE_ATTACHMENT_PAUSE_SECONDS if late else TIMED_PAUSE_SECONDS
    pauses(report, plan, pause)
    ack = next(
        f for f in report["frames"] if f["is_reply"] and f["id"] == FOLDER_REQUEST_ID
    )
    sent = timed_request(report, ack)
    created = frame_time(report, ack, guest)
    closed_at = close_time(report, guest)
    age = (closed_at - created) / 1e6
    require(
        UPLOAD_CLOSE_MIN_SECONDS <= age <= UPLOAD_CLOSE_MAX_SECONDS,
        "Timed folder close outside bounded host window",
    )
    received = bytes.fromhex(report["streams"]["folder"]["received_hex"])
    require(received == (b"" if late else b"\0\3\0\3"), "Timed-folder output differs")
    result: Report = {
        "close_after_request_ack_host_seconds": age,
        "measured_pause_seconds": pause,
    }
    if late:
        require(
            len(sent) == HTXF_HEADER_BYTES, "Late attachment sent folder item bytes"
        )
    else:
        reply = directory_reply_time(report, guest, sent, received)
        result["close_after_directory_reply_host_seconds"] = directory_gap(
            closed_at, reply
        )
    return result


def download_clock(report: Report, plan: Report, guest: Packets) -> Report:
    """Check the host-measured delay before a folder download's file choice.

    Returns
    -------
    dict[str, typing.Any]
        The seconds from the descriptor to the file length and the pause.
    """
    pauses(report, plan, TIMED_PAUSE_SECONDS)
    first_descriptor = span_time(report, guest, 0, 14)
    first_length = span_time(report, guest, 14, 4)
    age = (first_length - first_descriptor) / 1e6
    require(
        DELAYED_CLOSE_MIN_SECONDS <= age <= DELAYED_CLOSE_MAX_SECONDS,
        "Delayed folder choice outside bounded host window",
    )
    return {
        "first_file_length_after_descriptor_host_seconds": age,
        "measured_pause_seconds": TIMED_PAUSE_SECONDS,
    }
