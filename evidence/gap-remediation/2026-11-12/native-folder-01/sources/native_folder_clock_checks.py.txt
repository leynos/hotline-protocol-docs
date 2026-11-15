"""Check bounded folder clock observations independently of declared pauses."""

from native_folder_stream import upload
from pcap_tcp import direction
from verify_native_cleanup import flow
from verify_native_core import require
from verify_native_forks import fields
from verify_native_queues import frame_time


def pauses(report: dict, plan: dict, total: int) -> None:
    measured = []
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


def span_time(report: dict, guest: list[dict], start: int, size: int) -> int:
    packets, client, server = flow(report, "folder", guest)
    selected = direction(packets, server, client)
    base = (next(p["sequence"] for p in selected if p["flags"] & 2) + 1) & 0xFFFFFFFF
    seen: dict[int, int] = {}
    for packet in selected:
        if packet["flags"] & 4:
            continue
        offset = (packet["sequence"] + bool(packet["flags"] & 2) - base) & 0xFFFFFFFF
        end = offset + len(bytes.fromhex(packet["payload_hex"]))
        for index in range(max(start, offset), min(start + size, end)):
            seen[index] = min(
                seen.get(index, packet["timestamp_us"]), packet["timestamp_us"]
            )
    require(len(seen) == size, "Missing timed folder span bytes")
    return max(seen.values())


def upload_clock(name: str, report: dict, plan: dict, guest: list[dict]) -> dict:
    late = name == "folder-upload-late-attachment"
    pauses(report, plan, 125 if late else 130)
    ack = next(f for f in report["frames"] if f["is_reply"] and f["id"] == 10)
    values = fields(ack)
    require(
        set(values) == {107}
        and len(values[107]) == 4
        and not int.from_bytes(values[107], "big") & 1,
        "Timed upload reference differs",
    )
    sent = bytes.fromhex(report["streams"]["folder"]["sent_hex"])
    require(
        sent[:16] == b"HTXF" + values[107] + bytes(4) + b"\0\1\0\0",
        "Timed upload HTXF differs",
    )
    created = frame_time(report, ack, guest)
    packets, client, server = flow(report, "folder", guest)
    closes = [p for p in direction(packets, server, client) if p["flags"] & 5]
    require(bool(closes), "Missing native timed-folder close")
    age = (closes[0]["timestamp_us"] - created) / 1e6
    require(115 <= age <= 165, "Timed folder close outside bounded host window")
    received = bytes.fromhex(report["streams"]["folder"]["received_hex"])
    require(received == (b"" if late else b"\0\3\0\3"), "Timed-folder output differs")
    result = {
        "close_after_request_ack_host_seconds": age,
        "measured_pause_seconds": 125 if late else 130,
    }
    if not late:
        parsed = upload(sent, received)
        require(
            parsed["completed"] == 1
            and len(parsed["items"]) == 1
            and parsed["items"][0]["path"] == (b"wait",)
            and parsed["items"][0]["directory"],
            "Timed directory exchange differs",
        )
        directory_reply = span_time(report, guest, 2, 2)
        since_directory = (closes[0]["timestamp_us"] - directory_reply) / 1e6
        require(
            0 <= since_directory < 90,
            "Descriptor exchange may have reset a full connected timer",
        )
        result["close_after_directory_reply_host_seconds"] = since_directory
    else:
        require(len(sent) == 16, "Late attachment sent folder item bytes")
    return result


def download_clock(report: dict, plan: dict, guest: list[dict]) -> dict:
    pauses(report, plan, 130)
    first_descriptor = span_time(report, guest, 0, 14)
    first_length = span_time(report, guest, 14, 4)
    age = (first_length - first_descriptor) / 1e6
    require(125 <= age <= 175, "Delayed folder choice outside bounded host window")
    return {
        "first_file_length_after_descriptor_host_seconds": age,
        "measured_pause_seconds": 130,
    }
