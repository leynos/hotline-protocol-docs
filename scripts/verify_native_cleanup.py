#!/usr/bin/env python3
"""Verify download cancellation races without treating ACK as receive rollback."""

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path

from native_cleanup_cases import FILENAME, data_fork, downloads, seed, upload_cleanup
from native_filp import decode
from native_packet_evidence import reconcile
from native_transfer_cases import file_stream, resource_fork
from pcap_tcp import direction, lifetime, read_packets, stream
from protocol_capture import decode_frame, verify_capture
from verify_native_core import require
from verify_native_forks import check_file_info, check_metadata, fields
from verify_native_framing import check_quiet
from verify_native_queues import frame_time


def reply(report: dict, owner: str, identifier: int) -> dict:
    selected = [
        f
        for f in report["frames"]
        if f["connection"] == owner and f["is_reply"] == 1 and f["id"] == identifier
    ]
    require(len(selected) == 1, "Missing or duplicate cleanup reply")
    fields(selected[0])
    return selected[0]


def flow(
    report: dict, connection: str, guest: list[dict]
) -> tuple[list[dict], tuple, tuple]:
    event = next(
        e
        for e in report["events"]
        if e["event"] == "connect" and e["connection"] == connection
    )
    source = ("10.0.2.2", event["local_address"][1])
    endpoint = ("10.0.2.15", 5500 + event["peer_address"][1] - 15500)
    when = int(
        datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1e6
        + event["elapsed_ns"] / 1000
    )
    return lifetime(guest, source, endpoint, when), source, endpoint


def request_time(report: dict, response: dict, guest: list[dict]) -> int:
    """Observe complete incoming214 bytes, not the internal handler instant."""
    action = response["action"] - 1
    wire = bytes.fromhex(
        "".join(
            e["hex"]
            for e in report["events"]
            if e["action"] == action and e["event"] == "send"
        )
    )
    require(
        len(wire) == 30 and int.from_bytes(wire[2:4], "big") == 214,
        "Unexpected cleanup request bytes",
    )
    packets, source, endpoint = flow(report, response["connection"], guest)
    raw = stream(packets, source, endpoint)
    require(raw.count(wire) == 1, "Cleanup request not unique")
    start = raw.index(wire)
    selected = direction(packets, source, endpoint)
    base = (next(p["sequence"] for p in selected if p["flags"] & 2) + 1) & 0xFFFFFFFF
    seen: dict[int, int] = {}
    for packet in selected:
        if packet["flags"] & 4:
            continue
        offset = (packet["sequence"] + bool(packet["flags"] & 2) - base) & 0xFFFFFFFF
        count = len(bytes.fromhex(packet["payload_hex"]))
        for index in range(max(start, offset), min(start + len(wire), offset + count)):
            seen[index] = min(
                seen.get(index, packet["timestamp_us"]), packet["timestamp_us"]
            )
    require(len(seen) == len(wire), "Missing timed cleanup request bytes")
    return max(seen.values())


def bytes_after(
    packets: list[dict], source: tuple, endpoint: tuple, total: int, cutoff: int
) -> int:
    """Count bytes first observed after cutoff without double-counting retries."""
    selected = direction(packets, source, endpoint)
    base = (next(p["sequence"] for p in selected if p["flags"] & 2) + 1) & 0xFFFFFFFF
    before = []
    for packet in selected:
        if packet["flags"] & 4 or packet["timestamp_us"] > cutoff:
            continue
        start = (packet["sequence"] + bool(packet["flags"] & 2) - base) & 0xFFFFFFFF
        end = min(total, start + len(bytes.fromhex(packet["payload_hex"])))
        if start < end:
            before.append((start, end))
    covered, end = 0, 0
    for start, stop in sorted(before):
        covered += max(0, stop - max(start, end))
        end = max(end, stop)
    return total - covered


def check_download(
    report: dict, expectation: dict, baseline: bytes, packets: dict, guest: list[dict]
) -> dict:
    variant = expectation["variant"]
    values = fields(reply(report, "a", 10))
    reference = values[107]
    require(
        len(reference) == 4 and int.from_bytes(reference, "big") & 1 != 0,
        "Cleanup download reference parity differs",
    )
    require(
        int.from_bytes(values[108], "big") == len(baseline),
        "Cleanup advertised size differs",
    )
    require(
        int.from_bytes(values[207], "big") == len(data_fork()) + len(resource_fork()),
        "Cleanup logical size differs",
    )
    recorded = report["streams"]["reference"]
    require(
        bytes.fromhex(recorded["sent_hex"]) == b"HTXF" + reference + bytes(8),
        "Cleanup HTXF differs",
    )
    received = bytes.fromhex(recorded["received_hex"])
    require(baseline.startswith(received), "Cancelled data is not a baseline prefix")
    if variant in {"baseline", "nonowner"}:
        require(received == baseline, "Full/nonowner download was truncated")
        require(
            any(
                e["event"] == "quiet" and e["connection"] == "reference"
                for e in report["events"]
            ),
            "Missing completed/nonowner open-connection observation",
        )
    else:
        require(
            expectation["prefix_size"] <= len(received) < len(baseline),
            "Race did not establish bounded partial delivery",
        )
    response = reply(report, "a", 21)
    require(
        response["payload_hex"] == "0000"
        and reply(report, "a", 22)["payload_hex"] == "0000",
        "Owner/duplicate cleanup ACK differs",
    )
    require(
        packets["reference"]["guest_server_initiated_close"],
        "Missing native cleanup close",
    )
    require(
        report["streams"]["stale"]["received_hex"] == ""
        and packets["stale"]["guest_server_initiated_close"],
        "Removed reference reattached successfully",
    )
    require(
        bytes.fromhex(report["streams"]["stale"]["sent_hex"])
        == b"HTXF" + reference + bytes(8),
        "Stale-reference header differs",
    )
    after = sum(
        len(bytes.fromhex(e["hex"]))
        for e in report["events"]
        if e["connection"] == "reference"
        and e["event"] == "receive"
        and e["action"] > response["action"]
    )
    before = len(received) - after
    require(
        before
        == (
            len(baseline)
            if variant in {"baseline", "nonowner"}
            else expectation["prefix_size"]
        ),
        "Application receive/cancel ordering differs",
    )
    data_packets, client, server = flow(report, "reference", guest)
    ack_time = frame_time(report, response, guest)
    observed_request = request_time(report, response, guest)
    outgoing = direction(data_packets, server, client)
    closes = [p for p in outgoing if p["flags"] & 5]
    require(bool(closes), "Missing native close packet")
    result = {
        "received_stream_bytes": len(received),
        "application_bytes_read_after_owner_ack": after,
        "guest_bytes_first_observed_after_owner_request": bytes_after(
            data_packets, server, client, len(received), observed_request
        ),
        "guest_bytes_first_observed_after_owner_ack": bytes_after(
            data_packets, server, client, len(received), ack_time
        ),
        "guest_close_minus_owner_ack_us": closes[0]["timestamp_us"] - ack_time,
    }
    if variant == "nonowner":
        other = reply(report, "b", 20)
        require(other["payload_hex"] == "0000", "Nonowner cleanup ACK differs")
        result["guest_bytes_first_observed_after_nonowner_ack"] = bytes_after(
            data_packets,
            server,
            client,
            len(received),
            frame_time(report, other, guest),
        )
        require(
            result["guest_bytes_first_observed_after_nonowner_ack"] > 0,
            "Nonowner case did not overlap native data delivery",
        )
    return result


def check_upload(report: dict, expectation: dict, packets: dict) -> dict:
    small = expectation["kind"] == "cleanup-upload"
    filename = bytes.fromhex(expectation["name_hex"]) if small else FILENAME
    data = b"data-fork\r\n\x00\xff" if small else data_fork()
    values = fields(reply(report, "a", 10))
    reference = values[107]
    require(
        len(reference) == 4 and not int.from_bytes(reference, "big") & 1,
        "Cleanup upload reference differs",
    )
    body = file_stream(data, resource_fork())
    require(
        bytes.fromhex(report["streams"]["upload"]["sent_hex"])
        == b"HTXF" + reference + len(body).to_bytes(4, "big") + bytes(4) + body,
        "Cleanup upload body differs",
    )
    require(
        not report["streams"]["upload"]["received_hex"]
        and packets["upload"]["guest_server_initiated_close"],
        "Cleanup upload completion differs",
    )
    check_file_info(
        reply(report, "a", 12 if small else 11),
        filename,
        len(data) + len(resource_fork()),
    )
    if small:
        require(
            reply(report, "a", 11)["payload_hex"] == "0000"
            and reply(report, "a", 13)["payload_hex"] == "0000",
            "Upload214 ACK differs",
        )
    return {"uploaded_data_bytes": len(data), "pending_upload_survived214": small}


def verify(directory: Path) -> dict:
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    expected = seed() | downloads() | upload_cleanup()
    require(
        {p.name for p in (directory / "transcripts").iterdir()} == set(expected),
        "Cleanup corpus inventory differs",
    )
    source_hashes = {
        hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (directory / "sources").glob("protocol_capture*.txt")
    }
    baseline_report = verify_capture(directory / "transcripts/cleanup-baseline")
    baseline = bytes.fromhex(baseline_report["streams"]["reference"]["received_hex"])
    forks = decode(baseline)
    require(
        forks["DATA"] == data_fork() and forks["MACR"] == resource_fork(),
        "Native baseline fork bytes differ",
    )
    check_metadata(forks["INFO"], FILENAME, False)
    unread = json.loads((directory / "unread-output.json").read_text())
    require(
        set(unread) == {"cleanup-nonowner"}
        and set(unread["cleanup-nonowner"]) == {"a"},
        "Unread cleanup inventory differs",
    )
    suffix = bytes.fromhex(unread["cleanup-nonowner"]["a"])
    departure = decode_frame(suffix)
    require(
        len(suffix) == 28 and departure["type"] == 302 and departure["is_reply"] == 0,
        "Unread departure differs",
    )
    observations: list[dict] = []
    for name, (steps, expectation) in expected.items():
        case = directory / "transcripts" / name
        plan = json.loads((case / "plan.json").read_text())
        report = verify_capture(case)
        require(report["status"] == "completed", "Cleanup capture failed")
        require(
            report["driver_sha256"] in source_hashes, "Missing cleanup capture source"
        )
        require(
            plan["steps"] == steps and plan["expectation"] == expectation,
            "Cleanup plan differs",
        )
        packets = reconcile(
            report,
            host,
            guest,
            {k: bytes.fromhex(v) for k, v in unread.get(name, {}).items()},
        )
        check_quiet(report, plan)
        for owner in {f["connection"] for f in report["frames"]}:
            requests = [
                int.from_bytes(bytes.fromhex(s["hex"][:40])[4:8], "big")
                for s in steps
                if s["op"] == "send"
                and s["connection"] == owner
                and len(s["hex"]) >= 40
            ]
            replies = [
                f["id"]
                for f in report["frames"]
                if f["connection"] == owner and f["is_reply"]
            ]
            require(
                sorted(requests) == sorted(replies),
                "Cleanup request/reply inventory differs",
            )
        outcome = (
            check_download(report, expectation, baseline, packets, guest)
            if expectation["kind"] == "cleanup-download"
            else check_upload(report, expectation, packets)
        )
        observations.append({"case": name, "connections": packets, **outcome})
    require(
        any(
            c.get("guest_bytes_first_observed_after_owner_request", 0) > 0
            and c["received_stream_bytes"] < len(baseline)
            for c in observations
        ),
        "No observed in-progress cancellation race",
    )
    require(
        any(
            c.get("application_bytes_read_after_owner_ack", 0) > 0 for c in observations
        ),
        "No observed buffered receive after cleanup ACK",
    )
    for name, data in [
        (FILENAME.decode(), data_fork()),
        ("mothra-214-upload", b"data-fork\r\n\x00\xff"),
    ]:
        require(
            (directory / "native-files" / (name + ".data")).read_bytes() == data,
            "Native cleanup DATA differs",
        )
        require(
            (directory / "native-files" / (name + ".rsrc")).read_bytes()
            == resource_fork(),
            "Native cleanup MACR differs",
        )
    return {
        "cases": observations,
        "baseline_stream_bytes": len(baseline),
        "scope": "Ten finite ordinary-file cases; buffered-prefix and observed packet ordering, not a universal race byte count or cancellation deadline",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == "__main__":
    main()
