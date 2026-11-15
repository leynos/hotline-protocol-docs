#!/usr/bin/env python3
"""Verify controlled native queue positions, ownership, modes and expiry."""

import argparse
import hashlib
import json
import struct
from datetime import datetime
from pathlib import Path

from native_filp import decode
from native_packet_evidence import reconcile
from native_queue_cases import queues, timer
from native_transfer_cases import resource_fork
from pcap_tcp import direction, lifetime, read_packets, stream
from protocol_capture import decode_frame, verify_capture
from verify_native_core import require
from verify_native_forks import check_metadata, fields
from verify_native_framing import check_quiet


def reply(report: dict, owner: str, identifier: int) -> dict:
    selected = [
        f
        for f in report["frames"]
        if f["connection"] == owner and f["is_reply"] == 1 and f["id"] == identifier
    ]
    require(len(selected) == 1, "Missing or duplicate queue reply")
    fields(selected[0])
    return selected[0]


def frame_time(report: dict, frame: dict, guest: list[dict]) -> int:
    """Return complete-frame first observation in guest PCAP host UTC units."""
    event = next(
        e
        for e in report["events"]
        if e["event"] == "connect" and e["connection"] == frame["connection"]
    )
    client = ("10.0.2.2", event["local_address"][1])
    server = ("10.0.2.15", 5500)
    when = int(
        datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1e6
        + event["elapsed_ns"] / 1000
    )
    packets = lifetime(guest, client, server, when)
    data = struct.pack(
        ">BBHIIII",
        frame["flags"],
        frame["is_reply"],
        frame["type"],
        frame["id"],
        frame["error"],
        frame["total_size"],
        frame["data_size"],
    ) + bytes.fromhex(frame["payload_hex"])
    require(len(data) <= 4096, "Control timing frame exceeds analysis bound")
    raw = stream(packets, server, client)
    require(raw.count(data) == 1, "Control timing frame is not unique")
    start = raw.index(data)
    selected = direction(packets, server, client)
    base = (next(p["sequence"] for p in selected if p["flags"] & 2) + 1) & 0xFFFFFFFF
    seen: dict[int, int] = {}
    for packet in selected:
        if packet["flags"] & 4:
            continue
        offset = (packet["sequence"] + bool(packet["flags"] & 2) - base) & 0xFFFFFFFF
        count = len(bytes.fromhex(packet["payload_hex"]))
        for index in range(max(start, offset), min(start + len(data), offset + count)):
            seen[index] = min(
                seen.get(index, packet["timestamp_us"]), packet["timestamp_us"]
            )
    require(len(seen) == len(data), "Missing timed frame bytes")
    return max(seen.values())


def references(report: dict, plan: dict) -> dict:
    result = {}
    for action, step in enumerate(plan["steps"]):
        saves = step.get("save_fields", {})
        names = [name for name, field in saves.items() if field == 107]
        if not names:
            continue
        require(len(names) == 1, "Ambiguous saved queue reference")
        frame = next(f for f in reversed(report["frames"]) if f["action"] == action)
        values = fields(frame)
        reference = values[107]
        require(
            len(reference) == 4 and int.from_bytes(reference, "big") & 1 != 0,
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


def notices(report: dict, refs: dict) -> dict[str, list[dict]]:
    by_reference = {r["reference"]: name for name, r in refs.items()}
    result: dict[str, list[dict]] = {name: [] for name in refs}
    for frame in report["frames"]:
        if frame["type"] != 211:
            continue
        require(
            frame["is_reply"] == 0 and frame["error"] == 0,
            "Queue notification envelope differs",
        )
        values = {f["id"]: f["hex"] for f in frame["fields"]}
        require(
            set(values) == {107, 116} and len(frame["fields"]) == 2,
            "Queue notification field set differs",
        )
        require(
            len(bytes.fromhex(values[107])) == 4,
            "Queue notification reference width differs",
        )
        require(values[107] in by_reference, "Queue notification has unknown reference")
        name = by_reference[values[107]]
        require(
            frame["connection"] == refs[name]["frame"]["connection"],
            "Queue notice went to a different owner",
        )
        result[name].append({"position": int(values[116], 16), "frame": frame})
    return result


def check_download(
    report: dict, refs: dict, name: str, *, preview: bool = False, empty: bool = False
) -> None:
    recorded = report["streams"][name]
    require(
        bytes.fromhex(recorded["sent_hex"])
        == b"HTXF" + bytes.fromhex(refs[name]["reference"]) + bytes(8),
        "Queued HTXF differs",
    )
    received = bytes.fromhex(recorded["received_hex"])
    require(
        len(received) == int.from_bytes(refs[name]["values"][108], "big"),
        "Queued delivery count differs",
    )
    data = b"" if empty else b"data-fork\r\n\x00\xff"
    if preview:
        require(received == data, "Queued preview is not raw DATA")
    else:
        forks = decode(received)
        require(
            forks["DATA"] == data
            and forks["MACR"] == (b"" if empty else resource_fork()),
            "Queued fork bytes differ",
        )
        check_metadata(
            forks["INFO"],
            b"mothra-empty-fixture" if empty else b"mothra-fork-fixture",
            False,
        )


def check_case(
    name: str, report: dict, plan: dict, packets: dict, guest: list[dict]
) -> dict:
    refs = references(report, plan)
    notes = notices(report, refs)
    timing = {}
    if name == "queue-mode-matrix":
        expected_initial = {"blocker": None, **{f"m{i}": i - 10 for i in range(11, 17)}}
        expected_notes = {
            "blocker": [],
            **{f"m{i}": list(range(i - 11, -1, -1)) for i in range(11, 17)},
        }
        zero = fields(reply(report, "a", 17))
        require(
            set(zero) == {108} and zero[108] == b"\0\0",
            "Empty preview queued or allocated reference",
        )
        for index in range(11, 17):
            values = refs[f"m{index}"]["values"]
            require(
                int.from_bytes(values[108], "big")
                == (13 if index == 15 else 181 if index == 16 else 510),
                "Mode transfer size differs",
            )
            require(
                int.from_bytes(values[207], "big") == (0 if index == 16 else 330),
                "Mode logical size differs",
            )
            check_download(
                report, refs, f"m{index}", preview=index == 15, empty=index == 16
            )
    elif name == "queue-cancel-position":
        expected_initial = {"a1": None, "a2": 1, "a3": 2, "a4": 3}
        expected_notes = {"a1": [], "a2": [], "a3": [], "a4": [2, 1, 0]}
        require(
            not report["streams"]["a3"]["received_hex"],
            "Cancelled queued transfer delivered data",
        )
        require(
            packets["a3"]["guest_server_initiated_close"],
            "Queued cancellation did not close native data transport",
        )
        check_download(report, refs, "a4")
    elif name == "queue-two-owner-order":
        expected_initial = {"a1": None, "a2": 1, "a3": 2, "b1": None, "b2": 3}
        expected_notes = {"a1": [], "a2": [0], "a3": [1, 0], "b1": [], "b2": [0]}
        require(
            frame_time(report, notes["b2"][0]["frame"], guest)
            < frame_time(report, notes["a2"][0]["frame"], guest),
            "Eligible later owner did not advance first",
        )
        check_download(report, refs, "b2")
        check_download(report, refs, "a3")
        denied = reply(report, "b", 26)
        quiet = [
            e
            for e in report["events"]
            if e["event"] == "quiet" and e["connection"] == "a3"
        ]
        require(
            len(quiet) == 2 and any(e["action"] > denied["action"] for e in quiet),
            "No queued-data silence after nonowner214",
        )
        for identifier in [30, 31, 32, 33]:
            require(
                reply(report, "a", identifier)["payload_hex"] == "0000",
                "Duplicate/absent/zero/unknown cleanup ACK differs",
            )
    elif name == "queue-pending-timeout":
        expected_initial = {"expired": None, "waiting": 1}
        expected_notes = {"expired": [], "waiting": [0]}
        require(
            not report["streams"]["expired"]["received_hex"]
            and packets["expired"]["guest_server_initiated_close"],
            "Expired reference still delivered data",
        )
        check_download(report, refs, "waiting")
        pauses = [e for e in report["events"] if e["event"] == "pause"]
        require(len(pauses) == 12, "Missing timed queue observation windows")
        for event in pauses:
            prior = [e for e in report["events"] if e["action"] < event["action"]][-1]
            require(
                event["elapsed_ns"] - prior["elapsed_ns"] >= 45e9,
                "Shortened timed queue window",
            )
        admission_us = frame_time(report, notes["waiting"][0]["frame"], guest)
        created_us = frame_time(report, refs["expired"]["frame"], guest)
        age = (admission_us - created_us) / 1e6
        require(490 <= age <= 570, "Pending timeout outside bounded observation")
        timing = {
            "admission_after_initial_ack_host_seconds": age,
            "scope": "Host observer timing; no exact Mac-clock deadline claimed",
        }
    else:
        raise ValueError("Unknown queue case")
    for ref_name, position in expected_initial.items():
        values = refs[ref_name]["values"]
        require(
            (116 in values) == (position is not None),
            "Initial queue-position presence differs",
        )
        if position is not None:
            require(
                int.from_bytes(values[116], "big") == position,
                "Initial queue position differs",
            )
    require(
        {key: [n["position"] for n in ns] for key, ns in notes.items()}
        == expected_notes,
        "Queue notification sequence differs",
    )
    for frame in report["frames"]:
        if frame["is_reply"]:
            require(frame["error"] == 0, "Unexpected error reply")
    for owner in {f["connection"] for f in report["frames"]}:
        requests = [
            int.from_bytes(bytes.fromhex(step["hex"][:40])[4:8], "big")
            for step in plan["steps"]
            if step["op"] == "send"
            and step["connection"] == owner
            and len(step["hex"]) >= 40
        ]
        replies = [
            f["id"]
            for f in report["frames"]
            if f["connection"] == owner and f["is_reply"]
        ]
        require(
            sorted(requests) == sorted(replies), "Queue request/reply inventory differs"
        )
    return {
        "initial_positions": expected_initial,
        "notification_positions": expected_notes,
        **timing,
    }


def verify(directory: Path) -> dict:
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    expected = queues() | timer()
    require(
        {p.name for p in (directory / "transcripts").iterdir()} == set(expected),
        "Queue corpus inventory differs",
    )
    source_hashes = {
        hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (directory / "sources").glob("protocol_capture*.txt")
    }
    unread = json.loads((directory / "unread-output.json").read_text())
    observations = []
    for name, (steps, expectation) in expected.items():
        case = directory / "transcripts" / name
        report = verify_capture(case)
        plan = json.loads((case / "plan.json").read_text())
        require(report["status"] == "completed", "Queue capture failed")
        require(
            report["driver_sha256"] in source_hashes, "Missing queue capture source"
        )
        require(
            plan["steps"] == steps and plan["expectation"] == expectation,
            "Queue plan differs",
        )
        config = plan["environment"]["queue_test_configuration"]
        require(
            config["global_max_downloads"] == 2
            and config["per_client_max_downloads"] == 1,
            "Queue fixture configuration differs",
        )
        suffixes = {
            owner: bytes.fromhex(value) for owner, value in unread.get(name, {}).items()
        }
        for owner, suffix in suffixes.items():
            require(owner in {"a", "b"}, "Unread transfer data is not permitted")
            while suffix:
                require(len(suffix) >= 20, "Short unread notification")
                size = 20 + int.from_bytes(suffix[16:20], "big")
                require(size <= len(suffix), "Truncated unread notification")
                frame = decode_frame(suffix[:size])
                require(
                    frame["type"] in {301, 302}
                    and frame["is_reply"] == 0
                    and frame["error"] == 0,
                    "Unexpected unread control message",
                )
                suffix = suffix[size:]
        packets = reconcile(report, host, guest, suffixes)
        check_quiet(report, plan)
        observations.append(
            {
                "case": name,
                "connections": packets,
                **check_case(name, report, plan, packets, guest),
            }
        )
    return {
        "cases": observations,
        "scope": "Controlled two-global/one-per-session queues, finite ordering and bounded timeout observations; no universal FIFO or starvation guarantee",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == "__main__":
    main()
