#!/usr/bin/env python3
"""Verify A9 native 303 density, restoration and scoped host/guest TCP views."""

import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path

BATCH = Path(__file__).resolve().parent
MOTHRA = BATCH.parents[3]
sys.path.insert(0, str(MOTHRA.parent / "hotline-protocol-docs" / "scripts"))

from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import verify_capture
from verify_native_diagnostic_existing import semantic

A7 = (
    MOTHRA
    / "evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/capture"
)


def sha256(data: bytes) -> str:
    """Return the SHA-256 hex digest of the bytes."""
    return hashlib.sha256(data).hexdigest()


def saved_semantic(case: str, baseline: dict) -> tuple[dict, dict]:
    """Verify a saved capture and require its semantic result to equal the saved verification."""
    report = verify_capture(BATCH / case)
    report["_plan_path"] = BATCH / case / "plan.json"
    checked = semantic(case, report, baseline)
    if checked["status"] != "verified":
        raise ValueError(f"{case} semantic witness incomplete")
    saved = json.loads((BATCH / f"verification-{case}.json").read_text())
    if checked != saved:
        raise ValueError(f"{case} semantic result differs from saved verification")
    return report, checked


def packet_views(case: str, report: dict) -> dict:
    """Reassemble each connection of the host and guest packet captures for a case."""
    start_us = int(
        datetime.datetime.fromisoformat(report["started_at_utc"]).timestamp()
        * 1_000_000
    )
    result = {}
    for filename, client, server, base in [
        (f"host-{case}.pcap", "127.0.0.1", "127.0.0.1", 15500),
        (f"guest-after-{case}.pcap", "10.0.2.2", "10.0.2.15", 5500),
    ]:
        packets = read_packets(BATCH / filename)
        connections = {}
        for event in (e for e in report["events"] if e["event"] == "connect"):
            name = event["connection"]
            port = event["local_address"][1]
            destination = base + (name != "a")
            selected = lifetime(
                packets,
                (client, port),
                (server, destination),
                start_us + event["elapsed_ns"] // 1000,
            )
            sent = stream(selected, (client, port), (server, destination))
            received = stream(selected, (server, destination), (client, port))
            recorder_sent = bytes.fromhex(report["streams"][name]["sent_hex"])
            recorder_received = bytes.fromhex(report["streams"][name]["received_hex"])
            if sent != recorder_sent or not received.startswith(recorder_received):
                raise ValueError(f"{filename} {name} recorder/payload mismatch")
            terminal = [
                {
                    "packet": packet["index"],
                    "from_server": packet["src_port"] == destination,
                    "flags": packet["flags"],
                    "payload_hex": packet["payload_hex"],
                }
                for packet in selected
                if packet["flags"] & 5
            ]
            for packet in terminal:
                if (
                    packet["flags"] & 4
                    and packet["payload_hex"]
                    and bytes.fromhex(packet["payload_hex"])
                    not in {b"No TCP", b"tcp_disconnect"}
                ):
                    raise ValueError("Unrecognised non-application RST diagnostic")
            tail = received[len(recorder_received) :]
            connections[name] = {
                "local_port": port,
                "packets": len(selected),
                "sent_bytes": len(sent),
                "received_bytes": len(received),
                "recorder_received_bytes": len(recorder_received),
                "unread_tail_bytes": len(tail),
                "unread_tail_sha256": sha256(tail),
                "terminal_packets": terminal,
            }
            connections[name]["_sent"] = sent
            connections[name]["_received"] = received
        result[filename] = connections
    return result


def check_density(report: dict, checked: dict, views: dict, full: bytes) -> dict:
    """Check the density case's references, queue positions, text lengths and per-connection streams."""
    if len(checked["references"]) != 16 or checked["waiting_positions"] != list(
        range(1, 9)
    ):
        raise ValueError("Density references or queue positions differ")
    lengths = [
        checked["witnesses"][key]["field101_bytes"] for key in ("35", "60", "61", "90")
    ]
    if lengths != [417, 647, 763, 303]:
        raise ValueError("Native density text lengths differ")
    host = views["host-density.pcap"]
    guest = views["guest-after-density.pcap"]
    if set(host) != {"a", *(f"active{i}" for i in range(8))} or set(guest) != set(host):
        raise ValueError("Density data socket set differs")
    for view in (host, guest):
        control = view["a"]
        if (
            control["_sent"].hex() != report["streams"]["a"]["sent_hex"]
            or control["_received"].hex() != report["streams"]["a"]["received_hex"]
        ):
            raise ValueError("Density control stream differs")
    for index in range(8):
        name = f"active{index}"
        reference = bytes.fromhex(checked["references"][index])
        expected_header = b"HTXF" + reference + bytes(8)
        left, right = host[name], guest[name]
        if left["_sent"] != expected_header or right["_sent"] != expected_header:
            raise ValueError(f"{name} HTXF reference differs")
        if left["recorder_received_bytes"] or right["recorder_received_bytes"]:
            raise ValueError(f"{name} Recorder unexpectedly drained data")
        if not (
            0 < len(left["_received"]) <= len(right["_received"]) < len(full)
            and right["_received"].startswith(left["_received"])
            and full.startswith(right["_received"])
        ):
            raise ValueError(f"{name} host/guest/full FILP prefixes differ")
    return {
        "field101_bytes_at_fixed_points": lengths,
        "maximum_field101_bytes": max(lengths),
        "source_destination_bound": 1024,
        "below_bound_by_bytes": 1024 - max(lengths),
        "boundary_reached": False,
        "complete_ordinary_stream_bytes": len(full),
    }


def check_postflight(report: dict, views: dict) -> None:
    """Check that the postflight packet captures hold only the control stream and that it matches the report."""
    for view in views.values():
        if set(view) != {"a"}:
            raise ValueError("Unexpected postflight data socket")
        control = view["a"]
        if (
            control["_sent"].hex() != report["streams"]["a"]["sent_hex"]
            or control["_received"].hex() != report["streams"]["a"]["received_hex"]
        ):
            raise ValueError("Postflight control stream differs")


def strip_streams(views: dict) -> dict:
    """Remove the private reassembled streams from the packet views."""
    return {
        filename: {
            connection: {
                key: value for key, value in details.items() if not key.startswith("_")
            }
            for connection, details in sockets.items()
        }
        for filename, sockets in views.items()
    }


def main() -> None:
    """Verify the density corpus against the A7 baseline; write the result to --output when given, and print only its status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    baseline = verify_capture(A7)
    full = bytes.fromhex(baseline["streams"]["download"]["received_hex"])
    if len(full) != 1_049_073 or not full.startswith(b"FILP\0\1"):
        raise ValueError("A7 full FILP baseline differs")
    density, witness = saved_semantic("density", baseline)
    postflight, _ = saved_semantic("postflight", baseline)
    density_views = packet_views("density", density)
    postflight_views = packet_views("postflight", postflight)
    observation = check_density(density, witness, density_views, full)
    check_postflight(postflight, postflight_views)
    result = {
        "status": "verified",
        "method": "SYN-lifetime reassembly; RST diagnostic payload excluded from application streams",
        "density": observation,
        "density_packet_views": strip_streams(density_views),
        "postflight_packet_views": strip_streams(postflight_views),
    }
    if arguments.output:
        if arguments.output.exists():
            raise SystemExit(f"Refusing existing output: {arguments.output}")
        arguments.output.write_text(json.dumps(result, indent=2) + "\n")
    print("A9 density semantics and paired TCP prefixes: verified")


if __name__ == "__main__":
    main()
