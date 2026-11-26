#!/usr/bin/env python3
"""Reconcile A8 phase-1 application streams in saved host and guest PCAPs."""

import argparse
import datetime
import json
import sys
from pathlib import Path

BATCH = Path(__file__).resolve().parent
MOTHRA = BATCH.parents[3]
sys.path.insert(0, str(MOTHRA.parent / "hotline-protocol-docs" / "scripts"))

from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import verify_capture
from verify_native_diagnostic_existing import semantic


def check_case(case: str, baseline: dict) -> dict:
    """Verify one capture, compare its semantic result with the saved one and check its packet views."""
    report = verify_capture(BATCH / case)
    report["_plan_path"] = BATCH / case / "plan.json"
    checked = semantic(case, report, baseline)
    if checked["status"] != "verified":
        raise ValueError(f"{case} semantic witness incomplete")
    saved_name = (
        "verification-one-active-one-queued-corrected.json"
        if case == "one-active-one-queued"
        else "verification-postflight.json"
    )
    if checked != json.loads((BATCH / saved_name).read_text()):
        raise ValueError(f"{case} semantic result differs from saved verification")
    start_us = int(
        datetime.datetime.fromisoformat(report["started_at_utc"]).timestamp()
        * 1_000_000
    )
    names = (
        f"host-{case}.pcap",
        f"guest-after-{case}.pcap",
    )
    result = {}
    for filename in names:
        host = filename.startswith("host-")
        client = "127.0.0.1" if host else "10.0.2.2"
        server = "127.0.0.1" if host else "10.0.2.15"
        base = 15500 if host else 5500
        packets = read_packets(BATCH / filename)
        connections = {}
        for event in (e for e in report["events"] if e["event"] == "connect"):
            connection = event["connection"]
            local_port = event["local_address"][1]
            destination_port = base + (connection != "a")
            selected = lifetime(
                packets,
                (client, local_port),
                (server, destination_port),
                start_us + event["elapsed_ns"] // 1000,
            )
            sent = stream(selected, (client, local_port), (server, destination_port))
            received = stream(
                selected, (server, destination_port), (client, local_port)
            )
            recorder = report["streams"][connection]
            if sent.hex() != recorder["sent_hex"]:
                raise ValueError(f"{filename} {connection} sent stream differs")
            if received.hex() != recorder["received_hex"]:
                raise ValueError(f"{filename} {connection} received stream differs")
            terminals = [
                {
                    "packet": packet["index"],
                    "from_server": packet["src_port"] == destination_port,
                    "flags": packet["flags"],
                    "payload_hex": packet["payload_hex"],
                }
                for packet in selected
                if packet["flags"] & 5
            ]
            connections[connection] = {
                "packets": len(selected),
                "local_port": local_port,
                "client_to_server_bytes": len(sent),
                "server_to_client_bytes": len(received),
                "unread_payload_tail_bytes": 0,
                "terminal_packets": terminals,
            }
        result[filename] = connections
    if case == "one-active-one-queued":
        expected = {"a": (342, 1371), "active": (16, 65536)}
        guest_terminals = result[names[1]]["active"]["terminal_packets"]
        if not any(
            item["from_server"]
            and item["flags"] & 4
            and item["payload_hex"] == b"No TCP".hex()
            for item in guest_terminals
        ):
            raise ValueError("Missing raw guest No TCP terminal diagnostic")
    else:
        expected = {"a": (231, 2759)}
    for view in result.values():
        for connection, sizes in expected.items():
            observed = view[connection]
            if (
                observed["client_to_server_bytes"],
                observed["server_to_client_bytes"],
            ) != sizes:
                raise ValueError(f"{case} stream sizes differ")
    return result


def main() -> None:
    """Verify both captures against the preflight baseline; write the result to --output when given, and print only its status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    baseline = verify_capture(
        MOTHRA
        / "evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/capture"
    )
    result = {
        "status": "verified",
        "method": "SYN-lifetime TCP reassembly; RST diagnostic payload excluded from application streams",
        "one-active-one-queued": check_case("one-active-one-queued", baseline),
        "postflight": check_case("postflight", baseline),
    }
    if arguments.output:
        if arguments.output.exists():
            raise SystemExit(f"Refusing existing output: {arguments.output}")
        arguments.output.write_text(json.dumps(result, indent=2) + "\n")
    print("A8 phase-1 host/guest streams: verified")


if __name__ == "__main__":
    main()
