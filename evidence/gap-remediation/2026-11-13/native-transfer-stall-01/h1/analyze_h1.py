#!/usr/bin/env python3
"""Offline falsification of C36 H1 using the frozen data socket lifetime."""

import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT.parent / "hotline-protocol-docs/scripts"))
from pcap_tcp import lifetime, read_packets, stream  # noqa: E402


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    out = Path(__file__).resolve().parent
    failed = ROOT / "state/native-sessions/native-banlab-c35"
    boot = ROOT / "state/native-sessions/native-banlab-boot-c34"
    report_path = failed / "a7-capture/report.json"
    report = json.loads(report_path.read_text())
    assert report["status"] == "failed" and report["completed_actions"] == 21
    assert report["error"] == "TimeoutError: timed out"
    connect = [
        event
        for event in report["events"]
        if event["event"] == "connect" and event["connection"] == "download"
    ]
    assert len(connect) == 1
    event = connect[0]
    assert event["peer_address"] == ["127.0.0.1", 15731]
    local_port = event["local_address"][1]
    connected_us = int(
        dt.datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1_000_000
    ) + event["elapsed_ns"] // 1000
    received = bytes.fromhex(report["streams"]["download"]["received_hex"])
    assert len(received) == 98304
    result = {
        "hypothesis": "H1: guest emitted application bytes beyond recorder prefix",
        "input_sha256": {
            "report": sha(report_path),
            "namespace_pcap": sha(boot / "lab-namespace.pcap"),
            "guest_pcap": sha(boot / "lab-guest.pcap"),
        },
        "report": {
            "status": report["status"],
            "completed_actions": report["completed_actions"],
            "error": report["error"],
            "connect_action": event["action"],
            "local_port": local_port,
            "connected_us": connected_us,
            "received_bytes": len(received),
            "received_sha256": hashlib.sha256(received).hexdigest(),
        },
        "views": {},
    }
    for label, path, client, server, server_port in (
        ("namespace", boot / "lab-namespace.pcap", "127.0.0.1", "127.0.0.1", 15731),
        ("guest", boot / "lab-guest.pcap", "10.0.2.2", "10.0.2.15", 5501),
    ):
        packets = read_packets(path)
        flow = lifetime(
            packets,
            (client, local_port),
            (server, server_port),
            connected_us,
        )
        sent = stream(flow, (client, local_port), (server, server_port))
        application = stream(flow, (server, server_port), (client, local_port))
        assert sent == bytes.fromhex(report["streams"]["download"]["sent_hex"])
        assert application[: len(received)] == received
        payload_packets = [
            p for p in flow
            if p["src_ip"] == server
            and p["src_port"] == server_port
            and p["payload_hex"]
            and not p["flags"] & 4
        ]
        terminals = [
            {
                "index": p["index"],
                "timestamp_us": p["timestamp_us"],
                "flags": p["flags"],
                "from_server": p["src_ip"] == server and p["src_port"] == server_port,
                "diagnostic_payload_hex": p["payload_hex"] if p["flags"] & 4 else "",
            }
            for p in flow if p["flags"] & 5
        ]
        result["views"][label] = {
            "flow": {"client": [client, local_port], "server": [server, server_port]},
            "packets": len(flow),
            "first_packet": [flow[0]["index"], flow[0]["timestamp_us"]],
            "last_packet": [flow[-1]["index"], flow[-1]["timestamp_us"]],
            "server_payload_packets": len(payload_packets),
            "raw_server_payload_bytes": sum(len(bytes.fromhex(packet["payload_hex"])) for packet in payload_packets),
            "retransmission_or_overlap_bytes": sum(len(bytes.fromhex(packet["payload_hex"])) for packet in payload_packets) - len(application),
            "first_server_payload": [payload_packets[0]["index"], payload_packets[0]["timestamp_us"]],
            "last_server_payload": [payload_packets[-1]["index"], payload_packets[-1]["timestamp_us"]],
            "client_application_bytes": len(sent),
            "server_application_bytes": len(application),
            "server_application_sha256": hashlib.sha256(application).hexdigest(),
            "matches_recorder_prefix": application[: len(received)] == received,
            "suffix_bytes_beyond_recorder": len(application) - len(received),
            "terminal_packets": terminals,
        }
    assert result["views"]["guest"]["server_application_bytes"] == len(received)
    assert result["views"]["namespace"]["server_application_bytes"] == len(received)
    result["verdict"] = "H1 falsified: no additional guest application payload in exact SYN lifetime"
    (out / "analysis.json").write_text(json.dumps(result, indent=2) + "\n")
    print(result["verdict"])


if __name__ == "__main__":
    main()
