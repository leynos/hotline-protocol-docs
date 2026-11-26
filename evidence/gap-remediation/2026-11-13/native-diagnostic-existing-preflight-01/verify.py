#!/usr/bin/env python3
"""Verify the single native existing-file preflight and its paired TCP views."""

import datetime
import hashlib
import json
import sys
from pathlib import Path

BATCH = Path(__file__).resolve().parent
MOTHRA = BATCH.parents[3]
sys.path.insert(0, str(MOTHRA.parent / "hotline-protocol-docs" / "scripts"))

from native_filp import decode, metadata
from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import verify_capture


def sha256(data: bytes) -> str:
    """Return the SHA-256 hex digest of the bytes."""
    return hashlib.sha256(data).hexdigest()


def frame(report: dict, identifier: int) -> dict:
    """Return the one successful reply frame with the given identifier."""
    matches = [
        f for f in report["frames"] if f["is_reply"] == 1 and f["id"] == identifier
    ]
    assert len(matches) == 1
    assert matches[0]["error"] == 0
    return matches[0]


def fields(value: dict) -> dict[int, bytes]:
    """Return a frame's fields as a map from identifier to bytes."""
    return {f["id"]: bytes.fromhex(f["hex"]) for f in value["fields"]}


def main() -> None:
    """Verify the preflight capture against the load baseline."""
    verify_capture(BATCH / "capture")
    report = json.loads((BATCH / "capture/report.json").read_text())
    baseline = json.loads(
        (
            MOTHRA
            / "evidence/gap-remediation/2026-11-13/native-diagnostic-load-01/preflight/report.json"
        ).read_text()
    )
    assert report["status"] == "completed" and report["completed_actions"] == 29
    assert frame(report, 10)["fields"] == frame(baseline, 10)["fields"]
    assert frame(report, 11)["fields"] == frame(baseline, 11)["fields"]
    assert len(frame(report, 11)["fields"]) == 41
    info = fields(frame(report, 12))
    name = b"mothra-race-fixture"
    assert {key: info[key] for key in (201, 205, 206, 207, 213)} == {
        201: name,
        205: b"Text File",
        206: b"MOTH",
        207: bytes.fromhex("0010013d"),
        213: b"TEXT",
    }
    roster = frame(report, 13)["fields"]
    assert len(roster) == 1 and roster[0]["id"] == 300
    uid = bytes.fromhex(roster[0]["hex"])[:2]
    for action in (15, 26):
        sent = [
            e["hex"]
            for e in report["events"]
            if e["action"] == action and e["event"] == "send"
        ]
        assert sent == [
            "0000012f000000"
            + ("0e" if action == 15 else "11")
            + "000000000000000800000008000100670002"
            + uid.hex()
        ]
    before, after = frame(report, 14), frame(report, 17)
    assert before["fields"] == after["fields"]
    assert [(f["id"], len(f["hex"]) // 2) for f in before["fields"]] == [
        (101, 303),
        (102, 15),
    ]
    assert fields(before)[102] == b"framing-fixture"
    ack = fields(frame(report, 15))
    assert ack[108] == (1049073).to_bytes(4, "big")
    assert ack[207] == (1048893).to_bytes(4, "big")
    assert len(ack[107]) == 4
    assert frame(report, 16)["fields"] == []
    transfer = bytes.fromhex(report["streams"]["download"]["received_hex"])
    assert len(transfer) == 1049073
    decoded = decode(transfer)
    old = MOTHRA / "evidence/gap-remediation/2026-11-12/native-cleanup-01/native-files"
    expected = {
        "DATA": old / "mothra-race-fixture.data",
        "MACR": old / "mothra-race-fixture.rsrc",
    }
    for tag, path in expected.items():
        assert decoded[tag] == path.read_bytes()
    meta = metadata(decoded["INFO"])
    assert (meta["type"], meta["creator"], meta["name"], meta["comment"]) == (
        b"TEXT",
        b"MOTH",
        name,
        b"fixture-comment",
    )
    started_us = int(
        datetime.datetime.fromisoformat(report["started_at_utc"]).timestamp()
        * 1_000_000
    )
    packet_views = {}
    for filename, client, server, control_port, data_port in [
        ("host.pcap", "127.0.0.1", "127.0.0.1", 15500, 15501),
        ("guest-cumulative.pcap", "10.0.2.2", "10.0.2.15", 5500, 5501),
    ]:
        packets = read_packets(BATCH / filename)
        packet_views[filename] = {}
        for event in (e for e in report["events"] if e["event"] == "connect"):
            connection = event["connection"]
            local_port = event["local_address"][1]
            remote_port = control_port if connection == "a" else data_port
            selected = lifetime(
                packets,
                (client, local_port),
                (server, remote_port),
                started_us + event["elapsed_ns"] // 1000,
            )
            sent = stream(selected, (client, local_port), (server, remote_port))
            received = stream(selected, (server, remote_port), (client, local_port))
            assert sent.hex() == report["streams"][connection]["sent_hex"]
            assert received.hex() == report["streams"][connection]["received_hex"]
            terminals = [
                {
                    "packet": packet["index"],
                    "from_server": packet["src_port"] == remote_port,
                    "flags": packet["flags"],
                    "payload_hex": packet["payload_hex"],
                }
                for packet in selected
                if packet["flags"] & 5
            ]
            packet_views[filename][connection] = {
                "packets": len(selected),
                "sent_bytes": len(sent),
                "received_bytes": len(received),
                "terminal_packets": terminals,
            }
    host_terminal = packet_views["host.pcap"]["download"]["terminal_packets"]
    guest_terminal = packet_views["guest-cumulative.pcap"]["download"][
        "terminal_packets"
    ]
    assert [
        (p["from_server"], p["flags"], p["payload_hex"]) for p in host_terminal
    ] == [
        (True, 17, ""),
        (False, 17, ""),
    ]
    assert [
        (p["from_server"], p["flags"], p["payload_hex"]) for p in guest_terminal
    ] == [(True, 4, b"tcp_disconnect".hex())]
    output = {
        "status": "verified",
        "baseline_accounts_exact": True,
        "baseline_files_exact_41": True,
        "fixture_metadata_exact": True,
        "same_connection_uid_hex": uid.hex(),
        "download_reference_hex": ack[107].hex(),
        "download_stream_bytes": len(transfer),
        "info_bytes": len(decoded["INFO"]),
        "data_bytes": len(decoded["DATA"]),
        "data_sha256": sha256(decoded["DATA"]),
        "resource_bytes": len(decoded["MACR"]),
        "resource_sha256": sha256(decoded["MACR"]),
        "idle_303_before_after_exact": True,
        "packet_views": packet_views,
    }
    (BATCH / "verification.json").write_text(json.dumps(output, indent=2) + "\n")
    print("A7 existing-fixture readback: verified")


if __name__ == "__main__":
    main()
