#!/usr/bin/env python3
"""Replay A33 settings transitions, full A7 readbacks and six TCP lifetimes."""

import argparse
import hashlib
import json
import sys
from datetime import datetime
from itertools import pairwise
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[4].parent / "hotline-protocol-docs/scripts"
sys.path.insert(0, str(SCRIPTS))

from native_pm_cases import BASELINE_SHA256
from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import decode_frame, verify_capture
from verify_native_core import require
from verify_native_pm_packet import full_readback
from verify_native_settings_transition import semantic


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root: Path) -> dict:
    manifest = json.loads((root / "manifest.json").read_text())
    require(manifest["status"] == "native-304-transitions-a33", "Wrong corpus status")
    for name, expected in manifest["files"].items():
        require(digest(root / name) == expected, f"Corpus hash differs: {name}")
    for name, expected in manifest["protocol_sources"].items():
        require(digest(SCRIPTS / name) == expected, f"Protocol source differs: {name}")
    checks = (root / "SHA256SUMS").read_text().splitlines()
    require(
        {line.split("  ", 1)[1] for line in checks}
        == set(manifest["files"]) | {"manifest.json"},
        "SHA inventory differs",
    )
    for line in checks:
        expected, name = line.split("  ", 1)
        require(digest(root / name) == expected, f"SHA line differs: {name}")
    return manifest


def stage_gates(root: Path, result: dict) -> None:
    gates = json.loads((root / "stage-gates.json").read_text())
    require(gates["status"] == "completed" and not gates["error"], "Stage gate failed")
    require(gates["passed"] == result["verified_stages"], "Stage gate result differs")
    require(len(gates["passed"]) == 8, "Stage gate count differs")


def packet_views(root: Path, reports: dict[str, dict], uid: bytes) -> dict:
    host = read_packets(root / "host-six-flows.pcap")
    guest = read_packets(root / "guest-six-flows.pcap")
    for label, packets, port in (("host", host, 15500), ("guest", guest, 5500)):
        starts = [
            packet
            for packet in packets
            if packet["flags"] & 2
            and not packet["flags"] & 16
            and packet["dst_port"] in (port, port + 1)
        ]
        require(len(starts) == 6, f"{label}: expected six distinct SYN lifetimes")
    observed = {}
    for label, report in reports.items():
        started = int(
            datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1_000_000
        )
        sockets = {}
        for event in report["events"]:
            if event["event"] != "connect":
                continue
            name = event["connection"]
            local, target = event["local_address"][1], event["peer_address"][1]
            when = started + event["elapsed_ns"] // 1000
            recorded = report["streams"][name]
            views = {}
            for view, packets, client, server in (
                ("host", host, ("127.0.0.1", local), ("127.0.0.1", target)),
                (
                    "guest",
                    guest,
                    ("10.0.2.2", local),
                    ("10.0.2.15", 5500 + target - 15500),
                ),
            ):
                selected = lifetime(packets, client, server, when)
                sent = stream(selected, client, server)
                received = stream(selected, server, client)
                prefix = bytes.fromhex(recorded["received_hex"])
                require(
                    sent == bytes.fromhex(recorded["sent_hex"]),
                    f"{label}/{name}/{view}: TCP input differs",
                )
                require(
                    received.startswith(prefix),
                    f"{label}/{name}/{view}: TCP output prefix differs",
                )
                tail = received[len(prefix) :]
                if label == "observe" and name == "main":
                    decoded = decode_frame(tail)
                    require(
                        len(tail) == 28
                        and decoded["type"] == 302
                        and decoded["fields"] == [{"id": 103, "hex": uid.hex()}],
                        "Subject departure tail differs",
                    )
                else:
                    require(not tail, f"{label}/{name}/{view}: unexpected unread tail")
                views[view] = {
                    "packets": len(selected),
                    "sent_bytes": len(sent),
                    "received_bytes": len(received),
                    "recorder_prefix_bytes": len(prefix),
                    "unread_tail_bytes": len(tail),
                    "unread_tail_sha256": hashlib.sha256(tail).hexdigest(),
                    "unread_tail_hex": tail.hex() if len(tail) <= 64 else None,
                }
            sockets[name] = {"local_port": local, "target_port": target, "views": views}
        observed[label] = sockets
    saved = json.loads((root / "packet-reconciliation.json").read_text())
    require(observed == saved, "Saved packet reconciliation differs")
    require(sum(map(len, observed.values())) == 6, "TCP connection count differs")
    return observed


def snapshot_provenance(root: Path, raw_session: Path | None) -> dict:
    proof = json.loads((root / "snapshot-provenance.json").read_text())
    require(proof["prefix_verified"] is True, "Guest prefix assertion absent")
    if raw_session is not None:
        names = list(proof["snapshots"])
        for name in names:
            source = raw_session / name
            require(
                source.stat().st_size == proof["snapshots"][name]["bytes"],
                f"{name}: byte size differs",
            )
            require(
                digest(source) == proof["snapshots"][name]["sha256"],
                f"{name}: raw snapshot hash differs",
            )
        for old, new in pairwise(names):
            require(
                (raw_session / new)
                .read_bytes()
                .startswith((raw_session / old).read_bytes()),
                f"Guest snapshot prefix differs: {old}/{new}",
            )
    return {
        "raw_snapshots_replayed": raw_session is not None,
        "raw_snapshot_prefix_asserted": True,
    }


def verify(root: Path, raw_session: Path | None = None) -> dict:
    manifest = inventory(root)
    require(
        manifest["baseline_plan_sha256"] == BASELINE_SHA256,
        "A7 baseline identity differs",
    )
    reference = json.loads((root / "baseline-reference.json").read_text())
    before = full_readback(root, "preflight", reference)
    pre_report = verify_capture(root / "preflight")
    after = full_readback(root, "postflight", pre_report)
    require(before.keys() == after.keys(), "A7 readback shape differs")
    require(
        {k: v for k, v in before.items() if k != "uid_hex"}
        == {k: v for k, v in after.items() if k != "uid_hex"},
        "A7 before/after differs",
    )
    report = verify_capture(root / "observe")
    require(report["completed_actions"] == 129, "Observe action count differs")
    plan = json.loads((root / "observe/plan.json").read_text())
    result = semantic(report, plan)
    stage_gates(root, result)
    packets = packet_views(
        root,
        {
            "preflight": pre_report,
            "observe": report,
            "postflight": verify_capture(root / "postflight"),
        },
        bytes.fromhex(result["subject_uid_hex"]),
    )
    proof = snapshot_provenance(root, raw_session)
    terminal = (root / "host-capture-terminal.txt").read_text()
    stats = (root / "tcpdump.log").read_text()
    require(
        "ActiveState=inactive" in terminal
        and "MainPID=0" in terminal
        and "Result=success" in terminal,
        "Host recorder did not stop cleanly",
    )
    require(
        "0 packets dropped by kernel" in stats, "Host recorder loss/terminal differs"
    )
    return {
        "status": "verified",
        "stages": result["verified_stages"],
        "before": before,
        "after": after,
        "tcp_connections": sum(map(len, packets.values())),
        **proof,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "corpus", type=Path, nargs="?", default=Path(__file__).resolve().parent
    )
    parser.add_argument(
        "--raw-session",
        type=Path,
        help="Optional ignored cumulative snapshot directory",
    )
    args = parser.parse_args()
    print(json.dumps(verify(args.corpus, args.raw_session), indent=2))


if __name__ == "__main__":
    main()
