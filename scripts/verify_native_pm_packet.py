#!/usr/bin/env python3
"""Replay A29 PM semantics, full A7 readbacks and both saved TCP packet views."""

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path

from native_filp import decode as decode_filp
from native_pm_cases import BASELINE_SHA256, FULL_STREAM_BYTES, MAIN, PEER
from pcap_tcp import direction, lifetime, read_packets, stream
from protocol_capture import decode_frame, verify_capture
from verify_native_auth import reply
from verify_native_core import require
from verify_native_diagnostic_existing import section_witness
from verify_native_pm import semantic
from verify_native_shx import fields, frames


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inventory(root: Path) -> None:
    manifest = json.loads((root / "manifest.json").read_text())
    require(manifest["status"] == "bounded-native-pm-a29", "PM manifest status differs")
    for path, expected in manifest["files"].items():
        require(
            digest((root / path).read_bytes()) == expected,
            f"PM file hash differs: {path}",
        )
    checks = (root / "SHA256SUMS").read_text().splitlines()
    require(
        {line.split("  ", 1)[1] for line in checks}
        == set(manifest["files"]) | {"manifest.json"},
        "PM SHA inventory differs",
    )
    for line in checks:
        expected, path = line.split("  ", 1)
        require(
            digest((root / path).read_bytes()) == expected,
            f"PM SHA line differs: {path}",
        )


def full_readback(root: Path, label: str, source: dict) -> dict:
    path = root / label
    report = verify_capture(path)
    plan_raw = (path / "plan.json").read_bytes()
    require(digest(plan_raw) == BASELINE_SHA256, f"{label}: A7 plan differs")
    require(
        report["status"] == "completed" and report["completed_actions"] == 29,
        f"{label}: full A7 sequence incomplete",
    )
    for identifier in (10, 11, 12):
        require(
            reply(report, identifier, "a")["fields"]
            == reply(source, identifier, "a")["fields"],
            f"{label}: baseline reply {identifier} differs",
        )
    require(
        len(reply(report, 10, "a")["fields"]) == 2
        and len(reply(report, 11, "a")["fields"]) == 41,
        f"{label}: baseline count differs",
    )
    roster = reply(report, 13, "a")["fields"]
    require(
        len(roster) == 1 and roster[0]["id"] == 300,
        f"{label}: current roster ambiguous",
    )
    uid = bytes.fromhex(roster[0]["hex"])[:2]
    require(
        reply(report, 14, "a")["fields"] == reply(report, 17, "a")["fields"],
        f"{label}: idle diagnostic changed",
    )
    body = fields(reply(report, 14, "a"))[101]
    require(
        section_witness(body, 0, 0)["status"] == "complete",
        f"{label}: idle state incomplete",
    )
    for action in (15, 26):
        sent = b"".join(
            bytes.fromhex(e["hex"])
            for e in report["events"]
            if e["event"] == "send" and e["action"] == action
        )
        require(
            fields(decode_frame(sent))[103] == uid, f"{label}: diagnostic UID differs"
        )
    transfer = bytes.fromhex(report["streams"]["download"]["received_hex"])
    require(len(transfer) == FULL_STREAM_BYTES, f"{label}: full FILP truncated")
    forks = decode_filp(transfer)
    expected = json.loads(plan_raw)["expectation"]
    for tag, key in (
        ("DATA", "expected_data_sha256"),
        ("MACR", "expected_rsrc_sha256"),
    ):
        require(digest(forks[tag]) == expected[key], f"{label}: {tag} fork differs")
    return {
        "uid_hex": uid.hex(),
        "accounts": 2,
        "files": 41,
        "filp_bytes": len(transfer),
        "data_sha256": digest(forks["DATA"]),
        "macr_sha256": digest(forks["MACR"]),
    }


def check_pm(root: Path) -> tuple[dict, dict]:
    report = verify_capture(root / "observe")
    plan = json.loads((root / "observe/plan.json").read_text())
    require(report["completed_actions"] == 151, "PM action count differs")
    result = semantic(report, plan)
    require(
        result == json.loads((root / "observe-semantic.json").read_text()),
        "PM semantic receipt differs",
    )
    main_uid, peer_uid = (
        bytes.fromhex(result[key]) for key in ("main_uid_hex", "peer_uid_hex")
    )
    expected = [
        (
            "peer",
            {
                103: main_uid,
                102: MAIN,
                113: b"\0\1",
                101: b"pm-a26-direct",
                214: b"quote-a26",
            },
        ),
        (
            "main",
            {
                103: peer_uid,
                102: PEER,
                113: b"\0\2",
                101: PEER + b" does not accept private messages.",
            },
        ),
        ("main", {103: peer_uid, 102: PEER, 113: b"\0\4", 101: b"pm-a26-auto"}),
        ("peer", {103: main_uid, 102: MAIN, 113: b"\0\1", 101: b"pm-a26-with-auto"}),
        (
            "peer",
            {
                103: main_uid,
                102: MAIN,
                113: b"\0\2",
                101: MAIN + b" does not accept private messages.",
            },
        ),
        (
            "main",
            {
                103: peer_uid,
                102: PEER,
                113: b"\0\3",
                101: PEER + b" does not accept private chats.",
            },
        ),
    ]
    actual = [
        (f["connection"], fields(f))
        for f in report["frames"]
        if f["type"] == 104 and not f["is_reply"]
    ]
    require(actual == expected, "PM 104 exact variant bytes/order differ")
    received = bytes.fromhex(report["streams"]["main"]["received_hex"])
    require(received[:8] == b"TRTP\0\0\0\0", "PM handshake reply differs")
    main = frames(received[8:])
    refusal = next(
        i
        for i, f in enumerate(main)
        if f["type"] == 104 and fields(f).get(113) == b"\0\2"
    )
    automatic = next(
        i
        for i, f in enumerate(main)
        if f["type"] == 104 and fields(f).get(113) == b"\0\4"
    )
    require(
        any(f["is_reply"] and f["id"] == 61 for f in main[:refusal]),
        "Same-flow refusal preceded 108 ACK",
    )
    require(
        any(f["is_reply"] and f["id"] == 62 for f in main[:automatic]),
        "Same-flow auto preceded 108 ACK",
    )
    return report, result


def packet_views(root: Path, reports: dict[str, dict], peer_uid: bytes) -> dict:
    saved = json.loads((root / "packet-reconciliation.json").read_text())
    observed = {}
    for label, report in reports.items():
        host = read_packets(root / f"host-after-{label}.pcap")
        guest = read_packets(root / f"guest-after-{label}.pcap")
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
                sent, received = (
                    stream(selected, client, server),
                    stream(selected, server, client),
                )
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
                    require(
                        len(tail) == 28
                        and decode_frame(tail)["type"] == 302
                        and fields(decode_frame(tail)) == {103: peer_uid},
                        "PM teardown tail differs",
                    )
                else:
                    require(not tail, f"{label}/{name}/{view}: unexpected unread tail")
                ends = [
                    p["flags"]
                    for p in direction(selected, server, client)
                    if p["flags"] & 5
                ]
                views[view] = {
                    "packets": len(selected),
                    "sent_bytes": len(sent),
                    "received_bytes": len(received),
                    "recorded_received_bytes": len(prefix),
                    "unread_tail_bytes": len(tail),
                    "unread_tail_sha256": digest(tail),
                    "terminal_flags": ends,
                }
            sockets[name] = {"local_port": local, "target_port": target, "views": views}
        observed[label] = {"status": report["status"], "connections": sockets}
    require(observed == saved, "Saved PM packet reconciliation differs")
    for prefix in ("host", "guest"):
        previous = (root / f"{prefix}-after-preflight.pcap").read_bytes()
        for label in ("observe", "postflight"):
            current = (root / f"{prefix}-after-{label}.pcap").read_bytes()
            require(
                current.startswith(previous) and len(current) > len(previous),
                f"{prefix} cumulative snapshot boundary differs",
            )
            previous = current
    require(
        (root / "host.pcap").read_bytes()
        == (root / "host-after-postflight.pcap").read_bytes(),
        "Final host capture differs",
    )
    return observed


def verify(root: Path) -> dict:
    inventory(root)
    source = json.loads((root / "a7-report.json").read_text())
    pre = full_readback(root, "preflight", source)
    post = full_readback(root, "postflight", source)
    _, pm = check_pm(root)
    reports = {
        name: verify_capture(root / name)
        for name in ("preflight", "observe", "postflight")
    }
    packets = packet_views(root, reports, bytes.fromhex(pm["peer_uid_hex"]))
    return {
        "status": "verified-bounded-native-pm",
        "preflight": pre,
        "postflight": post,
        "pm": pm,
        "packet_connections": {k: list(v["connections"]) for k, v in packets.items()},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("batch", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify(args.batch)
    if args.output:
        if args.output.exists():
            parser.error("Refusing existing output")
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(result["status"])


if __name__ == "__main__":
    main()
