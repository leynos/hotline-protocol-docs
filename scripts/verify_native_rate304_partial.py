#!/usr/bin/env python3
"""Replay the failed native 304 first pair from a frozen, offline corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import runpy
from pathlib import Path

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-14/native-rate304-first-pair-01"
)
CASES = "1f03bde7d498f7831c82e87e09ec3e7d02bc43124a56cd1411e985546220e43f"
RUNNER = "a1d57bc585d145e03d7c499ee5896477d03c0da83a8a6483b65c32dbd88559b5"
PLAN = "d5f689b36f8532ab806a894d6875747d75e1ee14c046a98e6d03bf43e7ab0bf2"
DATA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
FORKS = {
    "admin": "26612ad46cd91b90050feacf517d32a9e56d4a4aa92fbe6618eaf6e9e5ac60a3",
    "fixture-low": "fce81359d0efcfc6c2dbf42852db66b0fb7a404b2889162b8f8fad81361ce2d5",
    "Prefs": "4ed2b3e14e6e8a6cf246d16f7d1b98f0b91d1b09f6ab5497de1056a6f617d196",
    "server-data": DATA,
    "server-rsrc": "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12",
    "board": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}
PORTS = {"main": 53738, "observer": 44482, "paced": 44496}


def need(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: Path) -> dict:
    return json.loads(path.read_text())


def inventory(corpus: Path) -> dict:
    manifest = read(corpus / "manifest.json")
    need(manifest["schema"] == "native-rate304-first-pair-01", "Corpus schema differs")
    need(manifest["case_status"] == "failed", "Case status must remain failed")
    files = manifest["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(actual == set(files), "Corpus inventory differs")
    for name, digest in files.items():
        need(sha(corpus / name) == digest, f"Corpus SHA differs: {name}")
    need(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{digest}  {name}" for name, digest in sorted(files.items())],
        "SHA256SUMS differs",
    )
    return manifest


def sources(raw: Path) -> None:
    freeze = read(raw / "source-freeze.json")
    need(len(freeze["hashes"]) == 35, "As-run source closure differs")
    for name, digest in freeze["hashes"].items():
        need(sha(raw / "sources" / name) == digest, f"As-run source differs: {name}")
    for name, digest in freeze["helper_hashes"].items():
        need(sha(raw / "helper-sources" / name) == digest, f"Helper differs: {name}")
    need(
        freeze["hashes"]["native_rate304_cases.py"] == CASES
        and freeze["hashes"]["native_rate304_control.py"] == RUNNER
        and sha(raw / "run-case-c107.sh")
        == "8a2f16948545742c82b2b87a387ce0cea5ae7cf624c061d0b7b944e152f18e79",
        "Approved runner or exact case launch differs",
    )


def scoped_identity(raw: Path) -> None:
    runtime, receipt = read(raw / "runtime.json"), read(raw / "capture-ready.json")
    need(
        runtime["emulator_pid"] == receipt["emulator_pid"] == 1956254
        and runtime["emulator_starttime"] == receipt["emulator_starttime"] == "7658344"
        and runtime["emulator_netns_inode"]
        == receipt["emulator_netns_inode"]
        == 4026533669
        and runtime["owned_working_image_inode"]
        == receipt["owned_working_image_inode"]
        == 2226400708
        and runtime["native_data_sha256"] == DATA
        and runtime["full_file_baseline"] == "not_exercised"
        and receipt["deadline_utc"] == "2026-11-14T10:36:36.309570+00:00",
        "Runtime identity or fixed deadline differs",
    )
    need(
        sha(raw / "rate304-plan/plan.json") == PLAN
        and read(raw / "rate304-plan/plan.json")["endpoint"]["port"] == 15880,
        "As-run case plan differs",
    )
    props = (raw / "case-unit-terminal.txt").read_text()
    need(
        "ActiveState=failed" in props
        and "ExecMainStatus=1" in props
        and "NetworkNamespacePath=/proc/1956254/ns/net" in props,
        "Failed unit provenance differs",
    )


def fields(frame: dict) -> dict[int, bytes]:
    return {item["id"]: bytes.fromhex(item["hex"]) for item in frame["fields"]}


def numbered(report: dict) -> None:
    actions = report["actions"]
    need(
        [action["label"] for action in actions]
        == [
            "observer-login",
            "observer-roster-initial",
            "paced-login",
            "paced-roster",
            "paced-304-00",
            "paced-500-00",
        ],
        "Case action boundary differs",
    )
    for action, kind, identifier in zip(
        actions, [107, 300, 107, 300, 304, 500], [1, 10, 1, 10, 1000, 2000], strict=True
    ):
        raw = bytes.fromhex(action["hex"])
        need(
            int.from_bytes(raw[:4], "big") == kind
            and int.from_bytes(raw[4:8], "big") == identifier,
            "Sent request kind or ID differs",
        )
    need(
        report["status"] == "failed"
        and report["error"]
        == "ValueError: Missing paced subject/observer301 and500 ACK icon2"
        and report["plan_sha256"] == PLAN
        and report["source_sha256"] == RUNNER
        and report["cases_sha256"] == CASES
        and report["oracle_sha256"] == DATA
        and report["native_clock_calibrated"] is False,
        "Failed-case status or source differs",
    )
    frames = report["frames"]
    need(len(frames) == 12, "Case frame count differs")
    join = [f for f in frames if f["connection"] == "observer" and f["type"] == 301]
    update = [f for f in frames if f["connection"] == "paced" and f["type"] == 301]
    ack = [
        f
        for f in frames
        if f["connection"] == "paced" and f["type"] == 0 and f["id"] == 2000
    ]
    departure = [f for f in frames if f["connection"] == "paced" and f["type"] == 302]
    need(
        len(join) == len(update) == len(ack) == len(departure) == 1
        and fields(join[0])[103] == b"\x00\x03"
        and fields(join[0])[104] == b"\x00\x01"
        and fields(update[0])[103] == b"\x00\x03"
        and fields(update[0])[104] == b"\x00\x02"
        and fields(departure[0])[103] == b"\x00\x02"
        and (ack[0]["flags"], ack[0]["is_reply"], ack[0]["error"]) == (0, 1, 0)
        and ack[0]["fields"] == [],
        "Initial join, late update, ACK or cleanup departure differs",
    )
    events = report["events"]
    shutdown = next(
        e["elapsed_ns"]
        for e in events
        if e["connection"] == "observer" and e["event"] == "shutdown_write"
    )
    need(
        actions[4]["elapsed_ns"]
        < actions[5]["elapsed_ns"]
        < shutdown
        < departure[0]["arrival_elapsed_ns"]
        < update[0]["arrival_elapsed_ns"]
        < ack[0]["arrival_elapsed_ns"]
        and not any(
            f["connection"] == "observer"
            and f["type"] == 301
            and fields(f).get(104) == b"\x00\x02"
            for f in frames
        )
        and 1_300_000_000 < shutdown < 1_500_000_000
        and 1_500_000_000 < update[0]["arrival_elapsed_ns"] < 1_700_000_000,
        "First-pair timing or client cleanup differs",
    )
    need(
        report["terminals"] == {"observer": "eof", "paced": "eof"}
        and (raw := bytes.fromhex(actions[4]["hex"]))[-2:] == b"\x00\x02"
        and bytes.fromhex(actions[5]["hex"])[4:8] == (2000).to_bytes(4, "big"),
        "304 value, barrier or terminal status differs",
    )


def packet_evidence(raw: Path, report: dict) -> None:
    parser = runpy.run_path(str(raw / "sources/pcap_tcp.py"))
    packets = parser["read_packets"]
    stream = parser["stream"]
    host = packets(raw / "primary-syn.pcap")
    ns = packets(raw / "lab-namespace.pcap")
    guest = packets(raw / "lab-guest.pcap")
    need(
        len(host) == 0 and len(ns) == 75 and len(guest) == 82,
        "Capture packet count differs",
    )
    for view in (ns, guest):
        syns = [p for p in view if p["flags"] & 2 and not p["flags"] & 16]
        need(
            {p["src_port"] for p in syns} == set(PORTS.values()) and len(syns) == 3,
            "Three SYN lifetimes differ",
        )
        need(not any(p["flags"] & 4 for p in view), "Unexpected TCP reset")
    readiness = read(raw / "readiness/report.json")
    need(
        readiness["status"] == "completed"
        and readiness["completed_actions"] == 18
        and readiness["error"] == "",
        "Separate 18-action readiness differs",
    )
    sent = [
        bytes.fromhex(event["hex"])
        for event in readiness["events"]
        if event["event"] == "send"
    ]
    need(
        len(sent) == 7
        and sent[0] == bytes.fromhex("54525450484f544c00010002")
        and [
            (int.from_bytes(value[:4], "big"), int.from_bytes(value[4:8], "big"))
            for value in sent[1:]
        ]
        == [(107, 1), (348, 10), (200, 11), (206, 12), (300, 13), (303, 14)],
        "Separate readiness request sequence differs",
    )
    for name, port in PORTS.items():
        expected = (
            readiness["streams"]["main"] if name == "main" else report["streams"][name]
        )
        for view, server in ((ns, "127.0.0.1"), (guest, "10.0.2.15")):
            client = ("127.0.0.1" if server.startswith("127") else "10.0.2.2", port)
            target = (server, 15880 if server.startswith("127") else 5500)
            need(
                stream(view, client, target).hex() == expected["sent_hex"]
                and stream(view, target, client).hex() == expected["received_hex"],
                f"{name} packet stream differs from recorder",
            )
    need(
        [
            (
                len(bytes.fromhex(readiness["streams"]["main"]["sent_hex"])),
                len(bytes.fromhex(readiness["streams"]["main"]["received_hex"])),
            ),
            (
                len(bytes.fromhex(report["streams"]["observer"]["sent_hex"])),
                len(bytes.fromhex(report["streams"]["observer"]["received_hex"])),
            ),
            (
                len(bytes.fromhex(report["streams"]["paced"]["sent_hex"])),
                len(bytes.fromhex(report["streams"]["paced"]["received_hex"])),
            ),
        ]
        == [(231, 2759), (108, 448), (159, 521)],
        "Full stream lengths differ",
    )
    journal = (raw / "capture-journal-terminal.txt").read_text()
    need(
        "0 packets captured" in journal
        and "75 packets captured" in journal
        and journal.count("0 packets dropped by kernel") == 2,
        "Recorder drop or primary-contact proof differs",
    )


def stopped(raw: Path) -> None:
    forks = read(raw / "stopped/forks.json")
    need(
        {name: row["sha256"] for name, row in forks.items()} == FORKS,
        "Stopped fork hashes differ",
    )
    for name in ("admin", "fixture-low", "Prefs", "board"):
        need(
            sha(raw / "stopped" / f"{name}.bin") == FORKS[name],
            f"Stopped {name} bytes differ",
        )
    catalog = (raw / "stopped/catalog-allocated.txt").read_text()
    users = [
        line
        for line in catalog.splitlines()
        if "/Users/" in line and line.endswith("/UserData")
    ]
    need(
        len(users) == 2
        and any("/Users/admin/UserData" in x for x in users)
        and any("/Users/fixture-low/UserData" in x for x in users),
        "Original account set differs",
    )
    need(
        "/Banned" not in catalog and forks["board"]["size"] == 0,
        "Stopped ban or board state differs",
    )
    units = (raw / "units-terminal.txt").read_text()
    need(
        units.count("ActiveState=inactive") == 3
        and "ActiveState=failed" in units
        and "ExecMainStatus=1" in units,
        "Unit terminal state differs",
    )
    need(
        (raw / "fuser-terminal.exit").read_text().strip() == "1",
        "Working image still held",
    )
    need(
        "Result=success" in (raw / "user-units-terminal.txt").read_text(),
        "Owned user-unit retirement missing",
    )
    need(
        "1909b4ed299f032f95d5fbac2f4b6446c49e860e57bf9018ec7a96dec24e8f74"
        in (raw / "stopped/image-sha256.txt").read_text(),
        "Stopped image hash differs",
    )


def verify(corpus: Path) -> None:
    inventory(corpus)
    raw = corpus / "raw"
    sources(raw)
    scoped_identity(raw)
    report = read(raw / "coordinator/report.json")
    numbered(report)
    packet_evidence(raw, report)
    stopped(raw)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    args = parser.parse_args()
    verify(args.corpus)
    print("native rate304 first pair: failed case and three complete flows verified")


if __name__ == "__main__":
    main()
