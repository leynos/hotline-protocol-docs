#!/usr/bin/env python3
"""Verify complete shx field variants against socket, packet and terminal bytes."""

import argparse
import hashlib
import json
from pathlib import Path

from pcap_tcp import lifetime, read_packets, stream
from peer_tolerance_fixture import CASES, login_reply
from serve_shx_fixture import fixture_frames, roster
from shx_syscalls import socket_io
from verify_native_core import require
from verify_native_shx import PEER, REVISION, check_terminal, fields, frames


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(directory: Path, source: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    require(
        manifest["cases"] == list(CASES)
        and manifest["ports"] == list(range(15600, 15600 + len(CASES)))
        and manifest["peer_binary_sha256"] == PEER
        and manifest["source_commit"] == REVISION
        and manifest["native_conformance"] is False
        and manifest["real_home_file_before"] == manifest["real_home_file_after"],
        "Peer manifest, identity or real HOME guard differs",
    )
    source_hashes = {sha(p) for p in (directory / "sources").iterdir()}
    require(
        manifest["source_fixture_sha256"] in source_hashes
        and manifest["source_runner_sha256"] in source_hashes,
        "Missing exact fixture or runner source",
    )
    require(
        {p.name for p in (directory / "captures").iterdir()} == set(CASES)
        and {p.name for p in (directory / "fixtures").iterdir()} == set(CASES),
        "Peer case inventory differs",
    )
    original = fixture_frames(source)
    host = read_packets(directory / "host.pcap")
    results = []
    for index, case in enumerate(CASES):
        port = 15600 + index
        capture = directory / "captures" / case
        fixture = json.loads(
            (directory / "fixtures" / case / "report.json").read_text()
        )
        commands = [
            "/version",
            f"/server -o -l admin -p mothra19 -n shx-peer-a -i 500 127.0.0.1:{port}",
            "/who -r",
            "mothra-shx-basic-chat",
            "/quit",
        ]
        report = check_terminal(capture, source_hashes, commands=commands)
        require(
            report["environment"]["controlled_receiver_fixture"]
            == {
                "profile": "controlled-receiver-fixture",
                "case": case,
                "source_peer": "shx 0.1.48 modern terminal build",
            },
            "Peer capture provenance differs",
        )
        require(
            fixture["profile"] == "controlled-receiver-fixture"
            and fixture["native_conformance"] is False
            and fixture["status"] == "completed"
            and fixture["case"] == case
            and fixture["endpoint"] == ["127.0.0.1", port]
            and fixture["events"][-1]["event"] == "eof",
            "Fixture status or endpoint differs",
        )
        records = socket_io(
            (capture / "syscalls.log").read_text(), server_ports=frozenset({port})
        )
        require(
            len({(r["pid"], r["fd"], r["client_port"]) for r in records}) == 1,
            "Ambiguous peer socket",
        )
        sent = b"".join(r["bytes"] for r in records if r["operation"] == "write")
        received = b"".join(r["bytes"] for r in records if r["operation"] == "read")
        client = ("127.0.0.1", records[0]["client_port"])
        server = ("127.0.0.1", port)
        require(
            fixture["client_address"] == list(client)
            and fixture["server_address"] == list(server),
            "Fixture socket identity differs",
        )
        packets = lifetime(host, client, server, records[0]["timestamp_us"])
        require(
            stream(packets, client, server) == sent
            and stream(packets, server, client) == received,
            "Independent packet bytes differ from peer syscalls",
        )
        require(
            b"".join(
                bytes.fromhex(e["hex"])
                for e in fixture["events"]
                if e["event"] == "receive"
            )
            == sent
            and b"".join(
                bytes.fromhex(e["hex"])
                for e in fixture["events"]
                if e["event"] == "send"
            )
            == received,
            "Fixture bytes differ from peer syscalls",
        )
        require(
            sent[:12] == bytes.fromhex("54525450484f544c00010002")
            and received[:8] == original["handshake"],
            "Peer handshake differs",
        )
        requests, replies = frames(sent[12:]), frames(received[8:])
        require(
            [frame["type"] for frame in requests] == [107, 300, 300, 105]
            and [frame["id"] for frame in requests] == [1, 2, 3, 4]
            and fields(requests[3]) == {101: b"mothra-shx-basic-chat"},
            "Peer continuation request order differs",
        )
        expected = (
            original["handshake"]
            + login_reply(original["login"], case)
            + original["privileges"]
            + original["agreement"]
        )
        if case == "early-122":
            expected += original["banner"]
        expected += (
            roster(original["roster"], 2, False)
            + roster(original["roster"], 3, False)
            + original["chat"]
        )
        require(received == expected, "Peer received wrong field or frame order")
        login_fields = fields(replies[0])
        require(
            login_fields[160] == b"\0\xbe"
            and (161 in login_fields) == (case != "omit-161")
            and login_fields.get(161)
            == (
                None
                if case == "omit-161"
                else b"\0\1"
                if case == "vary-161"
                else b"\0\0"
            )
            and (32767 in login_fields) == (case == "unknown-login"),
            "Login variant did not contain its claimed field bytes",
        )
        terminal = (capture / "stdout.bin").read_bytes()
        dump = capture / "work/hx.dump"
        require(
            b"shx-peer-a" in terminal and b"mothra-shx-basic-chat" in terminal,
            "Peer did not display roster and continuation chat",
        )
        if case == "early-122":
            require(
                terminal.count(b"unknown header type 0x0000007a") == 1
                and dump.is_file()
                and dump.read_bytes() == original["banner"],
                "Early native banner was not exactly dumped and tolerated",
            )
        else:
            require(
                b"unknown header type 0x0000007a" not in terminal and not dump.exists(),
                "Unexpected banner in peer control",
            )
        results.append(
            {
                "case": case,
                "port": port,
                "sent_bytes": len(sent),
                "received_bytes": len(received),
                "peer_exit": report["peer_exit_code"],
            }
        )
    sums = (directory / "SHA256SUMS").read_text().splitlines()
    prefix = Path("evidence/gap-remediation/2026-11-13/delegated-peer-01")
    expected_sums = {
        f"{sha(path)}  {prefix / path.relative_to(directory)}"
        for path in directory.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    require(set(sums) == expected_sums, "Evidence checksums differ")
    return {"status": "verified", "packet_count": len(host), "cases": results}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory, args.source), indent=2))


if __name__ == "__main__":
    main()
