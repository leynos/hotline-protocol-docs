#!/usr/bin/env python3
"""Verify full shx peer terminal, syscall, paired packet and saved-fork evidence."""

import argparse
import hashlib
import json
import re
from pathlib import Path

from native_filp import decode, metadata
from native_packet_evidence import reconcile
from native_transfer_cases import resource_fork
from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import ORACLE_SHA256, decode_frame, verify_capture
from shx_syscalls import socket_io
from verify_native_core import require

PEER = "8fbbe56cef439d4c1732e8d9fbe2c676b9d45fbd273a42b22f8034e3b3914fa0"
REVISION = "adb1bf8c8cb12f7eb2fa2c01673295a6312f262b"
CASES = {
    "basic-empty-name",
    "root-listing",
    "fork-download",
    "ambiguous-text",
    "wrong-password",
}
CHAT = b"mothra-peer-byte-\x80-\x9a-\xc3\xb6-\xff-END"
DATA = b"data-fork\r\n\0\xff"
NAME = b"mothra-fork-fixture"
LOGIN = "/server -o -l admin -p mothra19 -n shx-peer-a -i 500 127.0.0.1:15500"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fields(frame: dict) -> dict[int, bytes]:
    values = {f["id"]: bytes.fromhex(f["hex"]) for f in frame["fields"]}
    require(len(values) == len(frame["fields"]), "Unexpected repeated scalar field")
    return values


def frames(data: bytes) -> list[dict]:
    result = []
    while data:
        require(len(data) >= 20, "Incomplete peer frame header")
        size = int.from_bytes(data[16:20], "big")
        require(size <= 524288 and 20 + size <= len(data), "Incomplete peer frame")
        frame = decode_frame(data[: 20 + size])
        require(
            frame["flags"] == 0 and frame["total_size"] == size,
            "Unexpected peer fragmentation",
        )
        require(
            "fields" in frame and "payload_error" not in frame, "Malformed peer fields"
        )
        require(
            len(frame["fields"]) == frame["declared_field_count"]
            and not frame["unconsumed_hex"],
            "Incomplete or trailing peer fields",
        )
        result.append(frame)
        data = data[20 + size :]
    return result


def check_terminal(case: Path, source_hashes: set[str]) -> dict:
    report = json.loads((case / "report.json").read_text())
    plan = json.loads((case / "plan.json").read_text())
    profile = json.loads((case / "peer-profile.json").read_text())
    require(
        report["status"] == "completed" and report["peer_exit_code"] == 0,
        "Peer process failed",
    )
    require(
        report["native_conformance"] is False,
        "Driver cannot certify native conformance",
    )
    require(
        report["oracle_sha256"] == ORACLE_SHA256
        and report["peer_binary_sha256"] == PEER,
        "Peer/oracle identity differs",
    )
    require(
        profile["source_commit"] == REVISION and profile["binary_sha256"] == PEER,
        "Compiled profile differs",
    )
    require(
        report["plan_sha256"] == sha(case / "plan.json")
        and report["peer_profile_sha256"] == sha(case / "peer-profile.json"),
        "Plan/profile hash differs",
    )
    require(report["driver_sha256"] in source_hashes, "Missing exact peer driver")
    require(
        report["host_home_file_before"] == report["host_home_file_after"],
        "Real home file changed",
    )
    require(report["completed_steps"] == len(plan["steps"]), "Incomplete peer commands")
    commands = ["/version", LOGIN, "/who"]
    if case.name in {"root-listing", "fork-download"}:
        commands.append("/ls")
    if case.name == "fork-download":
        commands.append("/get mothra-fork-fixture")
    elif case.name == "basic-empty-name":
        commands.append("mothra-shx-basic-chat")
    elif case.name == "ambiguous-text":
        commands.append("/who")
    elif case.name == "wrong-password":
        commands = ["/version", LOGIN.replace("mothra19", "wrong-shx-pass")]
    commands.append("/quit")
    require(
        [s["command"] for s in plan["steps"]] == commands, "Peer command matrix differs"
    )
    require(
        plan["steps"][-1].get("expect_exit") == 0, "Missing normal exit requirement"
    )
    events = report["events"]
    require(
        b"".join(bytes.fromhex(e["hex"]) for e in events if e["event"] == "output")
        == (case / "stdout.bin").read_bytes(),
        "Raw terminal event bytes differ",
    )
    inputs = [bytes.fromhex(e["hex"]) for e in events if e["event"] == "input"]
    require(
        inputs == [(c + "\n").encode() for c in commands],
        "Sent terminal commands differ",
    )
    require(
        any(
            e["event"] == "process-exit" and bytes.fromhex(e["hex"]) == b"0"
            for e in events
        ),
        "Missing successful process-exit event",
    )
    terminal = (case / "stdout.bin").read_bytes()
    require(b"hx version 0.1.48" in terminal, "Missing running peer version")
    require((case / "home/.hxvars").is_file(), "Missing private exit-save file")
    return report


def check_packets(case: Path, host: list[dict], guest: list[dict]) -> list[dict]:
    trace = (case / "syscalls.log").read_text()
    records = socket_io(trace)
    require(bool(records), "Missing peer socket I/O")
    connections = []
    for port in sorted({r["client_port"] for r in records}):
        selected = [r for r in records if r["client_port"] == port]
        endpoint = selected[0]["server_port"]
        require(
            len({(r["pid"], r["fd"], r["server_port"]) for r in selected}) == 1,
            "Ambiguous peer socket identity",
        )
        sent = b"".join(r["bytes"] for r in selected if r["operation"] == "write")
        received = b"".join(r["bytes"] for r in selected if r["operation"] == "read")
        for label, packets, client, server in [
            ("host", host, ("127.0.0.1", port), ("127.0.0.1", endpoint)),
            ("guest", guest, ("10.0.2.2", port), ("10.0.2.15", endpoint - 10000)),
        ]:
            observed = lifetime(packets, client, server, selected[0]["timestamp_us"])
            require(
                stream(observed, client, server) == sent, label + " peer input differs"
            )
            require(
                stream(observed, server, client) == received,
                label + " peer output differs",
            )
        connections.append(
            {
                "port": port,
                "endpoint": endpoint,
                "pid": selected[0]["pid"],
                "sent": sent,
                "received": received,
            }
        )
    control = [c for c in connections if c["endpoint"] == 15500]
    require(len(control) == 1, "Expected exactly one peer control connection")
    pid = control[0]["pid"]
    report = json.loads((case / "report.json").read_text())
    encoded = "".join(f"\\x{b:02x}" for b in report["command"][-3].encode())
    require(
        re.search(
            rf'^{pid} \d+\.\d+ execve\("{re.escape(encoded)}", .* = 0$',
            trace,
            re.MULTILINE,
        )
        is not None,
        "Control socket process lacks successful peer exec",
    )
    return connections


def check_semantics(case: Path, connections: list[dict], agreement: bytes) -> dict:
    control = next(c for c in connections if c["endpoint"] == 15500)
    require(
        control["sent"].startswith(bytes.fromhex("54525450484f544c00010002")),
        "Peer handshake changed",
    )
    require(
        control["received"].startswith(bytes.fromhex("5452545000000000")),
        "Native handshake changed",
    )
    requests, replies = frames(control["sent"][12:]), frames(control["received"][8:])
    login = requests[0]
    credentials = b"wrong-shx-pass" if case.name == "wrong-password" else b"mothra19"
    require(
        (login["type"], login["id"], login["is_reply"]) == (107, 1, 0),
        "Basic peer login header changed",
    )
    require(
        fields(login)
        == {
            104: b"\x01\xf4",
            105: bytes(b ^ 255 for b in b"admin"),
            106: bytes(b ^ 255 for b in credentials),
            102: b"shx-peer-a",
        },
        "Peer login fields changed, including absent version160",
    )
    terminal = (case / "stdout.bin").read_bytes()
    if case.name == "wrong-password":
        require(
            len(requests) == len(replies) == len(connections) == 1,
            "Failed login continued",
        )
        require(
            replies[0]["error"] == 1
            and replies[0]["is_reply"] == 1
            and replies[0]["id"] == 1
            and fields(replies[0]) == {100: b"Incorrect login."},
            "Native login error differs",
        )
        require(
            b"login failed?" in terminal and b"Incorrect login." in terminal,
            "Peer did not report login failure",
        )
        return {"failed_login": True}
    require(
        replies[0]["error"] == 0
        and replies[0]["id"] == 1
        and replies[0]["is_reply"] == 1
        and fields(replies[0]) == {160: b"\0\xbe", 161: b"\0\0"},
        "Native empty-name login extras differ",
    )
    require(
        [r["type"] for r in replies[1:3]] == [354, 109]
        and fields(replies[2]) == {101: agreement},
        "Native privilege/agreement bootstrap differs",
    )
    require(
        [r["type"] for r in requests[:2]] == [107, 300],
        "Peer automatic roster request differs",
    )
    require(all(r["type"] != 121 for r in requests), "Unexpected late login acceptance")
    roster = next(r for r in replies if r["is_reply"] and r["id"] == requests[1]["id"])
    names = []
    for f in roster["fields"]:
        data = bytes.fromhex(f["hex"])
        require(
            f["id"] == 300
            and len(data) >= 8
            and int.from_bytes(data[6:8], "big") == len(data) - 8,
            "Native roster record differs",
        )
        names.append(data[8:])
    require(
        b"shx-peer-a" in names and b"login successful" in terminal,
        "Peer roster/login failed",
    )
    require(all(r["error"] == 0 for r in replies), "Unexpected native operation error")
    expected_types = {
        "basic-empty-name": [107, 300, 105],
        "root-listing": [107, 300, 200],
        "fork-download": [107, 300, 200, 202],
        "ambiguous-text": [107, 300],
    }
    require(
        [r["type"] for r in requests] == expected_types[case.name],
        "Peer operation sequence differs",
    )
    if case.name == "basic-empty-name":
        require(
            fields(requests[-1]) == {101: b"mothra-shx-basic-chat"},
            "Peer chat send differs",
        )
        require(
            any(
                r["type"] == 106 and b"mothra-shx-basic-chat" in fields(r).get(101, b"")
                for r in replies
            ),
            "Native chat echo missing",
        )
    if case.name == "ambiguous-text":
        chat = [fields(r)[101] for r in replies if r["type"] == 106]
        require(
            chat == [b"\rnative-byte-w:  " + CHAT],
            "Native ambiguous chat bytes changed",
        )
        require(CHAT in terminal, "Peer terminal reencoded ambiguous bytes")
    if case.name in {"root-listing", "fork-download"}:
        listing = next(
            r for r in replies if r["is_reply"] and r["id"] == requests[2]["id"]
        )
        found = []
        for f in listing["fields"]:
            value = bytes.fromhex(f["hex"])
            require(
                f["id"] == 200
                and len(value) >= 20
                and int.from_bytes(value[16:20], "big") == len(value) - 20,
                "Native listing layout differs",
            )
            if value[20:] == NAME:
                found.append(value)
        require(
            len(found) == 1
            and found[0][:8] == b"TEXTMOTH"
            and int.from_bytes(found[0][8:12], "big") == 330,
            "Missing exact fork fixture listing",
        )
        require(NAME in terminal, "Peer did not display listing")
    if case.name == "fork-download":
        require(len(connections) == 2, "Missing transfer socket")
        data = next(c for c in connections if c["endpoint"] == 15501)
        ack = fields(
            next(r for r in replies if r["is_reply"] and r["id"] == requests[-1]["id"])
        )
        require(
            ack[108] == (510).to_bytes(2, "big")
            and ack[207] == (330).to_bytes(2, "big"),
            "Native transfer sizes differ",
        )
        require(
            data["sent"] == b"HTXF" + ack[107] + (510).to_bytes(4, "big") + bytes(4),
            "Peer transfer attach/reference differs",
        )
        forks = decode(data["received"])
        require(
            forks["DATA"] == DATA and forks["MACR"] == resource_fork(),
            "Native fork contents differ",
        )
        require(metadata(forks["INFO"])["name"] == NAME, "Native INFO name differs")
        require(
            (case / "work/mothra-fork-fixture").read_bytes() == forks["DATA"],
            "Saved data fork differs",
        )
        require(
            (case / "work/.resource/mothra-fork-fixture").read_bytes() == forks["MACR"],
            "Saved resource fork differs",
        )
    else:
        require(len(connections) == 1, "Unexpected extra peer socket")
    return {
        "request_types": [r["type"] for r in requests],
        "received_types": [r["type"] for r in replies],
        "roster_names_hex": [n.hex() for n in names],
    }


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    require(
        set(manifest["cases"]) == CASES
        and {p.name for p in (directory / "captures").iterdir()} == CASES,
        "Full-peer corpus inventory differs",
    )
    require(
        manifest["peer_binary_sha256"] == PEER
        and manifest["oracle_sha256"] == ORACLE_SHA256,
        "Corpus identity differs",
    )
    sources = {sha(p) for p in (directory / "sources").iterdir()} | {
        sha(directory / "capture_shx_session.guarded.py.txt")
    }
    agreement = (
        (directory.parent / "native-agreement-01/original-agreement.data")
        .read_bytes()
        .replace(b"\r\n", b"\r")
    )
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    build = json.loads(
        (directory.parent / "shx-build-01/build/manifest.json").read_text()
    )
    require(
        build["binary_sha256"] == PEER and build["source_commit"] == REVISION,
        "Missing identified build provenance",
    )
    require(
        len(host) == manifest["host_capture_packets"] == 170
        and manifest["host_kernel_drops"] == 0,
        "Host recorder inventory differs",
    )
    observations = []
    for name in sorted(CASES):
        case = directory / "captures" / name
        require(
            json.loads((case / "peer-profile.json").read_text()) == build,
            "Captured peer build profile differs",
        )
        check_terminal(case, sources)
        connections = check_packets(case, host, guest)
        semantic = check_semantics(case, connections, agreement)
        observations.append(
            {
                "case": name,
                **semantic,
                "connections": [
                    {k: v for k, v in c.items() if k not in {"sent", "received"}}
                    | {
                        "sent_bytes": len(c["sent"]),
                        "received_bytes": len(c["received"]),
                    }
                    for c in connections
                ],
            }
        )
    witness = verify_capture(directory / "witness")
    require(witness["status"] == "completed", "Controlled witness failed")
    require(witness["driver_sha256"] in sources, "Missing exact witness driver")
    reconcile(witness, host, guest)
    witness_requests = frames(
        bytes.fromhex(witness["streams"]["main"]["sent_hex"])[12:]
    )
    require(
        [f["type"] for f in witness_requests] == [107, 105]
        and fields(witness_requests[-1]) == {101: CHAT},
        "Controlled witness input differs",
    )
    require(
        any(
            f["type"] == 106 and CHAT in fields(f).get(101, b"")
            for f in witness["frames"]
        ),
        "Witness chat evidence missing",
    )
    return {
        "cases": len(CASES),
        "paired_connections": 7,
        "observations": observations,
        "scope": "One modern build of historical source; native160/161, roster/chat/list/download and opaque high-byte output. No universal peer, rendering,162/122 or optional-profile acceptance claim.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == "__main__":
    main()
