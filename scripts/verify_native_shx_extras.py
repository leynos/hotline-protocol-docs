#!/usr/bin/env python3
"""Keep actual native name tests distinct from controlled banner/subject delivery."""

import argparse
import json
import re
from pathlib import Path

from native_packet_evidence import reconcile
from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import verify_capture
from serve_shx_fixture import MODES, SUBJECT, fixture_frames, wire
from shx_syscalls import socket_io
from verify_native_core import require
from verify_native_login_extras import preferences
from verify_native_shx import (
    LOGIN,
    PEER,
    check_packets,
    check_semantics,
    check_terminal,
    fields,
    frames,
    sha,
)

NAMES = {"ascii": b"mothra-peer-name", "macroman": b"mothra-peer-\x9a", "restored": b""}
COMMANDS = ["/version", LOGIN, "/who", "mothra-shx-basic-chat", "/quit"]


def receiver(
    case: Path,
    server_case: Path,
    host: list[dict],
    original: dict[str, bytes],
    sources: set[str],
) -> dict:
    mode = case.name
    commands = [
        "/version",
        LOGIN.replace(":15500", ":15510"),
        "/who -r",
        "mothra-shx-basic-chat",
        "/quit",
    ]
    report = check_terminal(case, sources, commands=commands)
    require(
        report["environment"]["controlled_receiver_fixture"]["profile"]
        == "controlled-receiver-fixture",
        "Receiver fixture was mislabelled native",
    )
    fixture = json.loads((server_case / "report.json").read_text())
    require(
        fixture["profile"] == "controlled-receiver-fixture"
        and fixture["native_conformance"] is False
        and fixture["status"] == "completed"
        and fixture["mode"] == mode,
        "Invalid controlled fixture report",
    )
    records = socket_io(
        (case / "syscalls.log").read_text(), server_ports=frozenset({15510})
    )
    require(
        len({(r["pid"], r["fd"], r["client_port"]) for r in records}) == 1,
        "Ambiguous receiver socket",
    )
    sent = b"".join(r["bytes"] for r in records if r["operation"] == "write")
    received = b"".join(r["bytes"] for r in records if r["operation"] == "read")
    port = records[0]["client_port"]
    client, server = ("127.0.0.1", port), ("127.0.0.1", 15510)
    require(
        fixture["client_address"] == list(client)
        and fixture["server_address"] == list(server),
        "Receiver server socket identity differs",
    )
    packets = lifetime(host, client, server, records[0]["timestamp_us"])
    require(
        stream(packets, client, server) == sent
        and stream(packets, server, client) == received,
        "Independent receiver packet bytes differ",
    )
    require(
        b"".join(
            bytes.fromhex(e["hex"])
            for e in fixture["events"]
            if e["event"] == "receive"
        )
        == sent
        and b"".join(
            bytes.fromhex(e["hex"]) for e in fixture["events"] if e["event"] == "send"
        )
        == received,
        "Fixture event bytes differ from real peer",
    )
    require(
        fixture["events"][-1]["event"] == "eof", "Fixture did not observe peer closure"
    )
    trace = (case / "syscalls.log").read_text()
    encoded = "".join(f"\\x{b:02x}" for b in report["command"][-3].encode())
    require(
        re.search(
            rf'^{records[0]["pid"]} \d+\.\d+ execve\("{re.escape(encoded)}", .* = 0$',
            trace,
            re.MULTILINE,
        )
        is not None,
        "Receiver process lacks identified exec",
    )
    require(
        sent[:12] == bytes.fromhex("54525450484f544c00010002"),
        "Receiver handshake differs",
    )
    requests, replies = frames(sent[12:]), frames(received[8:])
    require(
        [r["type"] for r in requests] == [107, 300, 300, 105]
        and [r["id"] for r in requests] == [1, 2, 3, 4],
        "Receiver did not reload and continue with chat",
    )
    require(
        fields(requests[0])
        == {
            104: b"\x01\xf4",
            105: bytes(b ^ 255 for b in b"admin"),
            106: bytes(b ^ 255 for b in b"mothra19"),
            102: b"shx-peer-a",
        },
        "Receiver fixture login bytes differ",
    )
    require(
        fields(requests[1]) == fields(requests[2]) == {}
        and fields(requests[3]) == {101: b"mothra-shx-basic-chat"},
        "Receiver continuation fields differ",
    )
    bootstrap = b"".join(
        original[k] for k in ["handshake", "login", "privileges", "agreement"]
    )
    require(received.startswith(bootstrap), "Receiver native bootstrap replay differs")
    expected_types = [0, 354, 109, 0] + ([122] if "banner" in mode else []) + [0, 106]
    require(
        [r["type"] for r in replies] == expected_types,
        "Receiver fixture response shape differs",
    )
    native_roster = frames(original["roster"])[0]["fields"]
    expected_roster = native_roster + (
        [{"id": 115, "hex": SUBJECT.hex()}] if "subject" in mode else []
    )
    rosters = [r for r in replies if r["is_reply"] and r["id"] in {2, 3}]
    require(
        len(rosters) == 2 and all(r["fields"] == expected_roster for r in rosters),
        "Subject addition or native roster bytes differ",
    )
    require(wire(replies[-1]) == original["chat"], "Continuation chat response differs")
    terminal = (case / "stdout.bin").read_bytes()
    notice = b"unknown header type 0x0000007a"
    subject_line = b"chat 0x0 subject: " + SUBJECT
    dump = case / "work/hx.dump"
    if "banner" in mode:
        banner = next(r for r in replies if r["type"] == 122)
        require(
            wire(banner) == original["banner"]
            and dump.is_file()
            and dump.read_bytes() == original["banner"],
            "Unknown banner dump differs from exact native frame",
        )
        require(terminal.count(notice) == 1, "Peer did not report unknown banner")
    else:
        require(
            not dump.exists() and notice not in terminal,
            "Control unexpectedly received a banner",
        )
    require(
        terminal.count(subject_line) == (2 if "subject" in mode else 0),
        "Peer subject display differs",
    )
    return {
        "mode": mode,
        "client_port": port,
        "sent_bytes": len(sent),
        "received_bytes": len(received),
        "banner": "unknown header, dumped, continued"
        if "banner" in mode
        else "not delivered",
        "subject": "displayed twice" if "subject" in mode else "absent",
    }


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    require(
        set(manifest["native_cases"]) == set(NAMES)
        and {p.name for p in (directory / "captures").iterdir()} == set(NAMES),
        "Native name session inventory differs",
    )
    require(
        set(manifest["receiver_cases"]) == MODES
        and {p.name for p in (directory / "receivers").iterdir()} == MODES
        and {p.name for p in (directory / "fixture-servers").iterdir()} == MODES,
        "Controlled receiver inventory differs",
    )
    require(manifest["peer_binary_sha256"] == PEER, "Receiver build differs")
    source_hashes = {sha(p) for p in (directory / "sources").iterdir()}
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == manifest["host_capture_packets"] == 230
        and manifest["host_kernel_drops"] == 0,
        "Host recording inventory differs",
    )
    agreement = (
        (directory.parent / "native-agreement-01/original-agreement.data")
        .read_bytes()
        .replace(b"\r\n", b"\r")
    )
    build = json.loads(
        (directory.parent / "shx-build-01/build/manifest.json").read_text()
    )
    native = []
    for name, expected in NAMES.items():
        case = directory / "captures" / name
        require(
            json.loads((case / "peer-profile.json").read_text()) == build,
            "Native name build profile differs",
        )
        require(
            preferences(directory / ("native-" + name))["name"] == expected,
            "Native preference name differs",
        )
        check_terminal(case, source_hashes, commands=COMMANDS)
        connections = check_packets(case, host, guest)
        result = check_semantics(
            case, connections, agreement, kind="basic-empty-name", login_name=expected
        )
        native.append({"case": name, "name_hex": expected.hex(), **result})
    require(
        preferences(directory / "native-restored")["bytes"]
        == preferences(directory.parent / "native-login-extras-01/native-restored")[
            "bytes"
        ],
        "Native baseline preferences were not restored",
    )
    require(
        {p.name for p in (directory / "flushes").iterdir()}
        == {"peer-" + n for n in NAMES},
        "Native setup control inventory differs",
    )
    for case in (directory / "flushes").iterdir():
        report = verify_capture(case)
        require(
            report["status"] == "completed"
            and report["driver_sha256"] in source_hashes,
            "Native setup control failed",
        )
        reconcile(report, host, guest)
    original = fixture_frames(directory.parent)
    require(
        frames(original["banner"])[0]["type"] == 122 and len(original["banner"]) == 71,
        "Missing exact native banner source",
    )
    receivers = []
    for mode in sorted(MODES):
        case = directory / "receivers" / mode
        require(
            json.loads((case / "peer-profile.json").read_text()) == build,
            "Controlled receiver build profile differs",
        )
        receivers.append(
            receiver(
                case,
                directory / "fixture-servers" / mode,
                host,
                original,
                source_hashes,
            )
        )
    return {
        "native_sessions": 3,
        "controlled_receiver_sessions": 4,
        "native_names": native,
        "receiver_matrix": receivers,
        "scope": "Native162 tolerance; controlled full-process delivery of native122 and source-derived115. One modern historical-source build; no original distributed binary, live SynHX server, banner UI or universal fallback claim.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == "__main__":
    main()
