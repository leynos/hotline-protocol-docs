#!/usr/bin/env python3
"""Deliver labelled receiver fixtures to a real peer; never a native-server oracle."""

import argparse
import json
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

from native_plan import packet, payload
from verify_native_shx import fields, frames

MODES = {"control", "banner", "subject", "banner-subject"}
SUBJECT = b"mothra-roster-subject"


def wire(frame: dict) -> bytes:
    return struct.pack(
        ">BBHIIII",
        frame["flags"],
        frame["is_reply"],
        frame["type"],
        frame["id"],
        frame["error"],
        frame["total_size"],
        frame["data_size"],
    ) + bytes.fromhex(frame["payload_hex"])


def fixture_frames(evidence: Path) -> dict[str, bytes]:
    """Recover exact native frames; subject addition is explicitly constructed."""
    report = json.loads(
        (evidence / "native-shx-01/captures/basic-empty-name/report.json").read_text()
    )
    # The peer report records terminal events, not decoded network frames.
    from shx_syscalls import socket_io

    records = socket_io(
        (evidence / "native-shx-01/captures/basic-empty-name/syscalls.log").read_text()
    )
    received = b"".join(r["bytes"] for r in records if r["operation"] == "read")
    native = frames(received[8:])
    banner_report = json.loads(
        (
            evidence / "native-login-extras-01/captures/name-a-190-delayed/report.json"
        ).read_text()
    )
    banner = next(f for f in banner_report["frames"] if f["type"] == 122)
    if report["status"] != "completed" or received[:8] != b"TRTP" + bytes(4):
        raise ValueError("Invalid retained bootstrap source")
    return {
        "handshake": received[:8],
        "login": wire(native[0]),
        "privileges": wire(native[1]),
        "agreement": wire(native[2]),
        "roster": wire(native[3]),
        "chat": wire(native[4]),
        "banner": wire(banner),
    }


def roster(original: bytes, identifier: int, subject: bool) -> bytes:
    frame = frames(original)[0]
    values = [(f["id"], bytes.fromhex(f["hex"])) for f in frame["fields"]]
    if subject:
        values.append((115, SUBJECT))
    return bytes.fromhex(packet(0, identifier, payload(values), reply=1))


def serve(evidence: Path, mode: str, output: Path) -> dict:
    if mode not in MODES:
        raise ValueError("Unknown receiver fixture")
    original = fixture_frames(evidence)
    output.mkdir(parents=True, exist_ok=False)
    events: list[dict] = []
    report = {
        "schema_version": 1,
        "profile": "controlled-receiver-fixture",
        "native_conformance": False,
        "mode": mode,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Full real peer receives retained native bootstrap/banner bytes and optional source-derived subject field. This listener is a controlled fixture, not native or historical SynHX server execution.",
        "events": events,
        "status": "running",
    }
    try:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 15510))
            listener.listen(1)
            listener.settimeout(30)
            (output / "ready.json").write_text(
                json.dumps({"endpoint": ["127.0.0.1", 15510]})
            )
            connection, address = listener.accept()
            with connection:
                connection.settimeout(30)
                report["client_address"] = list(address)
                report["server_address"] = list(connection.getsockname())

                def read(size: int) -> bytes:
                    value = bytearray()
                    while len(value) < size:
                        chunk = connection.recv(size - len(value))
                        if not chunk:
                            raise EOFError("Peer closed before fixture request")
                        events.append(
                            {
                                "event": "receive",
                                "timestamp_us": time.time_ns() // 1000,
                                "hex": chunk.hex(),
                            }
                        )
                        value.extend(chunk)
                    return bytes(value)

                def send(value: bytes) -> None:
                    connection.sendall(value)
                    events.append(
                        {
                            "event": "send",
                            "timestamp_us": time.time_ns() // 1000,
                            "hex": value.hex(),
                        }
                    )

                def request() -> dict:
                    header = read(20)
                    size = int.from_bytes(header[16:20], "big")
                    if size > 65535:
                        raise ValueError("Fixture request exceeds bound")
                    return frames(header + read(size))[0]

                if read(12) != bytes.fromhex("54525450484f544c00010002"):
                    raise ValueError("Unexpected peer handshake")
                login = request()
                if login["type"] != 107 or login["id"] != 1:
                    raise ValueError("Unexpected peer login")
                send(
                    original["handshake"]
                    + original["login"]
                    + original["privileges"]
                    + original["agreement"]
                )
                first = request()
                if first["type"] != 300:
                    raise ValueError("Missing automatic roster")
                send(roster(original["roster"], first["id"], "subject" in mode))
                if "banner" in mode:
                    send(original["banner"])
                reload = request()
                if reload["type"] != 300:
                    raise ValueError("Missing explicit roster reload")
                send(roster(original["roster"], reload["id"], "subject" in mode))
                chat = request()
                if chat["type"] != 105 or fields(chat) != {
                    101: b"mothra-shx-basic-chat"
                }:
                    raise ValueError("Peer did not continue with exact chat")
                send(original["chat"])
                if connection.recv(1) != b"":
                    raise ValueError("Unexpected trailing peer data")
                events.append(
                    {"event": "eof", "timestamp_us": time.time_ns() // 1000, "hex": ""}
                )
        report["status"] = "completed"
    except (OSError, ValueError, EOFError) as exc:
        report["status"], report["error"] = "failed", str(exc)
    finally:
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--mode", choices=sorted(MODES), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = serve(args.evidence, args.mode, args.output)
    print(result["profile"], result["mode"], result["status"])
    raise SystemExit(result["status"] != "completed")


if __name__ == "__main__":
    main()
