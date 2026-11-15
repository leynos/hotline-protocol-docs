#!/usr/bin/env python3
"""Serve bounded field variants to the identified shx peer on loopback."""

import argparse
import json
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from native_plan import packet, payload
from serve_shx_fixture import fixture_frames, roster
from verify_native_shx import fields, frames

CASES = ("control", "omit-161", "vary-161", "unknown-login", "early-122")


def login_reply(original: bytes, case: str) -> bytes:
    frame = frames(original)[0]
    values = [(f["id"], bytes.fromhex(f["hex"])) for f in frame["fields"]]
    if case == "omit-161":
        values = [(key, value) for key, value in values if key != 161]
    elif case == "vary-161":
        values = [(key, b"\0\1" if key == 161 else value) for key, value in values]
    elif case == "unknown-login":
        values.append((32767, b"mothra-unknown-login"))
    return bytes.fromhex(
        packet(frame["type"], frame["id"], payload(values), reply=frame["is_reply"])
    )


def serve(evidence: Path, case: str, port: int, output: Path) -> dict:
    if case not in CASES or not 15600 <= port <= 15609:
        raise ValueError("Case or reserved loopback port differs")
    original = fixture_frames(evidence)
    output.mkdir(parents=True, exist_ok=False)
    events: list[dict] = []
    report = {
        "schema_version": 1,
        "profile": "controlled-receiver-fixture",
        "native_conformance": False,
        "case": case,
        "endpoint": ["127.0.0.1", port],
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "events": events,
        "status": "running",
    }
    try:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
            listener.listen(1)
            listener.settimeout(30)
            (output / "ready.json").write_text(
                json.dumps({"endpoint": ["127.0.0.1", port]}) + "\n"
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
                report["login_fields"] = sorted(fields(login))
                send(original["handshake"] + login_reply(original["login"], case))
                send(original["privileges"] + original["agreement"])
                if case == "early-122":
                    send(original["banner"])
                first = request()
                if first["type"] != 300:
                    raise ValueError("Missing automatic roster")
                send(roster(original["roster"], first["id"], False))
                reload = request()
                if reload["type"] != 300:
                    raise ValueError("Missing explicit roster reload")
                send(roster(original["roster"], reload["id"], False))
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
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = serve(args.evidence, args.case, args.port, args.output)
    print(result["profile"], result["case"], result["status"])
    raise SystemExit(result["status"] != "completed")


if __name__ == "__main__":
    main()
