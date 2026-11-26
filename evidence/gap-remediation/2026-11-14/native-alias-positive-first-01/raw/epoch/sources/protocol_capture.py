#!/usr/bin/env python3
"""Record planned TCP exchanges without treating tool tests as native evidence."""

import argparse
import hashlib
import json
import re
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

ORACLE_SHA256 = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
MAX_CAPTURE_BYTES = 8 * 1024 * 1024
VARIABLE = re.compile(r"\{([a-z][a-z0-9_]*)\}")


def digest(data: bytes) -> str:
    """Return a SHA-256 identity for exact retained bytes."""
    return hashlib.sha256(data).hexdigest()


def field_saves(step: dict) -> dict[str, int]:
    """Normalize field selectors without changing the received value bytes."""
    result = dict(step.get("save_fields", {}))
    if "save_field" in step:
        saved = step["save_field"]
        if saved["name"] in result:
            raise ValueError("Repeated saved-field variable")
        result[saved["name"]] = saved["id"]
    return result


def validate_plan(plan: dict) -> None:
    """Reject invalid actions and unresolved connections before opening sockets."""
    if plan.get("schema_version") != 1:
        raise ValueError("Unsupported capture schema")
    if plan.get("profile") not in {"synthetic-tool-test", "native-mac-oracle"}:
        raise ValueError("Unknown evidence profile")
    if not plan.get("operator") or not plan.get("gap_ids"):
        raise ValueError("Operator and gap IDs are required")
    if (
        plan["profile"] == "native-mac-oracle"
        and plan["oracle_sha256"] != ORACLE_SHA256
    ):
        raise ValueError("Native profile requires the recorded Mac oracle hash")
    for endpoint in plan["endpoints"].values():
        if not isinstance(endpoint["host"], str) or not 1 <= endpoint["port"] <= 65535:
            raise ValueError("Invalid endpoint")
    connections: set[str] = set()
    declared: set[str] = set()
    writes_closed: set[str] = set()
    variables: set[str] = set()
    for step in plan["steps"]:
        op = step["op"]
        name = step.get("connection", "")
        if op == "connect":
            if (
                name in declared
                or not name
                or step["endpoint"] not in plan["endpoints"]
            ):
                raise ValueError("Invalid connection declaration")
            connections.add(name)
            declared.add(name)
        elif op == "pause":
            if not 0 <= step["seconds"] <= 3600:
                raise ValueError("Invalid pause")
        elif op in {
            "send",
            "read",
            "read_frame",
            "read_eof",
            "close",
            "shutdown_write",
            "expect_quiet",
        }:
            if name not in connections:
                raise ValueError(f"Unknown connection: {name}")
            if op == "close":
                connections.remove(name)
            if op in {"send", "shutdown_write"} and name in writes_closed:
                raise ValueError("Connection write side is already closed")
            if op == "shutdown_write":
                writes_closed.add(name)
        else:
            raise ValueError(f"Unknown action: {op}")
        if not 0 < step.get("timeout", 2) <= 3600:
            raise ValueError("Invalid action timeout")
        if "size_from" in step and op != "read":
            raise ValueError("Only fixed-length reads can use size_from")
        if "match_frame" in step:
            match = step["match_frame"]
            bounds = {"is_reply": 255, "type": 65535, "id": 0xFFFFFFFF}
            if (
                op != "read_frame"
                or not match
                or any(
                    k not in bounds or not isinstance(v, int) or not 0 <= v <= bounds[k]
                    for k, v in match.items()
                )
            ):
                raise ValueError("Invalid frame match")
        if op == "read":
            if "size_from" in step:
                if "size" in step or step["size_from"] not in variables:
                    raise ValueError("Unknown or ambiguous read size")
            elif not 0 < step["size"] <= MAX_CAPTURE_BYTES:
                raise ValueError("Read size exceeds capture limit")
        if op == "send":
            for variable in VARIABLE.findall(step["hex"]):
                if variable not in variables:
                    raise ValueError(f"Unknown saved bytes: {variable}")
            literal = VARIABLE.sub("00", step["hex"])
            if len(bytes.fromhex(literal)) > MAX_CAPTURE_BYTES:
                raise ValueError("Send size exceeds capture limit")
        if "expect_hex" in step:
            bytes.fromhex(step["expect_hex"])
        if "save" in step:
            saved = step["save"]
            if op not in {"read", "read_frame", "read_eof"}:
                raise ValueError("Only received bytes can be saved")
            if not re.fullmatch(r"[a-z][a-z0-9_]*", saved["name"]):
                raise ValueError("Invalid saved-byte name")
            if saved["offset"] < 0 or not 0 < saved["size"] <= MAX_CAPTURE_BYTES:
                raise ValueError("Invalid saved-byte bounds")
            variables.add(saved["name"])
        for variable, field_id in field_saves(step).items():
            if op != "read_frame" or not 0 <= field_id <= 65535:
                raise ValueError("Only a frame field can be saved by ID")
            if not re.fullmatch(r"[a-z][a-z0-9_]*", variable):
                raise ValueError("Invalid saved-field name")
            variables.add(variable)


def decode_frame(data: bytes) -> dict:
    """Describe a physical frame; preserve malformed/fragmented payloads as bytes."""
    flags, reply, kind, identifier, error, total, size = struct.unpack(
        ">BBHIIII", data[:20]
    )
    result = {
        "flags": flags,
        "is_reply": reply,
        "type": kind,
        "id": identifier,
        "error": error,
        "total_size": total,
        "data_size": size,
        "payload_hex": data[20:].hex(),
    }
    if total != size:
        result["decode_note"] = "Physical fragment only; no logical TLV inference"
        return result
    payload = data[20:]
    fields = []
    offset = 2
    if len(payload) >= 2:
        count = int.from_bytes(payload[:2], "big")
        for _ in range(count):
            if offset + 4 > len(payload):
                break
            field, length = struct.unpack(">HH", payload[offset : offset + 4])
            if offset + 4 + length > len(payload):
                break
            fields.append(
                {"id": field, "hex": payload[offset + 4 : offset + 4 + length].hex()}
            )
            offset += 4 + length
        result["fields"] = fields
        result["declared_field_count"] = count
        result["unconsumed_hex"] = payload[offset:].hex()
    else:
        result["decode_note"] = "Payload lacks a complete count word"
    return result


class Recorder:
    """Retain every successful send/receive chunk and action-relative timing."""

    def __init__(self, plan: dict) -> None:
        """Start a recording of one plan, with empty socket, event and frame lists."""
        self.plan = plan
        self.started = time.monotonic_ns()
        self.started_at_utc = datetime.now(timezone.utc).isoformat()
        self.sockets: dict[str, socket.socket] = {}
        self.variables: dict[str, bytes] = {}
        self.events: list[dict] = []
        self.frames: list[dict] = []
        self.byte_count = 0

    def event(self, action: int, name: str, direction: str, data: bytes = b"") -> None:
        """Append a timed event and refuse a session that exceeds the capture limit."""
        self.byte_count += len(data)
        self.events.append(
            {
                "action": action,
                "connection": name,
                "event": direction,
                "elapsed_ns": time.monotonic_ns() - self.started,
                "hex": data.hex(),
            }
        )

        if data and self.byte_count > MAX_CAPTURE_BYTES:
            raise ValueError("Session exceeds capture limit")

    def read(self, action: int, name: str, size: int | None, deadline: float) -> bytes:
        """Receive bytes from a connection, recording each receive: until the size arrives, or until EOF without a size; EOFError on early EOF, TimeoutError at the deadline."""
        chunks = bytearray()
        connection = self.sockets[name]
        while size is None or len(chunks) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Action timed out")
            connection.settimeout(remaining)
            count = min(65536, size - len(chunks)) if size is not None else 65536
            data = connection.recv(count)
            if not data:
                self.event(action, name, "eof")
                if size is not None:
                    raise EOFError(f"EOF before {size} requested bytes")
                break
            self.event(action, name, "receive", data)
            chunks.extend(data)
        return bytes(chunks)

    def execute(self, action: int, step: dict) -> None:
        """Run one plan step against its connection, record its events and raise on a step failure."""
        name = step.get("connection", "")
        op = step["op"]
        deadline = time.monotonic() + step.get("timeout", 2)
        if op == "connect":
            endpoint = self.plan["endpoints"][step["endpoint"]]
            self.sockets[name] = socket.create_connection(
                (endpoint["host"], endpoint["port"]), step.get("timeout", 2)
            )
            self.event(action, name, "connect")
            self.events[-1].update(
                local_address=list(self.sockets[name].getsockname()),
                peer_address=list(self.sockets[name].getpeername()),
            )
        elif op == "close":
            self.sockets.pop(name).close()
            self.event(action, name, "close")
        elif op == "pause":
            time.sleep(step["seconds"])
            self.event(action, name, "pause")
        elif op == "shutdown_write":
            self.sockets[name].shutdown(socket.SHUT_WR)
            self.event(action, name, "shutdown_write")
        elif op == "expect_quiet":
            self.sockets[name].settimeout(step.get("timeout", 2))
            try:
                data = self.sockets[name].recv(1)
            except TimeoutError:
                self.event(action, name, "quiet")
            else:
                self.event(action, name, "receive" if data else "eof", data)
                raise ValueError("Expected bounded silence, received bytes or EOF")
        elif op == "send":
            encoded = VARIABLE.sub(lambda m: self.variables[m[1]].hex(), step["hex"])
            data = bytes.fromhex(encoded)
            if len(data) > MAX_CAPTURE_BYTES - self.byte_count:
                raise ValueError("Send exceeds remaining capture limit")
            while data:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Action timed out")
                self.sockets[name].settimeout(remaining)
                count = self.sockets[name].send(data)
                if not count:
                    raise EOFError("Socket closed during send")
                self.event(action, name, "send", data[:count])
                data = data[count:]
        else:
            if op == "read_frame":
                for _ in range(256):
                    header = self.read(action, name, 20, deadline)
                    size = int.from_bytes(header[16:20], "big")
                    if size > MAX_CAPTURE_BYTES - 20:
                        raise ValueError("Frame exceeds capture limit")
                    data = header + self.read(action, name, size, deadline)
                    decoded = decode_frame(data)
                    self.frames.append(
                        {"action": action, "connection": name, **decoded}
                    )
                    if all(
                        decoded[k] == v for k, v in step.get("match_frame", {}).items()
                    ):
                        break
                else:
                    raise ValueError("Frame match exceeds256-frame observation bound")
            else:
                size = step.get("size") if op == "read" else None
                if "size_from" in step:
                    raw = self.variables[step["size_from"]]
                    if not 1 <= len(raw) <= 4:
                        raise ValueError("Saved size must contain one to four bytes")
                    size = int.from_bytes(raw, "big")
                    if not 0 < size <= MAX_CAPTURE_BYTES:
                        raise ValueError("Read size exceeds capture limit")
                data = self.read(action, name, size, deadline)
            if "expect_hex" in step and data != bytes.fromhex(step["expect_hex"]):
                raise ValueError(
                    f"Expected {step['expect_hex']}, received {data.hex()}"
                )
            if "save" in step:
                saved = step["save"]
                end = saved["offset"] + saved["size"]
                if end > len(data):
                    raise ValueError("Saved bytes exceed received value")
                self.variables[saved["name"]] = data[saved["offset"] : end]
            for variable, field_id in field_saves(step).items():
                decoded = self.frames[-1]
                fields = decoded.get("fields", [])
                matches = [f for f in fields if f["id"] == field_id]
                if (
                    len(matches) != 1
                    or decoded.get("unconsumed_hex")
                    or decoded.get("declared_field_count") != len(fields)
                    or decoded["total_size"] != decoded["data_size"]
                ):
                    raise ValueError("Saved field is missing, ambiguous or incomplete")
                self.variables[variable] = bytes.fromhex(matches[0]["hex"])

    def streams(self) -> dict:
        """Return the sent and received bytes of each connection as hexadecimal text."""
        streams = {}
        for event in self.events:
            name = event["connection"]
            if not name:
                continue
            stream = streams.setdefault(name, {"sent_hex": "", "received_hex": ""})
            if event["event"] == "send":
                stream["sent_hex"] += event["hex"]
            elif event["event"] == "receive":
                stream["received_hex"] += event["hex"]
        return streams


def run_plan(plan_path: Path, binary: Path, output: Path) -> dict:
    """Record a plan into a new directory; retain a failed exchange as failure."""
    source = plan_path.read_bytes()
    plan = json.loads(source)
    validate_plan(plan)
    if digest(binary.read_bytes()) != plan["oracle_sha256"]:
        raise ValueError("Oracle binary hash mismatch")
    output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(plan)
    status, error, completed = "completed", "", 0
    try:
        for index, step in enumerate(plan["steps"]):
            recorder.execute(index, step)
            completed += 1
    except (OSError, EOFError, ValueError, KeyboardInterrupt) as failure:
        status, error = "failed", f"{type(failure).__name__}: {failure}"
    finally:
        for name, connection in recorder.sockets.items():
            connection.close()
            recorder.event(completed, name, "close")
    report = {
        "schema_version": 1,
        "profile": plan["profile"],
        "status": status,
        "native_conformance": False,
        "identity_scope": "Local binary hash verified; remote process identity is operator-reported",
        "operator": plan["operator"],
        "oracle_sha256": plan["oracle_sha256"],
        "plan_sha256": digest(source),
        "driver_sha256": digest(Path(__file__).read_bytes()),
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "started_at_utc": recorder.started_at_utc,
        "gap_ids": plan["gap_ids"],
        "completed_actions": completed,
        "error": error,
        "events": recorder.events,
        "frames": recorder.frames,
        "streams": recorder.streams(),
    }
    (output / "plan.json").write_bytes(source)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "checksums.sha256").write_text(
        "".join(
            f"{digest((output / name).read_bytes())}  {name}\n"
            for name in ["plan.json", "report.json"]
        )
    )
    return report


def verify_capture(directory: Path) -> dict:
    """Check retained bytes and stream reconstruction, without certifying a peer."""
    names = set()
    for line in (directory / "checksums.sha256").read_text().splitlines():
        expected, name = line.split("  ", 1)
        if name not in {"plan.json", "report.json"} or name in names:
            raise ValueError("Invalid checksum inventory")
        names.add(name)
        if digest((directory / name).read_bytes()) != expected:
            raise ValueError(f"Checksum mismatch: {name}")
    if names != {"plan.json", "report.json"}:
        raise ValueError("Incomplete checksum inventory")
    plan_bytes = (directory / "plan.json").read_bytes()
    plan = json.loads(plan_bytes)
    validate_plan(plan)
    report = json.loads((directory / "report.json").read_text())
    if report["profile"] != plan["profile"] or report["native_conformance"]:
        raise ValueError("Evidence profile mismatch")
    if (
        report["plan_sha256"] != digest(plan_bytes)
        or report["oracle_sha256"] != plan["oracle_sha256"]
    ):
        raise ValueError("Source identity mismatch")
    if report["status"] not in {"completed", "failed"}:
        raise ValueError("Unknown capture status")
    if report["status"] == "completed" and (
        report["error"] or report["completed_actions"] != len(plan["steps"])
    ):
        raise ValueError("Incomplete plan reported as completed")
    recorder = Recorder(plan)
    recorder.events = report["events"]
    if recorder.streams() != report["streams"]:
        raise ValueError("Stream reconstruction mismatch")
    frames = []
    for index, step in enumerate(plan["steps"]):
        if step["op"] != "read_frame":
            continue
        first_frame = len(frames)
        data = bytes.fromhex(
            "".join(
                e["hex"]
                for e in report["events"]
                if e["action"] == index
                and e["event"] == "receive"
                and e["connection"] == step["connection"]
            )
        )
        while len(data) >= 20:
            size = 20 + int.from_bytes(data[16:20], "big")
            if size > len(data):
                break
            frames.append(
                {
                    "action": index,
                    "connection": step["connection"],
                    **decode_frame(data[:size]),
                }
            )
            data = data[size:]
        if report["status"] == "completed":
            matched = frames[first_frame:]
            if data or not matched:
                raise ValueError("Completed frame read has incomplete bytes")
            if not all(
                matched[-1][k] == v for k, v in step.get("match_frame", {}).items()
            ):
                raise ValueError("Completed frame read did not match")
    if report["frames"] != frames:
        raise ValueError("Decoded frame mismatch")
    return report


def main() -> None:
    """Capture a planned exchange or verify an existing transcript."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture")
    capture.add_argument("plan", type=Path)
    capture.add_argument("--oracle-binary", type=Path, required=True)
    capture.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.command == "capture":
        report = run_plan(args.plan, args.oracle_binary, args.output)
    else:
        report = verify_capture(args.directory)
    print(
        f"{report['profile']}: {report['status']}; {report['completed_actions']} actions"
    )
    if report["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
