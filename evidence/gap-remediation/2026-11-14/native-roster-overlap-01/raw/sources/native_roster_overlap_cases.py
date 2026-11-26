"""Prepare one two-session native 300/304 overlap, without account writes."""

import argparse
import hashlib
import json
from pathlib import Path

from native_auth_cases import authentication
from native_plan import close, connect, packet, payload, read, send
from protocol_capture import ORACLE_SHA256, validate_plan

OLD_A = b"Order A"
OLD_B = b"Order B"
NEW_B = b"Order New"
ICON_A = b"\0\x01"
ICON_B = b"\0\x02"
ICON_NEW = b"\0\x03"
MAX_PORT = 15820


def login_steps(connection: str, name: bytes, icon: bytes) -> list[dict]:
    """Return the steps that connect, handshake and log in a named connection with a name and icon."""
    return [
        connect(connection),
        send("54525450484f544c00010002", connection),
        {
            "op": "read",
            "connection": connection,
            "size": 8,
            "expect_hex": "5452545000000000",
            "timeout": 10,
        },
        authentication(
            b"admin", b"mothra19", name=name, icon=icon, connection=connection
        ),
        read(connection, match_frame={"is_reply": 1, "id": 1}),
        read(connection, match_frame={"type": 354}),
        read(connection, match_frame={"type": 109}),
    ]


def exchange(connection: str, kind: int, identifier: int) -> list[dict]:
    """Return the steps that send a request on a connection and read its reply."""
    return [
        send(packet(kind, identifier), connection),
        read(connection, match_frame={"is_reply": 1, "id": identifier}),
    ]


def source_plan(environment: dict, port: int = MAX_PORT) -> dict:
    """Build the roster overlap plan for the reserved port after checking that the runtime identity fields are present."""
    if port != MAX_PORT:
        raise ValueError("Roster overlap requires reserved port15820")
    required = (
        "emulator_pid",
        "emulator_starttime",
        "emulator_sha256",
        "emulator_netns_inode",
        "owned_working_image",
        "owned_working_image_inode",
    )
    if any(key not in environment for key in required):
        raise ValueError("Runtime identity incomplete")
    if environment.get("fixture_profile") != "control-only":
        raise ValueError("Only the control-only lab is prepared")
    steps = login_steps("a", OLD_A, ICON_A)
    steps += login_steps("b", OLD_B, ICON_B)
    steps += [
        read("a", match_frame={"type": 301}, save_field={"name": "b_uid", "id": 103})
    ]
    steps += exchange("a", 300, 10) + exchange("b", 300, 10)
    steps += [
        {"op": "expect_quiet", "connection": "a", "timeout": 0.25},
        {"op": "expect_quiet", "connection": "b", "timeout": 0.25},
        {"op": "shutdown_write", "connection": "b"},
        {"op": "read_eof", "connection": "b", "timeout": 10},
        close("b"),
        read("a", match_frame={"type": 302}),
        {"op": "shutdown_write", "connection": "a"},
        {"op": "read_eof", "connection": "a", "timeout": 10},
        close("a"),
    ]
    result = {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": "B70 isolated roster overlap operator",
        "oracle_sha256": ORACLE_SHA256,
        "gap_ids": ["GAP-035"],
        "environment": environment,
        "endpoints": {"control": {"host": "127.0.0.1", "port": port}},
        "steps": steps,
        "overlap": {
            "a_300": packet(300, 11),
            "b_304": packet(
                304, 20, payload([(102, NEW_B), (104, ICON_NEW), (113, b"\0\0")])
            ),
            "a_500": packet(500, 12),
            "b_500": packet(500, 12),
            "a_final_300": packet(300, 13),
            "max_frames": 32,
            "max_bytes": 65536,
            "drain_seconds": 5,
            "quiet_seconds": 0.5,
            "eof_seconds": 10,
        },
        "coordinator": {
            "schema_version": 1,
            "drain_action": -1,
            "operations": [
                {
                    "label": "a300-outstanding",
                    "op": "send",
                    "connection": "a",
                    "packet_key": "a_300",
                },
                {
                    "label": "b304-rename",
                    "op": "send",
                    "connection": "b",
                    "packet_key": "b_304",
                },
                {
                    "label": "a500-barrier",
                    "op": "send",
                    "connection": "a",
                    "packet_key": "a_500",
                },
                {
                    "label": "b500-barrier",
                    "op": "send",
                    "connection": "b",
                    "packet_key": "b_500",
                },
                {
                    "label": "overlap-drain",
                    "op": "drain",
                    "action": -1,
                    "required": [
                        ["a", 1, 0, 11],
                        ["a", 1, 0, 12],
                        ["b", 1, 0, 12],
                        ["a", 0, 301, 0],
                        ["b", 0, 301, 0],
                    ],
                },
                {
                    "label": "a300-stable",
                    "op": "send",
                    "connection": "a",
                    "packet_key": "a_final_300",
                },
                {
                    "label": "stable-drain",
                    "op": "drain",
                    "action": -1,
                    "required": [["a", 1, 0, 13]],
                },
                {"label": "quiet-a", "op": "quiet", "connection": "a"},
                {"label": "quiet-b", "op": "quiet", "connection": "b"},
            ],
            "teardown": "source steps from first shutdown_write through final close",
        },
        "expectation": {
            "case": "300-outstanding-304-rename",
            "a_name_hex": OLD_A.hex(),
            "b_old_name_hex": OLD_B.hex(),
            "b_new_name_hex": NEW_B.hex(),
            "a_icon_hex": ICON_A.hex(),
            "b_old_icon_hex": ICON_B.hex(),
            "b_new_icon_hex": ICON_NEW.hex(),
            "maximum_connections": 2,
            "full_file_baseline": "not_exercised",
        },
    }
    validate_plan(result)
    return result


def write_plan(output: Path, environment: dict, port: int = MAX_PORT) -> str:
    """Write the plan and its hash and return the plan's hash."""
    value = source_plan(environment, port)
    output.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(value, indent=2) + "\n").encode()
    (output / "plan.json").write_bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()
    (output / "source-hashes.json").write_text(json.dumps({"plan.json": sha}) + "\n")
    return sha


def main() -> None:
    """Write the plan for the runtime record and print its hash."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=MAX_PORT)
    args = parser.parse_args()
    print(write_plan(args.output, json.loads(args.runtime.read_text()), args.port))


if __name__ == "__main__":
    main()
