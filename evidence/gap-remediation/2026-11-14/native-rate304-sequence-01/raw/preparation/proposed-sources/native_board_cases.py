"""Prepare one bounded legacy-board 101/102/103 fixture for an isolated Mac."""

import argparse
import hashlib
import json
from pathlib import Path

from native_auth_cases import authentication
from native_plan import packet, payload
from protocol_capture import ORACLE_SHA256

PORT = 15860
HELLO = "54525450484f544c00010002"
HELLO_REPLY = "5452545000000000"
PATH = "Hotline19/MessageBoard.txt"
SEPARATOR = b"\r" + b"_" * 58 + b"\r"
MAX_CAPTURE_BYTES = 8 * 1024 * 1024
MAX_FRAMES = 300
WINDOW_SECONDS = 180
HARD_SECONDS = 210


def digest(data: bytes) -> str:
    """Return the SHA-256 hex digest of the bytes."""
    return hashlib.sha256(data).hexdigest()


def post_data(index: int) -> bytes:
    """Return the fixed body of a numbered board post."""
    if index == 0:
        return b""
    if index == 1:
        return b"board-A"
    if index == 2:
        return b"board-B"
    if index == 11:
        return b"X"
    if index == 12:
        return b"rejected:" + b"Z" * (8193 - len(b"rejected:"))
    if index == 10:
        raise ValueError("P10 requires measured aggregate and segment overhead")
    if not 3 <= index <= 9:
        raise ValueError("Unknown fixed post")
    size = 8191 if index == 3 else 8192
    prefix = f"P{index:02d}:".encode()
    return prefix + bytes((65 + index,)) * (size - len(prefix))


def post_packet(index: int, data: bytes) -> str:
    """Return the packet that posts a body on the board."""
    return packet(103, 1000 + index, payload([(101, data)]))


def planned_operations() -> list[dict]:
    """Return the planned board operations in order."""
    operations = [
        {
            "label": "initial101",
            "op": "read_board",
            "connection": "sender",
            "hex": packet(101, 100),
        }
    ]
    operations.append(
        {
            "label": "denied101",
            "op": "deny_read",
            "connection": "denied",
            "hex": packet(101, 101),
        }
    )
    for index in range(13):
        operations.append(
            {
                "label": f"p{index:02d}",
                "op": "post",
                "connection": "sender",
                "index": index,
                "data_hex": None if index == 10 else post_data(index).hex(),
                "request_id": 1000 + index,
                "hex": None if index == 10 else post_packet(index, post_data(index)),
                "pace_seconds": 1,
                "expect_success": index != 12,
                "expect_update_recipients": ["sender", "eligible"]
                if index != 12
                else [],
                "optional_waiting": index < 3,
                "barriers": [
                    {"connection": "eligible", "hex": packet(500, 200 + 2 * index)},
                    {"connection": "denied", "hex": packet(500, 201 + 2 * index)},
                ]
                if index < 3
                else [],
                "read_after_hex": packet(101, 110 + index)
                if index in {0, 1, 2, 9, 10, 11, 12}
                else None,
            }
        )
        if index == 2:
            operations.append(
                {
                    "label": "waiting-close",
                    "op": "close_waiting",
                    "connection": "waiting",
                }
            )
    return operations


def source_plan(environment: dict, port: int = PORT) -> dict:
    """Build the board plan for the reviewed control port after checking the runtime identity and the stopped board baseline."""
    if port != PORT or environment.get("fixture_profile") != "control-only":
        raise ValueError("Only the reviewed control-only port15860 is prepared")
    required = (
        "emulator_pid",
        "emulator_starttime",
        "emulator_sha256",
        "emulator_netns_inode",
        "owned_working_image",
        "owned_working_image_inode",
    )
    if any(not environment.get(key) for key in required):
        raise ValueError("Prepared runtime identity incomplete")
    board = environment.get("stopped_board_baseline", {})
    if board != {
        "path": PATH,
        "catalog_id": 11191,
        "data_size": 0,
        "resource_size": 0,
        "finder_type": "TEXT",
        "finder_creator": "ttxt",
    }:
        raise ValueError("Stopped empty-board baseline proof differs")
    credentials = {
        "sender": authentication(
            b"admin", b"mothra19", name=b"BoardSender", icon=b"\0\1"
        )["hex"],
        "eligible": authentication(
            b"admin", b"mothra19", name=b"BoardReader", icon=b"\0\2"
        )["hex"],
        "denied": authentication(
            b"fixture-low", b"next-pass", name=b"BoardDenied", icon=b"\0\3"
        )["hex"],
        "waiting": authentication(
            b"admin", b"mothra19", name=b"BoardWaiting", icon=None
        )["hex"],
    }
    return {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": "B79 isolated legacy board fixture",
        "gap_ids": ["GAP-046"],
        "oracle_sha256": ORACLE_SHA256,
        "environment": environment,
        "endpoint": {"host": "127.0.0.1", "port": port},
        "hello_hex": HELLO,
        "hello_reply_hex": HELLO_REPLY,
        "login_hex": credentials,
        "operations": planned_operations(),
        "bounds": {
            "case_flows": 4,
            "control_pre_flows": 1,
            "control_post_flows": 1,
            "case_numbered_requests": 32,
            "post_requests": 13,
            "successful_posts": 12,
            "max_frames": MAX_FRAMES,
            "max_bytes": MAX_CAPTURE_BYTES,
            "window_seconds": WINDOW_SECONDS,
            "hard_seconds": HARD_SECONDS,
            "full_a7": "not_exercised",
        },
        "static": {
            "format_address": "10082694",
            "separator_address": "100826bc",
            "path_address": "1008f87e",
            "separator_hex": SEPARATOR.hex(),
            "board_path": PATH,
            "oracle_packet": "state/delegation/legacy-board-oracle-01",
        },
    }


def write_plan(directory: Path, environment: dict, port: int = PORT) -> str:
    """Write the plan and the hashes of its sources and return the plan's hash."""
    value = source_plan(environment, port)
    directory.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(value, indent=2) + "\n").encode()
    (directory / "plan.json").write_bytes(raw)
    sha = digest(raw)
    (directory / "source-hashes.json").write_text(
        json.dumps(
            {
                "plan.json": sha,
                "native_board_cases.py": digest(Path(__file__).read_bytes()),
                "native_board_control.py": digest(
                    Path(__file__).with_name("native_board_control.py").read_bytes()
                ),
            }
        )
        + "\n"
    )
    return sha


def main() -> None:
    """Write the plan for the runtime record and print its hash."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    print(write_plan(args.output, json.loads(args.runtime.read_text()), args.port))


if __name__ == "__main__":
    main()
