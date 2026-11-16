"""Prepare one bounded legacy-board 101/102/103 fixture for an isolated Mac."""

import hashlib
import importlib
import json
import typing as typ
from pathlib import Path

import capture_identity
from native_auth_cases import authentication
from native_plan import packet, payload
from native_wire_names import FIELD_DATA, TYPE_EMPTY_ACK
from protocol_capture import ORACLE_SHA256
from script_cli import run

# The scripts that make this plan, in the fixed order of their identity digest.
CAPTURE_MODULES = ("native_board_cases.py",)

PORT = 15860
HELLO = "54525450484f544c00010002"
HELLO_REPLY = "5452545000000000"
PATH = "Hotline19/MessageBoard.txt"
SEPARATOR = b"\r" + b"_" * 58 + b"\r"
MAX_CAPTURE_BYTES = 8 * 1024 * 1024
MAX_FRAMES = 300
WINDOW_SECONDS = 180
HARD_SECONDS = 210

BOARD_READ = 101  # the request type of a board read (the plan's "read_board")
BOARD_POST = 103  # the request type of a board post (the plan's "post")
INITIAL_READ_ID = 100  # the request identifier of the first board read
DENIED_READ_ID = 101  # the request identifier of the read that is denied
POST_ID = 1000  # post N carries the request identifier POST_ID + N
BARRIER_ID = 200  # barrier N carries BARRIER_ID + 2N and then BARRIER_ID + 2N + 1
READ_AFTER_ID = 110  # the read after post N carries READ_AFTER_ID + N
POST_COUNT = 13  # the posts that the plan makes, numbered from 0
UNMEASURED_POST = 10  # post 10 needs measured overhead, so it is not planned
REJECTED_POST = 12  # the 8193-byte post that the board must refuse
WAITING_CLOSE_POST = 2  # the waiting connection closes after this post
BARRIER_POSTS = 3  # posts below this index have barrier replies on two connections
FIRST_FIXED_POST = 3  # the fixed posts run from FIRST_FIXED_POST to LAST_FIXED_POST
LAST_FIXED_POST = 9
SHORT_FIXED_POST = 3  # the one fixed post whose payload is a byte short
FIXED_POST_BYTES = 8192
SHORT_POST_BYTES = 8191
REJECTED_BYTES = 8193
FILL_BASE = 65  # fixed post N is filled with the byte FILL_BASE + N
UNMEASURED_POST_MESSAGE = "P10 requires measured aggregate and segment overhead"
UNKNOWN_POST_MESSAGE = "Unknown fixed post"
UNREVIEWED_PORT_MESSAGE = "Only the reviewed control-only port15860 is prepared"
INCOMPLETE_RUNTIME_MESSAGE = "Prepared runtime identity incomplete"
BASELINE_MESSAGE = "Stopped empty-board baseline proof differs"


def digest(data: bytes) -> str:
    """Return the SHA-256 digest of ``data`` in hexadecimal.

    Returns
    -------
    str
        The hexadecimal digest.
    """
    return hashlib.sha256(data).hexdigest()


def post_data(index: int) -> bytes:
    """Return the payload of one fixed post.

    Returns
    -------
    bytes
        The payload that post ``index`` carries.

    Raises
    ------
    ValueError
        For post 10, whose overhead must be measured, and for any other index
        that is not a fixed post.
    """
    match index:
        case 0:
            return b""
        case 1:
            return b"board-A"
        case 2:
            return b"board-B"
        case 11:
            return b"X"
        case 12:
            return b"rejected:" + b"Z" * (REJECTED_BYTES - len(b"rejected:"))
        case 10:
            raise ValueError(UNMEASURED_POST_MESSAGE)
    if not FIRST_FIXED_POST <= index <= LAST_FIXED_POST:
        raise ValueError(UNKNOWN_POST_MESSAGE)
    size = SHORT_POST_BYTES if index == SHORT_FIXED_POST else FIXED_POST_BYTES
    prefix = f"P{index:02d}:".encode()
    return prefix + bytes((FILL_BASE + index,)) * (size - len(prefix))


def post_packet(index: int, data: bytes) -> str:
    """Return the hexadecimal request that posts ``data`` as post ``index``.

    Returns
    -------
    str
        The hexadecimal packet.
    """
    return packet(BOARD_POST, POST_ID + index, payload([(FIELD_DATA, data)]))


def planned_operations() -> list[dict[str, typ.Any]]:
    """Plan the operations of the fixture in the order they are performed.

    Returns
    -------
    list[dict[str, typing.Any]]
        The operations, each with its label, operation, connection and fields.
    """
    operations = [
        {
            "label": "initial101",
            "op": "read_board",
            "connection": "sender",
            "hex": packet(BOARD_READ, INITIAL_READ_ID),
        }
    ]
    operations.append({
        "label": "denied101",
        "op": "deny_read",
        "connection": "denied",
        "hex": packet(BOARD_READ, DENIED_READ_ID),
    })
    for index in range(POST_COUNT):
        operations.append({
            "label": f"p{index:02d}",
            "op": "post",
            "connection": "sender",
            "index": index,
            "data_hex": None if index == UNMEASURED_POST else post_data(index).hex(),
            "request_id": POST_ID + index,
            "hex": None
            if index == UNMEASURED_POST
            else post_packet(index, post_data(index)),
            "pace_seconds": 1,
            "expect_success": index != REJECTED_POST,
            "expect_update_recipients": ["sender", "eligible"]
            if index != REJECTED_POST
            else [],
            "optional_waiting": index < BARRIER_POSTS,
            "barriers": [
                {
                    "connection": "eligible",
                    "hex": packet(TYPE_EMPTY_ACK, BARRIER_ID + 2 * index),
                },
                {
                    "connection": "denied",
                    "hex": packet(TYPE_EMPTY_ACK, BARRIER_ID + 1 + 2 * index),
                },
            ]
            if index < BARRIER_POSTS
            else [],
            "read_after_hex": packet(BOARD_READ, READ_AFTER_ID + index)
            if index in {0, 1, 2, 9, 10, 11, 12}
            else None,
        })
        if index == WAITING_CLOSE_POST:
            operations.append({
                "label": "waiting-close",
                "op": "close_waiting",
                "connection": "waiting",
            })
    return operations


def source_plan(
    environment: dict[str, typ.Any], port: int = PORT
) -> dict[str, typ.Any]:
    """Return the plan of the board fixture for a verified runtime.

    Returns
    -------
    dict[str, typing.Any]
        The plan, which records the environment, the logins and the operations.

    Raises
    ------
    ValueError
        If the port is not the reviewed one, the runtime identity is incomplete,
        or the stopped board baseline differs from the recorded one.
    """
    if port != PORT or environment.get("fixture_profile") != "control-only":
        raise ValueError(UNREVIEWED_PORT_MESSAGE)
    required = (
        "emulator_pid",
        "emulator_starttime",
        "emulator_sha256",
        "emulator_netns_inode",
        "owned_working_image",
        "owned_working_image_inode",
    )
    if any(not environment.get(key) for key in required):
        raise ValueError(INCOMPLETE_RUNTIME_MESSAGE)
    board = environment.get("stopped_board_baseline", {})
    if board != {
        "path": PATH,
        "catalog_id": 11191,
        "data_size": 0,
        "resource_size": 0,
        "finder_type": "TEXT",
        "finder_creator": "ttxt",
    }:
        raise ValueError(BASELINE_MESSAGE)
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


def write_plan(
    directory: Path, environment: dict[str, typ.Any], port: int = PORT
) -> str:
    """Write the plan and the hashes of its sources into ``directory``.

    Returns
    -------
    str
        The SHA-256 digest of the written ``plan.json``.
    """
    value = source_plan(environment, port)
    directory.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(value, indent=2) + "\n").encode()
    (directory / "plan.json").write_bytes(raw)
    sha = digest(raw)
    control = importlib.import_module("native_board_control")
    record = capture_identity.identity(control.CAPTURE_MODULES)
    (directory / "source-hashes.json").write_text(
        json.dumps({
            "plan.json": sha,
            "native_board_cases.py": digest(Path(__file__).read_bytes()),
            "native_board_control.py": record["digest"],
            control.IDENTITY_KEY: record,
        })
        + "\n"
    )
    return sha


def write_from_runtime(*, runtime: Path, output: Path, port: int = PORT) -> None:
    """Write the plan of a runtime record and print the digest of its plan.

    Parameters
    ----------
    runtime : pathlib.Path
        The runtime record, a JSON file of the verified environment.
    output : pathlib.Path
        The directory to create; it must not exist.
    port : int
        The endpoint port, which must be the reviewed one.
    """
    print(write_plan(output, json.loads(runtime.read_text()), port))


def main() -> None:
    """Prepare the fixture from the command line."""
    run(write_from_runtime, __doc__)


if __name__ == "__main__":
    main()
