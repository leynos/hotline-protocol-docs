"""Prepare one finite native preonline activity and failure liveness timeline."""

import argparse
import hashlib
import json
from pathlib import Path

from native_auth_cases import authentication
from native_plan import packet
from protocol_capture import ORACLE_SHA256

PORT = 15840
HELLO = "54525450484f544c00010002"
HELLO_REPLY = "5452545000000000"
NAME_B = b"TimerB"
MAX_SECONDS = 135


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_plan(environment: dict, port: int = PORT) -> dict:
    if port != PORT or environment.get("fixture_profile") != "control-only":
        raise ValueError("Only reserved control-only port15840 is prepared")
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
    observer_login = authentication(
        b"admin", b"mothra19", name=b"TimerObserver", icon=b"\0\1", identifier=1
    )["hex"]
    b_login = authentication(
        b"admin", b"mothra19", name=NAME_B, icon=None, identifier=1
    )["hex"]
    failed_login = authentication(
        b"admin", b"wrong-password", name=b"TimerF", icon=None, identifier=1
    )["hex"]
    partial_a = packet(107, 1)[:18]  # nine of the 20 header bytes
    partial_b = packet(121, 2)[:-2]  # 20 header bytes plus one payload byte
    assert len(bytes.fromhex(partial_a)) == 9
    assert len(bytes.fromhex(partial_b)) == 21
    operations = [
        {
            "at_seconds": 0,
            "label": "a-admit-partial107",
            "op": "admit",
            "connection": "a",
            "hex": partial_a,
        },
        {
            "at_seconds": 0,
            "label": "b-admit-preonline",
            "op": "admit",
            "connection": "b",
            "hex": "",
        },
        {
            "at_seconds": 0,
            "label": "f-admit-fail107",
            "op": "admit",
            "connection": "f",
            "hex": failed_login,
        },
    ]
    for at in range(5, MAX_SECONDS, 5):
        operations.append(
            {
                "at_seconds": at,
                "label": f"o500-{at:03d}",
                "op": "send",
                "connection": "o",
                "hex": packet(500, 100 + at // 5),
            }
        )
    for at in (35, 75, 120):
        operations.append(
            {
                "at_seconds": at,
                "label": f"s{at}-trtp",
                "op": "stimulus",
                "connection": f"s{at}",
                "hex": "",
            }
        )
    for at in (30, 35, 45, 46, 50, 60, 61, 75, 90, 106, 120, 135):
        operations.append(
            {
                "at_seconds": at,
                "label": f"checkpoint-{at:03d}",
                "op": "checkpoint",
                "connection": "",
                "hex": "",
            }
        )
    operations.extend(
        [
            {
                "at_seconds": 45,
                "label": "b107-selected",
                "op": "send",
                "connection": "b",
                "hex": b_login,
            },
            {
                "at_seconds": 46,
                "label": "o300-b-absent",
                "op": "send",
                "connection": "o",
                "hex": packet(300, 10),
            },
            {
                "at_seconds": 50,
                "label": "b121-partial-body",
                "op": "send",
                "connection": "b",
                "hex": partial_b,
            },
        ]
    )
    operations.sort(key=lambda op: (op["at_seconds"], op["label"]))
    return {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": "B74 isolated liveness coordinator",
        "oracle_sha256": ORACLE_SHA256,
        "gap_ids": ["GAP-005", "GAP-036"],
        "environment": environment,
        "endpoint": {"host": "127.0.0.1", "port": port},
        "observer_login_hex": observer_login,
        "hello_hex": HELLO,
        "hello_reply_hex": HELLO_REPLY,
        "schedule": {
            "schema_version": 1,
            "duration_seconds": MAX_SECONDS,
            "operations": operations,
            "read_mode": "nonblocking-all-open-sockets-after-each-operation-and-until-window-end",
            "checkpoints_seconds": [30, 35, 45, 46, 50, 60, 61, 75, 90, 106, 120, 135],
            "tail_mode": "bounded-drain-all-owned-sockets-after-client-write-half-close",
            "max_simultaneous": 5,
            "max_coordinator_flows": 7,
            "max_frames": 128,
            "max_bytes": 128 * 1024,
            "max_tail_bytes_per_flow": 64 * 1024,
            "hard_deadline_seconds": 160,
        },
        "controls": {
            "preflight": "separate unchanged 18-action control-only, 2 accounts/41 Files",
            "postflight": "separate unchanged 18-action control-only after coordinator",
            "full_a7": "not_exercised",
            "all_closes": "conditional wire observations, not required at 30/61 seconds",
        },
    }


def write_plan(output: Path, environment: dict, port: int = PORT) -> str:
    value = source_plan(environment, port)
    output.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(value, indent=2) + "\n").encode()
    (output / "plan.json").write_bytes(raw)
    identity = digest(raw)
    (output / "source-hashes.json").write_text(
        json.dumps({"plan.json": identity}) + "\n"
    )
    return identity


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    print(write_plan(args.output, json.loads(args.runtime.read_text()), args.port))


if __name__ == "__main__":
    main()
