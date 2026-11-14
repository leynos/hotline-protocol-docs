#!/usr/bin/env python3
"""Prepare one positive native alias-resolution rehearsal, without deletion."""

import argparse
import hashlib
import json
from pathlib import Path

from native_folder_cases import path
from native_plan import packet, payload
from protocol_capture import ORACLE_SHA256

PORT = 15980
ROOT = b"m-alias54-only"
TARGET = b"m-alias54-target"
TARGET_DATA = b"alias54-live-target\n"
ROOT_PATH = path((ROOT,))
HELLO = "54525450484f544c00010002"
HELLO_REPLY = "5452545000000000"
ENV_KEYS = (
    "fixture_profile",
    "emulator_pid",
    "emulator_starttime",
    "emulator_sha256",
    "emulator_netns_inode",
    "owned_working_image",
    "owned_working_image_inode",
    "owned_runtime",
    "initial_finf_sha256",
)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def example_operator_receipt() -> dict:
    """Illustrative schema only; never an as-run identity or action receipt."""
    return {
        "schema_version": 1,
        "target_name_hex": TARGET.hex(),
        "target_size": len(TARGET_DATA),
        "target_sha256": digest(TARGET_DATA),
        "alias_name_hex": b"m-alias54-target alias".hex(),
        "owned_destination_hex": ROOT.hex(),
        "finder_active": True,
        "unix_target_selected": True,
        "make_alias_enabled": True,
        "separate_alias": True,
        "copy_enabled": True,
        "paste_enabled": True,
        "unexpected_prompt": False,
        "overwrite_prompt": False,
        "action_count": 1,
        "screenshots": {
            key: "a" * 64
            for key in (
                "target",
                "make-alias-menu",
                "alias-result",
                "copy-menu",
                "paste-menu",
                "destination",
            )
        },
    }


def source_plan(environment: dict, port: int = PORT) -> dict:
    if port != PORT or environment.get("fixture_profile") != "control-only":
        raise ValueError("Only isolated control-only port 15980 is prepared")
    if any(not environment.get(key) for key in ENV_KEYS):
        raise ValueError("Incomplete runtime identity")
    profile = environment.get("capture_window_profile")
    purpose = environment.get("capture_window_purpose")
    if profile is None and purpose is None:
        epoch_seconds = 720
    elif (
        profile == "native-missing-alias-ui-30m-v1"
        and purpose == "native-missing-alias-positive"
    ):
        epoch_seconds = 1800
    else:
        raise ValueError("Unsupported alias capture window profile or purpose")
    pin = environment["initial_finf_sha256"]
    if (
        not isinstance(pin, str)
        or len(pin) != 64
        or any(char not in "0123456789abcdef" for char in pin)
    ):
        raise ValueError("Invalid pre-staged Finder-info SHA-256")
    requests = [
        {
            "label": "create-owned-folder",
            "kind": 205,
            "id": 10,
            "fields": [[201, ROOT.hex()], [202, "0000"]],
        },
        {"label": "read-owned-root", "kind": 200, "id": 11, "fields": [[202, "0000"]]},
        {
            "label": "read-copied-alias",
            "kind": 200,
            "id": 12,
            "fields": [[202, ROOT_PATH.hex()]],
        },
        {"label": "resolve-live-alias", "kind": 206, "id": 13, "fields": None},
    ]
    return {
        "schema_version": 1,
        "gap_id": "GAP-054",
        "phase": "positive-alias-only",
        "oracle_sha256": ORACLE_SHA256,
        "environment": environment,
        "endpoint": {"host": "127.0.0.1", "port": PORT},
        "hello": HELLO,
        "hello_reply": HELLO_REPLY,
        "requests": requests,
        "case_numbered_with_login": 5,
        "readiness_actions": 18,
        "readiness_numbered": 6,
        "total_numbered_including_readiness": 11,
        "handshakes": 2,
        "barrier500_requests": 0,
        "mutations": 1,
        "connections": {"readiness": 1, "case": 1},
        "limits": {
            "case_seconds": 210,
            "epoch_seconds": epoch_seconds,
            "start_margin_seconds": 390,
            "max_frames": 64,
            "max_bytes": 65536,
            "max_tail_bytes": 65536,
        },
        "operator_gate": {
            "stage": "after-read-owned-root-before-read-copied-alias",
            "schema_version": 1,
            "named_actions": [
                "Finder File > Make Alias",
                "Finder Edit > Copy",
                "Finder Edit > Paste",
            ],
            "external_receipt_required": True,
        },
        "target": {
            "basename_hex": TARGET.hex(),
            "bytes": len(TARGET_DATA),
            "sha256": digest(TARGET_DATA),
            "owned_folder_hex": ROOT.hex(),
        },
    }


def request_hex(spec: dict, alias: bytes | None = None) -> str:
    values = spec["fields"]
    if values is None:
        if spec["kind"] != 206 or alias is None or not 1 <= len(alias) <= 31:
            raise ValueError("Unresolved or invalid positive alias name")
        values = [[201, alias.hex()], [202, ROOT_PATH.hex()]]
    return packet(
        spec["kind"],
        spec["id"],
        payload([(int(field), bytes.fromhex(str(value))) for field, value in values]),
    )


def write_plan(output: Path, environment: dict, port: int = PORT) -> str:
    plan = source_plan(environment, port)
    output.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(plan, indent=2) + "\n").encode()
    (output / "plan.json").write_bytes(raw)
    (output / "source-hashes.json").write_text(
        json.dumps(
            {
                "plan.json": digest(raw),
                "native_missing_alias_cases.py": digest(Path(__file__).read_bytes()),
                "native_missing_alias_control.py": digest(
                    Path(__file__)
                    .with_name("native_missing_alias_control.py")
                    .read_bytes()
                ),
            },
            indent=2,
        )
        + "\n"
    )
    return digest(raw)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    print(write_plan(args.output, json.loads(args.runtime.read_text()), args.port))


if __name__ == "__main__":
    main()
