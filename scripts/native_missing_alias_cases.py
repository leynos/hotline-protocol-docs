#!/usr/bin/env python3
"""Prepare one positive native alias-resolution rehearsal, without deletion."""

import hashlib
import json
import sys
import typing as typ
from pathlib import Path

from native_folder_cases import path
from native_plan import packet, payload
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    TYPE_CREATE_FOLDER,
    TYPE_GET_FILE_INFO,
    TYPE_LIST_FILES,
)
from protocol_capture import ORACLE_SHA256
from script_cli import run

PORT = 16020
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
DEFAULT_EPOCH_SECONDS = 720
NAMED_WINDOW_EPOCH_SECONDS = 1800
NAMED_WINDOW_PROFILE = "native-missing-alias-ui-30m-v1"
NAMED_WINDOW_PURPOSE = "native-missing-alias-positive"
SHA256_HEX_LENGTH = 64
HEX_DIGITS = "0123456789abcdef"
SCREENSHOT_KEYS = (
    "target",
    "make-alias-menu",
    "alias-result",
    "copy-menu",
    "paste-menu",
    "destination",
)
# The longest alias name that a positive alias request may carry.
MAX_ALIAS_BYTES = 31


def digest(raw: bytes) -> str:
    """Return the hexadecimal SHA-256 digest of raw bytes.

    Parameters
    ----------
    raw : bytes
        The bytes to digest.

    Returns
    -------
    str
        The lowercase hexadecimal digest.
    """
    return hashlib.sha256(raw).hexdigest()


def example_operator_receipt() -> dict[str, typ.Any]:
    """Illustrative schema only; never an as-run identity or action receipt.

    Returns
    -------
    dict[str, typing.Any]
        A receipt of the expected shape, with placeholder values.
    """
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
        "screenshots": dict.fromkeys(SCREENSHOT_KEYS, "a" * 64),
    }


def check_identity(environment: dict[str, typ.Any], port: int) -> None:
    """Refuse any port, fixture profile or runtime identity that is not complete.

    Parameters
    ----------
    environment : dict[str, typing.Any]
        The runtime record of the isolated control run.
    port : int
        The endpoint port the plan would name.

    Raises
    ------
    ValueError
        When the port or fixture profile is not the isolated control, or when a
        runtime identity key is missing or empty.
    """
    if port != PORT or environment.get("fixture_profile") != "control-only":
        message = "Only isolated control-only port 16020 is prepared"
        raise ValueError(message)
    if any(not environment.get(key) for key in ENV_KEYS):
        message = "Incomplete runtime identity"
        raise ValueError(message)


def capture_epoch_seconds(environment: dict[str, typ.Any]) -> int:
    """Return the capture window of the runtime record.

    Parameters
    ----------
    environment : dict[str, typing.Any]
        The runtime record, which may name a capture window.

    Returns
    -------
    int
        The default window when neither window key is present, or the named
        alias window when both keys carry the named values.

    Raises
    ------
    ValueError
        When only one window key is present, or when the named values differ.
    """
    profile = environment.get("capture_window_profile")
    purpose = environment.get("capture_window_purpose")
    if profile is None and purpose is None:
        return DEFAULT_EPOCH_SECONDS
    if profile == NAMED_WINDOW_PROFILE and purpose == NAMED_WINDOW_PURPOSE:
        return NAMED_WINDOW_EPOCH_SECONDS
    message = "Unsupported alias capture window profile or purpose"
    raise ValueError(message)


def is_hex_digest(value: object) -> bool:
    """Return whether a value is a string of 64 lowercase hexadecimal characters.

    Returns
    -------
    bool
        True only for a string of exactly 64 characters from ``HEX_DIGITS``.
    """
    if not isinstance(value, str):
        return False
    if len(value) != SHA256_HEX_LENGTH:
        return False
    return all(char in HEX_DIGITS for char in value)


def check_pin(environment: dict[str, typ.Any]) -> None:
    """Refuse a pre-staged Finder-info digest that is not 64 lowercase hex digits.

    Raises
    ------
    ValueError
        When the digest is not a string of 64 lowercase hexadecimal characters.
    """
    pin = environment["initial_finf_sha256"]
    if not is_hex_digest(pin):
        message = "Invalid pre-staged Finder-info SHA-256"
        raise ValueError(message)


def requests() -> list[dict[str, typ.Any]]:
    """Return the four numbered requests of the positive alias case.

    Returns
    -------
    list[dict[str, typing.Any]]
        The requests in send order. The last carries no fields until the alias
        name is known.
    """
    return [
        {
            "label": "create-owned-folder",
            "kind": TYPE_CREATE_FOLDER,
            "id": 10,
            "fields": [[FIELD_FILE_NAME, ROOT.hex()], [FIELD_FILE_PATH, "0000"]],
        },
        {
            "label": "read-owned-root",
            "kind": TYPE_LIST_FILES,
            "id": 11,
            "fields": [[FIELD_FILE_PATH, "0000"]],
        },
        {
            "label": "read-copied-alias",
            "kind": TYPE_LIST_FILES,
            "id": 12,
            "fields": [[FIELD_FILE_PATH, ROOT_PATH.hex()]],
        },
        {
            "label": "resolve-live-alias",
            "kind": TYPE_GET_FILE_INFO,
            "id": 13,
            "fields": None,
        },
    ]


def source_plan(
    environment: dict[str, typ.Any], port: int = PORT
) -> dict[str, typ.Any]:
    """Return the plan of the positive alias case for one runtime record.

    Parameters
    ----------
    environment : dict[str, typing.Any]
        The runtime record of the isolated control run.
    port : int
        The endpoint port, which must be the isolated control port.

    Returns
    -------
    dict[str, typing.Any]
        The plan, with its requests, limits, operator gate and target. A refused
        port, identity, capture window or pin raises ``ValueError``.
    """
    check_identity(environment, port)
    epoch_seconds = capture_epoch_seconds(environment)
    check_pin(environment)
    return {
        "schema_version": 1,
        "gap_id": "GAP-054",
        "phase": "positive-alias-only",
        "oracle_sha256": ORACLE_SHA256,
        "environment": environment,
        "endpoint": {"host": "127.0.0.1", "port": PORT},
        "hello": HELLO,
        "hello_reply": HELLO_REPLY,
        "requests": requests(),
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


def usable_alias(kind: int, alias: bytes | None) -> bool:
    """Return whether a request of this kind can resolve this alias name.

    Returns
    -------
    bool
        True only for a file-information request with a name of 1 to 31 bytes.
    """
    if kind != TYPE_GET_FILE_INFO or alias is None:
        return False
    return 1 <= len(alias) <= MAX_ALIAS_BYTES


def request_hex(spec: dict[str, typ.Any], alias: bytes | None = None) -> str:
    """Return the hexadecimal frame of one request of the plan.

    Parameters
    ----------
    spec : dict[str, typing.Any]
        One request of the plan.
    alias : bytes | None
        The resolved alias name, required for the request that resolves it.

    Returns
    -------
    str
        The hexadecimal frame.

    Raises
    ------
    ValueError
        When the request needs an alias name and the name is missing or too long.
    """
    values = spec["fields"]
    if values is None:
        if alias is None or not usable_alias(spec["kind"], alias):
            message = "Unresolved or invalid positive alias name"
            raise ValueError(message)
        values = [[FIELD_FILE_NAME, alias.hex()], [FIELD_FILE_PATH, ROOT_PATH.hex()]]
    return packet(
        spec["kind"],
        spec["id"],
        payload([(int(field), bytes.fromhex(str(value))) for field, value in values]),
    )


def write_plan(output: Path, environment: dict[str, typ.Any], port: int = PORT) -> str:
    """Write the plan and its source hashes into a new output directory.

    Parameters
    ----------
    output : pathlib.Path
        The output directory, which must not exist yet.
    environment : dict[str, typing.Any]
        The runtime record of the isolated control run.
    port : int
        The endpoint port, which must be the isolated control port.

    Returns
    -------
    str
        The SHA-256 digest of the written plan bytes. A refused plan raises
        ``ValueError`` before the directory is created.
    """
    plan = source_plan(environment, port)
    output.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(plan, indent=2) + "\n").encode()
    (output / "plan.json").write_bytes(raw)
    hashes = {
        "plan.json": digest(raw),
        "native_missing_alias_cases.py": digest(Path(__file__).read_bytes()),
        "native_missing_alias_control.py": digest(
            Path(__file__).with_name("native_missing_alias_control.py").read_bytes()
        ),
    }
    (output / "source-hashes.json").write_text(
        json.dumps(hashes, indent=2) + "\n", encoding="utf-8"
    )
    return digest(raw)


def write_command(*, runtime: str, output: str, port: int = PORT) -> None:
    """Write one plan from a runtime record and print the plan digest.

    The runtime record is read first, then the output directory is created,
    which must not exist yet.
    """
    environment = json.loads(Path(runtime).read_text(encoding="utf-8"))
    sys.stdout.write(f"{write_plan(Path(output), environment, port)}\n")


def main() -> None:
    """Prepare the positive alias plan from the command line."""
    run(write_command, __doc__)


if __name__ == "__main__":
    main()
