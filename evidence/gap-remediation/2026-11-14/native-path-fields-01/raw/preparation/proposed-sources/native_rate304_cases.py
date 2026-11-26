#!/usr/bin/env python3
"""Prepare one finite, isolated native 304 rate/reset observation."""

import argparse
import hashlib
import json
from pathlib import Path

from native_auth_cases import authentication
from native_plan import packet, payload
from protocol_capture import ORACLE_SHA256

PORT = 15880
HELLO = "54525450484f544c00010002"
HELLO_REPLY = "5452545000000000"
AGREEMENT_SHA256 = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
SUBJECT_NAME = b"fixture-low"
OBS_NAME = b"framing-fixture"
ZERO_ACCESS = "0000000000000000"
TEMPORARY_BAN = b"You are temporarily banned on this server."


def digest(data: bytes) -> str:
    """Return the SHA-256 hex digest of the bytes."""
    return hashlib.sha256(data).hexdigest()


def source_plan(environment: dict, port: int = PORT) -> dict:
    """Build the rate-limit plan for the reserved control port after checking that the runtime identity fields are present."""
    if port != PORT or environment.get("fixture_profile") != "control-only":
        raise ValueError("Only reserved control-only port15880 is prepared")
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
    logins = {
        "observer": authentication(b"admin", b"mothra19", name=OBS_NAME, icon=b"\0\1")[
            "hex"
        ],
        "paced": authentication(
            b"fixture-low", b"next-pass", name=b"rate304-p", icon=b"\0\1"
        )["hex"],
        "burst": authentication(
            b"fixture-low", b"next-pass", name=b"rate304-b", icon=b"\0\1"
        )["hex"],
        "probe": authentication(
            b"fixture-low", b"next-pass", name=b"rate304-probe", icon=b"\0\1"
        )["hex"],
    }
    return {
        "schema_version": 1,
        "gap_id": "GAP-045",
        "profile": "native-mac-oracle",
        "oracle_sha256": ORACLE_SHA256,
        "environment": environment,
        "endpoint": {"host": "127.0.0.1", "port": port},
        "logins": logins,
        "scope": "native 304 local counter and reset, one process, no full A7 postflight",
        "schedule": {
            "schema_version": 2,
            "flows": ["observer", "paced", "burst", "probe"],
            "preflight": "separate unchanged 18-action control before runner contact",
            "max_connections_including_preflight": 5,
            "max_simultaneous": 3,
            "accepted_per_subject": 26,
            "minimum_subject_quiet_seconds": 70,
            "maximum_26_trial_seconds": 20,
            "hard_case_seconds": 210,
            "minimum_epoch_remaining_seconds": 390,
            "max_frames": 256,
            "max_bytes": 262144,
            "max_tail_bytes_per_flow": 65536,
            "observer_500_interval_seconds": 5,
            "barrier": "same-subject numbered 500 ACK after each accepted 304",
            "phase_mode": "send 26 ordered 304+500 pairs, then concurrently drain both sockets",
            "phase_completion": "26 subject301, 26 observer301 and 26 numbered500 ACKs within 20 host seconds",
            "read_mode": "bounded select drain of every open socket, no global frame order",
            "terminal_mode": "bounded EOF/RST/quiet with all observed raw tails",
            "postflight": "retained observer controls 348/200/206/300/303 only",
            "observer_303_target": "TLV103 BE16 initial own-roster UID, resolved at runtime",
        },
        "request_ids": {
            "login": 1,
            "roster": 10,
            "paced_304": list(range(1000, 1027)),
            "paced_500": list(range(2000, 2027)),
            "burst_304": list(range(3000, 3027)),
            "burst_500": list(range(4000, 4026)),
            "observer_500_start": 5000,
            "observer_controls": {
                "348": 6000,
                "200": 6001,
                "206": 6002,
                "300": 6003,
                "303": 6004,
            },
        },
        "icons": {
            "accepted": list(range(2, 28)),
            "post_quiet": 28,
            "terminal": 28,
        },
        "native_clock": "host timing only unless separate read-only guest clock witness retained",
        "ban_probe_field100_hex": TEMPORARY_BAN.hex(),
        "not_exercised": [
            "mxd policy",
            "full A7 postflight",
            "ban expiry",
            "account writes",
        ],
    }


def update(identifier: int, icon: int) -> str:
    """Return a settings update packet that sets the icon."""
    if not (0 <= icon <= 65535):
        raise ValueError("Icon out of range")
    return packet(304, identifier, payload([(104, icon.to_bytes(2, "big"))]))


def barrier(identifier: int) -> str:
    """Return a barrier request packet."""
    return packet(500, identifier)


def observer_control(
    kind: int, identifier: int, observer_uid: int | None = None
) -> str:
    """Return an approved observer control packet, resolving the user identifier for the information request."""
    if kind not in (348, 200, 206, 300, 303):
        raise ValueError("Unapproved observer control")
    if kind == 303:
        if observer_uid is None or not 1 <= observer_uid <= 65535:
            raise ValueError("303 requires resolved nonzero observer UID")
        return packet(
            kind, identifier, payload([(103, observer_uid.to_bytes(2, "big"))])
        )
    if observer_uid is not None:
        raise ValueError("Only 303 accepts a dynamic observer UID")
    return packet(kind, identifier)


def write_plan(output: Path, environment: dict, port: int = PORT) -> str:
    """Write the plan and the hash of the plan file, and return that hash."""
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
    """Write the plan for the runtime record and print its hash."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    print(write_plan(args.output, json.loads(args.runtime.read_text()), args.port))


if __name__ == "__main__":
    main()
