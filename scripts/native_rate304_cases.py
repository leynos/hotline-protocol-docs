#!/usr/bin/env python3
"""Prepare one finite, isolated native 304 rate/reset observation."""

import hashlib
import json
import sys
from pathlib import Path

from native_auth_cases import authentication
from native_plan import packet, payload
from native_wire_names import (
    FIELD_ICON,
    FIELD_USER_ID,
    TYPE_EMPTY_ACK,
    TYPE_ENUMERATE_ACCOUNTS,
    TYPE_GET_FILE_INFO,
    TYPE_GET_USER_ROSTER,
    TYPE_LIST_FILES,
    TYPE_SET_CLIENT_INFO,
)
from protocol_capture import ORACLE_SHA256
from script_cli import run

PORT = 15880
HELLO = "54525450484f544c00010002"
HELLO_REPLY = "5452545000000000"
AGREEMENT_SHA256 = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
SUBJECT_NAME = b"fixture-low"
OBS_NAME = b"framing-fixture"
ZERO_ACCESS = "0000000000000000"
TEMPORARY_BAN = b"You are temporarily banned on this server."
TYPE_OBSERVER_TARGET = 303  # the observer control whose target is field 103
MAX_UINT16 = 65535  # the largest value of a two-byte big-endian field
OBSERVER_CONTROLS = (
    TYPE_ENUMERATE_ACCOUNTS,
    TYPE_LIST_FILES,
    TYPE_GET_FILE_INFO,
    TYPE_GET_USER_ROSTER,
    TYPE_OBSERVER_TARGET,
)


def digest(data: bytes) -> str:
    """Return the SHA-256 hexadecimal digest of ``data``.

    Returns
    -------
    str
        The lowercase hexadecimal digest.
    """
    return hashlib.sha256(data).hexdigest()


def source_plan(environment: dict, port: int = PORT) -> dict:
    """Return the plan for the reserved control-only port.

    Returns
    -------
    dict
        The complete plan, with the runtime identity and the four logins.

    Raises
    ------
    ValueError
        When the port or fixture profile differs, or the runtime identity is
        incomplete.
    """
    if port != PORT or environment.get("fixture_profile") != "control-only":
        message = "Only reserved control-only port15880 is prepared"
        raise ValueError(message)
    required = (
        "emulator_pid",
        "emulator_starttime",
        "emulator_sha256",
        "emulator_netns_inode",
        "owned_working_image",
        "owned_working_image_inode",
    )
    if any(not environment.get(key) for key in required):
        message = "Prepared runtime identity incomplete"
        raise ValueError(message)
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
        "scope": (
            "native 304 local counter and reset, one process, no full A7 postflight"
        ),
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
            "phase_mode": (
                "send 26 ordered 304+500 pairs, then concurrently drain both sockets"
            ),
            "phase_completion": (
                "26 subject301, 26 observer301 and 26 numbered500 ACKs within "
                "20 host seconds"
            ),
            "read_mode": (
                "bounded select drain of every open socket, no global frame order"
            ),
            "terminal_mode": "bounded EOF/RST/quiet with all observed raw tails",
            "postflight": "retained observer controls 348/200/206/300/303 only",
            "observer_303_target": (
                "TLV103 BE16 initial own-roster UID, resolved at runtime"
            ),
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
        "native_clock": (
            "host timing only unless separate read-only guest clock witness retained"
        ),
        "ban_probe_field100_hex": TEMPORARY_BAN.hex(),
        "not_exercised": [
            "mxd policy",
            "full A7 postflight",
            "ban expiry",
            "account writes",
        ],
    }


def update(identifier: int, icon: int) -> str:
    """Return the set-client-info request that changes the icon.

    Returns
    -------
    str
        The hexadecimal packet.

    Raises
    ------
    ValueError
        When ``icon`` does not fit in two bytes.
    """
    if not 0 <= icon <= MAX_UINT16:
        message = "Icon out of range"
        raise ValueError(message)
    return packet(
        TYPE_SET_CLIENT_INFO,
        identifier,
        payload([(FIELD_ICON, icon.to_bytes(2, "big"))]),
    )


def barrier(identifier: int) -> str:
    """Return the empty acknowledgement that closes one pair.

    Returns
    -------
    str
        The hexadecimal packet.
    """
    return packet(TYPE_EMPTY_ACK, identifier)


def observer_control(
    kind: int, identifier: int, observer_uid: int | None = None
) -> str:
    """Return one approved observer control request.

    Returns
    -------
    str
        The hexadecimal packet.

    Raises
    ------
    ValueError
        When the control is not approved, or the observer UID is missing,
        out of range, or given for a control that does not take one.
    """
    if kind not in OBSERVER_CONTROLS:
        message = "Unapproved observer control"
        raise ValueError(message)
    if kind == TYPE_OBSERVER_TARGET:
        if observer_uid is None or not 1 <= observer_uid <= MAX_UINT16:
            message = "303 requires resolved nonzero observer UID"
            raise ValueError(message)
        return packet(
            kind,
            identifier,
            payload([(FIELD_USER_ID, observer_uid.to_bytes(2, "big"))]),
        )
    if observer_uid is not None:
        message = "Only 303 accepts a dynamic observer UID"
        raise ValueError(message)
    return packet(kind, identifier)


def write_plan(output: Path, environment: dict, port: int = PORT) -> str:
    """Write ``plan.json`` and its source hashes into a new directory.

    Returns
    -------
    str
        The SHA-256 digest of the written ``plan.json``.
    """
    value = source_plan(environment, port)
    output.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(value, indent=2) + "\n").encode()
    (output / "plan.json").write_bytes(raw)
    identity = digest(raw)
    (output / "source-hashes.json").write_text(
        json.dumps({"plan.json": identity}) + "\n"
    )
    return identity


def write_observation_plan(*, runtime: str, output: str, port: int = PORT) -> None:
    """Write the observation plan for a runtime record and print its digest.

    The runtime record is read before the output directory is created, which
    must not exist yet.
    """
    environment = json.loads(Path(runtime).read_text(encoding="utf-8"))
    identity = write_plan(Path(output), environment, port)
    sys.stdout.write(identity + "\n")


def main() -> None:
    """Prepare the observation plan from the command line."""
    run(write_observation_plan, __doc__)


if __name__ == "__main__":
    main()
