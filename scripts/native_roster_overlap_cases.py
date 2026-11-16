"""Prepare one two-session native 300/304 overlap, without account writes."""

import hashlib
import json
import sys
from pathlib import Path

import script_cli
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
    """Plan the handshake, the login and the three notices of one session.

    Returns
    -------
    list[dict]
        The steps that log the session in.
    """
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
    """Plan one request and the reply it must match.

    Returns
    -------
    list[dict]
        The send step and the read step of the exchange.
    """
    return [
        send(packet(kind, identifier), connection),
        read(connection, match_frame={"is_reply": 1, "id": identifier}),
    ]


def _check_environment(environment: dict, port: int) -> None:
    """Refuse a port or a runtime record that the overlap cannot run on.

    Parameters
    ----------
    environment : dict
        The runtime identity of the emulator and its lab.
    port : int
        The control port the overlap would use.

    Raises
    ------
    ValueError
        When the port is not the reserved one, the identity is incomplete, or
        the lab is not the control-only profile.
    """
    if port != MAX_PORT:
        message = "Roster overlap requires reserved port15820"
        raise ValueError(message)
    required = (
        "emulator_pid",
        "emulator_starttime",
        "emulator_sha256",
        "emulator_netns_inode",
        "owned_working_image",
        "owned_working_image_inode",
    )
    if any(key not in environment for key in required):
        message = "Runtime identity incomplete"
        raise ValueError(message)
    if environment.get("fixture_profile") != "control-only":
        message = "Only the control-only lab is prepared"
        raise ValueError(message)


def _steps() -> list[dict]:
    """Plan the two logins, the overlap setup and the teardown.

    Returns
    -------
    list[dict]
        The source steps, in the order they run.
    """
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
    return steps


def source_plan(environment: dict, port: int = MAX_PORT) -> dict:
    """Build the validated source plan of the overlap for one runtime record.

    Parameters
    ----------
    environment : dict
        The runtime identity of the emulator and its lab.
    port : int
        The control port; only the reserved port is accepted.

    Returns
    -------
    dict
        The plan, which has passed ``validate_plan``.
    """
    _check_environment(environment, port)
    steps = _steps()
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
    """Write the source plan and its hash record into a new directory.

    Parameters
    ----------
    output : pathlib.Path
        The directory to create; it must not exist.
    environment : dict
        The runtime identity of the emulator and its lab.
    port : int
        The control port; only the reserved port is accepted.

    Returns
    -------
    str
        The SHA-256 digest of ``plan.json``.
    """
    value = source_plan(environment, port)
    output.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(value, indent=2) + "\n").encode()
    (output / "plan.json").write_bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()
    (output / "source-hashes.json").write_text(json.dumps({"plan.json": sha}) + "\n")
    return sha


def command(*, runtime: str, output: str, port: int = MAX_PORT) -> None:
    """Write the overlap plan for a runtime record and print its digest.

    Parameters
    ----------
    runtime : str
        The runtime record, a JSON file.
    output : str
        The directory to create for the plan.
    port : int
        The control port; only the reserved port is accepted.
    """
    raw = Path(runtime).read_text(encoding="utf-8")
    digest = write_plan(Path(output), json.loads(raw), port)
    sys.stdout.write(f"{digest}\n")


def main() -> None:
    """Prepare the overlap plan from the command line."""
    script_cli.run(command, __doc__)


if __name__ == "__main__":
    main()
