"""Prepare one finite native preonline activity and failure liveness timeline."""

import hashlib
import json
import operator
import sys
import typing as typ
from pathlib import Path

from native_auth_cases import authentication
from native_plan import packet
from native_wire_names import (
    TYPE_ACCEPT_AGREEMENT,
    TYPE_EMPTY_ACK,
    TYPE_GET_USER_ROSTER,
    TYPE_LOGIN,
)
from protocol_capture import ORACLE_SHA256
from script_cli import run

PORT = 15840
HELLO = "54525450484f544c00010002"
HELLO_REPLY = "5452545000000000"
NAME_B = b"TimerB"
MAX_SECONDS = 135
SCHEMA_VERSION = 1  # the layout version of the plan and of its schedule
CONTROL_ONLY = "control-only"  # the fixture profile the plan accepts
PARTIAL_A_HEX_CHARS = 18  # nine of the 20 header bytes of the first partial frame
PARTIAL_A_BYTES = 9  # the byte length that the first partial frame must have
PARTIAL_B_BYTES = 21  # 20 header bytes plus one payload byte
PARTIAL_B_HEX_TRIM = 2  # the final byte pair is cut from the second partial frame
PACKET_STEP_SECONDS = 5  # the interval between the outbound 500 frames
OUTBOUND_IDENTIFIER_BASE = 100  # the identifier of the first outbound 500 frame
ABSENT_OBSERVER_IDENTIFIER = 10  # the identifier of the 300 frame sent while B is out
STIMULUS_SECONDS = (35, 75, 120)  # the times at which a stimulus is applied
CHECKPOINTS_SECONDS = (30, 35, 45, 46, 50, 60, 61, 75, 90, 106, 120, 135)
MAX_SIMULTANEOUS = 5  # the most flows open at once
MAX_COORDINATOR_FLOWS = 7  # the most flows the coordinator may open
MAX_FRAMES = 128  # the most frames the coordinator records
MAX_BYTES = 128 * 1024  # the most bytes the coordinator records
MAX_TAIL_BYTES_PER_FLOW = 64 * 1024  # the most tail bytes read from one flow
HARD_DEADLINE_SECONDS = 160  # the time after which the coordinator stops
PORT_MESSAGE = "Only reserved control-only port15840 is prepared"
IDENTITY_MESSAGE = "Prepared runtime identity incomplete"


def digest(data: bytes) -> str:
    """Return the SHA-256 digest of ``data`` as hexadecimal text.

    Parameters
    ----------
    data : bytes
        The bytes to hash.

    Returns
    -------
    str
        The hexadecimal digest.
    """
    return hashlib.sha256(data).hexdigest()


def _partial_frames() -> tuple[str, str]:
    """Return the two deliberately truncated frames of the schedule.

    Returns
    -------
    tuple[str, str]
        The partial 107 frame of connection a and the partial 121 frame of b.
    """
    partial_a = packet(TYPE_LOGIN, 1)[:PARTIAL_A_HEX_CHARS]
    partial_b = packet(TYPE_ACCEPT_AGREEMENT, 2)[:-PARTIAL_B_HEX_TRIM]
    assert len(bytes.fromhex(partial_a)) == PARTIAL_A_BYTES, "frame A length"  # ruff: ignore[assert]  # a wrong length refuses the plan; -O skips it
    assert len(bytes.fromhex(partial_b)) == PARTIAL_B_BYTES, "frame B length"  # ruff: ignore[assert]  # a wrong length refuses the plan; -O skips it
    return partial_a, partial_b


def _admissions(partial_a: str, failed_login: str) -> list[dict[str, typ.Any]]:
    """Return the three admissions made at time zero.

    Parameters
    ----------
    partial_a : str
        The truncated frame that connection a sends first.
    failed_login : str
        The login that connection f sends with a wrong password.

    Returns
    -------
    list[dict[str, typing.Any]]
        The admission operations, in their scheduled order.
    """
    return [
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


def _outbound_sends() -> list[dict[str, typ.Any]]:
    """Return the 500 frames that connection o sends every five seconds.

    Returns
    -------
    list[dict[str, typing.Any]]
        One send operation for each step before the end of the window.
    """
    return [
        {
            "at_seconds": at,
            "label": f"o500-{at:03d}",
            "op": "send",
            "connection": "o",
            "hex": packet(
                TYPE_EMPTY_ACK,
                OUTBOUND_IDENTIFIER_BASE + at // PACKET_STEP_SECONDS,
            ),
        }
        for at in range(PACKET_STEP_SECONDS, MAX_SECONDS, PACKET_STEP_SECONDS)
    ]


def _stimuli() -> list[dict[str, typ.Any]]:
    """Return the stimuli that the schedule applies to the stimulus flows.

    Returns
    -------
    list[dict[str, typing.Any]]
        One stimulus operation for each time in ``STIMULUS_SECONDS``.
    """
    return [
        {
            "at_seconds": at,
            "label": f"s{at}-trtp",
            "op": "stimulus",
            "connection": f"s{at}",
            "hex": "",
        }
        for at in STIMULUS_SECONDS
    ]


def _checkpoints() -> list[dict[str, typ.Any]]:
    """Return the checkpoints that the schedule places in the window.

    Returns
    -------
    list[dict[str, typing.Any]]
        One checkpoint operation for each time in ``CHECKPOINTS_SECONDS``.
    """
    return [
        {
            "at_seconds": at,
            "label": f"checkpoint-{at:03d}",
            "op": "checkpoint",
            "connection": "",
            "hex": "",
        }
        for at in CHECKPOINTS_SECONDS
    ]


def _late_operations(b_login: str, partial_b: str) -> list[dict[str, typ.Any]]:
    """Return the operations that follow the checkpoints at 45 and 46 seconds.

    Parameters
    ----------
    b_login : str
        The login that connection b sends once it is selected.
    partial_b : str
        The truncated frame that connection b sends at 50 seconds.

    Returns
    -------
    list[dict[str, typing.Any]]
        The send operations of connections b and o.
    """
    return [
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
            "hex": packet(TYPE_GET_USER_ROSTER, ABSENT_OBSERVER_IDENTIFIER),
        },
        {
            "at_seconds": 50,
            "label": "b121-partial-body",
            "op": "send",
            "connection": "b",
            "hex": partial_b,
        },
    ]


def _schedule(operations: list[dict[str, typ.Any]]) -> dict[str, typ.Any]:
    """Return the schedule block with its bounds and modes.

    Parameters
    ----------
    operations : list[dict[str, typing.Any]]
        The operations, already sorted.

    Returns
    -------
    dict[str, typing.Any]
        The schedule, in the key order of the plan.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "duration_seconds": MAX_SECONDS,
        "operations": operations,
        "read_mode": (
            "nonblocking-all-open-sockets-after-each-operation-and-until-window-end"
        ),
        "checkpoints_seconds": list(CHECKPOINTS_SECONDS),
        "tail_mode": ("bounded-drain-all-owned-sockets-after-client-write-half-close"),
        "max_simultaneous": MAX_SIMULTANEOUS,
        "max_coordinator_flows": MAX_COORDINATOR_FLOWS,
        "max_frames": MAX_FRAMES,
        "max_bytes": MAX_BYTES,
        "max_tail_bytes_per_flow": MAX_TAIL_BYTES_PER_FLOW,
        "hard_deadline_seconds": HARD_DEADLINE_SECONDS,
    }


def source_plan(
    environment: dict[str, typ.Any], port: int = PORT
) -> dict[str, typ.Any]:
    """Build the liveness plan for a prepared control-only runtime.

    Parameters
    ----------
    environment : dict[str, typing.Any]
        The prepared runtime identity, as recorded in the runtime record.
    port : int
        The reserved control port, which must be ``PORT``.

    Returns
    -------
    dict[str, typing.Any]
        The complete plan, in the key order that ``write_plan`` serialises.

    Raises
    ------
    ValueError
        If the port or the fixture profile is not the reserved one, or if a
        runtime identity field is missing.
    """
    if port != PORT or environment.get("fixture_profile") != CONTROL_ONLY:
        raise ValueError(PORT_MESSAGE)
    required = (
        "emulator_pid",
        "emulator_starttime",
        "emulator_sha256",
        "emulator_netns_inode",
        "owned_working_image",
        "owned_working_image_inode",
    )
    if any(not environment.get(key) for key in required):
        raise ValueError(IDENTITY_MESSAGE)
    observer_login = authentication(
        b"admin", b"mothra19", name=b"TimerObserver", icon=b"\0\1", identifier=1
    )["hex"]
    b_login = authentication(
        b"admin", b"mothra19", name=NAME_B, icon=None, identifier=1
    )["hex"]
    failed_login = authentication(
        b"admin", b"wrong-password", name=b"TimerF", icon=None, identifier=1
    )["hex"]
    partial_a, partial_b = _partial_frames()
    operations = _admissions(partial_a, failed_login)
    operations.extend(_outbound_sends())
    operations.extend(_stimuli())
    operations.extend(_checkpoints())
    operations.extend(_late_operations(b_login, partial_b))
    operations.sort(key=operator.itemgetter("at_seconds", "label"))
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": "native-mac-oracle",
        "operator": "B74 isolated liveness coordinator",
        "oracle_sha256": ORACLE_SHA256,
        "gap_ids": ["GAP-005", "GAP-036"],
        "environment": environment,
        "endpoint": {"host": "127.0.0.1", "port": port},
        "observer_login_hex": observer_login,
        "hello_hex": HELLO,
        "hello_reply_hex": HELLO_REPLY,
        "schedule": _schedule(operations),
        "controls": {
            "preflight": (
                "separate unchanged 18-action control-only, 2 accounts/41 Files"
            ),
            "postflight": (
                "separate unchanged 18-action control-only after coordinator"
            ),
            "full_a7": "not_exercised",
            "all_closes": (
                "conditional wire observations, not required at 30/61 seconds"
            ),
        },
    }


def write_plan(output: Path, environment: dict[str, typ.Any], port: int = PORT) -> str:
    """Write ``plan.json`` and its source hashes into a new directory.

    Parameters
    ----------
    output : pathlib.Path
        The output directory, which must not exist yet.
    environment : dict[str, typing.Any]
        The prepared runtime identity.
    port : int
        The reserved control port.

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


def _command(*, runtime: str, output: str, port: int = PORT) -> None:
    """Write the plan for the runtime record and print its digest.

    Parameters
    ----------
    runtime : str
        The runtime record, a JSON file describing the prepared environment.
    output : str
        The new output directory.
    port : int
        The reserved control port.
    """
    record = Path(runtime).read_text(encoding="utf-8")
    identity = write_plan(Path(output), json.loads(record), port)
    sys.stdout.write(identity + "\n")


def main() -> None:
    """Prepare the liveness timeline from the command line."""
    run(_command, __doc__)


if __name__ == "__main__":
    main()
