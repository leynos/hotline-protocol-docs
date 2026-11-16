"""Gate the plans and the observed frames of the configured-ban fixture.

Part of the configured-ban capture script (``native_configured_ban_control``),
whose ``CAPTURE_MODULES`` lists this module and which re-exports every public
name below. Each gate fails closed with a ``ValueError`` that names what
differed.
"""

import json
import typing as typ

import native_configured_ban_cases as cases
import native_control_readiness as base
from native_auth_cases import complement
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_DATA,
    FIELD_ERROR_TEXT,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    FIELD_USER_ID,
    TYPE_LOGIN_AGREEMENT,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
)
from protocol_capture import digest, validate_plan
from verify_native_auth import reply, roster
from verify_native_core import require
from verify_native_shx import fields

if typ.TYPE_CHECKING:
    from pathlib import Path

EXPECTED_PLANS = {"readiness", "guard", "seed", "held-apply"}
HELD_ACTIONS = 17
# The held-apply plan: its actions, then the EOF tail of each of the two sockets.
HELD_STEPS = HELD_ACTIONS + 6
SAVE_MARKER = b"reviewed-save\n"
CONTROL_PORT = 15770
# Reply identifiers of the account guard and seed exchanges.
LOOKUP_REPLY = 30
CREATE_REPLY = 31
READBACK_REPLY = 32
# The roster reply that follows the target's login.
ROSTER_REPLY = 32
UID_BYTES = 2
MIN_TARGET_FRAMES = 3
ROSTER_ROWS = 2
LOGIN_REPLY_SHAPE = (0, 1, 1, 0)
# The wire form of the 110 request type, which this fixture must never send.
ACCESS_REQUEST_TYPE = b"\0\x6e"
ACCESS_REQUEST_SLICE = slice(2, 4)
HEADER_HEX_CHARS = 8
type Report = dict[str, typ.Any]


def account_gate(report: Report, *, absent: bool) -> None:
    """Check the owned account before it is created or after it is seeded.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The case report.
    absent : bool
        ``True`` for the guard (the key must not exist), ``False`` for the seed
        (the account must be created and stored at zero privilege).
    """
    require(report["status"] == "completed", "Account guard or seed incomplete")
    base.login_gate(report["frames"])
    record = reply(report, LOOKUP_REPLY if absent else READBACK_REPLY)
    if absent:
        require(
            record["error"] == 1
            and fields(record)
            == {FIELD_ERROR_TEXT: b"No account with login \xd2" + cases.KEY + b"\xd3."},
            "Owned key already exists",
        )
    else:
        require(
            reply(report, CREATE_REPLY)["error"] == 0, "Owned account creation failed"
        )
        require(
            record["error"] == 0
            and fields(record)
            == {
                FIELD_NAME: cases.NAME,
                FIELD_LOGIN: complement(cases.KEY),
                FIELD_PASSWORD: b"x",
                FIELD_ACCESS_BITMAP: cases.ZERO,
            },
            "Stored owned target is not zero privilege",
        )


def _target_login(target: list[Report]) -> None:
    """Check the target's login reply, its zero access and its agreement."""
    require(
        len(target) >= MIN_TARGET_FRAMES
        and (
            target[0]["type"],
            target[0]["is_reply"],
            target[0]["id"],
            target[0]["error"],
        )
        == LOGIN_REPLY_SHAPE
        and fields(target[1]) == {FIELD_ACCESS_BITMAP: cases.ZERO}
        and (target[2]["type"], target[2]["is_reply"]) == (TYPE_LOGIN_AGREEMENT, 0),
        "Owned target login or zero access differs",
    )


def _roster_names_both(main: list[Report], uid: bytes) -> None:
    """Check the roster holds the target once and a distinct administrator."""
    rosters = [
        frame for frame in main if frame["is_reply"] and frame["id"] == ROSTER_REPLY
    ]
    require(len(rosters) == 1, "Current two-user roster missing")
    rows = roster(rosters[0])
    value = int.from_bytes(uid, "big")
    require(
        len(rows) == ROSTER_ROWS
        and sum(
            row["uid"] == value and row["name_hex"] == cases.NAME.hex() for row in rows
        )
        == 1
        and any(
            row["name_hex"] == b"framing-fixture".hex() and row["uid"] != value
            for row in rows
        ),
        "Admin and target roster identities differ",
    )


def identity_gate(frames: list[Report]) -> bytes:
    """Check the target's identity and return its user id.

    Parameters
    ----------
    frames : list[dict[str, typing.Any]]
        The decoded frames of the case.

    Returns
    -------
    bytes
        The two-byte user id that the target's join announced.
    """
    main = [frame for frame in frames if frame["connection"] == "main"]
    target = [frame for frame in frames if frame["connection"] == "target"]
    base.login_gate(main)
    _target_login(target)
    joins = [
        frame
        for frame in main
        if frame["type"] == TYPE_PRESENCE_UPDATE and not frame["is_reply"]
    ]
    require(len(joins) == 1, "Current target announcement missing or ambiguous")
    identity = fields(joins[0])
    uid = identity.get(FIELD_USER_ID, b"")
    require(
        len(uid) == UID_BYTES
        and int.from_bytes(uid, "big") > 0
        and identity.get(FIELD_NAME) == cases.NAME,
        "Current target UID/name differs",
    )
    _roster_names_both(main, uid)
    return uid


def _notices(report: Report) -> None:
    """Check that each socket received exactly the configured-ban notice."""
    for name in ("main", "target"):
        notices = [
            frame
            for frame in report["frames"]
            if frame["connection"] == name
            and frame["type"] == TYPE_MESSAGE_NOTIFICATION
        ]
        require(
            len(notices) == 1
            and (notices[0]["flags"], notices[0]["is_reply"], notices[0]["error"])
            == (0, 0, 0)
            and fields(notices[0]) == {FIELD_DATA: base.BAN_TEXT},
            f"{name} configured-ban notice differs",
        )
        require(
            any(
                e["connection"] == name and e["event"] == "eof"
                for e in report["events"]
            ),
            f"{name} close missing",
        )


def outcome(report: Report, plan: Report) -> None:
    """Check the held-apply report: its tail, its notices and its sends.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The case report.
    plan : dict[str, typing.Any]
        The plan that the case ran.
    """
    require(
        report["status"] == "completed"
        and report["completed_actions"] == len(plan["steps"])
        and len(plan["steps"]) == HELD_STEPS,
        "Held apply tail incomplete",
    )
    identity_gate(report["frames"])
    require(
        report.get("save_trigger") == "reviewed-save", "Reviewed Save trigger absent"
    )
    _notices(report)
    require(
        not any(
            e["event"] == "send"
            and bytes.fromhex(e["hex"])[ACCESS_REQUEST_SLICE] == ACCESS_REQUEST_TYPE
            for e in report["events"]
        ),
        "110 request forbidden in configured-ban fixture",
    )


def _plan_environment(plan: Report, emulator_pid: int) -> None:
    """Check a plan's environment, endpoint and absence of 110 requests."""
    env = plan["environment"]
    require(
        env.get("emulator_pid") == emulator_pid
        and env.get("source_a7_sha256") == cases.A7_SHA
        and env.get("fixture_profile") == "control-only"
        and env.get("full_file_baseline") == "not_exercised"
        and plan["endpoints"]["control"] == {"host": "127.0.0.1", "port": CONTROL_PORT},
        "Plan identity, profile or endpoint differs",
    )
    require(
        not any(
            step["op"] == "send"
            and bytes.fromhex(step["hex"][:HEADER_HEX_CHARS])[ACCESS_REQUEST_SLICE]
            == ACCESS_REQUEST_TYPE
            for step in plan["steps"]
            if "{" not in step.get("hex", "") and step["op"] == "send"
        ),
        "110 request in source plan",
    )


def plan_gate(directory: Path, emulator_pid: int) -> None:
    """Check every prepared plan against its recorded hash and the runtime.

    Parameters
    ----------
    directory : pathlib.Path
        The directory of plans and ``source-hashes.json``.
    emulator_pid : int
        The process that the receipt names.
    """
    hashes = json.loads((directory / "source-hashes.json").read_text(encoding="utf-8"))
    require(set(hashes) == EXPECTED_PLANS, "Source-plan inventory differs")
    for name in EXPECTED_PLANS:
        source = (directory / f"{name}.json").read_bytes()
        require(digest(source) == hashes[name], f"{name} plan changed")
        plan = json.loads(source)
        validate_plan(plan)
        _plan_environment(plan, emulator_pid)
    held = json.loads((directory / "held-apply.json").read_text(encoding="utf-8"))
    require(len(held["steps"]) == HELD_STEPS, "EOF tails absent from source plan")
