"""The login, readiness and guard gates of the isolated ban-control capture.

Part of the capture driver's module set (``native_control_readiness.CAPTURE_MODULES``).
Each gate raises ``ValueError`` at the first thing a report gets wrong, and the
order of the checks is the order in which a capture reaches them. The gates of
the ban itself are in ``native_control_readiness_ban``.
"""

import hashlib
import json
import typing as typ

import native_ban_control_cases as cases
from native_auth_cases import complement
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_ERROR_TEXT,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    HTXF_MAGIC_HEX,
    TYPE_ENUMERATE_ACCOUNTS,
    TYPE_GET_FILE_INFO,
    TYPE_GET_USER_ROSTER,
    TYPE_LIST_FILES,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from verify_native_account_updates import enumeration
from verify_native_auth import ADMIN, reply, roster
from verify_native_core import require
from verify_native_mkdir import listing
from verify_native_shx import fields

type Report = dict[str, typ.Any]
type Frame = dict[str, typ.Any]

TYPE_USER_NAMED = 303  # the request whose target is field 103
OWNED_PASSWORD = b"x"  # a password-presence placeholder
LOGIN_FRAMES = 3  # the 107 reply, then the 354 and 109 notifications
READINESS_ACTIONS = 18
FIXTURE_ACCOUNTS = 2
FIXTURE_FILES = 41
SESSION_NAME = b"framing-fixture"
GUARD_ID = 30
SEED_ID = 31
SEED_READBACK_ID = 32
TARGET_FRAMES = 3  # the target's 107 reply, then its 354 and 109
TRANSFER_REQUEST_PREFIX = "000000ca"  # type 202 in the header's hexadecimal text
BASELINE_FIELDS = {
    1: "4d3a600990071d9e91b56417c1552aaac0160adf2df3f409d6eeef67e9aec898",
    109: "a500d61db6e19baaf6e165ea9c6512fa3f56262533293f0b44372df434edde59",
    348: "9728c65a33486783ab96fdc6278aa9174b88354fce04073d3981d74086fd9ebe",
    200: "e53bd64a7ea62de8f2b351e7866044dc721d4f983e217368725d638663da9936",
    206: "6dd083b4bbace332c4b475dde19338d3e5fce3527f18a66c8d93fd2bf91e2a9a",
    303: "95edd6e7ab1ef42ef9042f5a78fb96d1f88c7e965ce017cd86c709676f8b978e",
}
# The control requests of the short readiness plan, as (reply id, request type).
CONTROL_REPLIES = [
    (10, TYPE_ENUMERATE_ACCOUNTS),
    (11, TYPE_LIST_FILES),
    (12, TYPE_GET_FILE_INFO),
    (13, TYPE_GET_USER_ROSTER),
    (14, TYPE_USER_NAMED),
]

__all__ = [
    "BASELINE_FIELDS",
    "field_digest",
    "fields",
    "guarded_account",
    "login_gate",
    "readiness",
]


def field_digest(frame: Frame) -> str:
    """Hash a frame's field ids and values, in order.

    Parameters
    ----------
    frame : dict[str, typing.Any]
        A decoded frame.

    Returns
    -------
    str
        The SHA-256 of the compact JSON of ``[id, hex]`` pairs.
    """
    data = [(item["id"], item["hex"]) for item in frame["fields"]]
    return hashlib.sha256(json.dumps(data, separators=(",", ":")).encode()).hexdigest()


def login_gate(frames: list[Frame]) -> None:
    """Check the fixture admin's login, privileges and agreement frames.

    Parameters
    ----------
    frames : list[dict[str, typing.Any]]
        The frames of one connection, the login sequence first.
    """
    require(len(frames) >= LOGIN_FRAMES, "Login sequence incomplete")
    ack, privileges, agreement = frames[:LOGIN_FRAMES]
    require(
        (ack["type"], ack["is_reply"], ack["id"], ack["error"]) == (0, 1, 1, 0)
        and field_digest(ack) == BASELINE_FIELDS[1],
        "Fixture admin login differs",
    )
    require(
        (privileges["type"], privileges["is_reply"], fields(privileges))
        == (TYPE_PRIVILEGES_NOTIFICATION, 0, {FIELD_ACCESS_BITMAP: ADMIN}),
        "Fixture admin privilege bitmap differs",
    )
    require(
        (agreement["type"], agreement["is_reply"]) == (TYPE_LOGIN_AGREEMENT, 0)
        and field_digest(agreement) == BASELINE_FIELDS[TYPE_LOGIN_AGREEMENT],
        "Fixture agreement bytes differ",
    )


def _control_replies(report: Report) -> None:
    """Check that each control reply succeeded and matches its baseline.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The readiness report.
    """
    for identifier, kind in CONTROL_REPLIES:
        frame = reply(report, identifier)
        require(frame["type"] == 0 and frame["error"] == 0, "Control reply failed")
        if kind in BASELINE_FIELDS:
            require(
                field_digest(frame) == BASELINE_FIELDS[kind],
                f"{kind} control baseline differs",
            )


def _original_state(report: Report) -> None:
    """Check the fixture's accounts, files, session and user barrier.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The readiness report.
    """
    require(
        len(enumeration(reply(report, 10))) == FIXTURE_ACCOUNTS,
        "Original account count differs",
    )
    require(
        len(listing(reply(report, 11))) == FIXTURE_FILES,
        "Original Files count differs",
    )
    rows = roster(reply(report, 13))
    require(
        len(rows) == 1 and rows[0]["name_hex"] == SESSION_NAME.hex(),
        "Foreign or absent session",
    )
    require(
        fields(reply(report, 14)).get(FIELD_NAME) == SESSION_NAME,
        "Idle admin UID barrier differs",
    )


def readiness(report: Report) -> None:
    """Check the short readiness capture.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The readiness report.
    """
    require(
        report["status"] == "completed"
        and report["completed_actions"] == READINESS_ACTIONS,
        "Short readiness incomplete",
    )
    login_gate(report["frames"])
    _control_replies(report)
    _original_state(report)
    require(
        all(
            TRANSFER_REQUEST_PREFIX not in event["hex"][:8]
            and HTXF_MAGIC_HEX not in event["hex"][:8]
            for event in report["events"]
            if event["event"] == "send"
        ),
        "Transfer request in control plan",
    )


def guarded_account(report: Report, *, absent: bool) -> None:
    """Check that the owned account is absent, or that it was created at zero.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The guard or seed report.
    absent : bool
        Whether the report is the guard, which must find no such account.
    """
    require(report["status"] == "completed", "Account guard or seed incomplete")
    login_gate(report["frames"])
    frame = reply(report, GUARD_ID if absent else SEED_READBACK_ID)
    if absent:
        require(
            frame["error"] == 1
            and fields(frame)
            == {FIELD_ERROR_TEXT: b"No account with login \xd2" + cases.KEY + b"\xd3."},
            "Owned key already exists",
        )
    else:
        require(reply(report, SEED_ID)["error"] == 0, "Owned account creation failed")
        require(
            frame["error"] == 0
            and fields(frame)
            == {
                FIELD_NAME: cases.NAME,
                FIELD_LOGIN: complement(cases.KEY),
                FIELD_PASSWORD: OWNED_PASSWORD,
                FIELD_ACCESS_BITMAP: cases.ZERO,
            },
            "Stored owned target is not zero privilege",
        )
