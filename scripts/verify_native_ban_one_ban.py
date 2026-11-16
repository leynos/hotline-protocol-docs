"""Replay the option-one ban request and its notice from frozen captures."""

import typing as typ

from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_DATA,
    FIELD_OPTIONS,
    FIELD_USER_ID,
    FRAME_HEADER_BYTES,
    HANDSHAKE_REPLY_HEX,
    HANDSHAKE_REQUEST_HEX,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
)
from protocol_capture import decode_frame, verify_capture
from verify_native_ban_one_core import (
    BAN_REQUEST_ID,
    BAN_REQUEST_TYPE,
    NOTICE,
    PROBE_COMPLETED_ACTIONS,
    UID_BYTES,
    fields,
    frame,
    loaded,
    need,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]


def _check_accounts(reports: dict[str, Report], fixture: Path) -> None:
    """Check that the guard, seed and ban captures completed and the account is set.

    Parameters
    ----------
    reports : dict[str, dict[str, typing.Any]]
        The verified capture report of each case.
    fixture : pathlib.Path
        The fixture directory of the corpus.
    """
    for name in ("guard", "seed", "ban-opt1"):
        report = reports[name]
        need(
            report["status"] == "completed"
            and report["completed_actions"]
            == len(loaded(fixture / f"{name}.json")["steps"]),
            f"{name} incomplete",
        )
    need(
        frame(reports["guard"], "main", 30)["error"] == 1,
        "Owned account was not absent",
    )
    need(frame(reports["seed"], "main", 31)["error"] == 0, "Owned account seed failed")
    created = frame(reports["seed"], "main", 32)
    need(
        created["error"] == 0 and fields(created)[FIELD_ACCESS_BITMAP] == bytes(8),
        "Owned account is not unprotected and zero privilege",
    )


def _check_login(ban: Report) -> bytes:
    """Check both logins and the target UID that the presence update assigns.

    Parameters
    ----------
    ban : dict[str, typing.Any]
        The verified capture report of the ban case.

    Returns
    -------
    bytes
        The two-byte UID of the dynamic target.
    """
    for connection in ("main", "target"):
        need(frame(ban, connection, 1)["error"] == 0, f"{connection} login failed")
    updates = [
        item
        for item in ban["frames"]
        if item["connection"] == "main" and item["type"] == TYPE_PRESENCE_UPDATE
    ]
    need(
        len(updates) == 1 and updates[0]["is_reply"] == 0,
        "Dynamic target 301 differs",
    )
    uid = fields(updates[0])[FIELD_USER_ID]
    need(
        len(uid) == UID_BYTES and uid != b"\0\0",
        "Dynamic target UID invalid",
    )
    return uid


def _check_request(ban: Report, uid: bytes) -> None:
    """Check that the 110 request is sent once, to the target, with the ban option.

    Parameters
    ----------
    ban : dict[str, typing.Any]
        The verified capture report of the ban case.
    uid : bytes
        The two-byte UID of the dynamic target.
    """
    sends = [
        bytes.fromhex(event["hex"])
        for event in ban["events"]
        if event["event"] == "send"
        and len(event["hex"]) >= 2 * FRAME_HEADER_BYTES
        and int(event["hex"][4:8], 16) == BAN_REQUEST_TYPE
    ]
    need(len(sends) == 1, "110 must be sent exactly once")
    request = decode_frame(sends[0])
    need(
        request["id"] == BAN_REQUEST_ID
        and fields(request) == {FIELD_USER_ID: uid, FIELD_OPTIONS: b"\0\x01"},
        "110 target or option differs",
    )


def _check_notice(ban: Report) -> None:
    """Check the option-one 104 notice, the target EOF and the ban ACK.

    Parameters
    ----------
    ban : dict[str, typing.Any]
        The verified capture report of the ban case.
    """
    notices = [
        item
        for item in ban["frames"]
        if item["connection"] == "target" and item["type"] == TYPE_MESSAGE_NOTIFICATION
    ]
    need(
        len(notices) == 1
        and notices[0]["is_reply"] == 0
        and fields(notices[0]) == {FIELD_DATA: NOTICE},
        "Option-one 104 notice differs",
    )
    need(
        any(
            event["connection"] == "target" and event["event"] == "eof"
            for event in ban["events"]
        ),
        "Target EOF missing",
    )
    need(frame(ban, "main", BAN_REQUEST_ID)["error"] == 0, "Ban ACK failed")


def _check_probe(probe: Report) -> None:
    """Check that the probe failed after its handshake and before any login.

    Parameters
    ----------
    probe : dict[str, typing.Any]
        The verified capture report of the probe case.
    """
    need(
        probe["status"] == "failed"
        and probe["completed_actions"] == PROBE_COMPLETED_ACTIONS
        and probe["error"] == "TimeoutError: timed out",
        "Probe failure was recast",
    )
    observed = [(event["event"], event["hex"]) for event in probe["events"]]
    need(
        observed
        == [
            ("connect", ""),
            ("send", HANDSHAKE_REQUEST_HEX),
            ("receive", HANDSHAKE_REPLY_HEX),
            ("close", ""),
        ],
        "Probe prefix differs or login was attempted",
    )


def verify_ban(corpus: Path) -> dict[str, typ.Any]:
    """Replay the option-one ban witness and return its UID, notice and probe.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The target UID, the notice bytes and the probe outcome.
    """
    fixture = corpus / "fixture"
    reports = {
        name: verify_capture(fixture / f"{name}-capture")
        for name in ("guard", "seed", "ban-opt1", "probe")
    }
    _check_accounts(reports, fixture)
    ban = reports["ban-opt1"]
    uid = _check_login(ban)
    _check_request(ban, uid)
    _check_notice(ban)
    _check_probe(reports["probe"])
    return {
        "target_uid_hex": uid.hex(),
        "notice_hex": NOTICE.hex(),
        "probe": "failed_after_successful_handshake_before_login",
    }
