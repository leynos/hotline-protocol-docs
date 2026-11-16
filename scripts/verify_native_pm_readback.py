"""Check the full A7 readbacks that frame the private-message observation."""

import json
import typing as typ

from native_filp import decode as decode_filp
from native_pm_baseline import BASELINE_SHA256, FULL_STREAM_BYTES
from native_wire_names import FIELD_DATA, FIELD_USER_ID, FIELD_USER_RECORD
from protocol_capture import decode_frame, digest, verify_capture
from verify_native_auth import reply
from verify_native_core import require
from verify_native_diagnostic_existing import section_witness
from verify_native_shx import fields

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

BASELINE_ACTIONS = 29
BASELINE_REPLY_IDS = (10, 11, 12)
ACCOUNT_REPLY_FIELDS = 2
FILE_REPLY_FIELDS = 41
ROSTER_REPLY_ID = 13
IDLE_REPLY_IDS = (14, 17)
DIAGNOSTIC_REQUEST_ACTIONS = (15, 26)
USER_ID_BYTES = 2


def check_replies(report: Report, source: Report, label: str) -> None:
    """Check the account and file replies against the source report.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The capture's report.
    source : dict[str, typing.Any]
        The A7 source report that holds the reference replies.
    label : str
        The capture's name, for the message.
    """
    for identifier in BASELINE_REPLY_IDS:
        require(
            reply(report, identifier, "a")["fields"]
            == reply(source, identifier, "a")["fields"],
            f"{label}: baseline reply {identifier} differs",
        )
    require(
        len(reply(report, 10, "a")["fields"]) == ACCOUNT_REPLY_FIELDS
        and len(reply(report, 11, "a")["fields"]) == FILE_REPLY_FIELDS,
        f"{label}: baseline count differs",
    )


def roster_uid(report: Report, label: str) -> bytes:
    """Read the one current user id from the roster reply.

    Returns
    -------
    bytes
        The two-byte user id.
    """
    roster = reply(report, ROSTER_REPLY_ID, "a")["fields"]
    require(
        len(roster) == 1 and roster[0]["id"] == FIELD_USER_RECORD,
        f"{label}: current roster ambiguous",
    )
    return bytes.fromhex(roster[0]["hex"])[:USER_ID_BYTES]


def check_idle_diagnostics(report: Report, uid: bytes, label: str) -> None:
    """Check the idle diagnostic replies and the requests that asked for them.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The capture's report.
    uid : bytes
        The user id that the requests must carry.
    label : str
        The capture's name, for the message.
    """
    first, last = IDLE_REPLY_IDS
    require(
        reply(report, first, "a")["fields"] == reply(report, last, "a")["fields"],
        f"{label}: idle diagnostic changed",
    )
    body = fields(reply(report, first, "a"))[FIELD_DATA]
    require(
        section_witness(body, 0, 0)["status"] == "complete",
        f"{label}: idle state incomplete",
    )
    for action in DIAGNOSTIC_REQUEST_ACTIONS:
        sent = b"".join(
            bytes.fromhex(e["hex"])
            for e in report["events"]
            if e["event"] == "send" and e["action"] == action
        )
        require(
            fields(decode_frame(sent))[FIELD_USER_ID] == uid,
            f"{label}: diagnostic UID differs",
        )


def check_download(report: Report, plan_raw: bytes, label: str) -> dict[str, typ.Any]:
    """Check the downloaded fork file against the plan's expectation.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The capture's report.
    plan_raw : bytes
        The capture's plan, as read.
    label : str
        The capture's name, for the message.

    Returns
    -------
    dict[str, typing.Any]
        The stream length and the fork hashes.
    """
    transfer = bytes.fromhex(report["streams"]["download"]["received_hex"])
    require(len(transfer) == FULL_STREAM_BYTES, f"{label}: full FILP truncated")
    forks = decode_filp(transfer)
    expected = json.loads(plan_raw)["expectation"]
    for tag, key in (
        ("DATA", "expected_data_sha256"),
        ("MACR", "expected_rsrc_sha256"),
    ):
        require(digest(forks[tag]) == expected[key], f"{label}: {tag} fork differs")
    return {
        "filp_bytes": len(transfer),
        "data_sha256": digest(forks["DATA"]),
        "macr_sha256": digest(forks["MACR"]),
    }


def full_readback(root: Path, label: str, source: Report) -> Report:
    """Verify one A7 readback capture and summarise it.

    The checks run in a fixed order, so the first failure decides the error:
    the capture's own verification, the plan hash, completion, the baseline
    replies, the roster, the idle diagnostics and the downloaded file.

    Parameters
    ----------
    root : pathlib.Path
        The corpus root.
    label : str
        ``preflight`` or ``postflight``.
    source : dict[str, typing.Any]
        The A7 source report.

    Returns
    -------
    dict[str, typing.Any]
        The user id, counts, stream length and fork hashes.
    """
    path = root / label
    report = verify_capture(path)
    plan_raw = (path / "plan.json").read_bytes()
    require(digest(plan_raw) == BASELINE_SHA256, f"{label}: A7 plan differs")
    require(
        report["status"] == "completed"
        and report["completed_actions"] == BASELINE_ACTIONS,
        f"{label}: full A7 sequence incomplete",
    )
    check_replies(report, source, label)
    uid = roster_uid(report, label)
    check_idle_diagnostics(report, uid, label)
    download = check_download(report, plan_raw, label)
    return {
        "uid_hex": uid.hex(),
        "accounts": ACCOUNT_REPLY_FIELDS,
        "files": FILE_REPLY_FIELDS,
        **download,
    }
