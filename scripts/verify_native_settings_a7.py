"""Check the original A7 account, file, metadata, idle and fork controls."""

import json

from native_filp import decode, metadata
from native_wire_names import (
    FIELD_FILE_CREATOR,
    FIELD_FILE_SIZE,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    FIELD_USER_RECORD,
)
from verify_native_core import require
from verify_native_settings_core import (
    DATA_SHA,
    FIELD_DIGESTS,
    RSRC_SHA,
    Report,
    reply,
    sha,
    values,
)

BASELINE_ACTIONS = 29
FILES_REPLY = 11  # the identifier of each A7 request whose reply is checked
INFO_REPLY = 12
ROSTER_REPLY = 13
IDLE_REPLY = 14
TRANSFER_REPLY = 15
ACK_REPLY = 16
IDLE_AGAIN_REPLY = 17
FILES_COUNT = 41
ACCOUNT_COUNT = 2
UID_BYTES = 2
SIZE_BYTES = 4  # the transfer and file sizes are BE32
FILP_BYTES = 1049073  # the flattened file's length on the wire
FILE_BYTES = 1048893  # the logical size that the transfer advertises
REFERENCE_BYTES = 4
SENT_ACTIONS = (15, 26)  # the transfer requests, which end with the user id
INFO_FIELDS = (b"TEXT", b"MOTH", b"mothra-race-fixture", b"fixture-comment")


def baseline_replies(report: Report) -> None:
    """Check the completion, the field digests and the file and metadata replies.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The A7 capture report.
    """
    require(
        report["status"] == "completed"
        and report["completed_actions"] == BASELINE_ACTIONS,
        "A7 29-action completion differs",
    )
    for identifier, prefix in FIELD_DIGESTS.items():
        fields = reply(report, identifier)["fields"]
        digest = sha(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode())
        require(digest == prefix, f"A7 field {identifier} baseline differs")
    require(
        len(reply(report, FILES_REPLY)["fields"]) == FILES_COUNT,
        "A7 Files count differs",
    )
    require(
        values(reply(report, INFO_REPLY))[FIELD_FILE_CREATOR] == b"MOTH",
        "A7 metadata creator differs",
    )


def admin_uid(report: Report) -> bytes:
    """Read the admin's user id from the roster reply.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The A7 capture report.

    Returns
    -------
    bytes
        The two-byte user id.
    """
    roster = reply(report, ROSTER_REPLY)["fields"]
    require(
        len(roster) == 1 and roster[0]["id"] == FIELD_USER_RECORD,
        "A7 admin roster differs",
    )
    uid = bytes.fromhex(roster[0]["hex"])[:UID_BYTES]
    require(len(uid) == UID_BYTES and int.from_bytes(uid, "big") != 0, "A7 UID missing")
    return uid


def transfer_bytes(report: Report) -> bytes:
    """Check the idle replies and the transfer advertisement; read the download.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The A7 capture report.

    Returns
    -------
    bytes
        The flattened file received on the download connection.
    """
    require(
        reply(report, IDLE_REPLY)["fields"]
        == reply(report, IDLE_AGAIN_REPLY)["fields"],
        "A7 idle 303 changed",
    )
    ack = values(reply(report, TRANSFER_REPLY))
    require(
        ack[FIELD_TRANSFER_SIZE] == FILP_BYTES.to_bytes(SIZE_BYTES, "big")
        and ack[FIELD_FILE_SIZE] == FILE_BYTES.to_bytes(SIZE_BYTES, "big")
        and len(ack[FIELD_TRANSFER_REFERENCE]) == REFERENCE_BYTES,
        "A7 transfer advertisement differs",
    )
    require(reply(report, ACK_REPLY)["fields"] == [], "A7 transfer ACK differs")
    transfer = bytes.fromhex(report["streams"]["download"]["received_hex"])
    require(len(transfer) == FILP_BYTES, "A7 FILP transfer length differs")
    return transfer


def check_forks(transfer: bytes) -> None:
    """Check the data and resource forks and the INFO metadata of the file.

    Parameters
    ----------
    transfer : bytes
        The flattened file.
    """
    forks = decode(transfer)
    require(
        sha(forks["DATA"]) == DATA_SHA and sha(forks["MACR"]) == RSRC_SHA,
        "A7 DATA/MACR fork differs",
    )
    info = metadata(forks["INFO"])
    require(
        (info["type"], info["creator"], info["name"], info["comment"]) == INFO_FIELDS,
        "A7 INFO metadata differs",
    )


def a7_semantics(report: Report) -> Report:
    """Check full original A7 account, file, metadata, idle and fork controls.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The A7 capture report.

    Returns
    -------
    dict[str, typing.Any]
        The user id, the account and file counts and the length of the download.
    """
    baseline_replies(report)
    uid = admin_uid(report)
    transfer = transfer_bytes(report)
    check_forks(transfer)
    for action in SENT_ACTIONS:
        sent = [
            e["hex"]
            for e in report["events"]
            if e["action"] == action and e["event"] == "send"
        ]
        require(
            len(sent) == 1 and sent[0].endswith(uid.hex()),
            "A7 same-connection UID differs",
        )
    return {
        "uid": uid.hex(),
        "accounts": ACCOUNT_COUNT,
        "files": FILES_COUNT,
        "filp_bytes": len(transfer),
    }
