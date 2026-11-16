"""Check the outcome of one recorded account batch and the accounts it left.

The order of the checks in each function is the order in which a corrupt case
is refused, so a function reads its evidence in the sequence that it always has.
"""

import typing as typ

import native_account_batch_model as model
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_DATA,
    FIELD_ERROR_TEXT,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from verify_native_account_updates import enumeration
from verify_native_auth import ADMIN, reply
from verify_native_core import require
from verify_native_shx import fields

type Report = dict[str, typ.Any]

SAVE_ERROR = b"Error saving list of accounts."
DENIED_MODIFY = b"You are not allowed to modify account information."
ERRORS = {
    **dict.fromkeys(
        [
            "empty-copy-continues",
            "empty-tlv-continues",
            "empty-batch",
            "identity-after-limit",
            "rename-collision",
            "distinct-rename-collision",
        ],
        SAVE_ERROR,
    ),
    "create-update-denied": DENIED_MODIFY,
    "zero-role-denied": DENIED_MODIFY,
    "delete-create-denied": b"You are not allowed to create new accounts.",
    "update-delete-denied": b"You are not allowed to delete accounts.",
    "subset-denied": b"Cannot create account with more access than yourself.",
}
BATCH_ID = 10  # the request that carries the batch
LIVENESS_ID = 90  # the empty request that shows that the connection still answers
FIRST_INSPECTION_ID = 100  # the reads of the owned accounts are numbered from here
NOTICE_FLAGS_FIELD = 109  # a field of the collision notice whose meaning is open
NOTICE_FLAGS = b"\0\1"
COLLISION_NOTICE = (
    b"Cannot create account \xd2m-b28-collision\xd3 because there is already an "
    b"account with that login."
)


def check_terminal(report: Report, spec: Report) -> Report:
    """Check the batch's terminal ACK, which is an error for refused batches.

    Returns
    -------
    dict[str, typing.Any]
        The terminal reply frame.
    """
    frame = reply(report, BATCH_ID)
    message = ERRORS.get(spec["case"])
    require(
        frame["error"] == (1 if message else 0)
        and fields(frame) == ({FIELD_ERROR_TEXT: message} if message else {}),
        "Batch terminal ACK/error differs",
    )
    return frame


def check_admission(report: Report, spec: Report) -> None:
    """Check the access bitmap that the batch's session was admitted with."""
    access = next(
        f for f in report["frames"] if f["type"] == TYPE_PRIVILEGES_NOTIFICATION
    )
    require(
        fields(access)
        == {
            FIELD_ACCESS_BITMAP: ADMIN
            if spec["role"] == "admin"
            else model.ROLES[spec["role"]]
        },
        "Batch role admission mask differs",
    )


def check_notices(report: Report, spec: Report, frame: Report) -> None:
    """Check the per-item notices: one before the terminal ACK on a collision."""
    notices = [f for f in report["frames"] if f["type"] == TYPE_MESSAGE_NOTIFICATION]
    if spec["case"] == "collision-continues":
        require(
            len(notices) == 1
            and notices[0]["is_reply"] == 0
            and notices[0]["error"] == 0
            and fields(notices[0])
            == {FIELD_DATA: COLLISION_NOTICE, NOTICE_FLAGS_FIELD: NOTICE_FLAGS}
            and report["frames"].index(notices[0]) < report["frames"].index(frame),
            "Batch collision notice/continuation differs",
        )
    else:
        require(not notices, "Unexpected per-item batch notice")


def batch_result(report: Report, spec: Report) -> None:
    """Check one batch's terminal ACK, admission, notices and liveness."""
    frame = check_terminal(report, spec)
    check_admission(report, spec)
    check_notices(report, spec, frame)
    require(
        reply(report, LIVENESS_ID)["error"] == 0
        and fields(reply(report, LIVENESS_ID)) == {},
        "Batch error lost control liveness",
    )


def inspect(
    report: Report,
    names: list[str],
    states: dict[str, model.State],
    baseline: list[str],
) -> None:
    """Check the reads of the named accounts and the enumeration after them."""
    for identifier, label in enumerate(names, FIRST_INSPECTION_ID):
        model.account_reply(reply(report, identifier), label, states)
    require(
        enumeration(reply(report, LIVENESS_ID)) == model.enumeration(states, baseline),
        "Batch inspection global account state differs",
    )
