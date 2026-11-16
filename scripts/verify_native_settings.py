#!/usr/bin/env python3
"""Verify the bounded native settings-113 matrix without assuming duplicate policy."""

import json
import typing as typ
from pathlib import Path

from native_settings_cases import CASES, cases
from native_wire_names import (
    FIELD_DATA,
    FIELD_ICON,
    FIELD_OPTIONS,
    FIELD_USER_ID,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
)
from protocol_capture import verify_capture
from script_cli import run
from verify_native_core import fields, require

type Report = dict[str, typ.Any]

__all__ = ["CASES", "cases", "fields", "main", "semantic", "verify"]  # for importers

PM_ID = 70
# The barrier replies, as (request identifier, connection).
BARRIERS = [(41, "main"), (71, "main"), (72, "subject"), (81, "main"), (82, "subject")]
MIN_UPDATES = 3  # the login, the setting and the restore each announce the subject
SUBJECT_ICON = b"\0\x07"
ONE_REFUSAL = b"\0\x01"  # the 113 value that the message carries on delivery
FEEDBACK_OPTIONS = {0, 2, 4}  # none, refusal and automatic response
FEEDBACK_REFUSAL = 2
FEEDBACK_AUTO = 4
FLAG_REFUSE = 1
FLAG_AUTO = 4
UID_BYTES = 2
MAX_FEEDBACK = 1
SCOPE = "304 field 113 only; duplicate selections measured per case"


def check_acknowledgements(frames: list[Report]) -> None:
    """Require the PM acknowledgement and every barrier acknowledgement.

    Parameters
    ----------
    frames : list[dict[str, typing.Any]]
        The decoded frames of the report.
    """
    replies = [f for f in frames if f["is_reply"] and f["id"] == PM_ID]
    require(len(replies) == 1 and replies[0]["error"] == 0, "PM ACK missing/failed")
    for identifier, connection in BARRIERS:
        ack = [
            f
            for f in frames
            if f["connection"] == connection and f["is_reply"] and f["id"] == identifier
        ]
        require(len(ack) == 1 and ack[0]["error"] == 0, "Barrier ACK missing/failed")


def subject_uid(frames: list[Report]) -> bytes:
    """Require a stable, nonzero subject user id and icon in the first updates.

    Parameters
    ----------
    frames : list[dict[str, typing.Any]]
        The decoded frames of the report.

    Returns
    -------
    bytes
        The subject's two-byte user id.
    """
    updates = [
        f
        for f in frames
        if f["connection"] == "main"
        and f["type"] == TYPE_PRESENCE_UPDATE
        and not f["is_reply"]
    ]
    require(len(updates) >= MIN_UPDATES, "Login/settings/restore 301 missing")
    uid = fields(updates[0]).get(FIELD_USER_ID, b"")
    require(
        len(uid) == UID_BYTES and int.from_bytes(uid, "big") != 0,
        "Dynamic subject UID missing",
    )
    require(
        all(fields(f).get(FIELD_USER_ID) == uid for f in updates[:MIN_UPDATES]),
        "Subject UID changed",
    )
    require(
        all(fields(f).get(FIELD_ICON) == SUBJECT_ICON for f in updates[:MIN_UPDATES]),
        "Subject icon control changed",
    )
    return uid


def delivery(frames: list[Report], expected: Report) -> tuple[bool, int]:
    """Read the delivery of the message and the option of its feedback.

    Parameters
    ----------
    frames : list[dict[str, typing.Any]]
        The decoded frames of the report.
    expected : dict[str, typing.Any]
        The case's expectation, which names the message text.

    Returns
    -------
    tuple[bool, int]
        Whether the subject received the message, and the feedback option.
    """
    notices = [
        f
        for f in frames
        if f["type"] == TYPE_MESSAGE_NOTIFICATION and not f["is_reply"]
    ]
    received = [fields(f) for f in notices if f["connection"] == "subject"]
    feedback = [fields(f) for f in notices if f["connection"] == "main"]
    pm_text = bytes.fromhex(expected["pm_text"])
    delivered = (
        len(received) == 1
        and received[0].get(FIELD_DATA) == pm_text
        and received[0].get(FIELD_OPTIONS) == ONE_REFUSAL
    )
    require(not received or delivered, "PM delivery bytes differ")
    require(len(feedback) <= MAX_FEEDBACK, "Multiple PM feedback messages")
    option = (
        int.from_bytes(feedback[0].get(FIELD_OPTIONS, b""), "big") if feedback else 0
    )
    require(option in FEEDBACK_OPTIONS, "Unknown PM feedback option")
    require(
        not feedback or option in {FEEDBACK_REFUSAL, FEEDBACK_AUTO},
        "PM feedback lacks option",
    )
    return delivered, option


def inferred_flags(option: int, *, delivered: bool) -> int:
    """Infer the effective refusal and auto flags from delivery and feedback.

    A refusal suppresses the original; an automatic response may coexist with it.

    Parameters
    ----------
    option : int
        The feedback option.
    delivered : bool
        Whether the subject received the original message.

    Returns
    -------
    int
        The field-113 flags that explain what was observed.
    """
    refuse = not delivered
    auto = option == FEEDBACK_AUTO
    require(
        not (delivered and option == FEEDBACK_REFUSAL),
        "Refusal feedback with delivery",
    )
    require(not (refuse and option == 0), "Suppression without refusal feedback")
    return (FLAG_REFUSE if refuse else 0) | (FLAG_AUTO if auto else 0)


def check_flags(observed: int, expected: Report) -> None:
    """Compare the inferred flags with the case's expectation.

    A duplicate case may select either of its submitted values.

    Parameters
    ----------
    observed : int
        The inferred flags.
    expected : dict[str, typing.Any]
        The case's expectation.
    """
    if expected["duplicate"]:
        allowed = {
            int.from_bytes(value, "big") for value in CASES[expected["case"]][0] or []
        }
        require(observed in allowed, "Duplicate selection outside submitted values")
    else:
        require(observed == expected["expected_flags"], "Field-113 state differs")


def semantic(report: Report, expected: Report) -> Report:
    """Infer effective refusal/auto flags from independent PM delivery/feedback.

    Parameters
    ----------
    report : dict[str, typing.Any]
        A verified capture report.
    expected : dict[str, typing.Any]
        The case's expectation.

    Returns
    -------
    dict[str, typing.Any]
        The case, the observed flags, the subject user id and the feedback option.
    """
    frames = report["frames"]
    check_acknowledgements(frames)
    uid = subject_uid(frames)
    delivered, option = delivery(frames, expected)
    observed = inferred_flags(option, delivered=delivered)
    check_flags(observed, expected)
    return {
        "case": expected["case"],
        "observed_flags": observed,
        "subject_uid_hex": uid.hex(),
        "feedback_option": option,
    }


def check_case(case: Path, steps: list[Report], expected: Report) -> Report:
    """Check one case's plan, replay its capture and read its semantics.

    Parameters
    ----------
    case : pathlib.Path
        The case's capture directory.
    steps : list[dict[str, typing.Any]]
        The steps that the planner prepares for the case.
    expected : dict[str, typing.Any]
        The expectation that the planner prepares for the case.

    Returns
    -------
    dict[str, typing.Any]
        The semantic result of the case.
    """
    plan = json.loads((case / "plan.json").read_text())
    require(plan["steps"] == steps and plan["expectation"] == expected, "Plan differs")
    report = verify_capture(case)
    require(
        report["status"] == "completed" and report["profile"] == "native-mac-oracle",
        "Capture incomplete/profile differs",
    )
    return semantic(report, expected)


def verify(directory: Path) -> Report:
    """Verify every case of a settings corpus.

    Parameters
    ----------
    directory : pathlib.Path
        The directory that holds one capture per case.

    Returns
    -------
    dict[str, typing.Any]
        The semantic result of each case, and the scope of the check.
    """
    expected_cases = cases()
    names = {p.name for p in directory.iterdir() if p.is_dir()}
    require(names == set(expected_cases), "Settings corpus inventory differs")
    results = [
        check_case(directory / name, steps, expected)
        for name, (steps, expected) in expected_cases.items()
    ]
    return {"cases": results, "scope": SCOPE}


def command(directory: str) -> None:
    """Print the verification result of a directory of cases as JSON.

    Parameters
    ----------
    directory
        The directory that holds one capture per case.
    """
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Run the command line; a successful run returns instead of exiting.

    Raises
    ------
    SystemExit
        With a non-zero status when the command line cannot be used.
    """
    try:
        run(command, __doc__)
    except SystemExit as stop:
        if stop.code:  # the command line library exits with 0 on success
            raise


if __name__ == "__main__":
    main()
