"""Check the replies of the diagnostic-load cleanup against its baseline.

Part of the diagnostic-load planner (``native_diagnostic_load_cases``), whose
``CAPTURE_MODULES`` lists this module and which re-exports every public name
below. Each check fails closed with a ``ValueError`` that names what differed.
"""

import dataclasses as dc
import json
import typing as typ

from native_diagnostic_load_cases_steps import NAME
from native_wire_names import FIELD_FILE_NAME, FIELD_USER_RECORD
from verify_native_mkdir import listing as file_listing

if typ.TYPE_CHECKING:
    from pathlib import Path

    from protocol_capture import Recorder

type Report = dict[str, typ.Any]

# The reply identifiers of the cleanup capture, in the order they are sent.
INFO_REPLY = 10
FILES_REPLY = 11
FINAL_INFO_REPLY = 12
FINAL_FILES_REPLY = 13
FINAL_ACCOUNTS_REPLY = 14
ROSTER_REPLY = 15
DIAGNOSTIC_REPLY = 16
DELETION_REPLY = 17
DIAGNOSTIC_FIELDS = [101, 102]


def choose_owned_branch(info: Report, listing_frame: Report) -> str:
    """Refuse deletion unless both replies identify this exact owned file.

    Parameters
    ----------
    info : dict[str, typing.Any]
        The file-info reply.
    listing_frame : dict[str, typing.Any]
        The listing reply.

    Returns
    -------
    str
        ``present`` to delete the file, ``absent`` when it is not there.

    Raises
    ------
    ValueError
        If the envelope differs or the file's presence is ambiguous.
    """
    entries = file_listing(listing_frame)
    values = [
        bytes.fromhex(f["hex"])
        for f in info.get("fields", [])
        if f["id"] == FIELD_FILE_NAME
    ]
    if info["is_reply"] != 1 or info["type"] != 0:
        message = "File-info envelope differs"
        raise ValueError(message)
    listed = NAME in entries
    if info["error"] == 0 and all((values == [NAME], listed)):
        return "present"
    if info["error"] == 1 and not any((values, listed)):
        return "absent"
    message = "Owned file presence is ambiguous; no deletion"
    raise ValueError(message)


@dc.dataclass(slots=True)
class Run:
    """The state of one cleanup run, kept so that a failure still reports it."""

    recorder: Recorder
    selected: Report
    completed: int = 0
    status: str = "completed"
    error: str = ""


def reply_of(recorder: Recorder, identifier: int) -> Report:
    """Find the reply of one request among the recorded frames.

    Returns
    -------
    dict[str, typing.Any]
        The first matching frame.
    """
    return next(
        f for f in recorder.frames if f["is_reply"] == 1 and f["id"] == identifier
    )


@dc.dataclass(frozen=True, slots=True)
class Baseline:
    """The files and accounts views that the preflight recorded."""

    files: Report
    accounts: Report


def read_baseline(baseline: Path) -> Baseline:
    """Read the preflight views from the baseline capture.

    Returns
    -------
    Baseline
        The files reply and the accounts reply of the preflight.
    """
    previous = json.loads((baseline / "report.json").read_text(encoding="utf-8"))
    frames = previous["frames"]
    return Baseline(
        files=next(f for f in frames if f["is_reply"] == 1 and f["id"] == FILES_REPLY),
        accounts=next(
            f for f in frames if f["is_reply"] == 1 and f["id"] == INFO_REPLY
        ),
    )


def _is_admin_row(row: Report) -> bool:
    """Say whether a roster row is the admin's.

    Returns
    -------
    bool
        ``True`` for a user record that names the framing fixture.
    """
    return row["id"] == FIELD_USER_RECORD and b"framing-fixture" in bytes.fromhex(
        row["hex"]
    )


def _check_roster(roster_reply: Report) -> None:
    """Require the roster to hold the admin alone.

    Raises
    ------
    ValueError
        If the roster is not exactly the one admin row.
    """
    rows = roster_reply.get("fields", [])
    if len(rows) != 1 or not _is_admin_row(rows[0]):
        message = "Current admin roster ambiguous"
        raise ValueError(message)


def _check_diagnostic(diagnostic_reply: Report) -> None:
    """Require an idle diagnostic that no longer names the owned file.

    Raises
    ------
    ValueError
        If the envelope differs or the owned name remains.
    """
    dfields = diagnostic_reply.get("fields", [])
    if (
        diagnostic_reply["error"] != 0
        or [f["id"] for f in dfields] != DIAGNOSTIC_FIELDS
    ):
        message = "Idle diagnostic envelope differs"
        raise ValueError(message)
    if NAME in bytes.fromhex(dfields[0]["hex"]):
        message = "Owned name remains in idle diagnostic"
        raise ValueError(message)


def check_final(run: Run, baseline: Baseline) -> None:
    """Require the end state to match the preflight, apart from the owned file.

    Raises
    ------
    ValueError
        If the deletion failed or any view differs from the baseline.
    """
    recorder = run.recorder
    final_info = reply_of(recorder, FINAL_INFO_REPLY)
    final_files = reply_of(recorder, FINAL_FILES_REPLY)
    final_accounts = reply_of(recorder, FINAL_ACCOUNTS_REPLY)
    roster_reply = reply_of(recorder, ROSTER_REPLY)
    diagnostic_reply = reply_of(recorder, DIAGNOSTIC_REPLY)
    if run.selected["expectation"]["branch"] == "present":
        deletion = reply_of(recorder, DELETION_REPLY)
        if deletion["error"] != 0:
            message = "Owned deletion failed"
            raise ValueError(message)
    if final_info["error"] != 1:
        message = "Owned file remains after cleanup"
        raise ValueError(message)
    if final_files["fields"] != baseline.files["fields"]:
        message = "Full Files view differs from preflight"
        raise ValueError(message)
    if final_accounts["fields"] != baseline.accounts["fields"]:
        message = "Account baseline differs from preflight"
        raise ValueError(message)
    _check_roster(roster_reply)
    _check_diagnostic(diagnostic_reply)
