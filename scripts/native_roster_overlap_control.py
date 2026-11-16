#!/usr/bin/env python3
"""Run one bounded control-only 300/304 overlap; preserve both socket orders."""

import json
import sys
from pathlib import Path

import native_roster_overlap_cases as cases
import script_cli
from native_ban_expiry_control import runtime_gate, utc
from native_roster_overlap_control_audit import verify_operation_map
from native_roster_overlap_control_checks import (
    UPDATE_FIELDS,
    UPDATE_OPAQUE_FIELD,
    check_overlap,
    exact_rows,
    expected_frame,
    frame_key,
    need,
    one,
    sha,
)
from native_roster_overlap_control_drain import MAX_BYTES, MAX_FRAMES, DualDrain
from native_roster_overlap_control_session import MAX_SECONDS, Session
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_ICON,
    FIELD_NAME,
    FIELD_USER_ID,
    TYPE_GET_USER_ROSTER,
    TYPE_LOGIN,
)
from protocol_capture import ORACLE_SHA256, Recorder, decode_frame, validate_plan
from verify_native_auth import ADMIN, roster
from verify_native_shx import fields

SETUP_A_FRAMES = 5  # session a's setup: login reply, 354, 109, 301 and roster
SETUP_B_FRAMES = 4  # session b's setup: login reply, 354, 109 and roster

# The names below were defined or imported by this module before it was split.
# Its importers, its tests and the patches they apply keep their import paths.
__all__ = [
    "ADMIN",
    "MAX_BYTES",
    "MAX_FRAMES",
    "MAX_SECONDS",
    "ORACLE_SHA256",
    "DualDrain",
    "Recorder",
    "cases",
    "check_overlap",
    "check_setup",
    "command",
    "decode_frame",
    "exact_rows",
    "expected_frame",
    "fields",
    "frame_key",
    "main",
    "need",
    "one",
    "prepared",
    "roster",
    "run",
    "runtime_gate",
    "sha",
    "utc",
    "validate_plan",
    "verify_operation_map",
]


def prepared(path: Path) -> dict:
    """Load the prepared plan from a directory and check it against its record.

    Parameters
    ----------
    path : pathlib.Path
        The directory that holds ``plan.json`` and ``source-hashes.json``.

    Returns
    -------
    dict
        The prepared plan, which has passed ``validate_plan``.
    """
    raw = (path / "plan.json").read_bytes()
    plan = json.loads(raw)
    validate_plan(plan)
    need(
        json.loads((path / "source-hashes.json").read_text(encoding="utf-8"))
        == {"plan.json": sha(raw)},
        "Prepared plan hash differs",
    )
    need(
        plan == cases.source_plan(plan["environment"], cases.MAX_PORT),
        "Prepared overlap plan differs",
    )
    kinds = {
        int.from_bytes(bytes.fromhex(s["hex"])[2:4], "big")
        for s in plan["steps"]
        if s["op"] == "send" and not s["hex"].startswith("54525450")
    }
    need(
        kinds <= {TYPE_LOGIN, TYPE_GET_USER_ROSTER} and len(plan["endpoints"]) == 1,
        "Unexpected setup request or endpoint",
    )
    return plan


def check_setup(recorder: Recorder) -> tuple[int, int]:
    """Check the frames of the setup logins and roster replies.

    Parameters
    ----------
    recorder : Recorder
        The recorder that holds the setup frames and the variables.

    Returns
    -------
    tuple[int, int]
        The UIDs of accounts a and b.
    """
    a = [f for f in recorder.frames if f["connection"] == "a"]
    b = [f for f in recorder.frames if f["connection"] == "b"]
    need(
        len(a) == SETUP_A_FRAMES and len(b) == SETUP_B_FRAMES,
        "Initial frame count differs",
    )
    need(
        [(f["type"], f["is_reply"], f["id"]) for f in a]
        == [
            (0, 1, 1),
            (354, 0, a[1]["id"]),
            (109, 0, a[2]["id"]),
            (301, 0, a[3]["id"]),
            (0, 1, 10),
        ],
        "A initial frame order differs",
    )
    need(
        [(f["type"], f["is_reply"], f["id"]) for f in b]
        == [(0, 1, 1), (354, 0, b[1]["id"]), (109, 0, b[2]["id"]), (0, 1, 10)],
        "B initial frame order differs",
    )
    for label, frames in (("a", a), ("b", b)):
        need(
            frames[0]["error"] == 0
            and len(frames[1]["fields"]) == 1
            and fields(frames[1]) == {FIELD_ACCESS_BITMAP: ADMIN},
            f"{label} login/access differs",
        )
    a_uid, b_uid = exact_rows(a[4])
    exact_rows(b[3], a_uid, b_uid)
    need(
        recorder.variables.get("b_uid") == b_uid.to_bytes(2, "big"),
        "B dynamic 301 UID differs from roster",
    )
    update = fields(a[3])
    need(
        len(a[3]["fields"]) == UPDATE_FIELDS
        and set(update) == {FIELD_NAME, FIELD_USER_ID, FIELD_ICON, UPDATE_OPAQUE_FIELD}
        and update.get(FIELD_USER_ID) == b_uid.to_bytes(2, "big")
        and update.get(FIELD_NAME) == cases.OLD_B
        and update.get(FIELD_ICON) == cases.ICON_B,
        "B initial 301 identity/icon differs",
    )
    return a_uid, b_uid


def run(plan_dir: Path, receipt_path: Path, binary: Path, output: Path) -> dict:
    """Run the overlap, write its plan and report, and return the report.

    The plan, the receipt and the oracle binary are admitted before any socket
    is opened. The overlap then runs its setup, its coordinator operations and
    its teardown; a failure in any of them is recorded in the report rather
    than raised. The report is checked against the source plan before it is
    written.

    Parameters
    ----------
    plan_dir : pathlib.Path
        The directory that holds the prepared plan.
    receipt_path : pathlib.Path
        The capture receipt, a JSON file with the overlap deadline.
    binary : pathlib.Path
        The oracle binary, whose digest must be the pinned one.
    output : pathlib.Path
        The directory to create for ``plan.json`` and ``report.json``.

    Returns
    -------
    dict
        The as-run report.
    """
    session = Session(prepared(plan_dir), plan_dir, receipt_path)
    runtime_gate(session.receipt, session.plan["environment"], session.deadline)
    need(sha(binary.read_bytes()) == ORACLE_SHA256, "Oracle data fork differs")
    session.open(output, Recorder)
    status, error = "completed", ""
    try:
        session.setup()
        session.uids = check_setup(session.recorder)
        runtime_gate(session.receipt, session.plan["environment"], session.deadline)
        session.coordinate()
        session.teardown()
    except (
        OSError,
        EOFError,
        ValueError,
        TimeoutError,
        KeyError,
        IndexError,
        StopIteration,
        KeyboardInterrupt,
    ) as failure:
        status, error = "failed", f"{type(failure).__name__}: {failure}"
        session.fail_teardown()
    finally:
        session.close()
    result = session.report(status, error, ORACLE_SHA256)
    if result["status"] == "completed":
        try:
            verify_operation_map(session.plan, result)
        except (ValueError, KeyError, IndexError) as failure:
            result["status"] = "failed"
            result["error"] = f"As-run map: {failure}"
    (output / "plan.json").write_text(json.dumps(session.plan, indent=2) + "\n")
    (output / "report.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def command(*, plan_dir: str, capture_receipt: str, binary: str, output: str) -> None:
    """Run the overlap, print its report, and exit with status 1 unless it completed.

    Parameters
    ----------
    plan_dir : str
        The directory that holds the prepared plan.
    capture_receipt : str
        The capture receipt, a JSON file with the overlap deadline.
    binary : str
        The oracle binary, whose digest must be the pinned one.
    output : str
        The directory to create for ``plan.json`` and ``report.json``.

    Raises
    ------
    SystemExit
        With status 1 when the overlap did not complete.
    """
    result = run(Path(plan_dir), Path(capture_receipt), Path(binary), Path(output))
    sys.stdout.write(json.dumps(result, indent=2) + "\n")
    if result["status"] != "completed":
        raise SystemExit(1)


def main() -> None:
    """Run the overlap from the command line."""
    script_cli.run(command, __doc__)


if __name__ == "__main__":
    main()
