"""Run the conditional cleanup of the owned diagnostic-load file.

Part of the diagnostic-load planner (``native_diagnostic_load_cases``), whose
``CAPTURE_MODULES`` lists this module and which re-exports every public name
below. The cleanup deletes the owned file only when both replies identify that
exact file, and it fails closed in every other case.
"""

import datetime as dt
import json
import typing as typ

from native_diagnostic_load_cases_checks import (
    DELETION_REPLY,
    DIAGNOSTIC_REPLY,
    FILES_REPLY,
    FINAL_ACCOUNTS_REPLY,
    FINAL_FILES_REPLY,
    FINAL_INFO_REPLY,
    INFO_REPLY,
    ROSTER_REPLY,
    Baseline,
    Report,
    Run,
    check_final,
    choose_owned_branch,
    read_baseline,
    reply_of,
)
from native_diagnostic_load_cases_steps import (
    ACCOUNTS_REQUEST,
    NAME,
    Step,
    diagnostic,
    exchange,
    roster,
)
from native_plan import close
from native_queue_cases import session
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    TYPE_DELETE_FILE,
    TYPE_GET_FILE_INFO,
    TYPE_LIST_FILES,
)
from protocol_capture import ORACLE_SHA256, Recorder, digest, validate_plan

if typ.TYPE_CHECKING:
    from pathlib import Path

CONTROL_PORT = 15500
IDENTITY_SCOPE = (
    "Local binary hash verified; remote process identity is operator-reported"
)


class Plans(typ.NamedTuple):
    """The three plans of the cleanup and the steps that all of them begin with."""

    prefix: list[Step]
    undecided: Report
    absent: Report
    present: Report


def _plan(runtime: Report, steps: list[Step], branch: str) -> Report:
    """Build one plan of the cleanup.

    Returns
    -------
    dict[str, typing.Any]
        The plan for ``branch``.
    """
    return {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": "delegated native diagnostic load cleanup operator",
        "oracle_sha256": ORACLE_SHA256,
        "gap_ids": ["GAP-037"],
        "environment": runtime,
        "endpoints": {"control": {"host": "127.0.0.1", "port": CONTROL_PORT}},
        "steps": steps,
        "expectation": {
            "case": "conditional-cleanup",
            "branch": branch,
            "owned_name_hex": NAME.hex(),
        },
    }


def build_plans(runtime: Report) -> Plans:
    """Build and validate the undecided, absent and present plans.

    Returns
    -------
    Plans
        The shared prefix and the three plans.
    """
    prefix = session("a") + exchange(
        TYPE_GET_FILE_INFO, INFO_REPLY, [(FIELD_FILE_NAME, NAME)]
    )
    prefix += exchange(TYPE_LIST_FILES, FILES_REPLY, [(FIELD_FILE_PATH, b"\0\0")])
    suffix = exchange(TYPE_GET_FILE_INFO, FINAL_INFO_REPLY, [(FIELD_FILE_NAME, NAME)])
    suffix += exchange(TYPE_LIST_FILES, FINAL_FILES_REPLY, [(FIELD_FILE_PATH, b"\0\0")])
    suffix += exchange(ACCOUNTS_REQUEST, FINAL_ACCOUNTS_REPLY, [])
    suffix += roster(ROSTER_REPLY) + diagnostic(DIAGNOSTIC_REPLY) + [close("a")]
    deletion = exchange(TYPE_DELETE_FILE, DELETION_REPLY, [(FIELD_FILE_NAME, NAME)])
    plans = Plans(
        prefix,
        _plan(runtime, prefix, "unresolved"),
        _plan(runtime, prefix + suffix, "absent"),
        _plan(runtime, prefix + deletion + suffix, "present"),
    )
    for plan in plans[1:]:
        validate_plan(plan)
    return plans


def execute(run: Run, plans: Plans, baseline: Baseline) -> None:
    """Run the prefix, choose the branch from its replies and run that branch.

    Parameters
    ----------
    run : Run
        The run state; its ``selected`` plan and ``completed`` count are
        updated as the run proceeds.
    plans : Plans
        The prefix and the three plans.
    baseline : Baseline
        The views to compare the end state with.
    """
    recorder = run.recorder
    for step in plans.prefix:
        recorder.execute(run.completed, step)
        run.completed += 1
    branch = choose_owned_branch(
        reply_of(recorder, INFO_REPLY), reply_of(recorder, FILES_REPLY)
    )
    run.selected = plans.present if branch == "present" else plans.absent
    recorder.plan = run.selected
    for step in run.selected["steps"][len(plans.prefix) :]:
        recorder.execute(run.completed, step)
        run.completed += 1
    check_final(run, baseline)


def _report(run: Run, plan_bytes: bytes, identity: Report) -> Report:
    """Assemble the report of a cleanup run.

    Returns
    -------
    dict[str, typing.Any]
        The report, carrying the identity of the scripts that made it.
    """
    selected, recorder = run.selected, run.recorder
    return {
        "schema_version": 1,
        "profile": selected["profile"],
        "status": run.status,
        "native_conformance": False,
        "identity_scope": IDENTITY_SCOPE,
        "operator": selected["operator"],
        "oracle_sha256": selected["oracle_sha256"],
        "plan_sha256": digest(plan_bytes),
        "driver_sha256": identity["digest"],
        "driver_identity": identity,
        "recorded_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "started_at_utc": recorder.started_at_utc,
        "gap_ids": selected["gap_ids"],
        "completed_actions": run.completed,
        "error": run.error,
        "events": recorder.events,
        "frames": recorder.frames,
        "streams": recorder.streams(),
        "branch": selected["expectation"]["branch"],
    }


class CleanupPaths(typ.NamedTuple):
    """The files and directories that a cleanup reads and writes."""

    binary: Path
    output: Path
    baseline: Path


def conditional_cleanup(runtime: Report, paths: CleanupPaths, identity: Report) -> None:
    """Run one fail-closed capture; delete only a positively identified owned file.

    Parameters
    ----------
    runtime : dict[str, typing.Any]
        The runtime record, used as the plan environment.
    paths : CleanupPaths
        The oracle binary (whose hash must be the recorded one), the new
        directory that receives the plan, the report and the checksums, and
        the preflight capture whose views the end state must match.
    identity : dict[str, typing.Any]
        The record of the scripts that make this capture.

    Raises
    ------
    ValueError
        If the oracle binary differs.
    SystemExit
        With status 1 when the cleanup did not complete.
    """
    binary, output, baseline_dir = paths
    baseline = read_baseline(baseline_dir)
    plans = build_plans(runtime)
    if digest(binary.read_bytes()) != ORACLE_SHA256:
        message = "Oracle binary hash mismatch"
        raise ValueError(message)
    output.mkdir(parents=True, exist_ok=False)
    run = Run(Recorder(plans.undecided), plans.undecided)
    try:
        execute(run, plans, baseline)
    except (OSError, EOFError, ValueError, StopIteration) as failure:
        run.status, run.error = "failed", f"{type(failure).__name__}: {failure}"
    finally:
        for name, connection in run.recorder.sockets.items():
            connection.close()
            run.recorder.event(run.completed, name, "close")
    plan_bytes = (json.dumps(run.selected, indent=2) + "\n").encode()
    report = _report(run, plan_bytes, identity)
    (output / "plan.json").write_bytes(plan_bytes)
    (output / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (output / "checksums.sha256").write_text(
        "".join(
            f"{digest((output / name).read_bytes())}  {name}\n"
            for name in ("plan.json", "report.json")
        ),
        encoding="utf-8",
    )
    print(
        f"native-mac-oracle cleanup: {run.status}; {run.completed} actions; "
        f"branch {report['branch']}"
    )
    if run.status != "completed":
        raise SystemExit(1)
