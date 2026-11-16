#!/usr/bin/env python3
"""Run the bounded B74 liveness schedule inside its owned network namespace.

The runner is split across the modules of ``CAPTURE_MODULES``, and this one
re-exports every public name of them. The report records which scripts made the
capture (decision D31): ``source_sha256`` is the digest of the modules of
``CAPTURE_MODULES`` and ``source_identity`` holds the commit and the hash of
each; ``cases_sha256`` and ``cases_identity`` do the same for the plan
generator. A report made before that decision holds the hash of one file in
each of ``source_sha256`` and ``cases_sha256``.
"""

import argparse
import datetime as dt
import json
import os
import time
import typing as typ
from pathlib import Path

import capture_identity
import native_liveness_cases as cases
from native_ban_expiry_control import runtime_gate, utc
from native_liveness_control_checks import (
    Epoch,
    agreement_ok,
    check_b_preonline,
    check_complete,
    check_failure,
    check_observer,
    matching,
    observer_online,
    perform_operation,
    perform_schedule,
    successful,
)
from native_liveness_control_report import verify_report as check_report
from native_liveness_control_timeline import Timeline, digest, need
from protocol_capture import ORACLE_SHA256

# The scripts that make this capture, in the fixed order of its identity digest.
CAPTURE_MODULES = (
    "native_liveness_control.py",
    "native_liveness_control_checks.py",
    "native_liveness_control_report.py",
    "native_liveness_control_timeline.py",
)
# The plan generator, whose identity the report records beside this script's.
CASES_MODULES = ("native_liveness_cases.py",)

__all__ = [
    "CAPTURE_MODULES",
    "CASES_MODULES",
    "ORACLE_SHA256",
    "Timeline",
    "agreement_ok",
    "check_b_preonline",
    "check_complete",
    "check_failure",
    "check_observer",
    "digest",
    "main",
    "matching",
    "need",
    "perform_operation",
    "prepared",
    "run",
    "successful",
    "verify_report",
]

type Report = dict[str, typ.Any]

MAX_WINDOW_SECONDS = 720
OBSERVER_WAIT_SECONDS = 8
POLL_SLICE_SECONDS = 0.05
NS_PER_SECOND = 1_000_000_000
NET_NAMESPACE_PATH = "/proc/self/ns/net"
OBSERVER_FLOW = "o"
SEPARATE_CONTROL = "operator-provided separate18 control report, not runner-executed"


def _identified(report: Report) -> bool:
    """Say whether a report names the live scripts that are checking it.

    Returns
    -------
    bool
        ``True`` when the source and the plan generator that made the report
        are the live ones, by their identity records and their digests.
    """
    return all(
        capture_identity.check(report[f"{role}_identity"], modules)
        and report[f"{role}_sha256"] == report[f"{role}_identity"]["digest"]
        for role, modules in (("cases", CASES_MODULES), ("source", CAPTURE_MODULES))
    )


def verify_report(plan: Report, report: Report) -> None:
    """Check a complete custom report; this is not generic verify_capture.

    Parameters
    ----------
    plan : dict[str, typing.Any]
        The prepared plan.
    report : dict[str, typing.Any]
        The report that the run built.
    """
    check_report(plan, report, _identified)


def prepared(directory: Path) -> Report:
    """Read the prepared plan and require it to be the one the generator makes.

    Returns
    -------
    dict[str, typing.Any]
        The plan.
    """
    raw = (directory / "plan.json").read_bytes()
    hashes = json.loads((directory / "source-hashes.json").read_text(encoding="utf-8"))
    need(hashes == {"plan.json": digest(raw)}, "Prepared plan hash differs")
    plan = json.loads(raw)
    need(
        plan == cases.source_plan(plan["environment"], plan["endpoint"]["port"]),
        "Prepared schedule differs from frozen producer",
    )
    return plan


def _run_window(timeline: Timeline, epoch: Epoch) -> None:
    """Log the observer in, run the schedule and the window, and check the frames."""
    timeline.connect(OBSERVER_FLOW)
    timeline.send(OBSERVER_FLOW, epoch.plan["observer_login_hex"])
    timeline.wait_for(
        lambda: observer_online(timeline),
        OBSERVER_WAIT_SECONDS,
        "observer online107/354/109",
    )
    check_observer(timeline)
    runtime_gate(epoch.receipt, epoch.plan["environment"], epoch.deadline_utc)
    t0 = time.monotonic()
    timeline.operations.append({
        "label": "t0",
        "elapsed_ns": time.monotonic_ns() - timeline.recorder.started,
    })
    perform_schedule(timeline, epoch, t0)
    while time.monotonic() < t0 + cases.MAX_SECONDS:
        timeline.poll(
            min(POLL_SLICE_SECONDS, t0 + cases.MAX_SECONDS - time.monotonic())
        )
    epoch.window_completed = True
    epoch.window_elapsed_ns = time.monotonic_ns() - timeline.recorder.started
    timeline.window_frame_count = len(timeline.frames)
    timeline.window_status = {
        name: timeline.terminals.get(name, "bounded_no_eof_through_window")
        for name in timeline.buffers
    }
    check_complete(timeline)


def _drain(timeline: Timeline, status: str, error: str) -> tuple[str, str]:
    """Drain and close every flow, recording a failure of the teardown.

    Returns
    -------
    tuple[str, str]
        The status and the error, extended if the teardown failed.
    """
    try:
        timeline.final_drain()
    except (OSError, ValueError, TimeoutError) as failure:
        status = "failed"
        error += f"; teardown {type(failure).__name__}: {failure}"
    for name in list(timeline.recorder.sockets):
        timeline.close(name)
    return status, error


class Outcome(typ.NamedTuple):
    """How a run ended, as its report records it."""

    status: str
    error: str
    started: float


class RunPaths(typ.NamedTuple):
    """The files and directories that one liveness run reads and writes."""

    plan_dir: Path
    receipt: Path
    binary: Path
    output: Path


def _report(
    timeline: Timeline, epoch: Epoch, outcome: Outcome, paths: RunPaths
) -> Report:
    """Assemble the report of a run.

    Returns
    -------
    dict[str, typing.Any]
        The report, with the identity of the scripts that made it.
    """
    window = epoch.window_completed
    source = capture_identity.identity(CAPTURE_MODULES)
    producer = capture_identity.identity(CASES_MODULES)
    return {
        "schema_version": 1,
        "status": outcome.status,
        "error": outcome.error,
        "window_completed": window,
        "window_elapsed_ns": epoch.window_elapsed_ns if window else None,
        "window_frame_count": timeline.window_frame_count,
        "native_conformance": False,
        "preflight": SEPARATE_CONTROL,
        "postflight": SEPARATE_CONTROL,
        "plan_sha256": digest((paths.plan_dir / "plan.json").read_bytes()),
        "oracle_sha256": ORACLE_SHA256,
        "receipt_sha256": digest(paths.receipt.read_bytes()),
        "cases_sha256": producer["digest"],
        "cases_identity": producer,
        "source_sha256": source["digest"],
        "source_identity": source,
        "started_at_utc": timeline.recorder.started_at_utc,
        "recorded_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "elapsed_seconds": time.monotonic() - outcome.started,
        "operations": timeline.operations,
        "events": timeline.recorder.events,
        "frames": timeline.frames,
        "unparsed_hex": {name: data.hex() for name, data in timeline.buffers.items()},
        "terminals": timeline.terminals,
        "window_status": timeline.window_status,
        "streams": timeline.recorder.streams(),
    }


def _gate(paths: RunPaths) -> tuple[Report, Report, dt.datetime]:
    """Gate the plan, the receipt, the namespace and the binary before the run.

    Returns
    -------
    tuple[dict[str, typing.Any], dict[str, typing.Any], datetime.datetime]
        The plan, the receipt and the epoch deadline.
    """
    plan = prepared(paths.plan_dir)
    receipt = json.loads(paths.receipt.read_text(encoding="utf-8"))
    deadline_utc = utc(receipt["deadline_utc"])
    need(
        0
        < (deadline_utc - dt.datetime.now(dt.UTC)).total_seconds()
        <= MAX_WINDOW_SECONDS,
        "Epoch must fit12min",
    )
    runtime_gate(receipt, plan["environment"], deadline_utc)
    need(
        os.stat(NET_NAMESPACE_PATH).st_ino  # ruff: ignore[os-stat]  # /proc identity; the tests substitute os.stat
        == plan["environment"]["emulator_netns_inode"],
        "Caller is outside the owned emulator namespace",
    )
    need(digest(paths.binary.read_bytes()) == ORACLE_SHA256, "Oracle binary differs")
    return plan, receipt, deadline_utc


def run(paths: RunPaths) -> Report:
    """Run the schedule and its window, and write the plan and the report.

    Parameters
    ----------
    paths : RunPaths
        The prepared plan directory, the capture receipt, the native binary
        and the new output directory.

    Returns
    -------
    dict[str, typing.Any]
        The report, with ``status`` ``completed`` or ``failed``.
    """
    plan, receipt, deadline_utc = _gate(paths)
    paths.output.mkdir(parents=True, exist_ok=False)
    end = min(
        time.monotonic() + plan["schedule"]["hard_deadline_seconds"],
        time.monotonic() + (deadline_utc - dt.datetime.now(dt.UTC)).total_seconds(),
    )
    timeline = Timeline(plan, end)
    epoch = Epoch(plan, receipt, deadline_utc, end)
    started = time.monotonic()
    status, error = "completed", ""
    try:
        _run_window(timeline, epoch)
    except (
        OSError,
        ValueError,
        TimeoutError,
        EOFError,
        KeyError,
        IndexError,
        KeyboardInterrupt,
    ) as failure:
        status, error = "failed", f"{type(failure).__name__}: {failure}"
    finally:
        status, error = _drain(timeline, status, error)
    report = _report(timeline, epoch, Outcome(status, error, started), paths)
    if report["status"] == "completed":
        try:
            verify_report(plan, report)
        except (ValueError, KeyError, IndexError) as failure:
            report["status"] = "failed"
            report["error"] = f"Offline report check: {failure}"
    (paths.output / "plan.json").write_bytes(
        (paths.plan_dir / "plan.json").read_bytes()
    )
    (paths.output / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return report


def main() -> None:
    """Run the schedule from the command line and exit non-zero if it failed.

    Raises
    ------
    SystemExit
        With status 1 when the run did not complete.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--capture-receipt", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(
        RunPaths(args.plan_dir, args.capture_receipt, args.binary, args.output)
    )
    print(json.dumps({"status": result["status"], "error": result["error"]}))
    if result["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
