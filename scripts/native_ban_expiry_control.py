#!/usr/bin/env python3
"""Gate three finite native ban-expiry capture epochs; never wait through expiry.

The controller is split across modules, and this one re-exports every public
name of them: ``native_ban_expiry_control_core`` (bounds, the timing record and
small helpers), ``_outcome`` (what each case must have observed), ``_runtime``
(the live runtime checks) and ``_case`` (one case on the wire). This module runs
an epoch.
"""

import argparse
import datetime as dt
import json
import time
import typing as typ
from pathlib import Path

import native_ban_expiry_cases as cases
from native_ban_expiry_cases import TEMPORARY_NOTICE as TEMP_TEXT
from native_ban_expiry_control_case import (
    CAPTURE_FAILURES,
    ban_timing,
    run_case,
)
from native_ban_expiry_control_core import (
    ALIAS_PURPOSE,
    ALIAS_WINDOW,
    EPOCH_CASES,
    MAX_BRACKET_SECONDS,
    MAX_WINDOW_SECONDS,
    POST_EARLIEST,
    POST_LATEST,
    PRE_EARLIEST,
    PRE_LATEST,
    Report,
    TimingBounds,
    capture_window_bounds,
    digest,
    load,
    plan_gate,
    require,
    runtime_cap_seconds,
    utc,
)
from native_ban_expiry_control_outcome import (
    account_gate,
    field_map,
    identity_before_110,
    outcome_gate,
    probe_gate,
    relevant,
)
from native_ban_expiry_control_runtime import (
    live_service,
    namespace_gate,
    runtime_gate,
)
from native_control_readiness import readiness
from protocol_capture import ORACLE_SHA256, Recorder, verify_capture

__all__ = [
    "ALIAS_PURPOSE",
    "ALIAS_WINDOW",
    "EPOCH_CASES",
    "MAX_BRACKET_SECONDS",
    "MAX_WINDOW_SECONDS",
    "ORACLE_SHA256",
    "POST_EARLIEST",
    "POST_LATEST",
    "PRE_EARLIEST",
    "PRE_LATEST",
    "TEMP_TEXT",
    "EpochPaths",
    "Recorder",
    "TimingBounds",
    "account_gate",
    "ban_timing",
    "capture_window_bounds",
    "cases",
    "digest",
    "field_map",
    "identity_before_110",
    "live_service",
    "load",
    "main",
    "namespace_gate",
    "outcome_gate",
    "plan_gate",
    "probe_gate",
    "relevant",
    "require",
    "run_case",
    "run_epoch",
    "runtime_cap_seconds",
    "runtime_gate",
    "settle_first_epoch",
    "utc",
]

SETTLE_SECONDS = 35
SETTLE_NEEDED_SECONDS = 45
DEADLINE_MARGIN_SECONDS = 10
NANOSECONDS = 1_000_000_000
BASELINES = {
    "first": "full18_control_only",
    "pre": "not_exercised_ban_active",
    "post": "not_exercised_preserve_first_lookup",
}


class EpochPaths(typ.NamedTuple):
    """The files and directories an epoch reads and writes."""

    plans: Path
    readiness_dir: Path | None
    receipt: Path
    binary: Path
    output: Path
    bounds: Path | None = None


def settle_first_epoch(summary: Report, deadline_utc: dt.datetime) -> None:
    """Leave a socket-free margin after readiness before the account cases.

    Parameters
    ----------
    summary : dict[str, typing.Any]
        The epoch summary, which receives the record of the wait.
    deadline_utc : datetime.datetime
        The deadline of the epoch.
    """
    started = dt.datetime.now(dt.UTC)
    require(
        (deadline_utc - started).total_seconds() >= SETTLE_NEEDED_SECONDS,
        "Insufficient epoch deadline for35s post-readiness settling",
    )
    started_ns = time.monotonic_ns()
    settle: dict[str, str | float | int] = {"started_utc": started.isoformat()}
    summary["post_readiness_settle"] = settle
    time.sleep(SETTLE_SECONDS)
    elapsed = (time.monotonic_ns() - started_ns) / NANOSECONDS
    settle.update(
        completed_utc=dt.datetime.now(dt.UTC).isoformat(),
        elapsed_seconds=elapsed,
        runner_socket_actions_during_wait=0,
    )
    require(
        elapsed >= SETTLE_SECONDS
        and (deadline_utc - dt.datetime.now(dt.UTC)).total_seconds()
        > DEADLINE_MARGIN_SECONDS,
        "Post-readiness settling incomplete or epoch deadline reached",
    )


def _prior_readiness(phase: str, paths: EpochPaths) -> str | None:
    """Gate the full-login readiness of the first epoch, and refuse it later.

    Returns
    -------
    str | None
        The SHA-256 of the readiness report, or ``None`` for a later epoch.

    Raises
    ------
    ValueError
        If the first epoch has no readiness capture.
    """
    if phase != "first":
        require(
            paths.readiness_dir is None,
            "Later epoch must not perform a prior Login107 readiness",
        )
        return None
    if paths.readiness_dir is None:
        message = "First epoch requires full18 readiness"
        raise ValueError(message)
    ready_plan = load(paths.readiness_dir / "plan.json")
    ready_report = verify_capture(paths.readiness_dir)
    require(
        ready_plan == load(paths.plans / "readiness.json"),
        "Control-only readiness plan changed",
    )
    require(
        ready_report["oracle_sha256"] == ORACLE_SHA256,
        "Readiness oracle differs",
    )
    readiness(ready_report)
    return digest((paths.readiness_dir / "report.json").read_bytes())


def _timing_gate(phase: str, paths: EpochPaths, receipt: Report) -> Report | None:
    """Gate a later epoch against the frozen ban time bracket.

    Returns
    -------
    dict[str, typing.Any] | None
        The timing record, or ``None`` for the first epoch.

    Raises
    ------
    ValueError
        If a later epoch has no frozen bracket.
    """
    if phase == "first":
        return None
    if paths.bounds is None:
        message = "Later probe requires frozen ban time bracket"
        raise ValueError(message)
    bounds = TimingBounds.from_json(load(paths.bounds))
    return bounds.gate(phase, dt.datetime.now(dt.UTC), receipt)


class Epoch(typ.NamedTuple):
    """What an epoch's gates compare each case with."""

    phase: str
    receipt: Report
    environment: Report
    deadline: dt.datetime


def _run_cases(paths: EpochPaths, summary: Report, epoch: Epoch) -> None:
    """Run each case of an epoch in order, recording each in the summary."""
    phase, receipt, environment, deadline = epoch
    if phase == "first":
        settle_first_epoch(summary, deadline)
    for name in EPOCH_CASES[phase]:
        runtime_gate(receipt, environment, deadline)
        planned, actual = plan_gate(paths.plans / f"{name}.json")
        require(
            actual == name and planned["environment"] == environment,
            "Case order/runtime differs",
        )
        report = run_case(planned, name, paths.output / name, deadline)
        summary["cases"][name] = {
            "status": report["status"],
            "error": report["error"],
            "plan_sha256": digest((paths.plans / f"{name}.json").read_bytes()),
        }
        require(report["status"] == "completed", f"{name}: {report['error']}")
        if name == "tempban":
            bracket = ban_timing(report, receipt)
            (paths.output / "ban-clock.json").write_text(
                json.dumps(bracket.to_json(), indent=2) + "\n"
            )


def run_epoch(phase: str, paths: EpochPaths) -> Report:
    """Run one epoch: gate its runtime, then run its cases and write a summary.

    Parameters
    ----------
    phase : str
        ``first``, ``pre`` or ``post``.
    paths : EpochPaths
        The plans, the readiness capture, the runtime receipt, the native
        binary, the output directory and, for a later epoch, the frozen ban
        time bracket.

    Returns
    -------
    dict[str, typing.Any]
        The summary, with ``status`` ``completed`` or ``failed``.
    """
    require(phase in EPOCH_CASES, "Unknown expiry epoch")
    receipt = load(paths.receipt)
    first = load(paths.plans / f"{EPOCH_CASES[phase][0]}.json")
    deadline = utc(receipt["deadline_utc"])
    runtime_gate(receipt, first["environment"], deadline)
    require(
        digest(paths.binary.read_bytes()) == ORACLE_SHA256,
        "Native binary identity differs",
    )
    readiness_sha = _prior_readiness(phase, paths)
    timing_result = _timing_gate(phase, paths, receipt)
    paths.output.mkdir(parents=True, exist_ok=False)
    summary: Report = {
        "phase": phase,
        "status": "completed",
        "full_file_baseline": "not_exercised",
        "capture_receipt_sha256": digest(paths.receipt.read_bytes()),
        "readiness_report_sha256": readiness_sha,
        "preprobe_baseline": BASELINES[phase],
        "cases": {},
        "timing_gate": timing_result,
    }
    try:
        _run_cases(
            paths, summary, Epoch(phase, receipt, first["environment"], deadline)
        )
    except CAPTURE_FAILURES as failure:
        summary["status"] = "failed"
        summary["error"] = f"{type(failure).__name__}: {failure}"
    (paths.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main() -> None:
    """Run one epoch from the command line and exit non-zero if it failed.

    Raises
    ------
    SystemExit
        With status 1 when the epoch did not complete.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", required=True)
    parser.add_argument("--phase", choices=tuple(EPOCH_CASES), required=True)
    parser.add_argument("--plans", type=Path, required=True)
    parser.add_argument("--readiness-dir", type=Path)
    parser.add_argument("--capture-receipt", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ban-clock", type=Path)
    args = parser.parse_args()
    result = run_epoch(
        args.phase,
        EpochPaths(
            args.plans,
            args.readiness_dir,
            args.capture_receipt,
            args.binary,
            args.output,
            args.ban_clock,
        ),
    )
    print(json.dumps(result, indent=2))
    if result["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
