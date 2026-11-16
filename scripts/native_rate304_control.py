#!/usr/bin/env python3
"""Run and verify one bounded native 304 reset/limit experiment.

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
import native_rate304_cases as cases
from native_ban_expiry_control import runtime_gate, utc
from native_control_readiness import BASELINE_FIELDS, field_digest
from native_rate304_control_classify import classify
from native_rate304_control_frames import (
    agreement,
    digest,
    exact_fields,
    login_identity,
    need,
    one,
    subject_identity,
    successful,
    update_frame,
)
from native_rate304_control_perform import perform
from native_rate304_control_phases import (
    observer_baseline,
    phase_complete,
    roster_uid,
    run_update_phase,
    update_and_barrier,
    validated_phase_progress,
)
from native_rate304_control_report import expected_actions
from native_rate304_control_report import verify_report as check_report
from native_rate304_control_wire import Wire
from protocol_capture import ORACLE_SHA256, decode_frame

# The scripts that make this capture, in the fixed order of its identity digest.
CAPTURE_MODULES = (
    "native_rate304_control.py",
    "native_rate304_control_classify.py",
    "native_rate304_control_frames.py",
    "native_rate304_control_perform.py",
    "native_rate304_control_phases.py",
    "native_rate304_control_report.py",
    "native_rate304_control_wire.py",
)
# The plan generator, whose identity the report records beside this script's.
CASES_MODULES = ("native_rate304_cases.py",)

__all__ = [
    "BASELINE_FIELDS",
    "CAPTURE_MODULES",
    "CASES_MODULES",
    "ORACLE_SHA256",
    "RunPaths",
    "Wire",
    "agreement",
    "classify",
    "decode_frame",
    "digest",
    "exact_fields",
    "expected_actions",
    "field_digest",
    "login_identity",
    "main",
    "need",
    "observer_baseline",
    "one",
    "perform",
    "phase_complete",
    "prepared",
    "roster_uid",
    "run",
    "run_update_phase",
    "subject_identity",
    "successful",
    "update_and_barrier",
    "update_frame",
    "validated_phase_progress",
    "verify_report",
]

type Report = dict[str, typ.Any]

MAX_WINDOW_SECONDS = 720
MIN_REMAINING_SECONDS = 390
HARD_DEADLINE_SECONDS = 210
NAMESPACE_PATH = "/proc/self/ns/net"


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
    """Check a finished report against its plan and its own events.

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
    need(
        json.loads((directory / "source-hashes.json").read_text(encoding="utf-8"))
        == {"plan.json": digest(raw)},
        "Prepared plan hash differs",
    )
    plan = json.loads(raw)
    need(
        plan == cases.source_plan(plan["environment"], plan["endpoint"]["port"]),
        "Prepared plan differs from frozen producer",
    )
    return plan


class RunPaths(typ.NamedTuple):
    """The files and directories that one 304 run reads and writes."""

    plan_dir: Path
    receipt: Path
    binary: Path
    output: Path


class Gated(typ.NamedTuple):
    """What the gates before a run read: the plan, the receipt and its deadline."""

    plan: Report
    receipt_raw: bytes
    receipt: Report
    deadline_utc: dt.datetime
    remaining: float


def _gate(paths: RunPaths) -> Gated:
    """Gate the plan, the receipt, the namespace and the binary before the run.

    Returns
    -------
    Gated
        The plan, the receipt's bytes, the receipt, the epoch deadline and the
        seconds that were left when the gate began.
    """
    plan = prepared(paths.plan_dir)
    receipt_raw = paths.receipt.read_bytes()
    receipt = json.loads(receipt_raw)
    deadline_utc = utc(receipt["deadline_utc"])
    remaining = (deadline_utc - dt.datetime.now(dt.UTC)).total_seconds()
    need(
        MIN_REMAINING_SECONDS <= remaining <= MAX_WINDOW_SECONDS
        and (deadline_utc - utc(receipt["epoch_started_utc"])).total_seconds()
        <= MAX_WINDOW_SECONDS,
        "Capture epoch lacks390s or exceeds12min",
    )
    runtime_gate(receipt, plan["environment"], deadline_utc)
    need(
        os.stat(NAMESPACE_PATH).st_ino  # ruff: ignore[os-stat]  # /proc identity; the tests substitute os.stat
        == plan["environment"]["emulator_netns_inode"],
        "Runner outside owned lab namespace",
    )
    need(digest(paths.binary.read_bytes()) == ORACLE_SHA256, "Oracle binary differs")
    return Gated(plan, receipt_raw, receipt, deadline_utc, remaining)


class Outcome(typ.NamedTuple):
    """How a run ended, as its report records it."""

    status: str
    error: str
    result: Report
    started: float


def _report(
    wire: Wire, plan: Report, outcome: Outcome, inputs: tuple[Path, bytes]
) -> Report:
    """Assemble the report of a run.

    Returns
    -------
    dict[str, typing.Any]
        The report, with the identity of the scripts that made it.
    """
    plan_dir, receipt_raw = inputs
    result = outcome.result
    producer = capture_identity.identity(CASES_MODULES)
    source = capture_identity.identity(CAPTURE_MODULES)
    return {
        "schema_version": 1,
        "status": outcome.status,
        "error": outcome.error,
        "plan_sha256": digest((plan_dir / "plan.json").read_bytes()),
        "cases_sha256": producer["digest"],
        "cases_identity": producer,
        "source_sha256": source["digest"],
        "source_identity": source,
        "oracle_sha256": ORACLE_SHA256,
        "receipt_sha256": digest(receipt_raw),
        "started_at_utc": wire.recorder.started_at_utc,
        "recorded_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "elapsed_seconds": time.monotonic() - outcome.started,
        "native_clock_calibrated": False,
        "phase_mode": plan["schedule"]["phase_mode"],
        "phase_receipts": result.get("phase_receipts", {}),
        "identities": {
            k: wire.identities.get(k, result.get(k))
            for k in ("observer_uid", "paced_uid", "burst_uid")
        },
        "phase_progress": {
            name: validated_phase_progress(wire, name, wire.identities[f"{name}_uid"])
            for name in ("paced", "burst")
            if f"{name}_uid" in wire.identities
        },
        "timing": result.get("timing", {}),
        "actions": wire.actions,
        "events": wire.recorder.events,
        "frames": wire.frames,
        "streams": wire.recorder.streams(),
        "unparsed_hex": {name: raw.hex() for name, raw in wire.buffers.items()},
        "terminals": wire.terminals,
        "preflight": "operator-provided separate18 report, not runner-executed",
        "postflight": "retained observer controls only; no fresh login/full A7",
    }


def _release(wire: Wire, status: str, error: str) -> tuple[str, str]:
    """Close every flow and release any descriptor that a failed close left.

    Returns
    -------
    tuple[str, str]
        The status and the error, extended if the teardown failed.
    """
    try:
        wire.close_all()
    except (OSError, ValueError, TimeoutError) as failure:
        status = "failed"
        error += f"; teardown {type(failure).__name__}: {failure}"
    for name, sock in list(wire.recorder.sockets.items()):
        sock.close()
        wire.recorder.sockets.pop(name)
        wire.recorder.event(-1, name, "close_after_failure")
    return status, error


def run(paths: RunPaths) -> Report:
    """Run the experiment and write its plan and report.

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
    gated = _gate(paths)
    plan = gated.plan
    paths.output.mkdir(parents=True, exist_ok=False)

    def guard() -> None:
        """Re-read the runtime before each connection."""
        runtime_gate(gated.receipt, plan["environment"], gated.deadline_utc)

    wire = Wire(
        plan,
        min(
            time.monotonic() + HARD_DEADLINE_SECONDS,
            time.monotonic() + gated.remaining,
        ),
        guard,
    )
    started = time.monotonic()
    status, error, result = "completed", "", {}
    try:
        result = perform(wire, plan)
        guard()
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
        status, error = _release(wire, status, error)
    report = _report(
        wire,
        plan,
        Outcome(status, error, result, started),
        (paths.plan_dir, gated.receipt_raw),
    )
    if status == "completed":
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
    """Run the experiment from the command line and exit non-zero if it failed.

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
    report = run(
        RunPaths(args.plan_dir, args.capture_receipt, args.binary, args.output)
    )
    print(json.dumps({"status": report["status"], "error": report["error"]}))
    if report["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
