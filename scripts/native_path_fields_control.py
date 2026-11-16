#!/usr/bin/env python3
"""Run and independently check one bounded native 212/325 path matrix.

The runner is split across the modules of ``CAPTURE_MODULES``, and this one
re-exports every public name of them. The report records which scripts made the
capture (decision D31): ``source_sha256`` is the digest of the modules of
``CAPTURE_MODULES`` and ``source_identity`` holds the commit and the hash of
each; ``cases_sha256`` and ``cases_identity`` do the same for the plan
generator. A report made before that decision holds the hash of one file in
each of ``source_sha256`` and ``cases_sha256``. The plan's ``source-hashes.json``
likewise gains ``native_path_fields_control_identity``.
"""

import argparse
import datetime as dt
import json
import os
import time
import typing as typ
from pathlib import Path

import capture_identity
import native_path_fields_cases as cases
from native_ban_expiry_control import runtime_gate, utc
from native_path_fields_control_classify import classify_views
from native_path_fields_control_frames import (
    AGREEMENT_SHA,
    MARKERS,
    PARENTS,
    check_names,
    exact_fields,
    exact_transition,
    file_info,
    file_types,
    file_view,
    location,
    login_gate,
    need,
    news_view,
    one,
    record_view,
    sha,
    success,
)
from native_path_fields_control_perform import connect_login, exchange, perform
from native_path_fields_control_report import verify_report as check_report
from native_path_fields_control_wire import Wire
from protocol_capture import ORACLE_SHA256

# The scripts that make this capture, in the fixed order of its identity digest.
CAPTURE_MODULES = (
    "native_path_fields_control.py",
    "native_path_fields_control_classify.py",
    "native_path_fields_control_frames.py",
    "native_path_fields_control_perform.py",
    "native_path_fields_control_report.py",
    "native_path_fields_control_wire.py",
)
# The plan generator, whose identity the report records beside this script's.
CASES_MODULES = ("native_path_fields_cases.py",)
IDENTITY_KEY = "native_path_fields_control_identity"

__all__ = [
    "AGREEMENT_SHA",
    "CAPTURE_MODULES",
    "CASES_MODULES",
    "IDENTITY_KEY",
    "MARKERS",
    "ORACLE_SHA256",
    "PARENTS",
    "RunPaths",
    "Wire",
    "check_names",
    "classify_views",
    "connect_login",
    "exact_fields",
    "exact_transition",
    "exchange",
    "file_info",
    "file_types",
    "file_view",
    "location",
    "login_gate",
    "main",
    "need",
    "news_view",
    "one",
    "perform",
    "prepared",
    "record_view",
    "run",
    "sha",
    "success",
    "verify_report",
]

type Report = dict[str, typ.Any]

MIN_REMAINING_SECONDS = 390
HARD_DEADLINE_SECONDS = 210
NAMESPACE_PATH = "/proc/self/ns/net"
LIMIT_KEYS = (
    ("max_bytes", "max_bytes"),
    ("max_frames", "max_frames"),
    ("max_tail_bytes_per_flow", "max_tail_bytes"),
)


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
        for role, modules in (("source", CAPTURE_MODULES), ("cases", CASES_MODULES))
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


def _sources_match(hashes: Report, raw: bytes) -> bool:
    """Say whether the recorded source hashes describe the live scripts.

    Returns
    -------
    bool
        ``True`` when the plan, the generator and the control scripts are the
        ones recorded, the control's by its identity record and its digest.
    """
    record = hashes.get(IDENTITY_KEY)
    if not isinstance(record, dict):
        return False
    return hashes == {
        "plan.json": sha(raw),
        "native_path_fields_cases.py": sha(Path(cases.__file__).read_bytes()),
        "native_path_fields_control.py": record.get("digest"),
        IDENTITY_KEY: record,
    } and capture_identity.check(record, CAPTURE_MODULES)


def prepared(directory: Path) -> Report:
    """Read the prepared plan and require it to be the one the generator makes.

    Returns
    -------
    dict[str, typing.Any]
        The plan.
    """
    raw = (directory / "plan.json").read_bytes()
    need(
        _sources_match(
            json.loads((directory / "source-hashes.json").read_text(encoding="utf-8")),
            raw,
        ),
        "Prepared plan or source hash differs",
    )
    plan = json.loads(raw)
    need(
        plan == cases.source_plan(plan["environment"], plan["endpoint"]["port"]),
        "Prepared plan differs from source",
    )
    return plan


class RunPaths(typ.NamedTuple):
    """The files and directories that one path-fields run reads and writes."""

    plan_dir: Path
    receipt: Path
    binary: Path
    output: Path


class Gated(typ.NamedTuple):
    """What the gates before a run read: the plan, the receipt and its deadline."""

    plan: Report
    receipt_raw: bytes
    receipt: Report
    deadline: dt.datetime
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
    deadline = utc(receipt["deadline_utc"])
    remaining = (deadline - dt.datetime.now(dt.UTC)).total_seconds()
    need(
        remaining >= MIN_REMAINING_SECONDS, "Fixed epoch start margin under 390 seconds"
    )
    need(
        receipt["emulator_pid"] == plan["environment"]["emulator_pid"],
        "Runtime receipt differs",
    )
    runtime_gate(receipt, plan["environment"], deadline)
    need(
        os.stat(NAMESPACE_PATH).st_ino  # ruff: ignore[os-stat]  # /proc identity; the tests substitute os.stat
        == plan["environment"]["emulator_netns_inode"],
        "Wrong network namespace",
    )
    need(sha(paths.binary.read_bytes()) == ORACLE_SHA256, "Oracle binary differs")
    return Gated(plan, receipt_raw, receipt, deadline, remaining)


def _wire_plan(plan: Report) -> Report:
    """Name the endpoint and the limits that the transport enforces.

    Returns
    -------
    dict[str, typing.Any]
        The reduced plan that the transport reads.
    """
    return {
        "endpoint": plan["endpoint"],
        "schedule": {
            **{name: plan["limits"][key] for name, key in LIMIT_KEYS},
            "max_simultaneous": 1,
        },
    }


def _release(wire: Wire, status: str, error: str) -> tuple[str, str]:
    """Close every flow and release any descriptor that a failed close left.

    Returns
    -------
    tuple[str, str]
        The status and the error, extended if the close failed.
    """
    try:
        wire.close_all()
    except (OSError, ValueError, TimeoutError) as exc:
        status, error = "failed", error + f"; close {type(exc).__name__}: {exc}"
        for name, sock in list(wire.recorder.sockets.items()):
            sock.close()
            wire.recorder.sockets.pop(name)
            wire.recorder.event(-1, name, "close_after_failure")
    return status, error


def _report(
    wire: Wire, outcome: tuple[str, str], gated: Gated, plan_dir: Path
) -> Report:
    """Assemble the report of a run.

    Returns
    -------
    dict[str, typing.Any]
        The report, with the identity of the scripts that made it.
    """
    status, error = outcome
    partial = getattr(wire, "partial", {})
    source = capture_identity.identity(CAPTURE_MODULES)
    producer = capture_identity.identity(CASES_MODULES)
    return {
        "schema_version": 1,
        "status": status,
        "error": error,
        "plan_sha256": sha((plan_dir / "plan.json").read_bytes()),
        "source_sha256": source["digest"],
        "source_identity": source,
        "cases_sha256": producer["digest"],
        "cases_identity": producer,
        "oracle_sha256": ORACLE_SHA256,
        "receipt_sha256": sha(gated.receipt_raw),
        "started_at_utc": wire.recorder.started_at_utc,
        "recorded_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "events": wire.recorder.events,
        "frames": wire.frames,
        "actions": wire.actions,
        "streams": wire.recorder.streams(),
        "terminals": wire.terminals,
        "unparsed_hex": {name: raw.hex() for name, raw in wire.buffers.items()},
        "views": partial.get("views", []),
        "results": partial.get("results", []),
        "progress": partial.get("progress", []),
        "request_count": wire.request_count,
        "mutation_count": partial.get("mutation_count", 0),
        "own_uid": partial.get("own_uid"),
        "current_case_index": partial.get("current_case_index"),
        "stopped_catalogue_proof": "not_exercised_by_live_runner",
    }


def run(paths: RunPaths) -> Report:
    """Run the matrix and write its plan and report.

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
    plan, receipt, deadline = gated.plan, gated.receipt, gated.deadline
    paths.output.mkdir(parents=True, exist_ok=False)

    def guard() -> None:
        """Re-read the runtime before each connection."""
        runtime_gate(receipt, plan["environment"], deadline)

    wire = Wire(
        _wire_plan(plan),
        min(
            time.monotonic() + HARD_DEADLINE_SECONDS, time.monotonic() + gated.remaining
        ),
        guard,
    )
    wire.request_count = 0
    status, error = "completed", ""
    try:
        perform(wire, plan, guard)
        runtime_gate(receipt, plan["environment"], deadline)
    except (OSError, ValueError, TimeoutError, EOFError, KeyError, IndexError) as exc:
        status, error = "failed", f"{type(exc).__name__}: {exc}"
    finally:
        status, error = _release(wire, status, error)
    report = _report(wire, (status, error), gated, paths.plan_dir)
    if status == "completed":
        try:
            verify_report(plan, report)
        except (ValueError, KeyError, IndexError) as exc:
            report["status"] = "failed"
            report["error"] = f"Offline report check: {exc}"
    (paths.output / "plan.json").write_bytes(
        (paths.plan_dir / "plan.json").read_bytes()
    )
    (paths.output / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return report


def main() -> None:
    """Run the matrix from the command line and exit non-zero if it failed.

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
