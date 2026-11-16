#!/usr/bin/env python3
"""Run and verify one finite, isolated native legacy-board exchange.

The runner is split across the modules of ``CAPTURE_MODULES``, and this one
re-exports every public name of them. The report records which scripts made the
capture (decision D31): ``runner_sha256`` is the digest of the modules of
``CAPTURE_MODULES`` and ``runner_identity`` holds the commit and the hash of
each; ``producer_sha256`` and ``producer_identity`` do the same for the plan
generator. A report made before that decision holds the hash of one file in each
of ``runner_sha256`` and ``producer_sha256``. The plan's ``source-hashes.json``
likewise gains ``native_board_control_identity``.
"""

import argparse
import datetime as dt
import json
import os
import time
import typing as typ
from pathlib import Path

import capture_identity
import native_board_cases as cases
from native_ban_expiry_control import runtime_gate, utc
from native_board_control_case import CaseResults, execute_case
from native_board_control_flows import (
    AGREEMENT_SHA,
    check_segment,
    login,
    post,
    read_board,
    read_denied,
    success,
)
from native_board_control_report import verify_report
from native_board_control_wire import (
    Wire,
    frame_fields,
    need,
    one,
    sha,
    strict,
)
from protocol_capture import ORACLE_SHA256, Recorder

# The scripts that make this capture, in the fixed order of its identity digest.
CAPTURE_MODULES = (
    "native_board_control.py",
    "native_board_control_case.py",
    "native_board_control_flows.py",
    "native_board_control_report.py",
    "native_board_control_wire.py",
)
# The plan generator, whose identity the report records beside this script's.
PRODUCER_MODULES = ("native_board_cases.py",)
IDENTITY_KEY = "native_board_control_identity"

__all__ = [
    "AGREEMENT_SHA",
    "CAPTURE_MODULES",
    "IDENTITY_KEY",
    "PRODUCER_MODULES",
    "CaseResults",
    "Wire",
    "check_segment",
    "execute_case",
    "frame_fields",
    "login",
    "main",
    "need",
    "one",
    "post",
    "prepared",
    "read_board",
    "read_denied",
    "run",
    "sha",
    "strict",
    "success",
    "verify_report",
]

MAX_WINDOW_SECONDS = 720
NS_PER_SECOND = 1e9
type Report = dict[str, typ.Any]


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
        "native_board_cases.py": sha(Path(cases.__file__).read_bytes()),
        "native_board_control.py": record.get("digest"),
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
    plan = json.loads(raw)
    need(
        _sources_match(
            json.loads((directory / "source-hashes.json").read_text(encoding="utf-8")),
            raw,
        ),
        "Prepared board source hash differs",
    )
    need(
        plan == cases.source_plan(plan["environment"], cases.PORT),
        "Prepared board plan differs",
    )
    return plan


class RunPaths(typ.NamedTuple):
    """The files and directories that one board run reads and writes."""

    plan_dir: Path
    receipt: Path
    binary: Path
    output: Path


def _report(
    recorder: Recorder, results: CaseResults, outcome: tuple[str, str], paths: RunPaths
) -> Report:
    """Assemble the report of a run.

    Returns
    -------
    dict[str, typing.Any]
        The report, with the identity of the scripts that made it.
    """
    status, error = outcome
    runner = capture_identity.identity(CAPTURE_MODULES)
    producer = capture_identity.identity(PRODUCER_MODULES)
    return {
        "status": status,
        "error": error,
        "plan_sha256": sha((paths.plan_dir / "plan.json").read_bytes()),
        "started_utc": recorder.started_at_utc,
        "ended_utc": dt.datetime.now(dt.UTC).isoformat(),
        "elapsed_seconds": (time.monotonic_ns() - recorder.started) / NS_PER_SECOND,
        "byte_count": recorder.byte_count,
        "frames": recorder.frames,
        "events": recorder.events,
        "streams": recorder.streams(),
        "post_data_hex": [x.hex() for x in results.payloads],
        "segments_hex": [x.hex() for x in results.segments],
        "reads": results.reads,
        "whole_board_sha256": sha(b"".join(reversed(results.segments))),
        "storage": "requires_stopped_guest_fork",
        "full_a7": "not_exercised",
        "capture_receipt_sha256": sha(paths.receipt.read_bytes()),
        "native_source_sha256": ORACLE_SHA256,
        "runner_sha256": runner["digest"],
        "runner_identity": runner,
        "producer_sha256": producer["digest"],
        "producer_identity": producer,
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
        "Board epoch deadline differs",
    )
    runtime_gate(receipt, plan["environment"], deadline_utc)
    need(
        os.stat("/proc/self/ns/net").st_ino  # ruff: ignore[os-stat]  # /proc identity; the tests substitute os.stat
        == receipt["emulator_netns_inode"],
        "Runner not in isolated guest namespace",
    )
    need(sha(paths.binary.read_bytes()) == ORACLE_SHA256, "Native source fork differs")
    return plan, receipt, deadline_utc


def run(paths: RunPaths) -> Report:
    """Run the case and write its report, even when the case fails.

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
    recorder = Recorder(plan)
    wire = Wire(
        recorder,
        min(
            time.monotonic() + cases.HARD_SECONDS,
            time.monotonic() + (deadline_utc - dt.datetime.now(dt.UTC)).total_seconds(),
        ),
    )
    status = "failed"
    error = ""
    results = CaseResults()
    try:
        execute_case(wire, plan, results)
        runtime_gate(receipt, plan["environment"], deadline_utc)
        status = "completed"
    except (OSError, ValueError, TimeoutError, EOFError, KeyError) as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        for name in list(recorder.sockets):
            try:
                wire.close(name)
            except (OSError, ValueError, TimeoutError, EOFError) as exc:
                error += f"; {name} tail: {type(exc).__name__}: {exc}"
                status = "failed"
        report = _report(recorder, results, (status, error), paths)
        (paths.output / "report.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
    if status == "completed":
        try:
            verify_report(plan, report)
        except ValueError as exc:
            report["status"] = "failed"
            report["error"] = f"Report verification: {exc}"
            (paths.output / "report.json").write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8"
            )
    return report


def main() -> None:
    """Run the case from the command line and exit non-zero if it failed.

    Raises
    ------
    SystemExit
        With status 1 when the case did not complete.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = run(RunPaths(args.plan, args.receipt, args.binary, args.output))
    print(json.dumps({"status": report["status"], "error": report["error"]}))
    if report["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
