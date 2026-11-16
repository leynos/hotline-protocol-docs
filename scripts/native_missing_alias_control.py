#!/usr/bin/env python3
"""Run one positive alias rehearsal; never remove the target.

The runner is split across the modules of ``CAPTURE_MODULES``, and this one
re-exports every public name of them. The report records which scripts made the
capture (decision D31): ``source_sha256`` is the digest of the modules of
``CAPTURE_MODULES`` and ``source_identity`` holds the commit and the hash of
each; ``cases_sha256`` and ``cases_identity`` do the same for the plan
generator. A report made before that decision holds the hash of one file in
each of ``source_sha256`` and ``cases_sha256``. The plan's ``source-hashes.json``
likewise gains ``native_missing_alias_control_identity``.
"""

import argparse
import datetime as dt
import json
import os
import time
import typing as typ
from pathlib import Path

import capture_identity
import native_missing_alias_cases as cases
from native_ban_expiry_control import runtime_gate, utc
from native_missing_alias_control_frames import (
    AGREEMENT_SHA,
    ALIAS_205,
    ALIAS_206,
    ALIAS_213,
    SCREEN_KEYS,
    Wire,
    digest,
    direct,
    exact_fields,
    need,
    positive_alias,
)
from native_missing_alias_control_host import host_state, same_data_target, same_target
from native_missing_alias_control_operator import check_screens, operator_gate
from native_missing_alias_control_perform import exchange, perform
from protocol_capture import ORACLE_SHA256
from verify_native_auth import ADMIN

# The scripts that make this capture, in the fixed order of its identity digest.
CAPTURE_MODULES = (
    "native_missing_alias_control.py",
    "native_missing_alias_control_frames.py",
    "native_missing_alias_control_host.py",
    "native_missing_alias_control_operator.py",
    "native_missing_alias_control_perform.py",
)
# The plan generator, whose identity the report records beside this script's.
CASES_MODULES = ("native_missing_alias_cases.py",)
IDENTITY_KEY = "native_missing_alias_control_identity"

__all__ = [
    "ADMIN",
    "AGREEMENT_SHA",
    "ALIAS_205",
    "ALIAS_206",
    "ALIAS_213",
    "CAPTURE_MODULES",
    "CASES_MODULES",
    "IDENTITY_KEY",
    "ORACLE_SHA256",
    "SCREEN_KEYS",
    "RunPaths",
    "Wire",
    "check_screens",
    "digest",
    "direct",
    "exact_fields",
    "exchange",
    "host_state",
    "main",
    "need",
    "operator_gate",
    "perform",
    "positive_alias",
    "prepared",
    "run",
    "same_data_target",
    "same_target",
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
        "plan.json": digest(raw),
        "native_missing_alias_cases.py": digest(Path(cases.__file__).read_bytes()),
        "native_missing_alias_control.py": record.get("digest"),
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
        "Prepared plan/source hash differs",
    )
    plan = json.loads(raw)
    need(
        plan == cases.source_plan(plan["environment"], plan["endpoint"]["port"]),
        "Prepared plan differs from source",
    )
    return plan


class RunPaths(typ.NamedTuple):
    """The files and directories that one rehearsal reads and writes."""

    plan_dir: Path
    capture_receipt: Path
    operator_receipt: Path
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
    """Gate the plan, the receipt, the namespace and the host before the run.

    Returns
    -------
    Gated
        The plan, the receipt's bytes, the receipt, the epoch deadline and the
        seconds that were left when the gate began.
    """
    plan = prepared(paths.plan_dir)
    profile = plan["environment"].get("capture_window_profile")
    receipt_raw = paths.capture_receipt.read_bytes()
    receipt = json.loads(receipt_raw)
    deadline = utc(receipt["deadline_utc"])
    remaining = (deadline - dt.datetime.now(dt.UTC)).total_seconds()
    need(remaining >= MIN_REMAINING_SECONDS, "M2 fixed epoch margin below 390 seconds")
    need(
        receipt["emulator_pid"] == plan["environment"]["emulator_pid"],
        "Capture/runtime PID differs",
    )
    runtime_gate(receipt, plan["environment"], deadline, capture_window_profile=profile)
    need(
        os.stat(NAMESPACE_PATH).st_ino  # ruff: ignore[os-stat]  # /proc identity; the tests substitute os.stat
        == plan["environment"]["emulator_netns_inode"],
        "Wrong isolated network namespace",
    )
    need(digest(paths.binary.read_bytes()) == ORACLE_SHA256, "Oracle DATA differs")
    need(
        host_state(plan)["finder"]["sha256"]
        == plan["environment"]["initial_finf_sha256"],
        "Pre-socket Finder sidecar differs from runtime pin",
    )
    need(not paths.output.exists(), "Output exists")
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


def _postflight(
    wire: Wire, paths: RunPaths, gated: Gated, outcome: tuple[str, str]
) -> tuple[str, str]:
    """Re-check the sources, the runtime and the host after the run.

    Returns
    -------
    tuple[str, str]
        The status and the error, extended if the postflight failed.
    """
    status, error = outcome
    plan, profile = gated.plan, gated.plan["environment"].get("capture_window_profile")
    try:
        need(prepared(paths.plan_dir) == plan, "Post-run source/plan differs")
        runtime_gate(
            gated.receipt,
            plan["environment"],
            gated.deadline,
            capture_window_profile=profile,
        )
        postflight = host_state(plan)
        wire.partial["host_postflight"] = postflight
        if wire.partial.get("host_before") is not None:
            same_data_target(wire.partial["host_before"], postflight)
    except (OSError, ValueError, KeyError) as exc:
        status, error = "failed", error + f"; postflight {type(exc).__name__}: {exc}"
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
    source = capture_identity.identity(CAPTURE_MODULES)
    producer = capture_identity.identity(CASES_MODULES)
    return {
        "schema_version": 1,
        "status": status,
        "error": error,
        "plan_sha256": digest((plan_dir / "plan.json").read_bytes()),
        "source_sha256": source["digest"],
        "source_identity": source,
        "cases_sha256": producer["digest"],
        "cases_identity": producer,
        "receipt_sha256": digest(gated.receipt_raw),
        "started_at_utc": wire.recorder.started_at_utc,
        "recorded_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "events": wire.recorder.events,
        "frames": wire.frames,
        "actions": wire.actions,
        "streams": wire.recorder.streams(),
        "terminals": wire.terminals,
        "unparsed_hex": {name: data.hex() for name, data in wire.buffers.items()},
        **getattr(wire, "partial", {}),
    }


def run(paths: RunPaths) -> Report:
    """Run the rehearsal and write its plan and report.

    Parameters
    ----------
    paths : RunPaths
        The prepared plan directory, the capture receipt, the operator's
        receipt, the native binary and the new output directory.

    Returns
    -------
    dict[str, typing.Any]
        The report, with ``status`` ``completed`` or ``failed``.
    """
    gated = _gate(paths)
    plan, receipt, deadline = gated.plan, gated.receipt, gated.deadline
    profile = plan["environment"].get("capture_window_profile")
    paths.output.mkdir(parents=True, exist_ok=False)

    def guard() -> None:
        """Re-read the runtime before each wait."""
        runtime_gate(
            receipt, plan["environment"], deadline, capture_window_profile=profile
        )

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
        perform(wire, plan, paths.operator_receipt, guard)
    except (OSError, ValueError, TimeoutError, EOFError, KeyError, IndexError) as exc:
        status, error = "failed", f"{type(exc).__name__}: {exc}"
    finally:
        status, error = _release(wire, status, error)
    status, error = _postflight(wire, paths, gated, (status, error))
    report = _report(wire, (status, error), gated, paths.plan_dir)
    (paths.output / "plan.json").write_bytes(
        (paths.plan_dir / "plan.json").read_bytes()
    )
    (paths.output / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return report


def main() -> None:
    """Run the rehearsal from the command line and exit non-zero if it failed.

    Raises
    ------
    SystemExit
        With status 1 when the run did not complete.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--capture-receipt", type=Path, required=True)
    parser.add_argument("--operator-receipt", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(
        RunPaths(
            args.plan_dir,
            args.capture_receipt,
            args.operator_receipt,
            args.binary,
            args.output,
        )
    )
    print(json.dumps({"status": result["status"], "error": result["error"]}))
    if result["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
