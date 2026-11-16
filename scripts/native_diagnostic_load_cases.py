#!/usr/bin/env python3
"""Build bounded native 303 transfer-state observations on one owned file.

The planner is split across the modules of ``CAPTURE_MODULES``, and this one
re-exports every public name of them. The conditional cleanup records which
scripts made its capture (decision D31): ``driver_sha256`` is the digest of the
modules of ``CAPTURE_MODULES`` and ``driver_identity`` holds the commit and the
hash of each. A report made before that decision holds the hash of this one
file in ``driver_sha256``.
"""

import argparse
import json
import typing as typ
from pathlib import Path

import capture_identity
from native_diagnostic_load_cases_checks import choose_owned_branch
from native_diagnostic_load_cases_cleanup import CleanupPaths, conditional_cleanup
from native_diagnostic_load_cases_steps import (
    BODY,
    CASES,
    NAME,
    active_queue,
    boundary,
    diagnostic,
    exchange,
    preflight,
    request,
    roster,
    seed,
)
from protocol_capture import ORACLE_SHA256, validate_plan

# The scripts that make this capture, in the fixed order of its identity digest.
CAPTURE_MODULES = (
    "native_diagnostic_load_cases.py",
    "native_diagnostic_load_cases_checks.py",
    "native_diagnostic_load_cases_cleanup.py",
    "native_diagnostic_load_cases_steps.py",
)

__all__ = [
    "BODY",
    "CAPTURE_MODULES",
    "CASES",
    "NAME",
    "active_queue",
    "boundary",
    "choose_owned_branch",
    "conditional_cleanup",
    "diagnostic",
    "exchange",
    "main",
    "preflight",
    "request",
    "roster",
    "seed",
]

CONTROL_PORT = 15500
DATA_PORT = 15501

type Report = dict[str, typ.Any]


def _cleanup(
    parser: argparse.ArgumentParser, args: argparse.Namespace, environment: Report
) -> None:
    """Run the conditional cleanup, or refuse a call that lacks its guards."""
    if any((
        not args.conditional_cleanup,
        args.oracle_binary is None,
        args.baseline is None,
    )):
        parser.error("Cleanup requires conditional guard, oracle binary and baseline")
    conditional_cleanup(
        environment,
        CleanupPaths(args.oracle_binary, args.output, args.baseline),
        capture_identity.identity(CAPTURE_MODULES),
    )


def _write_plan(args: argparse.Namespace, environment: Report) -> None:
    """Write the plan of one case to a new file."""
    plan = {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": "delegated native diagnostic load operator",
        "oracle_sha256": ORACLE_SHA256,
        "gap_ids": ["GAP-037"],
        "environment": environment,
        "endpoints": {
            "control": {"host": "127.0.0.1", "port": CONTROL_PORT},
            "data": {"host": "127.0.0.1", "port": DATA_PORT},
        },
        "steps": CASES[args.case](),
        "expectation": {"case": args.case, "owned_name_hex": NAME.hex()},
    }
    validate_plan(plan)
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(plan, output, indent=2)
        output.write("\n")


def main() -> None:
    """Write the plan of one case, or run the conditional cleanup."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=[*CASES, "cleanup"])
    parser.add_argument("--runtime-record", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--conditional-cleanup", action="store_true")
    parser.add_argument("--oracle-binary", type=Path)
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    environment = json.loads(args.runtime_record.read_text(encoding="utf-8"))
    if args.case == "cleanup":
        _cleanup(parser, args, environment)
        return
    if args.conditional_cleanup:
        parser.error("Conditional cleanup is only valid for the cleanup case")
    _write_plan(args, environment)


if __name__ == "__main__":
    main()
