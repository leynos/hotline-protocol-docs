#!/usr/bin/env python3
"""Prepare the fixed, unexecuted 8-active/16-waiting native 303 case."""

import argparse
import json
from pathlib import Path

from native_diagnostic_existing_cases import NAME, diagnostic, request, roster
from native_plan import close
from native_queue_cases import attach, cancel, session
from protocol_capture import ORACLE_SHA256, validate_plan

ACTIVE_IDS = tuple(range(100, 108))
QUEUED_IDS = tuple(range(120, 136))
QUEUED_CANCEL_IDS = tuple(range(200, 216))
ACTIVE_CANCEL_IDS = tuple(range(220, 228))
MAX_REFERENCES = 24
MAX_DATA_SOCKETS = 8


def near() -> list[dict]:
    steps = session("a") + roster(10)
    for index, identifier in enumerate(ACTIVE_IDS):
        variable = f"active{index}"
        steps += request(identifier, variable) + attach(variable)
    for index, identifier in enumerate(QUEUED_IDS):
        steps += request(identifier, f"queued{index}")
        if index == 7:
            steps += diagnostic(140)
    steps += diagnostic(141)
    for index in reversed(range(len(QUEUED_IDS))):
        steps += cancel("a", QUEUED_CANCEL_IDS[index], f"queued{index}")
    for index in reversed(range(len(ACTIVE_IDS))):
        variable = f"active{index}"
        steps += cancel("a", ACTIVE_CANCEL_IDS[index], variable) + [close(variable)]
    return steps + diagnostic(240) + [close("a")]


def build(runtime: dict) -> dict:
    plan = {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": "delegated A11 near-boundary preparation; no live traffic authorised",
        "oracle_sha256": ORACLE_SHA256,
        "gap_ids": ["GAP-037"],
        "environment": runtime,
        "endpoints": {
            "control": {"host": "127.0.0.1", "port": 15500},
            "data": {"host": "127.0.0.1", "port": 15501},
        },
        "expectation": {
            "case": "near-boundary",
            "fixture_name_hex": NAME.hex(),
            "global_download_limit": 8,
            "per_client_download_limit": 8,
            "per_ip_limit": 5,
            "maximum_references": MAX_REFERENCES,
            "maximum_data_sockets": MAX_DATA_SOCKETS,
            "predicted_field101_bytes": 995,
            "a7_required_preflight_commit": "66b406a3db343467491e9446634c1b9bf8475fcc",
        },
        "steps": near(),
    }
    validate_plan(plan)
    return plan


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-record", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit(f"Refusing existing output: {args.output}")
    runtime = json.loads(args.runtime_record.read_text())
    plan = build(runtime)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(plan, indent=2) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
