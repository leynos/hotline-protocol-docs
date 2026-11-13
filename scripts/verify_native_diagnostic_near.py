#!/usr/bin/env python3
"""Verify A11's fixed 303 near-boundary report and exact-reference cleanup."""

import argparse
import json
from pathlib import Path

from native_diagnostic_existing_cases import NAME
from native_diagnostic_near_cases import (
    ACTIVE_CANCEL_IDS,
    ACTIVE_IDS,
    QUEUED_CANCEL_IDS,
    QUEUED_IDS,
)
from protocol_capture import decode_frame, verify_capture
from verify_native_diagnostic_existing import (
    check_cancellations,
    check_diagnostic,
    check_references,
    current_uid,
    require,
    section_witness,
)
from verify_native_diagnostic_existing import (
    semantic as existing_semantic,
)


def sent_ids(report: dict) -> list[int]:
    ids = []
    for event in report["events"]:
        if event["event"] != "send" or event["connection"] != "a":
            continue
        raw = bytes.fromhex(event["hex"])
        if raw.startswith(b"TRTP"):
            continue
        ids.append(decode_frame(raw)["id"])
    return ids


def expected_ids() -> list[int]:
    return (
        [1, 10]
        + list(ACTIVE_IDS)
        + list(QUEUED_IDS[:8])
        + [140]
        + list(QUEUED_IDS[8:])
        + [141]
        + list(reversed(QUEUED_CANCEL_IDS))
        + list(reversed(ACTIVE_CANCEL_IDS))
        + [240]
    )


def near_complete(diagnostics: dict, witnesses: dict) -> bool:
    near_bytes = diagnostics["141"]["field101_bytes"]
    delta = near_bytes - diagnostics["140"]["field101_bytes"]
    return (
        all(item["status"] == "complete" for item in witnesses.values())
        and near_bytes == 995
        and delta == 8 * 29
    )


def require_positions(positions: list[int]) -> None:
    require(positions == list(range(1, 17)), "Queue positions differ")


def semantic(report: dict) -> dict:
    require(report["status"] == "completed", "Capture incomplete")
    plan = json.loads(report["_plan_path"].read_text())
    expectation = plan["expectation"]
    require(expectation["case"] == "near-boundary", "Wrong case")
    require(expectation["fixture_name_hex"] == NAME.hex(), "Wrong fixture")
    require(
        (expectation["maximum_references"], expectation["maximum_data_sockets"])
        == (24, 8),
        "Bounds differ",
    )
    require(
        (
            expectation["global_download_limit"],
            expectation["per_client_download_limit"],
            expectation["per_ip_limit"],
        )
        == (8, 8, 5),
        "Settings differ",
    )
    ids = sent_ids(report)
    require(len(ids) == len(set(ids)), "Duplicate request ID")
    require(ids == expected_ids(), "Request ID sequence differs")
    uid = current_uid(report)
    references = check_references(report, list(ACTIVE_IDS), list(QUEUED_IDS))
    require_positions(references["waiting_positions"])
    saved = [bytes.fromhex(value) for value in references["references"]]
    check_cancellations(
        report,
        {
            **{
                identifier: saved[8 + index]
                for index, identifier in enumerate(QUEUED_CANCEL_IDS)
            },
            **{
                identifier: saved[index]
                for index, identifier in enumerate(ACTIVE_CANCEL_IDS)
            },
        },
    )
    diagnostics = {
        str(identifier): check_diagnostic(report, identifier, uid)
        for identifier in (140, 141, 240)
    }
    points = {140: (8, 8), 141: (8, 16), 240: (0, 0)}
    witnesses = {
        str(identifier): section_witness(
            bytes.fromhex(diagnostics[str(identifier)]["field101_hex"]), *counts
        )
        for identifier, counts in points.items()
    }
    near_bytes = diagnostics["141"]["field101_bytes"]
    delta = near_bytes - diagnostics["140"]["field101_bytes"]
    complete = near_complete(diagnostics, witnesses)
    return {
        "case": "near-boundary",
        "status": "verified" if complete else "incomplete-witness",
        **references,
        "diagnostics": diagnostics,
        "witnesses": witnesses,
        "predicted_field101_bytes": 995,
        "observed_extra_waiting_bytes": delta,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=("near-boundary", "postflight"))
    parser.add_argument("capture", type=Path)
    parser.add_argument("--a7-baseline", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit(f"Refusing existing output: {args.output}")
    report = verify_capture(args.capture)
    report["_plan_path"] = args.capture / "plan.json"
    if args.case == "postflight":
        require(args.a7_baseline is not None, "A7 baseline required")
        baseline = verify_capture(args.a7_baseline)
        result = existing_semantic("postflight", report, baseline)
    else:
        result = semantic(report)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"{args.case}: {result['status']}")
    if result["status"] != "verified":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
