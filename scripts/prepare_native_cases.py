#!/usr/bin/env python3
"""Prepare bounded native framing and ordinary-fork fixture plans."""

import argparse
import json
from pathlib import Path

from native_framing_cases import framing
from native_resume_cases import downloads as resume_downloads
from native_resume_cases import upload_continuations, upload_probes
from native_transfer_cases import downloads, transfers
from protocol_capture import ORACLE_SHA256, validate_plan


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "suite",
        choices=[
            "framing",
            "transfers",
            "downloads",
            "resume-downloads",
            "resume-upload-probes",
            "resume-upload-continuations",
        ],
    )
    parser.add_argument("--runtime-record", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cases = {
        "framing": framing,
        "transfers": transfers,
        "downloads": downloads,
        "resume-downloads": resume_downloads,
        "resume-upload-probes": upload_probes,
        "resume-upload-continuations": upload_continuations,
    }[args.suite]()
    args.output.mkdir(parents=True, exist_ok=False)
    for name, (steps, expectation) in cases.items():
        plan = {
            "schema_version": 1,
            "profile": "native-mac-oracle",
            "operator": "native fixture operator",
            "oracle_sha256": ORACLE_SHA256,
            "environment": json.loads(args.runtime_record.read_text()),
            "gap_ids": [
                "GAP-011",
                "GAP-012",
                "GAP-013",
                "GAP-014",
                "GAP-015",
                "GAP-017",
            ]
            if args.suite == "framing"
            else ["GAP-058", "GAP-064"]
            if args.suite.startswith("resume-")
            else ["GAP-009", "GAP-055", "GAP-056", "GAP-064"],
            "endpoints": {
                "control": {"host": "127.0.0.1", "port": 15500},
                "data": {"host": "127.0.0.1", "port": 15501},
            },
            "expectation": expectation,
            "steps": steps,
        }
        validate_plan(plan)
        (args.output / (name + ".json")).write_text(json.dumps(plan, indent=2) + "\n")
    print(f"Prepared {len(cases)} {args.suite} plans")


if __name__ == "__main__":
    main()
