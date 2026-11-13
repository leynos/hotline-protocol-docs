#!/usr/bin/env python3
"""Verify the bounded native settings-113 matrix without assuming duplicate policy."""

import argparse
import json
from pathlib import Path

from native_settings_cases import CASES, cases
from protocol_capture import verify_capture
from verify_native_core import require


def fields(frame: dict) -> dict[int, bytes]:
    return {entry["id"]: bytes.fromhex(entry["hex"]) for entry in frame["fields"]}


def semantic(report: dict, expected: dict) -> dict:
    """Infer effective refusal/auto flags from independent PM delivery/feedback."""
    frames = report["frames"]
    replies = [f for f in frames if f["is_reply"] and f["id"] == 70]
    require(len(replies) == 1 and replies[0]["error"] == 0, "PM ACK missing/failed")
    for identifier, connection in [
        (41, "main"),
        (71, "main"),
        (72, "subject"),
        (81, "main"),
        (82, "subject"),
    ]:
        ack = [
            f
            for f in frames
            if f["connection"] == connection and f["is_reply"] and f["id"] == identifier
        ]
        require(len(ack) == 1 and ack[0]["error"] == 0, "Barrier ACK missing/failed")
    updates = [
        f
        for f in frames
        if f["connection"] == "main" and f["type"] == 301 and not f["is_reply"]
    ]
    require(len(updates) >= 3, "Login/settings/restore 301 missing")
    uid = fields(updates[0]).get(103, b"")
    require(
        len(uid) == 2 and int.from_bytes(uid, "big") != 0, "Dynamic subject UID missing"
    )
    require(all(fields(f).get(103) == uid for f in updates[:3]), "Subject UID changed")
    require(
        all(fields(f).get(104) == b"\0\x07" for f in updates[:3]),
        "Subject icon control changed",
    )
    notices = [f for f in frames if f["type"] == 104 and not f["is_reply"]]
    received = [fields(f) for f in notices if f["connection"] == "subject"]
    feedback = [fields(f) for f in notices if f["connection"] == "main"]
    pm_text = bytes.fromhex(expected["pm_text"])
    delivered = (
        len(received) == 1
        and received[0].get(101) == pm_text
        and received[0].get(113) == b"\0\x01"
    )
    require(not received or delivered, "PM delivery bytes differ")
    require(len(feedback) <= 1, "Multiple PM feedback messages")
    feedback_option = (
        int.from_bytes(feedback[0].get(113, b""), "big") if feedback else 0
    )
    require(feedback_option in {0, 2, 4}, "Unknown PM feedback option")
    require(not feedback or feedback_option in {2, 4}, "PM feedback lacks option")
    # A refusal suppresses the original; auto response may coexist with it.
    refuse = not delivered
    auto = feedback_option == 4
    require(not (delivered and feedback_option == 2), "Refusal feedback with delivery")
    require(
        not (refuse and feedback_option == 0), "Suppression without refusal feedback"
    )
    observed = (1 if refuse else 0) | (4 if auto else 0)
    if expected["duplicate"]:
        allowed = {
            int.from_bytes(value, "big") for value in CASES[expected["case"]][0] or []
        }
        require(observed in allowed, "Duplicate selection outside submitted values")
    else:
        require(observed == expected["expected_flags"], "Field-113 state differs")
    return {
        "case": expected["case"],
        "observed_flags": observed,
        "subject_uid_hex": uid.hex(),
        "feedback_option": feedback_option,
    }


def verify(directory: Path) -> dict:
    expected_cases = cases()
    names = {p.name for p in directory.iterdir() if p.is_dir()}
    require(names == set(expected_cases), "Settings corpus inventory differs")
    results = []
    for name, (steps, expected) in expected_cases.items():
        case = directory / name
        plan = json.loads((case / "plan.json").read_text())
        require(
            plan["steps"] == steps and plan["expectation"] == expected, "Plan differs"
        )
        report = verify_capture(case)
        require(
            report["status"] == "completed"
            and report["profile"] == "native-mac-oracle",
            "Capture incomplete/profile differs",
        )
        results.append(semantic(report, expected))
    return {
        "cases": results,
        "scope": "304 field 113 only; duplicate selections measured per case",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == "__main__":
    main()
