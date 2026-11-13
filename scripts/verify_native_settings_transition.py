#!/usr/bin/env python3
"""Verify or explicitly run one stage-gated same-session 304 matrix."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import native_settings_transition_cases as cases
from protocol_capture import Recorder, digest, validate_plan, verify_capture
from verify_native_auth import reply, roster
from verify_native_core import require
from verify_native_shx import fields


def stage_frames(report: dict, window: dict, kind: int, connection: str) -> list[dict]:
    return [
        frame
        for frame in report["frames"]
        if window["first"] <= frame["action"] <= window["last"]
        and frame["type"] == kind
        and not frame["is_reply"]
        and frame["connection"] == connection
    ]


def check_stage(
    report: dict, plan: dict, window: dict, uid: bytes, main_uid: bytes = b"\0\x20"
) -> dict:
    label = window["label"]
    stage = next(s for s in cases.STAGES if s.label == label)
    require(len(uid) == 2, f"{label}: subject UID length differs")
    for connection in ("main", "subject"):
        update = stage_frames(report, window, 301, connection)
        require(len(update) == 1, f"{label}: 301 count differs on {connection}")
        actual = fields(update[0])
        require(
            actual.get(103) == uid
            and actual.get(102) == stage.expected_name
            and actual.get(104) == stage.expected_icon,
            f"{label}: 301 name/icon/UID differs on {connection}",
        )
    all_104 = [
        frame
        for frame in report["frames"]
        if window["first"] <= frame["action"] <= window["last"]
        and frame["type"] == 104
        and not frame["is_reply"]
    ]
    expected_total = 2 if stage.expected_auto is not None else 1
    require(
        len(all_104) == expected_total, f"{label}: 104 delivery/feedback count differs"
    )
    original = stage_frames(report, window, 104, "subject")
    require(len(original) == 1, f"{label}: subject PM missing")
    original_fields = fields(original[0])
    require(
        set(original_fields) == {101, 102, 103, 113}
        and original_fields[113] == b"\0\1"
        and original_fields[103] == main_uid
        and original_fields[102] == b"framing-fixture"
        and original_fields[101] == bytes.fromhex(window["pm_text_hex"]),
        f"{label}: original PM fields differ",
    )
    sender = stage_frames(report, window, 104, "main")
    require(
        len(sender) == int(stage.expected_auto is not None),
        f"{label}: auto count differs",
    )
    if sender:
        auto = fields(sender[0])
        require(
            set(auto) == {101, 102, 103, 113}
            and auto[103] == uid
            and auto[102] == stage.expected_name
            and auto[113] == b"\0\4"
            and auto[101] == stage.expected_auto,
            f"{label}: automatic text, identity or option differs",
        )
    replies = [
        frame
        for frame in report["frames"]
        if window["first"] <= frame["action"] <= window["last"]
        and frame["is_reply"]
        and frame["id"] == window["pm_id"]
        and frame["connection"] == "main"
    ]
    require(
        len(replies) == 1 and replies[0]["error"] == 0 and not replies[0]["fields"],
        f"{label}: PM ACK differs",
    )
    return {
        "label": label,
        "uid_hex": uid.hex(),
        "auto_hex": stage.expected_auto.hex()
        if stage.expected_auto is not None
        else None,
    }


def current_uids(report: dict, plan: dict) -> tuple[bytes, bytes]:
    saved = [
        i
        for i, step in enumerate(plan["steps"])
        if step.get("save_fields") == {"peer_uid": 103}
    ]
    require(len(saved) == 1, "Subject UID save step differs")
    first = roster(reply(report, 10))
    require(
        len(first) == 1 and bytes.fromhex(first[0]["name_hex"]) == b"framing-fixture",
        "Initial main roster differs",
    )
    main_uid = first[0]["uid"].to_bytes(2, "big")
    announced = [
        frame
        for frame in report["frames"]
        if frame["action"] == saved[0]
        and frame["type"] == 301
        and frame["connection"] == "main"
    ]
    require(len(announced) == 1, "Initial subject announcement missing")
    values = fields(announced[0])
    require(values.get(102) == cases.SUBJECT, "Initial subject identity differs")
    uid = values.get(103, b"")
    require(len(uid) == 2 and uid != main_uid, "Subject UID differs")
    return uid, main_uid


def semantic(report: dict, plan: dict, *, completed_only: bool = True) -> dict:
    require(
        plan["expectation"]["case"] == "same-session-304-transitions",
        "Wrong settings case",
    )
    if completed_only:
        require(report["status"] == "completed", "Transition capture did not complete")
    uid, main_uid = current_uids(report, plan)
    windows = plan["expectation"]["windows"]
    require(len(windows) == len(cases.STAGES), "Transition stage count differs")
    result = [check_stage(report, plan, w, uid, main_uid) for w in windows]
    if completed_only:
        tail = [
            frame
            for frame in report["frames"]
            if frame["action"] > windows[-1]["last"]
            and frame["type"] == 301
            and not frame["is_reply"]
        ]
        require(len(tail) == 2, "Owned session restore 301 count differs")
        for frame in tail:
            value = fields(frame)
            require(
                value.get(103) == uid
                and value.get(102) == cases.SUBJECT
                and value.get(104) == b"\0\1",
                "Owned session restore state differs",
            )
    return {"verified_stages": result, "subject_uid_hex": uid.hex()}


def run_gated(plan_path: Path, binary: Path, output: Path) -> dict:
    """Execute a separately authorised plan, stopping after its first bad stage."""
    source = plan_path.read_bytes()
    plan = json.loads(source)
    validate_plan(plan)
    require(
        plan["expectation"]["case"] == "same-session-304-transitions", "Wrong run case"
    )
    require(
        digest(binary.read_bytes()) == plan["oracle_sha256"],
        "Oracle binary hash differs",
    )
    output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(plan)
    completed, status, error = 0, "completed", ""
    checked = []
    try:
        for index, step in enumerate(plan["steps"]):
            recorder.execute(index, step)
            completed += 1
            for window in plan["expectation"]["windows"]:
                if window["last"] == index:
                    uid, main_uid = current_uids({"frames": recorder.frames}, plan)
                    checked.append(
                        check_stage(
                            {"frames": recorder.frames}, plan, window, uid, main_uid
                        )
                    )
    except (OSError, EOFError, ValueError, KeyboardInterrupt) as failure:
        status, error = "failed", f"{type(failure).__name__}: {failure}"
    finally:
        for name, connection in list(recorder.sockets.items()):
            connection.close()
            recorder.event(completed, name, "close")
    report = {
        "schema_version": 1,
        "profile": plan["profile"],
        "status": status,
        "native_conformance": False,
        "identity_scope": "Local binary hash verified; remote process identity is operator-reported",
        "operator": plan["operator"],
        "oracle_sha256": plan["oracle_sha256"],
        "plan_sha256": digest(source),
        "driver_sha256": digest(Path(__file__).read_bytes()),
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "started_at_utc": recorder.started_at_utc,
        "gap_ids": plan["gap_ids"],
        "completed_actions": completed,
        "error": error,
        "events": recorder.events,
        "frames": recorder.frames,
        "streams": recorder.streams(),
    }
    (output / "plan.json").write_bytes(source)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "checksums.sha256").write_text(
        "".join(
            f"{digest((output / name).read_bytes())}  {name}\n"
            for name in ("plan.json", "report.json")
        )
    )
    (output / "stage-gates.json").write_text(
        json.dumps({"passed": checked, "status": status, "error": error}, indent=2)
        + "\n"
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--verify", type=Path, help="Existing capture directory; offline"
    )
    group.add_argument(
        "--run", type=Path, help="Plan path; requires separate live START"
    )
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.run:
        if args.binary is None or args.output is None:
            parser.error("--run requires --binary and --output")
        report = run_gated(args.run, args.binary, args.output)
        if report["status"] != "completed":
            parser.exit(1, report["error"] + "\n")
        capture = args.output
    else:
        capture = args.verify
    report = verify_capture(capture)
    result = semantic(report, json.loads((capture / "plan.json").read_text()))
    if args.output and not args.run:
        if args.output.exists():
            parser.error("Refusing existing output")
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
