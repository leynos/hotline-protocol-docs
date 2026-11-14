#!/usr/bin/env python3
"""Gate and replay two bounded delayed-121 default-response observations."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from native_121_default_cases import DEFAULT, observe
from native_pm_cases import BASELINE_SHA256, load_baseline
from protocol_capture import (
    Recorder,
    decode_frame,
    digest,
    validate_plan,
    verify_capture,
)
from verify_native_auth import ADMIN, reply, roster
from verify_native_core import require
from verify_native_shx import fields

AGREEMENT_SHA256 = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"


def at(report: dict, action: int, connection: str, kind: int) -> dict:
    found = [
        f
        for f in report["frames"]
        if (f["action"], f["connection"], f["type"]) == (action, connection, kind)
    ]
    require(len(found) == 1, f"Action {action}: expected type {kind} on {connection}")
    return found[0]


def own_uid(report: dict) -> bytes:
    users = roster(reply(report, 10))
    require(
        len(users) == 1 and bytes.fromhex(users[0]["name_hex"]) == b"framing-fixture",
        "Initial observer identity differs",
    )
    return users[0]["uid"].to_bytes(2, "big")


def subject_uid(report: dict, case: dict, observer: bytes) -> bytes:
    frame = at(report, case["first"] + 10, "main", 301)
    value = fields(frame)
    uid = value.get(103, b"")
    require(
        len(uid) == 2
        and uid != observer
        and value.get(102) == bytes.fromhex(case["name_hex"])
        and value.get(104) == bytes.fromhex(case["icon_hex"]),
        f"{case['label']}: 301 identity/name/icon differs",
    )
    return uid


def check_auto(frame: dict, uid: bytes, name: bytes) -> None:
    require(
        fields(frame) == {103: uid, 102: name, 113: b"\0\4", 101: DEFAULT},
        "Automatic response default text/identity differs",
    )


def check_roster(
    report: dict, identifier: int, own: bytes, subject: tuple[bytes, bytes, int] | None
) -> None:
    users = roster(reply(report, identifier))
    expected = {(own, b"framing-fixture", 1)}
    if subject is not None:
        expected.add(subject)
    actual = {
        (u["uid"].to_bytes(2, "big"), bytes.fromhex(u["name_hex"]), u["icon"])
        for u in users
    }
    require(actual == expected, f"Roster {identifier} differs")


def layout(plan: dict) -> list[dict]:
    require(plan["expectation"]["case"] == "delayed-121-default-215", "Wrong 121 case")
    steps, expected = observe()
    require(
        plan["steps"] == steps and plan["expectation"]["cases"] == expected,
        "121 steps/cases differ",
    )
    require(
        plan["expectation"]["baseline_plan_sha256"] == BASELINE_SHA256,
        "A7 baseline pin differs",
    )
    return expected


def gate(report: dict, plan: dict, index: int) -> str | None:
    if index == 8:
        own_uid(report)
        return "observer-identity"
    for case in plan["expectation"]["cases"]:
        first, label, subject = case["first"], case["label"], case["subject_connection"]
        offset = index - first
        if offset not in {4, 5, 7, 9, 10, 11, 13, 15, 17, 18, 19, 27, 29}:
            continue
        own = own_uid(report)
        name, icon = (
            bytes.fromhex(case["name_hex"]),
            int.from_bytes(bytes.fromhex(case["icon_hex"]), "big"),
        )
        if offset in {4, 9, 13, 17}:
            connection = "main" if offset == 17 else subject
            identifier = {
                4: case["login_id"],
                9: case["agreement_id"],
                13: case["agreement_id"] + 1,
                17: case["pm_id"],
            }[offset]
            frame = at(report, index, connection, 0)
            expected = {160: b"\0\xbe", 161: b"\0\0"} if offset == 4 else {}
            require(
                frame["is_reply"]
                and frame["id"] == identifier
                and frame["error"] == 0
                and fields(frame) == expected,
                f"{label}: ACK {identifier} differs",
            )
            if offset == 13:
                extra = [
                    f
                    for f in report["frames"]
                    if first <= f["action"] <= index
                    and f["connection"] == subject
                    and f["type"] == 122
                ]
                require(len(extra) <= 1, f"{label}: optional 122 count differs")
        elif offset == 5:
            frame = at(report, index, subject, 109)
            value = fields(frame)
            require(
                set(value) == {101}
                and len(value[101]) == 242
                and hashlib.sha256(value[101]).hexdigest() == AGREEMENT_SHA256,
                f"{label}: pending agreement differs",
            )
        elif offset == 7:
            check_roster(report, 11 if label == "absent" else 12, own, None)
        elif offset == 10:
            subject_uid(report, case, own)
        else:
            uid = subject_uid(report, case, own)
            if offset == 11:
                require(
                    fields(at(report, index, subject, 354)) == {110: ADMIN},
                    f"{label}: own 354 differs",
                )
            elif offset == 15:
                check_roster(report, case["agreement_id"] + 2, own, (uid, name, icon))
            elif offset == 18:
                check_auto(at(report, index, "main", 104), uid, name)
            elif offset == 19:
                require(
                    fields(at(report, index, subject, 104))
                    == {
                        103: own,
                        102: b"framing-fixture",
                        113: b"\0\1",
                        101: bytes.fromhex(case["pm_text_hex"]),
                    },
                    f"{label}: original PM differs",
                )
            elif offset == 27:
                require(
                    fields(at(report, index, "main", 302)) == {103: uid},
                    f"{label}: departure UID differs",
                )
            elif offset == 29:
                check_roster(report, case["pm_id"] + 2, own, None)
                window = [f for f in report["frames"] if first <= f["action"] <= index]
                require(
                    len([f for f in window if f["type"] == 104 and not f["is_reply"]])
                    == 2,
                    f"{label}: 104 count differs",
                )
                sent = b"".join(
                    bytes.fromhex(e["hex"])
                    for e in report["events"]
                    if e["action"] == first + 16 and e["event"] == "send"
                )
                require(
                    fields(decode_frame(sent))[103] == uid,
                    f"{label}: PM target UID differs",
                )
                require(
                    len(
                        [
                            f
                            for f in report["frames"]
                            if first <= f["action"] <= index and f["type"] == 302
                        ]
                    )
                    == 1,
                    f"{label}: departure count differs",
                )
        return f"{label}-{offset}"
    return None


def semantic(report: dict, plan: dict) -> dict:
    require(report["status"] == "completed", "121 capture did not complete")
    layout(plan)
    passed = []
    for index in range(8, 69):
        result = gate(report, plan, index)
        if result is not None:
            passed.append(result)
    require(len(passed) == 27, "121 semantic gate count differs")
    return {"status": "verified", "gates": passed}


def run_gated(plan_path: Path, binary: Path, baseline_path: Path, output: Path) -> dict:
    raw = plan_path.read_bytes()
    plan = json.loads(raw)
    validate_plan(plan)
    layout(plan)
    load_baseline(baseline_path.read_bytes())
    require(
        digest(binary.read_bytes()) == plan["oracle_sha256"],
        "Oracle binary hash differs",
    )
    output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(plan)
    completed, status, error, passed = 0, "completed", "", []
    try:
        for index, step in enumerate(plan["steps"]):
            recorder.execute(index, step)
            completed += 1
            result = gate(
                {"frames": recorder.frames, "events": recorder.events}, plan, index
            )
            if result is not None:
                passed.append(result)
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
        "operator": plan["operator"],
        "oracle_sha256": plan["oracle_sha256"],
        "plan_sha256": digest(raw),
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
    (output / "plan.json").write_bytes(raw)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    checks = [
        f"{digest((output / name).read_bytes())}  {name}"
        for name in ("plan.json", "report.json")
    ]
    (output / "checksums.sha256").write_text("\n".join(checks) + "\n")
    gates = {"passed": passed, "status": status, "error": error}
    (output / "stage-gates.json").write_text(json.dumps(gates, indent=2) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--verify", type=Path, help="Existing capture; offline")
    group.add_argument("--run", type=Path, help="Plan; separate live START required")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--baseline-plan", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.run:
        if args.binary is None or args.baseline_plan is None or args.output is None:
            parser.error("--run requires --binary, --baseline-plan and --output")
        report = run_gated(args.run, args.binary, args.baseline_plan, args.output)
        if report["status"] != "completed":
            parser.exit(1, report["error"] + "\n")
    capture = args.output if args.run else args.verify
    result = semantic(
        verify_capture(capture), json.loads((capture / "plan.json").read_text())
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
