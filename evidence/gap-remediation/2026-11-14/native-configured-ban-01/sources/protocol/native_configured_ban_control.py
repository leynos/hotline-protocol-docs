#!/usr/bin/env python3
"""Gate a control-only configured-ban fixture and retain held TCP sessions."""

import argparse
import json
import os
import select
import time
from datetime import datetime, timezone
from pathlib import Path

import native_configured_ban_cases as cases
import native_control_readiness as base
from native_auth_cases import complement
from protocol_capture import ORACLE_SHA256, Recorder, digest, run_plan, validate_plan
from verify_native_auth import reply, roster
from verify_native_core import require
from verify_native_shx import fields

EXPECTED_PLANS = {"readiness", "guard", "seed", "held-apply"}
HELD_ACTIONS = 17
SAVE_MARKER = b"reviewed-save\n"


def account_gate(report: dict, *, absent: bool) -> None:
    require(report["status"] == "completed", "Account guard or seed incomplete")
    base.login_gate(report["frames"])
    record = reply(report, 30 if absent else 32)
    if absent:
        require(
            record["error"] == 1
            and fields(record)
            == {100: b"No account with login \xd2" + cases.KEY + b"\xd3."},
            "Owned key already exists",
        )
    else:
        require(reply(report, 31)["error"] == 0, "Owned account creation failed")
        require(
            record["error"] == 0
            and fields(record)
            == {
                102: cases.NAME,
                105: complement(cases.KEY),
                106: b"x",
                110: cases.ZERO,
            },
            "Stored owned target is not zero privilege",
        )


def identity_gate(frames: list[dict]) -> bytes:
    main = [frame for frame in frames if frame["connection"] == "main"]
    target = [frame for frame in frames if frame["connection"] == "target"]
    base.login_gate(main)
    require(
        len(target) >= 3
        and (
            target[0]["type"],
            target[0]["is_reply"],
            target[0]["id"],
            target[0]["error"],
        )
        == (0, 1, 1, 0)
        and fields(target[1]) == {110: cases.ZERO}
        and (target[2]["type"], target[2]["is_reply"]) == (109, 0),
        "Owned target login or zero access differs",
    )
    joins = [frame for frame in main if frame["type"] == 301 and not frame["is_reply"]]
    require(len(joins) == 1, "Current target announcement missing or ambiguous")
    identity = fields(joins[0])
    uid = identity.get(103, b"")
    require(
        len(uid) == 2
        and int.from_bytes(uid, "big") > 0
        and identity.get(102) == cases.NAME,
        "Current target UID/name differs",
    )
    rosters = [frame for frame in main if frame["is_reply"] and frame["id"] == 32]
    require(len(rosters) == 1, "Current two-user roster missing")
    rows = roster(rosters[0])
    require(
        len(rows) == 2
        and sum(
            row["uid"] == int.from_bytes(uid, "big")
            and row["name_hex"] == cases.NAME.hex()
            for row in rows
        )
        == 1
        and any(
            row["name_hex"] == b"framing-fixture".hex()
            and row["uid"] != int.from_bytes(uid, "big")
            for row in rows
        ),
        "Admin and target roster identities differ",
    )
    return uid


def outcome(report: dict, plan: dict) -> None:
    require(
        report["status"] == "completed"
        and report["completed_actions"] == len(plan["steps"])
        and len(plan["steps"]) == HELD_ACTIONS + 6,
        "Held apply tail incomplete",
    )
    identity_gate(report["frames"])
    require(
        report.get("save_trigger") == "reviewed-save", "Reviewed Save trigger absent"
    )
    for name in ("main", "target"):
        notices = [
            frame
            for frame in report["frames"]
            if frame["connection"] == name and frame["type"] == 104
        ]
        require(
            len(notices) == 1
            and (
                notices[0]["flags"],
                notices[0]["is_reply"],
                notices[0]["error"],
            )
            == (0, 0, 0)
            and fields(notices[0]) == {101: base.BAN_TEXT},
            f"{name} configured-ban notice differs",
        )
        require(
            any(
                e["connection"] == name and e["event"] == "eof"
                for e in report["events"]
            ),
            f"{name} close missing",
        )
    require(
        not any(
            e["event"] == "send" and bytes.fromhex(e["hex"])[2:4] == b"\0\x6e"
            for e in report["events"]
        ),
        "110 request forbidden in configured-ban fixture",
    )


def plan_gate(directory: Path, emulator_pid: int) -> None:
    hashes = json.loads((directory / "source-hashes.json").read_text())
    require(set(hashes) == EXPECTED_PLANS, "Source-plan inventory differs")
    for name in EXPECTED_PLANS:
        source = (directory / f"{name}.json").read_bytes()
        require(digest(source) == hashes[name], f"{name} plan changed")
        plan = json.loads(source)
        validate_plan(plan)
        env = plan["environment"]
        require(
            env.get("emulator_pid") == emulator_pid
            and env.get("source_a7_sha256") == cases.A7_SHA
            and env.get("fixture_profile") == "control-only"
            and env.get("full_file_baseline") == "not_exercised"
            and plan["endpoints"]["control"] == {"host": "127.0.0.1", "port": 15770},
            "Plan identity, profile or endpoint differs",
        )
        require(
            not any(
                step["op"] == "send"
                and bytes.fromhex(step["hex"][:8])[2:4] == b"\0\x6e"
                for step in plan["steps"]
                if "{" not in step.get("hex", "") and step["op"] == "send"
            ),
            "110 request in source plan",
        )
    held = json.loads((directory / "held-apply.json").read_text())
    require(len(held["steps"]) == HELD_ACTIONS + 6, "EOF tails absent from source plan")


def report_from_recorder(
    recorder: Recorder,
    source: bytes,
    completed: int,
    status: str,
    error: str,
    save_trigger: str | None,
) -> dict:
    plan = recorder.plan
    return {
        "schema_version": 1,
        "profile": plan["profile"],
        "status": status,
        "native_conformance": False,
        "operator": plan["operator"],
        "oracle_sha256": plan["oracle_sha256"],
        "controller_uid": os.geteuid(),
        "plan_sha256": digest(source),
        "driver_sha256": digest(Path(__file__).read_bytes()),
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "started_at_utc": recorder.started_at_utc,
        "gap_ids": plan["gap_ids"],
        "planned_actions": len(plan["steps"]),
        "completed_actions": completed,
        "save_trigger": save_trigger,
        "error": error,
        "events": recorder.events,
        "frames": recorder.frames,
        "streams": recorder.streams(),
    }


def wait_for_reviewed_save(recorder: Recorder, trigger: Path, deadline: float) -> None:
    require(not trigger.exists(), "Save trigger already exists before hold")
    while time.monotonic() < deadline:
        ready, _, _ = select.select(list(recorder.sockets.values()), [], [], 0.05)
        require(not ready, "Notice, data or EOF arrived before reviewed Save")
        if trigger.exists():
            require(trigger.read_bytes() == SAVE_MARKER, "Save trigger differs")
            ready, _, _ = select.select(list(recorder.sockets.values()), [], [], 0)
            require(not ready, "Socket changed before reviewed Save")
            return
    raise TimeoutError("Reviewed Save trigger did not arrive")


def run_held(
    plan_path: Path, binary: Path, output: Path, trigger: Path, receipt: Path
) -> dict:
    source = plan_path.read_bytes()
    plan = json.loads(source)
    validate_plan(plan)
    require(digest(binary.read_bytes()) == ORACLE_SHA256, "Oracle binary differs")
    require(len(plan["steps"]) == HELD_ACTIONS + 6, "Planned EOF tails absent")
    output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(plan)
    status, error, completed, save_trigger = "completed", "", 0, None
    try:
        for index, step in enumerate(plan["steps"]):
            if index == HELD_ACTIONS:
                require(
                    identity_gate(recorder.frames)
                    == recorder.variables.get("target_uid"),
                    "Saved target UID differs",
                )
                base.capture_gate(json.loads(receipt.read_text()))
                (output / "held-ready.json").write_text(
                    json.dumps(
                        {
                            "source_plan_sha256": digest(source),
                            "completed_actions": completed,
                            "target_uid_hex": recorder.variables["target_uid"].hex(),
                            "controller_uid": os.geteuid(),
                        },
                        indent=2,
                    )
                    + "\n"
                )
                wait_for_reviewed_save(recorder, trigger, time.monotonic() + 120)
                base.capture_gate(json.loads(receipt.read_text()))
                save_trigger = "reviewed-save"
            recorder.execute(index, step)
            completed += 1
    except (
        OSError,
        EOFError,
        ValueError,
        KeyError,
        IndexError,
        TimeoutError,
        KeyboardInterrupt,
    ) as failure:
        status, error = "failed", f"{type(failure).__name__}: {failure}"
    finally:
        for name, connection in list(recorder.sockets.items()):
            connection.close()
            recorder.event(completed, name, "close")
    report = report_from_recorder(
        recorder, source, completed, status, error, save_trigger
    )
    (output / "plan.json").write_bytes(source)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "checksums.sha256").write_text(
        "".join(
            f"{digest((output / name).read_bytes())}  {name}\n"
            for name in ("plan.json", "report.json")
        )
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--runtime-record", type=Path, required=True)
    prepare.add_argument("--port", type=int, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    execute = sub.add_parser("execute")
    execute.add_argument("--plans", type=Path, required=True)
    execute.add_argument("--binary", type=Path, required=True)
    execute.add_argument("--capture-ready", type=Path, required=True)
    execute.add_argument("--output", type=Path, required=True)
    execute.add_argument("--save-trigger", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        env = json.loads(args.runtime_record.read_text())
        hashes = cases.write_plans(args.output, env, args.port)
        (args.output / "source-hashes.json").write_text(
            json.dumps(hashes, indent=2) + "\n"
        )
        return
    base.require_controller_uid()
    receipt = json.loads(args.capture_ready.read_text())
    base.capture_gate(receipt)
    plan_gate(args.plans, receipt["emulator_pid"])
    args.output.mkdir(parents=True, exist_ok=False)
    for name, gate in (
        ("readiness", base.readiness),
        ("guard", lambda r: account_gate(r, absent=True)),
        ("seed", lambda r: account_gate(r, absent=False)),
    ):
        base.capture_gate(json.loads(args.capture_ready.read_text()))
        report = run_plan(args.plans / f"{name}.json", args.binary, args.output / name)
        gate(report)
    report = run_held(
        args.plans / "held-apply.json",
        args.binary,
        args.output / "held-apply",
        args.save_trigger,
        args.capture_ready,
    )
    outcome(report, json.loads((args.plans / "held-apply.json").read_text()))


if __name__ == "__main__":
    main()
