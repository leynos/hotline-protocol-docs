#!/usr/bin/env python3
"""Gate a control-only settings phase while sockets remain live for app Quit."""

import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import native_settings_persistence_cases as cases
from native_control_readiness import capture_gate, login_gate, readiness
from protocol_capture import (
    ORACLE_SHA256,
    Recorder,
    digest,
    validate_plan,
    verify_capture,
)
from verify_native_auth import ADMIN, reply, roster
from verify_native_core import require
from verify_native_shx import fields

LIMIT_SECONDS = 720


def frame_at(report: dict, index: int, connection: str, kind: int) -> dict:
    """Return the one unsolicited frame of a type on a connection at an action index."""
    found = [
        frame
        for frame in report["frames"]
        if (frame["action"], frame["connection"], frame["type"], frame["is_reply"])
        == (index, connection, kind, 0)
    ]
    require(len(found) == 1, f"Action {index}: expected one {kind} on {connection}")
    return found[0]


def gate_readiness(report: dict, plan: dict) -> None:
    """Check the readiness capture and its plan, prefixing a missing-field or value failure with the readiness check's name."""
    try:
        require(report["status"] == "completed", "capture failed")
        require(plan["expectation"]["case"] == "control-readiness", "wrong case")
        require(plan["steps"] == cases.control.plans()["readiness"], "steps differ")
        readiness(report)
    except (KeyError, ValueError) as error:
        raise ValueError(f"readiness: {error}") from error


def gate_identity(report: dict, plan: dict) -> tuple[bytes, bytes]:
    """Check the observer's and the subject's login identities and return the subject's and own identifiers."""
    login_gate(report["frames"][:3])
    users = roster(reply(report, 10))
    require(
        len(users) == 1 and bytes.fromhex(users[0]["name_hex"]) == b"framing-fixture",
        "Initial observer identity differs",
    )
    own = users[0]["uid"].to_bytes(2, "big")
    subject_frames = [f for f in report["frames"] if f["connection"] == "subject"]
    require(
        len(subject_frames) >= 3
        and subject_frames[0]["is_reply"]
        and subject_frames[0]["id"] == 1
        and subject_frames[0]["error"] == 0
        and fields(subject_frames[1]) == {110: ADMIN}
        and subject_frames[2]["type"] == 109,
        "Subject login/privileges/agreement differ",
    )
    announced = fields(
        frame_at(report, plan["expectation"]["identity_action"], "main", 301)
    )
    uid = announced.get(103, b"")
    require(
        len(uid) == 2
        and uid != own
        and announced.get(102) == cases.BASELINE_NAME
        and announced.get(104) == b"\0\3",
        "Subject identity/name/icon differs",
    )
    return uid, own


def gate_update(
    report: dict,
    plan: dict,
    uid: bytes,
    stage: dict | None = None,
    *,
    both: bool = True,
) -> None:
    """Check that a settings update reached the connections with the expected identifier, name and icon."""
    stage = stage or plan["expectation"]["stages"][0]
    index = stage["update_action"]
    names = ("main", "subject") if both else ("main",)
    for offset, name in enumerate(names):
        value = fields(frame_at(report, index + offset, name, 301))
        require(
            value.get(103) == uid
            and value.get(102) == bytes.fromhex(stage["name_hex"])
            and value.get(104) == bytes.fromhex(stage["icon_hex"]),
            f"{stage['label']} 301 update differs on {name}",
        )


def gate_pm(
    report: dict,
    start: int,
    uid: bytes,
    own: bytes,
    *,
    phase: int,
    stage: dict | None = None,
) -> None:
    """Check the private message and its delivery for a phase and stage."""
    identifier = stage["pm_id"] if stage else 60
    text = (
        bytes.fromhex(stage["pm_text_hex"])
        if stage
        else b"a41-before"
        if phase == 1
        else b"a41-after-restart"
    )
    window = [
        f
        for f in report["frames"]
        if start <= f["action"] <= report["completed_actions"]
    ]
    ack = [
        f
        for f in window
        if f["connection"] == "main" and f["is_reply"] and f["id"] == identifier
    ]
    require(
        len(ack) == 1 and ack[0]["error"] == 0 and not ack[0]["fields"],
        "PM ACK differs",
    )
    original = [
        f
        for f in window
        if f["connection"] == "subject" and f["type"] == 104 and not f["is_reply"]
    ]
    require(
        len(original) == 1
        and fields(original[0])
        == {103: own, 102: b"framing-fixture", 113: b"\0\1", 101: text},
        "Original PM delivery differs",
    )
    automatic = [
        f
        for f in window
        if f["connection"] == "main" and f["type"] == 104 and not f["is_reply"]
    ]
    active = bool(stage and stage["auto"])
    expected = (
        {
            103: uid,
            102: bytes.fromhex(stage["name_hex"]),
            113: b"\0\4",
            101: cases.MARKER_TEXT,
        }
        if active
        else None
    )
    require(
        len(automatic) == int(active)
        and (not active or fields(automatic[0]) == expected),
        "Automatic PM feedback differs",
    )


def phase_gate(report: dict, plan: dict, index: int) -> str | None:
    """Run the gate that applies to one action of a phase and return its name, or none."""
    phase = int(plan["expectation"]["case"][-1])
    identity = plan["expectation"]["identity_action"]
    if index == identity:
        gate_identity(report, plan)
        return "identity"
    if index < identity:
        return None
    uid, own = gate_identity(report, plan)
    baseline = plan["expectation"]["baseline_pm_action"]
    if index in (baseline + 2, baseline + 8):
        gate_pm(report, baseline, uid, own, phase=phase)
        return "baseline-pm" if index == baseline + 8 else "baseline-delivery"
    for stage in plan["expectation"].get("stages", []):
        update = stage["update_action"]
        if index in (update, update + 1):
            gate_update(report, plan, uid, stage, both=index == update + 1)
            return f"{stage['label']}-301-{index - update + 1}"
        pm = stage["pm_action"]
        delivery = pm + (3 if stage["auto"] else 2)
        last = pm + (9 if stage["auto"] else 8)
        if index in (delivery, last):
            gate_pm(report, pm, uid, own, phase=phase, stage=stage)
            return f"{stage['label']}-{'barrier' if index == last else 'delivery'}"
    return None


def semantic(report: dict, plan: dict) -> dict:
    """Replay bounded stage gates; a completed phase still needs guest shutdown proof."""
    verify_plan(plan)
    require(report["status"] == "completed", "Phase capture incomplete")
    require(report["completed_actions"] == len(plan["steps"]), "Quit EOF count differs")
    passed = []
    for index in range(plan["expectation"]["observation_actions"]):
        result = phase_gate(
            {"frames": report["frames"], "completed_actions": index + 1}, plan, index
        )
        if result is not None:
            passed.append(result)
    require(passed == report["gates"], "Live and replayed stage gates differ")
    eof = [event for event in report["events"] if event["event"] == "eof"]
    require(
        [(event["action"], event["connection"]) for event in eof]
        == [
            (plan["expectation"]["observation_actions"], "subject"),
            (plan["expectation"]["observation_actions"] + 1, "main"),
        ],
        "Owned socket EOFs differ",
    )
    return {
        "status": "verified_phase_only",
        "gates": passed,
        "guest_shutdown_proven": False,
    }


def verify_plan(plan: dict) -> int:
    """Check a persistence plan against the source plans and return its phase."""
    validate_plan(plan)
    case = plan["expectation"]["case"]
    require(
        case in {"settings-persistence-phase1", "settings-persistence-phase2"},
        "Wrong case",
    )
    phase = int(case[-1])
    env = plan["environment"]
    port = plan["endpoints"]["control"]["port"]
    require(plan == cases.plans(env, port)[f"phase{phase}"], "Prepared plan changed")
    require(
        env["fixture_profile"] == "control-only"
        and env["full_file_baseline"] == "not_exercised"
        and plan["oracle_sha256"] == ORACLE_SHA256,
        "Profile/oracle differs",
    )
    return phase


def run_gated(
    plan_path: Path,
    readiness_dir: Path,
    receipt_path: Path,
    binary: Path,
    output: Path,
) -> dict:
    """Run only after a separate root START and an already verified recorder receipt."""
    if os.geteuid() != 0:
        raise PermissionError("Live phase requires root /proc identity checks")
    raw = plan_path.read_bytes()
    plan = json.loads(raw)
    phase = verify_plan(plan)
    plan_hashes = json.loads((plan_path.parent / "source-hashes.json").read_text())
    require(plan_hashes[f"phase{phase}"] == digest(raw), "Plan source hash differs")
    sources = json.loads((plan_path.parent / "source-code-sha256.json").read_text())
    for name, expected in sources.items():
        require(
            name
            in {
                "native_settings_persistence_cases.py",
                "native_settings_persistence.py",
                "native_control_readiness.py",
                "native_ban_control_cases.py",
            }
            and digest((Path(__file__).parent / name).read_bytes()) == expected,
            f"Source code differs: {name}",
        )
    ready_plan = json.loads((readiness_dir / "plan.json").read_text())
    ready_report = verify_capture(readiness_dir)
    gate_readiness(ready_report, ready_plan)
    require(
        ready_plan["environment"] == plan["environment"]
        and ready_plan["endpoints"] == plan["endpoints"]
        and ready_report["oracle_sha256"] == plan["oracle_sha256"],
        "Readiness runtime/endpoint differs",
    )
    receipt = json.loads(receipt_path.read_text())
    capture_gate(receipt)
    require(
        receipt["emulator_pid"] == plan["environment"]["emulator_pid"],
        "Runtime PID differs",
    )
    require(digest(binary.read_bytes()) == ORACLE_SHA256, "Oracle binary differs")
    output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(plan)
    status, error, passed, completed = "completed", "", [], 0
    try:
        for index, step in enumerate(
            plan["steps"][: plan["expectation"]["observation_actions"]]
        ):
            if (time.monotonic_ns() - recorder.started) / 1e9 >= LIMIT_SECONDS:
                raise TimeoutError("Phase exceeded 12 minutes")
            recorder.execute(index, step)
            completed += 1
            result = phase_gate(
                {"frames": recorder.frames, "completed_actions": completed}, plan, index
            )
            if result is not None:
                passed.append(result)
        (output / "hold-ready.json").write_text(
            json.dumps(
                {
                    "utc": datetime.now(timezone.utc).isoformat(),
                    "phase": phase,
                    "sockets": sorted(recorder.sockets),
                },
                indent=2,
            )
            + "\n"
        )
        # Operator now performs native File > Quit with both sessions still open.
        for index, step in enumerate(
            plan["steps"][plan["expectation"]["observation_actions"] :],
            start=plan["expectation"]["observation_actions"],
        ):
            remaining = LIMIT_SECONDS - (time.monotonic_ns() - recorder.started) / 1e9
            if remaining <= 0:
                raise TimeoutError("Phase exceeded 12 minutes before app Quit")
            recorder.execute(
                index, {**step, "timeout": min(step["timeout"], remaining)}
            )
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
    report = {
        "schema_version": 1,
        "profile": plan["profile"],
        "status": status,
        "native_conformance": False,
        "persistence_proven": False,
        "full_file_baseline": "not_exercised",
        "oracle_sha256": ORACLE_SHA256,
        "plan_sha256": digest(raw),
        "driver_sha256": digest(Path(__file__).read_bytes()),
        "readiness_report_sha256": digest((readiness_dir / "report.json").read_bytes()),
        "capture_receipt_sha256": digest(receipt_path.read_bytes()),
        "started_at_utc": recorder.started_at_utc,
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "completed_actions": completed,
        "error": error,
        "gates": passed,
        "events": recorder.events,
        "frames": recorder.frames,
        "streams": recorder.streams(),
    }
    (output / "plan.json").write_bytes(raw)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "checksums.sha256").write_text(
        "".join(
            f"{digest((output / name).read_bytes())}  {name}\n"
            for name in ("plan.json", "report.json")
        )
    )
    return report


def main() -> None:
    """Parse the command line, run the gated persistence capture and print its status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--readiness-dir", type=Path, required=True)
    parser.add_argument("--capture-receipt", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run_gated(
        args.plan, args.readiness_dir, args.capture_receipt, args.binary, args.output
    )
    print(
        json.dumps(
            {
                "status": result["status"],
                "gates": result["gates"],
                "error": result["error"],
            }
        )
    )
    if result["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
