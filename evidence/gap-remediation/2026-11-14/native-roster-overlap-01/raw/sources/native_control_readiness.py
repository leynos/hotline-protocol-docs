#!/usr/bin/env python3
"""Prepare and gate one disposable native ban-control capture."""

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import native_ban_control_cases as cases
from native_auth_cases import complement
from native_plan import payload
from protocol_capture import ORACLE_SHA256, Recorder, digest, run_plan, validate_plan
from verify_native_account_updates import enumeration
from verify_native_auth import ADMIN, reply, roster
from verify_native_core import require
from verify_native_mkdir import listing
from verify_native_shx import fields

BASELINE_FIELDS = {
    1: "4d3a600990071d9e91b56417c1552aaac0160adf2df3f409d6eeef67e9aec898",
    109: "a500d61db6e19baaf6e165ea9c6512fa3f56262533293f0b44372df434edde59",
    348: "9728c65a33486783ab96fdc6278aa9174b88354fce04073d3981d74086fd9ebe",
    200: "e53bd64a7ea62de8f2b351e7866044dc721d4f983e217368725d638663da9936",
    206: "6dd083b4bbace332c4b475dde19338d3e5fce3527f18a66c8d93fd2bf91e2a9a",
    303: "95edd6e7ab1ef42ef9042f5a78fb96d1f88c7e965ce017cd86c709676f8b978e",
}
BAN_TEXT = b"You are permanently banned on this server."
ORIGINAL_ACCOUNTS = {
    "00040066000d61646d696e6973747261746f72006900059e9b929691006a000178006e0008fff3cfefff800000",
    "00040066000b666978747572652d6c6f770069000b9996878b8a8d9ad2939088006a000178006e00080000000000000000",
}


def field_digest(frame: dict) -> str:
    """Return a digest of a frame's field identifiers and values."""
    data = [(item["id"], item["hex"]) for item in frame["fields"]]
    return hashlib.sha256(json.dumps(data, separators=(",", ":")).encode()).hexdigest()


def login_gate(frames: list[dict]) -> None:
    """Check that the administrator login, privilege bitmap and agreement match the baseline."""
    require(len(frames) >= 3, "Login sequence incomplete")
    ack, privileges, agreement = frames[:3]
    require(
        (ack["type"], ack["is_reply"], ack["id"], ack["error"]) == (0, 1, 1, 0)
        and field_digest(ack) == BASELINE_FIELDS[1],
        "Fixture admin login differs",
    )
    require(
        (privileges["type"], privileges["is_reply"], fields(privileges))
        == (354, 0, {110: ADMIN}),
        "Fixture admin privilege bitmap differs",
    )
    require(
        (agreement["type"], agreement["is_reply"]) == (109, 0)
        and field_digest(agreement) == BASELINE_FIELDS[109],
        "Fixture agreement bytes differ",
    )


def readiness(report: dict) -> None:
    """Check that the short readiness capture completed, that the control replies succeed and match their baselines where one exists, and the roster count."""
    require(
        report["status"] == "completed" and report["completed_actions"] == 18,
        "Short readiness incomplete",
    )
    login_gate(report["frames"])
    expected = [(10, 348), (11, 200), (12, 206), (13, 300), (14, 303)]
    for identifier, kind in expected:
        frame = reply(report, identifier)
        require(frame["type"] == 0 and frame["error"] == 0, "Control reply failed")
        if kind in BASELINE_FIELDS:
            require(
                field_digest(frame) == BASELINE_FIELDS[kind],
                f"{kind} control baseline differs",
            )
    require(len(enumeration(reply(report, 10))) == 2, "Original account count differs")
    require(len(listing(reply(report, 11))) == 41, "Original Files count differs")
    rows = roster(reply(report, 13))
    require(
        len(rows) == 1 and rows[0]["name_hex"] == b"framing-fixture".hex(),
        "Foreign or absent session",
    )
    require(
        fields(reply(report, 14)).get(102) == b"framing-fixture",
        "Idle admin UID barrier differs",
    )
    require(
        all(
            "000000ca" not in event["hex"][:8] and "48545846" not in event["hex"][:8]
            for event in report["events"]
            if event["event"] == "send"
        ),
        "Transfer request in control plan",
    )


def guarded_account(report: dict, *, absent: bool) -> None:
    """Check the account guard's lookup reply or the seed's creation and read-back replies."""
    require(report["status"] == "completed", "Account guard or seed incomplete")
    login_gate(report["frames"])
    frame = reply(report, 30 if absent else 32)
    if absent:
        require(
            frame["error"] == 1
            and fields(frame)
            == {100: b"No account with login \xd2" + cases.KEY + b"\xd3."},
            "Owned key already exists",
        )
    else:
        require(reply(report, 31)["error"] == 0, "Owned account creation failed")
        require(
            frame["error"] == 0
            and fields(frame)
            == {
                102: cases.NAME,
                105: complement(cases.KEY),
                106: b"x",
                110: cases.ZERO,
            },
            "Stored owned target is not zero privilege",
        )


def target_gate(frames: list[dict]) -> bytes:
    """Check the target's login, zero access and join notice and return its saved user identifier."""
    main = [f for f in frames if f["connection"] == "main"]
    target = [f for f in frames if f["connection"] == "target"]
    login_gate(main)
    require(
        len(target) >= 3
        and target[0]["type"] == 0
        and target[0]["is_reply"] == 1
        and target[0]["error"] == 0,
        "Owned target login failed",
    )
    require(
        fields(target[1]) == {110: cases.ZERO}, "Target effective access is not zero"
    )
    require(target[2]["type"] == 109, "Target agreement missing")
    joins = [f for f in main if f["type"] == 301 and not f["is_reply"]]
    require(len(joins) == 1, "Target announcement missing or ambiguous")
    identity = fields(joins[0])
    uid = identity.get(103, b"")
    require(
        len(uid) == 2
        and int.from_bytes(uid, "big") > 0
        and identity.get(102) == cases.NAME,
        "Target UID/name mismatch",
    )
    roster_replies = [f for f in main if f["is_reply"] and f["id"] == 32]
    require(len(roster_replies) == 1, "Current roster reply missing or ambiguous")
    rows = roster(roster_replies[0])
    require(
        len(rows) == 2
        and sum(
            r["uid"] == int.from_bytes(uid, "big") and r["name_hex"] == cases.NAME.hex()
            for r in rows
        )
        == 1,
        "Current roster target mismatch",
    )
    require(
        any(
            r["name_hex"] == b"framing-fixture".hex()
            and r["uid"] != int.from_bytes(uid, "big")
            for r in rows
        ),
        "Admin and target identities overlap",
    )
    return uid


def execute_ban_step(recorder: Recorder, index: int, step: dict) -> None:
    """Run one ban step, first checking the saved target identifier before the ban request."""
    if step["op"] == "send" and step["hex"].startswith("0000006e00000021"):
        require(
            recorder.variables.get("target_uid") == target_gate(recorder.frames),
            "Saved target UID differs",
        )
    recorder.execute(index, step)


def outcome(report: dict) -> None:
    """Check the permanent ban notice and that the target connection closed."""
    require(report["status"] == "completed", "Ban capture incomplete")
    target = [f for f in report["frames"] if f["connection"] == "target"]
    main = [f for f in report["frames"] if f["connection"] == "main"]
    notice = [f for f in target if f["type"] == 104 and not f["is_reply"]]
    require(
        len(notice) == 1 and fields(notice[0]) == {101: BAN_TEXT},
        "Permanent notice differs",
    )
    require(
        any(
            e["connection"] == "target" and e["event"] == "eof"
            for e in report["events"]
        ),
        "Target close missing",
    )
    require(
        len([f for f in main if f["is_reply"] and f["id"] == 33 and f["error"] == 0])
        == 1,
        "Admin ACK missing",
    )
    require(
        len([f for f in main if f["type"] == 302 and not f["is_reply"]]) == 1,
        "Departure missing",
    )
    after(report)


def probe(report: dict) -> None:
    """Check that a fresh login of the banned account is rejected with the ban text."""
    require(report["status"] == "completed", "107 probe incomplete")
    frame = reply(report, 1)
    require(
        frame["type"] == 0 and frame["error"] == 1 and fields(frame) == {100: BAN_TEXT},
        "Permanent login rejection differs",
    )
    sends = [e["hex"] for e in report["events"] if e["event"] == "send"]
    require(
        len(sends) == 2
        and sends[0] == "54525450484f544c00010002"
        and sends[1].startswith("0000006b00000001"),
        "Fresh TRTP plus Login107 absent",
    )


def after(report: dict) -> None:
    """Check that the administrator's account list is unchanged after the ban."""
    require(report["status"] == "completed", "Post-ban admin readback incomplete")
    login_gate(report["frames"])
    owned = payload(
        [
            (102, cases.NAME),
            (105, complement(cases.KEY)),
            (106, b"x"),
            (110, cases.ZERO),
        ]
    ).hex()
    require(
        set(enumeration(reply(report, 40))) == ORIGINAL_ACCOUNTS | {owned},
        "Original or owned account changed after ban",
    )
    require(
        len(listing(reply(report, 41))) == 41
        and field_digest(reply(report, 41)) == BASELINE_FIELDS[200],
        "Post-ban Files changed",
    )
    require(
        field_digest(reply(report, 42)) == BASELINE_FIELDS[206],
        "Post-ban fixture metadata changed",
    )
    require(len(roster(reply(report, 43))) == 1, "Post-ban roster differs")


def capture_gate(receipt: dict) -> None:
    """Check the capture receipt's primary-contact count and route fields and the PCAP magic bytes of its capture files, which is not a validity check."""
    require(
        receipt["primary_syn_count"] == 0 and receipt["ns_routes"] == [],
        "Primary contact or external route",
    )
    for label in ("host", "namespace", "guest"):
        path = Path(receipt[f"{label}_pcap"])
        require(
            path.open("rb").read(24)[:4]
            in (
                bytes.fromhex("d4c3b2a1"),
                bytes.fromhex("a1b2c3d4"),
                bytes.fromhex("4d3cb2a1"),
            ),
            f"{label} capture not ready",
        )
        if label == "host":
            require(path.stat().st_size == 24, "Primary SYN recorder is nonempty")
    for label in ("host", "namespace"):
        pid = receipt[f"{label}_recorder_pid"]
        require(
            Path(f"/proc/{pid}").exists(),
            f"{label} recorder absent",
        )
        start = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
        require(
            start == str(receipt[f"{label}_recorder_starttime"]),
            f"{label} recorder PID reused",
        )
    pid = receipt["emulator_pid"]
    proc = Path(f"/proc/{pid}")
    require(proc.exists(), "Actual lab emulator absent")
    start = (proc / "stat").read_text().rsplit(") ", 1)[1].split()[19]
    require(start == str(receipt["emulator_starttime"]), "Emulator PID reused")
    require(
        digest((proc / "exe").read_bytes()) == receipt["emulator_sha256"]
        and os.readlink(proc / "fd/6") == receipt["owned_working_image"]
        and os.readlink(proc / "ns/net") == receipt["emulator_netns"],
        "Emulator executable, image or namespace changed",
    )


def require_controller_uid() -> None:
    """Require the coordinator to run as root so that it can inspect the emulator."""
    if os.geteuid() != 0:
        raise PermissionError(
            "Live coordinator requires root to inspect emulator /proc identity"
        )


def plan_gate(directory: Path, emulator_pid: int) -> None:
    """Check the prepared plans against their source hashes and the emulator identity."""
    names = {"readiness", "guard", "seed", "ban", "probe"}
    hashes = json.loads((directory / "source-hashes.json").read_text())
    require(set(hashes) == names, "Plan inventory differs")
    for name in names:
        source = (directory / f"{name}.json").read_bytes()
        require(digest(source) == hashes[name], f"{name} source plan changed")
        plan = json.loads(source)
        validate_plan(plan)
        env = plan["environment"]
        require(
            env.get("emulator_pid") == emulator_pid
            and env.get("source_a7_sha256") == cases.A7_SHA
            and env.get("fixture_profile") == "control-only"
            and env.get("full_file_baseline") == "not_exercised"
            and plan["endpoints"]["control"]["host"] == "127.0.0.1"
            and plan["endpoints"]["control"]["port"] not in {15500, 15501},
            "Plan identity, profile or endpoint differs",
        )


def run_guarded_ban(plan_path: Path, binary: Path, output: Path) -> dict:
    """Run the ban plan under its gates and write the report."""
    source = plan_path.read_bytes()
    plan = json.loads(source)
    validate_plan(plan)
    require(digest(binary.read_bytes()) == ORACLE_SHA256, "Oracle identity differs")
    output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(plan)
    status, error, completed = "completed", "", 0
    try:
        for index, step in enumerate(plan["steps"]):
            execute_ban_step(recorder, index, step)
            completed += 1
    except (
        OSError,
        EOFError,
        ValueError,
        KeyError,
        IndexError,
        StopIteration,
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
        "operator": plan["operator"],
        "oracle_sha256": plan["oracle_sha256"],
        "controller_uid": os.geteuid(),
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
    return report


def main() -> None:
    """Parse the command line and prepare or run the readiness plans."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--runtime-record", type=Path, required=True)
    prepare.add_argument("--port", type=int, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    execute = sub.add_parser("run")
    execute.add_argument("--plans", type=Path, required=True)
    execute.add_argument("--binary", type=Path, required=True)
    execute.add_argument("--capture-ready", type=Path, required=True)
    execute.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        result = cases.write_plans(
            args.output, json.loads(args.runtime_record.read_text()), args.port
        )
        (args.output / "source-hashes.json").write_text(
            json.dumps(result, indent=2) + "\n"
        )
    else:
        require_controller_uid()
        receipt = json.loads(args.capture_ready.read_text())
        capture_gate(receipt)
        plan_gate(args.plans, receipt["emulator_pid"])
        args.output.mkdir(parents=True, exist_ok=False)
        stages = [
            ("readiness", readiness),
            ("guard", lambda r: guarded_account(r, absent=True)),
            ("seed", lambda r: guarded_account(r, absent=False)),
            ("ban", outcome),
            ("probe", probe),
        ]
        for name, gate in stages:
            capture_gate(receipt)
            plan = args.plans / f"{name}.json"
            planned = json.loads(plan.read_text())
            require(
                planned["environment"].get("emulator_pid") == receipt["emulator_pid"],
                "Plan/actual emulator PID mismatch",
            )
            destination = args.output / name
            report = (
                run_guarded_ban(plan, args.binary, destination)
                if name == "ban"
                else run_plan(plan, args.binary, destination)
            )
            gate(report)


if __name__ == "__main__":
    main()
