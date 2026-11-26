#!/usr/bin/env python3
"""Build bounded native 303 transfer-state observations on one owned file."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from native_cleanup_cases import data_fork
from native_diagnostic_cases import diagnostic_request
from native_plan import close, connect, packet, payload, read, send
from native_queue_cases import attach, cancel, session
from native_transfer_cases import file_stream, resource_fork
from protocol_capture import ORACLE_SHA256, Recorder, digest, validate_plan
from verify_native_mkdir import listing as file_listing

NAME = b"m-diag37-" + b"x" * 22
BODY = file_stream(data_fork(), resource_fork())


def exchange(kind: int, identifier: int, fields: list[tuple[int, bytes]]) -> list[dict]:
    """Return the steps that send one request and read its reply on the main connection."""
    return [
        send(packet(kind, identifier, payload(fields)), "a"),
        read("a", match_frame={"is_reply": 1, "id": identifier}),
    ]


def request(owner: str, identifier: int, variable: str) -> list[dict]:
    """Return the steps that request the fixture file and save its reference and size."""
    return [
        send(packet(202, identifier, payload([(201, NAME)])), owner),
        read(
            owner,
            match_frame={"is_reply": 1, "id": identifier},
            save_fields={variable: 107, variable + "_size": 108},
        ),
    ]


def roster(identifier: int = 14) -> list[dict]:
    """Return the steps that fetch the user list and save the admin's user identifier."""
    return [
        send(packet(300, identifier), "a"),
        read(
            "a",
            match_frame={"is_reply": 1, "id": identifier},
            save={"name": "admin_uid", "offset": 26, "size": 2},
        ),
    ]


def diagnostic(identifier: int, uid: str | bytes = "admin_uid") -> list[dict]:
    """Return the steps that send a diagnostic request for a user and read its reply."""
    return [
        diagnostic_request("a", identifier, uid),
        read("a", match_frame={"is_reply": 1, "id": identifier}),
    ]


def preflight() -> list[dict]:
    """Return the preflight steps that check the fixture file and roster before the load cases."""
    return (
        session("a")
        + exchange(348, 10, [])
        + exchange(200, 11, [(202, b"\0\0")])
        + exchange(206, 12, [(201, NAME)])
        + roster()
        + diagnostic(15)
        + [close("a")]
    )


def seed() -> list[dict]:
    """Return the steps that upload the fixture file."""
    steps = session("a") + [
        send(
            packet(
                203, 10, payload([(201, NAME), (108, len(BODY).to_bytes(4, "big"))])
            ),
            "a",
        ),
        read(
            "a",
            match_frame={"is_reply": 1, "id": 10},
            save_field={"name": "upload_ref", "id": 107},
        ),
        connect("upload", "data"),
        send(
            "48545846{upload_ref}"
            + len(BODY).to_bytes(4, "big").hex()
            + "00000000"
            + BODY.hex(),
            "upload",
        ),
        {"op": "read_eof", "connection": "upload", "timeout": 60},
        close("upload"),
    ]
    return steps + exchange(206, 11, [(201, NAME)]) + [close("a")]


def active_queue() -> list[dict]:
    """Return the steps for one active and one queued download, with diagnostics and cancellations."""
    steps = session("a") + roster(10)
    steps += request("a", 11, "active")
    steps += attach("active")
    steps += request("a", 12, "queued")
    steps += diagnostic(13)
    steps += diagnostic(14, b"\xff\xff")
    steps += cancel("a", 15, "queued") + cancel("a", 16, "active")
    steps += [
        {"op": "read_eof", "connection": "active", "timeout": 30},
        close("active"),
    ]
    return steps + diagnostic(17) + [close("a")]


def boundary() -> list[dict]:
    """Return the steps for eight active and eight queued downloads with diagnostics, then cancel them all."""
    steps = session("a") + roster(10)
    for index in range(8):
        steps += request("a", 20 + index, f"active{index}")
        steps += attach(f"active{index}")
    for index in range(8):
        steps += request("a", 40 + index, f"queued{index}")
        if index == 3:
            steps += diagnostic(60)
    steps += diagnostic(61)
    for index in reversed(range(8)):
        steps += cancel("a", 70 + index, f"queued{index}")
    for index in reversed(range(8)):
        steps += cancel("a", 80 + index, f"active{index}")
        steps += [
            {"op": "read_eof", "connection": f"active{index}", "timeout": 30},
            close(f"active{index}"),
        ]
    return steps + diagnostic(90) + [close("a")]


def cleanup() -> list[dict]:
    """Return the steps that delete the fixture file and check the roster."""
    return (
        session("a")
        + exchange(204, 10, [(201, NAME)])
        + exchange(206, 11, [(201, NAME)])
        + exchange(348, 12, [])
        + exchange(200, 13, [(202, b"\0\0")])
        + roster()
        + diagnostic(15)
        + [close("a")]
    )


CASES = {
    "preflight": preflight,
    "seed": seed,
    "active-queue": active_queue,
    "boundary": boundary,
    "cleanup": cleanup,
}


def choose_owned_branch(info: dict, listing_frame: dict) -> str:
    """Refuse deletion unless both replies identify this exact owned file."""
    entries = file_listing(listing_frame)
    values = [bytes.fromhex(f["hex"]) for f in info.get("fields", []) if f["id"] == 201]
    if info["is_reply"] != 1 or info["type"] != 0:
        raise ValueError("File-info envelope differs")
    if info["error"] == 0 and values == [NAME] and NAME in entries:
        return "present"
    if info["error"] == 1 and not values and NAME not in entries:
        return "absent"
    raise ValueError("Owned file presence is ambiguous; no deletion")


def conditional_cleanup(
    runtime: dict, binary: Path, output: Path, baseline: Path
) -> None:
    """Run one fail-closed capture; delete only a positively identified owned file."""
    source = baseline / "report.json"
    previous = json.loads(source.read_text())
    baseline_files = next(
        frame
        for frame in previous["frames"]
        if frame["is_reply"] == 1 and frame["id"] == 11
    )
    baseline_accounts = next(
        frame
        for frame in previous["frames"]
        if frame["is_reply"] == 1 and frame["id"] == 10
    )
    prefix = session("a") + exchange(206, 10, [(201, NAME)])
    prefix += exchange(200, 11, [(202, b"\0\0")])
    suffix = exchange(206, 12, [(201, NAME)])
    suffix += exchange(200, 13, [(202, b"\0\0")])
    suffix += exchange(348, 14, []) + roster(15) + diagnostic(16) + [close("a")]

    def plan(steps: list[dict], branch: str) -> dict:
        """Return a cleanup plan for one branch of the conditional cleanup."""
        return {
            "schema_version": 1,
            "profile": "native-mac-oracle",
            "operator": "delegated native diagnostic load cleanup operator",
            "oracle_sha256": ORACLE_SHA256,
            "gap_ids": ["GAP-037"],
            "environment": runtime,
            "endpoints": {"control": {"host": "127.0.0.1", "port": 15500}},
            "steps": steps,
            "expectation": {
                "case": "conditional-cleanup",
                "branch": branch,
                "owned_name_hex": NAME.hex(),
            },
        }

    absent = plan(prefix + suffix, "absent")
    present = plan(prefix + exchange(204, 17, [(201, NAME)]) + suffix, "present")
    validate_plan(absent)
    validate_plan(present)
    if digest(binary.read_bytes()) != ORACLE_SHA256:
        raise ValueError("Oracle binary hash mismatch")
    output.mkdir(parents=True, exist_ok=False)
    selected = absent
    recorder = Recorder(selected)
    status, error, completed = "completed", "", 0
    try:
        for step in prefix:
            recorder.execute(completed, step)
            completed += 1
        info = next(f for f in recorder.frames if f["is_reply"] == 1 and f["id"] == 10)
        listing = next(
            f for f in recorder.frames if f["is_reply"] == 1 and f["id"] == 11
        )
        branch = choose_owned_branch(info, listing)
        selected = present if branch == "present" else absent
        recorder.plan = selected
        for step in selected["steps"][len(prefix) :]:
            recorder.execute(completed, step)
            completed += 1
        final_info = next(
            f for f in recorder.frames if f["is_reply"] == 1 and f["id"] == 12
        )
        final_files = next(
            f for f in recorder.frames if f["is_reply"] == 1 and f["id"] == 13
        )
        final_accounts = next(
            f for f in recorder.frames if f["is_reply"] == 1 and f["id"] == 14
        )
        roster_reply = next(
            f for f in recorder.frames if f["is_reply"] == 1 and f["id"] == 15
        )
        diagnostic_reply = next(
            f for f in recorder.frames if f["is_reply"] == 1 and f["id"] == 16
        )
        if selected is present:
            deletion = next(
                f for f in recorder.frames if f["is_reply"] == 1 and f["id"] == 17
            )
            if deletion["error"] != 0:
                raise ValueError("Owned deletion failed")
        if final_info["error"] != 1:
            raise ValueError("Owned file remains after cleanup")
        if final_files["fields"] != baseline_files["fields"]:
            raise ValueError("Full Files view differs from preflight")
        if final_accounts["fields"] != baseline_accounts["fields"]:
            raise ValueError("Account baseline differs from preflight")
        rows = roster_reply.get("fields", [])
        if (
            len(rows) != 1
            or rows[0]["id"] != 300
            or b"framing-fixture" not in bytes.fromhex(rows[0]["hex"])
        ):
            raise ValueError("Current admin roster ambiguous")
        dfields = diagnostic_reply.get("fields", [])
        if diagnostic_reply["error"] != 0 or [f["id"] for f in dfields] != [101, 102]:
            raise ValueError("Idle diagnostic envelope differs")
        if NAME in bytes.fromhex(dfields[0]["hex"]):
            raise ValueError("Owned name remains in idle diagnostic")
    except (OSError, EOFError, ValueError, StopIteration) as failure:
        status, error = "failed", f"{type(failure).__name__}: {failure}"
    finally:
        for name, connection in recorder.sockets.items():
            connection.close()
            recorder.event(completed, name, "close")
    plan_bytes = (json.dumps(selected, indent=2) + "\n").encode()
    report = {
        "schema_version": 1,
        "profile": selected["profile"],
        "status": status,
        "native_conformance": False,
        "identity_scope": "Local binary hash verified; remote process identity is operator-reported",
        "operator": selected["operator"],
        "oracle_sha256": selected["oracle_sha256"],
        "plan_sha256": digest(plan_bytes),
        "driver_sha256": digest(Path(__file__).read_bytes()),
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "started_at_utc": recorder.started_at_utc,
        "gap_ids": selected["gap_ids"],
        "completed_actions": completed,
        "error": error,
        "events": recorder.events,
        "frames": recorder.frames,
        "streams": recorder.streams(),
        "branch": selected["expectation"]["branch"],
    }
    (output / "plan.json").write_bytes(plan_bytes)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "checksums.sha256").write_text(
        "".join(
            f"{digest((output / name).read_bytes())}  {name}\n"
            for name in ("plan.json", "report.json")
        )
    )
    print(
        f"native-mac-oracle cleanup: {status}; {completed} actions; branch {report['branch']}"
    )
    if status != "completed":
        raise SystemExit(1)


def main() -> None:
    """Write the plan for the chosen case, or the conditional cleanup plans, to the output directory."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=CASES)
    parser.add_argument("--runtime-record", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--conditional-cleanup", action="store_true")
    parser.add_argument("--oracle-binary", type=Path)
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    environment = json.loads(args.runtime_record.read_text())
    if args.conditional_cleanup:
        if (
            args.case != "cleanup"
            or args.oracle_binary is None
            or args.baseline is None
        ):
            parser.error(
                "Conditional cleanup needs cleanup case, oracle binary and baseline"
            )
        conditional_cleanup(environment, args.oracle_binary, args.output, args.baseline)
        return
    plan = {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": "delegated native diagnostic load operator",
        "oracle_sha256": ORACLE_SHA256,
        "gap_ids": ["GAP-037"],
        "environment": environment,
        "endpoints": {
            "control": {"host": "127.0.0.1", "port": 15500},
            "data": {"host": "127.0.0.1", "port": 15501},
        },
        "steps": CASES[args.case](),
        "expectation": {"case": args.case, "owned_name_hex": NAME.hex()},
    }
    validate_plan(plan)
    with args.output.open("x") as output:
        json.dump(plan, output, indent=2)
        output.write("\n")


if __name__ == "__main__":
    main()
