#!/usr/bin/env python3
"""Run one positive alias rehearsal; never remove the target."""

import argparse
import hashlib
import json
import os
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

import native_missing_alias_cases as cases
from native_ban_expiry_control import runtime_gate, utc
from native_plan import login
from native_rate304_control import Wire as RateWire
from protocol_capture import ORACLE_SHA256
from verify_native_auth import ADMIN
from verify_native_mkdir import listing
from verify_native_shx import fields

AGREEMENT_SHA = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
ALIAS_205 = bytes.fromhex("553534542028616c69617329")
ALIAS_206 = b"M54X"
ALIAS_213 = b"U54T"
SCREEN_KEYS = (
    "target",
    "make-alias-menu",
    "alias-result",
    "copy-menu",
    "paste-menu",
    "destination",
)


class Wire(RateWire):
    """A control wire that also counts requests and keeps partial results."""
    request_count: int = 0
    partial: dict


def need(ok: bool, message: str) -> None:
    """Raise a value error with the message unless the condition holds."""
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    """Return the SHA-256 hex digest of the bytes."""
    return hashlib.sha256(raw).hexdigest()


def prepared(directory: Path) -> dict:
    """Check the prepared plan against its source hashes and return it."""
    raw = (directory / "plan.json").read_bytes()
    expected = {
        "plan.json": digest(raw),
        "native_missing_alias_cases.py": digest(Path(cases.__file__).read_bytes()),
        "native_missing_alias_control.py": digest(Path(__file__).read_bytes()),
    }
    need(
        json.loads((directory / "source-hashes.json").read_text()) == expected,
        "Prepared plan/source hash differs",
    )
    plan = json.loads(raw)
    need(
        plan == cases.source_plan(plan["environment"], plan["endpoint"]["port"]),
        "Prepared plan differs from source",
    )
    return plan


def host_state(plan: dict) -> dict:
    """Record the identity and content of the owned target and its Finder record on the host."""
    runtime = Path(plan["environment"]["owned_runtime"])
    need(
        runtime.is_absolute() and runtime.name == "native-alias-live-03",
        "Unexpected owned runtime root",
    )
    need(
        Path(plan["environment"]["owned_working_image"]).parent == runtime,
        "Owned shared path is not the captured image runtime",
    )
    shared = runtime / "shared"
    target = shared / cases.TARGET.decode("ascii")
    finf = shared / ".finf" / cases.TARGET.decode("ascii")
    need(not runtime.is_symlink(), "Owned runtime path is a symlink")
    result = {"parents": {}}
    for name, parent in (("shared", shared), ("finf", shared / ".finf")):
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode), f"Owned {name} parent is not a directory")
        result["parents"][name] = {
            "path": str(parent),
            "dev": info.st_dev,
            "inode": info.st_ino,
            "uid": info.st_uid,
        }
    for name, path, wanted in (
        ("target", target, cases.TARGET_DATA),
        ("finder", finf, b"U54TM54X" + bytes(24)),
    ):
        info = path.lstat()
        need(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 1000
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1,
            f"Owned {name} mode/owner/link differs",
        )
        need(info.st_size == len(wanted), f"Owned {name} length differs")
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as handle:
            opened = os.fstat(handle.fileno())
            need(
                (opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino),
                f"Owned {name} changed before read",
            )
            raw = handle.read(len(wanted) + 1)
        need(len(raw) == len(wanted), f"Owned {name} read length differs")
        if name == "target":
            need(raw == wanted, "Owned target DATA differs")
        else:
            need(raw[:8] == wanted[:8], "Owned Finder type/creator differs")
        result[name] = {
            "path": str(path),
            "dev": info.st_dev,
            "inode": info.st_ino,
            "mtime_ns": info.st_mtime_ns,
            "uid": info.st_uid,
            "mode": stat.S_IMODE(info.st_mode),
            "nlink": info.st_nlink,
            "size": info.st_size,
            "sha256": digest(raw),
            "type_creator_hex": raw[:8].hex() if name == "finder" else None,
        }
    return result


def same_data_target(before: dict, after: dict) -> None:
    """Require the owned target's identity and content to be unchanged."""
    for key in (
        "path",
        "dev",
        "inode",
        "uid",
        "mode",
        "nlink",
        "size",
        "sha256",
        "type_creator_hex",
    ):
        need(
            before["target"][key] == after["target"][key],
            "Owned target identity/content changed",
        )


def same_target(before: dict, after: dict) -> None:
    """Require the owned parents, target and Finder record to be unchanged across the interface step."""
    need(before["parents"] == after["parents"], "Owned parent changed across UI")
    same_data_target(before, after)
    for key in (
        "path",
        "dev",
        "inode",
        "uid",
        "mode",
        "nlink",
        "size",
        "type_creator_hex",
    ):
        need(
            before["finder"][key] == after["finder"][key],
            "Owned Finder identity/type changed across UI",
        )
    # The Finder may change flags or positions; retain both full hashes.


def operator_gate(receipt: dict, plan: dict) -> bytes:
    """Check the operator receipt against the plan and return the receipt bytes."""
    need(
        receipt.get("schema_version") == 1
        and receipt.get("target_name_hex") == plan["target"]["basename_hex"]
        and receipt.get("target_size") == 20
        and receipt.get("target_sha256") == plan["target"]["sha256"]
        and receipt.get("owned_destination_hex") == cases.ROOT.hex(),
        "Operator target/destination differs",
    )
    need(
        all(
            receipt.get(key) is True
            for key in (
                "finder_active",
                "unix_target_selected",
                "make_alias_enabled",
                "separate_alias",
                "copy_enabled",
                "paste_enabled",
            )
        )
        and receipt.get("unexpected_prompt") is False
        and receipt.get("overwrite_prompt") is False
        and receipt.get("action_count") == 1,
        "Finder UI gate/one-alias action differs",
    )
    screens = receipt.get("screenshots")
    need(
        isinstance(screens, dict)
        and set(screens) == set(SCREEN_KEYS)
        and all(
            isinstance(value, str)
            and len(value) == 64
            and all(c in "0123456789abcdef" for c in value)
            for value in screens.values()
        ),
        "Finder screenshots missing",
    )
    name = bytes.fromhex(receipt["alias_name_hex"])
    need(
        1 <= len(name) <= 31
        and name != cases.TARGET
        and not any(c in name for c in (0, 47, 58)),
        "Dynamic alias basename invalid",
    )
    return name


def check_screens(receipt: dict, directory: Path) -> None:
    """Check that each Finder screenshot exists and matches its recorded hash."""
    need(
        (directory / "screens").is_dir() and not (directory / "screens").is_symlink(),
        "Finder screenshot directory differs",
    )
    for key, expected in receipt["screenshots"].items():
        image = directory / "screens" / f"{key}.png"
        need(
            image.is_file()
            and not image.is_symlink()
            and digest(image.read_bytes()) == expected,
            f"Finder screenshot differs: {key}",
        )


def exact_fields(frame: dict) -> dict[int, bytes]:
    """Return a well-formed reply's fields, refusing malformed or repeated ones."""
    value = fields(frame)
    need(
        frame["flags"] == 0
        and frame["total_size"] == frame["data_size"]
        and frame["declared_field_count"] == len(frame["fields"])
        and len(value) == len(frame["fields"])
        and frame.get("unconsumed_hex") == "",
        "Malformed/repeated reply field",
    )
    return value


def direct(frames: list[dict], identifier: int) -> dict:
    """Return the one successful direct reply with the given identifier."""
    matches = [
        f
        for f in frames
        if f["connection"] == "main"
        and f["type"] == 0
        and f["is_reply"] == 1
        and f["id"] == identifier
    ]
    need(len(matches) == 1, f"Missing/duplicate reply {identifier}")
    frame = matches[0]
    need(
        frame["flags"] == 0 and frame["error"] == 0,
        f"Native status/error for {identifier}",
    )
    return frame


def positive_alias(frame: dict, name: bytes) -> dict:
    """Check that a reply identifies the resolved tagged alias and describe it."""
    value = exact_fields(frame)
    need(
        value.get(201) == name
        and value.get(205) == ALIAS_205
        and value.get(206) == ALIAS_206
        and value.get(213) == ALIAS_213,
        "206 did not identify the resolved tagged alias",
    )
    return {
        "name_hex": name.hex(),
        "field207_hex": value.get(207, b"").hex(),
        "fields": sorted(value),
        "raw_sha256": digest(bytes.fromhex(frame["raw_hex"])),
    }


def exchange(wire: Wire, spec: dict, alias: bytes | None = None) -> dict:
    """Send one planned request, wait for its reply and count it."""
    raw = cases.request_hex(spec, alias)
    wire.send("main", raw, spec["label"])
    wire.request_count += 1
    wire.partial["request_count"] = wire.request_count
    if spec["kind"] == 205:
        wire.partial["mutation_count"] = 1
    wire.wait_for(lambda: bool(wire.match("main", 0, spec["id"], 1)), 5, spec["label"])
    return direct(wire.frames, spec["id"])


def perform(wire: Wire, plan: dict, receipt_path: Path, guard) -> None:
    """Run the missing-alias sequence: host checks, operator step, requests and the positive alias check."""
    wire.partial = {
        "request_count": 0,
        "mutation_count": 0,
        "operator": None,
        "host_before": None,
        "host_after": None,
        "positive206": None,
        "stage": "start",
    }
    before = host_state(plan)
    need(
        before["finder"]["sha256"] == plan["environment"]["initial_finf_sha256"],
        "Pre-staged Finder sidecar differs from runtime pin",
    )
    wire.partial["host_before"] = before
    guard()
    wire.execute({"op": "connect", "connection": "main", "endpoint": "control"})
    wire.execute({"op": "send", "connection": "main", "hex": cases.HELLO})
    wire.execute(
        {"op": "read", "connection": "main", "size": 8, "expect_hex": cases.HELLO_REPLY}
    )
    wire.buffers["main"] = bytearray()
    wire.send("main", login()[3]["hex"], "login")
    wire.request_count = 1
    wire.partial["request_count"] = 1
    wire.wait_for(
        lambda: (
            bool(wire.match("main", 0, 1, 1))
            and bool(wire.match("main", 354, None, 0))
            and bool(wire.match("main", 109, None, 0))
        ),
        5,
        "admin login",
    )
    ack = direct(wire.frames, 1)
    need(
        exact_fields(ack) == {160: b"\0\xbe", 161: b"\0\0"},
        "Login version/extras differ",
    )
    grants = wire.match("main", 354, None, 0)
    agreements = wire.match("main", 109, None, 0)
    need(
        len(grants) == len(agreements) == 1
        and exact_fields(grants[0]) == {110: ADMIN}
        and digest(exact_fields(agreements[0]).get(101, b"")) == AGREEMENT_SHA,
        "Admin grant/agreement differs",
    )
    create, root = plan["requests"][:2]
    exchange(wire, create)
    wire.partial["stage"] = "created"
    roots = listing(exchange(wire, root))
    need(
        len(roots) == 42 and cases.ROOT in roots,
        "Owned Files folder/root count differs",
    )
    wire.partial["stage"] = "awaiting-reviewed-Finder-receipt"
    print(
        json.dumps(
            {
                "event": "READY",
                "stage": wire.partial["stage"],
                "plan_sha256": digest((json.dumps(plan, indent=2) + "\n").encode()),
                "emulator_pid": plan["environment"]["emulator_pid"],
                "emulator_netns_inode": plan["environment"]["emulator_netns_inode"],
                "numbered_requests": wire.request_count,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    until = min(time.monotonic() + 120, wire.deadline)
    while not receipt_path.is_file():
        need(time.monotonic() < until, "Reviewed Finder receipt absent")
        guard()
        wire.poll(0.1)
    need(not receipt_path.is_symlink(), "Finder receipt is a symlink")
    operator_raw = receipt_path.read_bytes()
    receipt = json.loads(operator_raw)
    name = operator_gate(receipt, plan)
    check_screens(receipt, receipt_path.parent)
    after = host_state(plan)
    same_target(before, after)
    wire.partial["host_after"] = after
    wire.partial["operator"] = {
        "sha256": digest(operator_raw),
        "alias_name_hex": name.hex(),
        "screenshots": receipt["screenshots"],
    }
    wire.partial["stage"] = "reviewed-Finder-receipt"
    listed = listing(exchange(wire, plan["requests"][2]))
    need(set(listed) == {name}, "Copied alias directory ambiguous/foreign")
    wire.partial["stage"] = "copied-alias-listed"
    frame = exchange(wire, plan["requests"][3], name)
    wire.partial["positive206"] = positive_alias(frame, name)
    wire.partial["stage"] = "positive206-live-wire-only"


def run(
    plan_dir: Path,
    capture_receipt: Path,
    operator_receipt: Path,
    binary: Path,
    output: Path,
) -> dict:
    """Check the plans and receipts, run the capture and write the result."""
    plan = prepared(plan_dir)
    receipt_raw = capture_receipt.read_bytes()
    receipt = json.loads(receipt_raw)
    deadline = utc(receipt["deadline_utc"])
    remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
    need(remaining >= 390, "M2 fixed epoch margin below 390 seconds")
    need(
        receipt["emulator_pid"] == plan["environment"]["emulator_pid"],
        "Capture/runtime PID differs",
    )
    runtime_gate(receipt, plan["environment"], deadline)
    need(
        os.stat("/proc/self/ns/net").st_ino
        == plan["environment"]["emulator_netns_inode"],
        "Wrong isolated network namespace",
    )
    need(digest(binary.read_bytes()) == ORACLE_SHA256, "Oracle DATA differs")
    need(
        host_state(plan)["finder"]["sha256"]
        == plan["environment"]["initial_finf_sha256"],
        "Pre-socket Finder sidecar differs from runtime pin",
    )
    need(not output.exists(), "Output exists")
    output.mkdir(parents=True, exist_ok=False)
    wire = Wire(
        {
            "endpoint": plan["endpoint"],
            "schedule": {
                "max_bytes": plan["limits"]["max_bytes"],
                "max_frames": plan["limits"]["max_frames"],
                "max_tail_bytes_per_flow": plan["limits"]["max_tail_bytes"],
                "max_simultaneous": 1,
            },
        },
        min(time.monotonic() + 210, time.monotonic() + remaining),
        lambda: runtime_gate(receipt, plan["environment"], deadline),
    )
    wire.request_count = 0
    status, error = "completed", ""
    try:
        perform(
            wire,
            plan,
            operator_receipt,
            lambda: runtime_gate(receipt, plan["environment"], deadline),
        )
    except (OSError, ValueError, TimeoutError, EOFError, KeyError, IndexError) as exc:
        status, error = "failed", f"{type(exc).__name__}: {exc}"
    finally:
        try:
            wire.close_all()
        except (OSError, ValueError, TimeoutError) as exc:
            status, error = "failed", error + f"; close {type(exc).__name__}: {exc}"
            for name, sock in list(wire.recorder.sockets.items()):
                sock.close()
                wire.recorder.sockets.pop(name)
                wire.recorder.event(-1, name, "close_after_failure")
    try:
        need(prepared(plan_dir) == plan, "Post-run source/plan differs")
        runtime_gate(receipt, plan["environment"], deadline)
        postflight = host_state(plan)
        wire.partial["host_postflight"] = postflight
        if wire.partial.get("host_before") is not None:
            same_data_target(wire.partial["host_before"], postflight)
    except (OSError, ValueError, KeyError) as exc:
        status, error = "failed", error + f"; postflight {type(exc).__name__}: {exc}"
    report = {
        "schema_version": 1,
        "status": status,
        "error": error,
        "plan_sha256": digest((plan_dir / "plan.json").read_bytes()),
        "source_sha256": digest(Path(__file__).read_bytes()),
        "cases_sha256": digest(Path(cases.__file__).read_bytes()),
        "receipt_sha256": digest(receipt_raw),
        "started_at_utc": wire.recorder.started_at_utc,
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "events": wire.recorder.events,
        "frames": wire.frames,
        "actions": wire.actions,
        "streams": wire.recorder.streams(),
        "terminals": wire.terminals,
        "unparsed_hex": {name: data.hex() for name, data in wire.buffers.items()},
        **getattr(wire, "partial", {}),
    }
    (output / "plan.json").write_bytes((plan_dir / "plan.json").read_bytes())
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> None:
    """Parse the command line, run the capture and print its status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--capture-receipt", type=Path, required=True)
    parser.add_argument("--operator-receipt", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(
        args.plan_dir,
        args.capture_receipt,
        args.operator_receipt,
        args.binary,
        args.output,
    )
    print(json.dumps({"status": result["status"], "error": result["error"]}))
    if result["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
