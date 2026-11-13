#!/usr/bin/env python3
"""Prepare one bounded, same-session native 304 transition observation."""

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from native_auth_cases import authentication
from native_plan import close, login, packet, payload, read, send
from native_pm_cases import BASELINE_SHA256, load_baseline, variable_message
from protocol_capture import ORACLE_SHA256, validate_plan

SUBJECT = b"A32-Subject"
EXPLICIT = b"A32-Explicit"
DEFAULT = b"I'm not able to respond right now. Please try later!"


@dataclass(frozen=True)
class Stage:
    label: str
    name: bytes | None
    icon: bytes | None
    option: bytes | None
    auto: bytes | None
    expected_name: bytes
    expected_icon: bytes
    expected_auto: bytes | None


STAGES = (
    Stage(
        "explicit",
        EXPLICIT,
        b"\0\7",
        b"\0\4",
        b"a32-explicit",
        EXPLICIT,
        b"\0\7",
        b"a32-explicit",
    ),
    Stage("omitted", None, None, b"\0\4", None, b"***", b"\0\0", DEFAULT),
    Stage("empty", b"", b"", b"\0\4", b"", b"***", b"\0\0", DEFAULT),
    Stage(
        "unknown-only",
        b"A32-Unknown",
        b"\0\11",
        b"\0\10",
        None,
        b"A32-Unknown",
        b"\0\11",
        None,
    ),
    Stage(
        "mixed-unknown",
        b"A32-Mixed",
        b"\0\12",
        b"\0\14",
        None,
        b"A32-Mixed",
        b"\0\12",
        DEFAULT,
    ),
    Stage(
        "disable-absent",
        b"A32-Off-A",
        b"\0\13",
        None,
        None,
        b"A32-Off-A",
        b"\0\13",
        None,
    ),
    Stage(
        "disable-zero",
        b"A32-Off-Z",
        b"\0\14",
        b"\0\0",
        None,
        b"A32-Off-Z",
        b"\0\14",
        None,
    ),
    Stage(
        "reenable",
        b"A32-Reenable",
        b"\0\15",
        b"\0\4",
        None,
        b"A32-Reenable",
        b"\0\15",
        DEFAULT,
    ),
)


def settings(stage: Stage, identifier: int) -> dict:
    values = []
    for field, value in (
        (102, stage.name),
        (104, stage.icon),
        (113, stage.option),
        (215, stage.auto),
    ):
        if value is not None:
            values.append((field, value))
    return send(packet(304, identifier, payload(values)), "subject")


def barrier(identifier: int) -> list[dict]:
    result = []
    for connection in ("main", "subject"):
        result += [
            send(packet(500, identifier, payload([])), connection),
            read(connection, match_frame={"is_reply": 1, "id": identifier}),
            {"op": "expect_quiet", "connection": connection, "timeout": 2},
        ]
    return result


def observe() -> tuple[list[dict], list[dict]]:
    steps = login() + [
        send(packet(300, 10)),
        read(match_frame={"is_reply": 1, "id": 10}),
    ]
    steps += [{**step, "connection": "subject"} for step in login()[:3]]
    steps += [
        authentication(b"admin", b"mothra19", name=SUBJECT, connection="subject"),
        read("subject"),
        read("subject"),
        read("subject"),
        read("main", match_frame={"type": 301}, save_fields={"peer_uid": 103}),
    ]
    windows = []
    for index, stage in enumerate(STAGES):
        start = len(steps)
        steps += [settings(stage, 20 + index)]
        steps += [
            read("main", match_frame={"type": 301}),
            read("subject", match_frame={"type": 301}),
        ]
        text = f"a32-pm-{index}-{stage.label}".encode()
        steps += [
            variable_message(108, 60 + index, "peer_uid", [(113, b"\0\1"), (101, text)])
        ]
        steps += [read("main", match_frame={"is_reply": 1, "id": 60 + index})]
        if stage.expected_auto is not None:
            steps += [read("main", match_frame={"type": 104})]
        steps += [read("subject", match_frame={"type": 104})]
        steps += barrier(100 + index)
        windows.append(
            {
                "label": stage.label,
                "first": start,
                "last": len(steps) - 1,
                "pm_id": 60 + index,
                "pm_text_hex": text.hex(),
            }
        )
    # Restore only the two owned session settings; closing them ends session state.
    restore = Stage("restore", SUBJECT, b"\0\1", b"\0\0", None, SUBJECT, b"\0\1", None)
    steps += [
        settings(restore, 90),
        read("main", match_frame={"type": 301}),
        read("subject", match_frame={"type": 301}),
    ]
    steps += barrier(190)
    steps += [close("subject"), close()]
    return steps, windows


def plans(runtime: dict, baseline_raw: bytes) -> dict[str, dict]:
    baseline = load_baseline(baseline_raw)
    for key in ("oracle_sha256", "emulator_pid", "emulator_sha256", "guest_pcap"):
        if runtime.get(key) != baseline["environment"].get(key):
            raise ValueError("Runtime identity differs from pinned A7 baseline")
    steps, windows = observe()
    observed = {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": "A32 offline preparation; separate live START and oracle.lock required",
        "oracle_sha256": ORACLE_SHA256,
        "gap_ids": ["GAP-029", "GAP-030"],
        "environment": runtime,
        "endpoints": {"control": {"host": "127.0.0.1", "port": 15500}},
        "steps": steps,
        "expectation": {
            "case": "same-session-304-transitions",
            "windows": windows,
            "baseline_plan_sha256": BASELINE_SHA256,
            "pm_count": len(STAGES),
        },
    }
    validate_plan(observed)
    return {"preflight": baseline, "observe": observed, "postflight": baseline}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-record", type=Path, required=True)
    parser.add_argument("--baseline-plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Refusing existing output")
    baseline_raw = args.baseline_plan.read_bytes()
    prepared = plans(json.loads(args.runtime_record.read_text()), baseline_raw)
    args.output.mkdir(parents=True)
    for label, plan in prepared.items():
        (args.output / f"{label}.json").write_bytes(
            baseline_raw
            if label != "observe"
            else (json.dumps(plan, indent=2) + "\n").encode()
        )


if __name__ == "__main__":
    main()
