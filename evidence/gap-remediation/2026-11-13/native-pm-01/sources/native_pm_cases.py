#!/usr/bin/env python3
"""Prepare bounded, two-session native private-message observations."""

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from native_auth_cases import authentication
from native_live_account_cases import request
from native_plan import close, login, packet, payload, read, send
from protocol_capture import ORACLE_SHA256, validate_plan

MAIN = b"PM-Main-A26"
PEER = b"PM-Peer-A26"
QUOTE = b"quote-a26"
BASELINE_SHA256 = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"
FULL_STREAM_BYTES = 1049073


def check_baseline_structure(plan: dict) -> None:
    """Require the A7 baseline plan to have the recorded identity, expectation, steps and endpoints."""
    validate_plan(plan)
    if plan["profile"] != "native-mac-oracle" or plan["oracle_sha256"] != ORACLE_SHA256:
        raise ValueError("A7 baseline oracle identity differs")
    if plan["expectation"] != {
        "case": "existing-fixture-full-readback",
        "name_hex": b"mothra-race-fixture".hex(),
        "expected_stream_bytes": FULL_STREAM_BYTES,
        "expected_data_sha256": "fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83",
        "expected_rsrc_sha256": "40a42dbcf2d879e22d9a5a9acf46bf15fa9fe3a77837f757a990e514436801e5",
    }:
        raise ValueError("A7 baseline full-fork expectation differs")
    steps = plan["steps"]
    if len(steps) != 29 or plan["endpoints"] != {
        "control": {"host": "127.0.0.1", "port": 15500},
        "data": {"host": "127.0.0.1", "port": 15501},
    }:
        raise ValueError("A7 baseline full 29-step/data-endpoint shape differs")
    if (
        steps[19]
        != {
            "op": "connect",
            "connection": "download",
            "endpoint": "data",
            "timeout": 10,
        }
        or steps[21].get("size") != FULL_STREAM_BYTES
        or steps[24]["op"] != "read_eof"
    ):
        raise ValueError("A7 baseline full download sequence differs")


def load_baseline(raw: bytes) -> dict:
    """Check the A7 baseline's hash and structure and return the plan."""
    if hashlib.sha256(raw).hexdigest() != BASELINE_SHA256:
        raise ValueError("A7 baseline input SHA-256 differs")
    plan = json.loads(raw)
    check_baseline_structure(plan)
    return plan


@dataclass(frozen=True)
class Case:
    """One private message case: its option, text, quote and push settings."""
    option: int
    text: bytes
    quote: bytes = b""
    sender_push: int = 0
    recipient_push: int = 0
    sender: str = "main"


CASES = {
    "direct-quoted": Case(1, b"pm-a26-direct", QUOTE, recipient_push=1),
    "recipient-refuses": Case(1, b"pm-a26-refused", sender_push=1),
    "auto-and-original": Case(1, b"pm-a26-with-auto", sender_push=1, recipient_push=1),
    "sender-refuses": Case(1, b"pm-a26-sender-refuses"),
    "option-two": Case(2, b"pm-a26-option-two", recipient_push=1),
    "option-three": Case(3, b"pm-a26-option-three", recipient_push=1, sender="peer"),
    "empty": Case(1, b""),
}


def variable_message(
    kind: int,
    identifier: int,
    uid: str,
    fields: list[tuple[int, bytes]],
    connection: str = "main",
) -> dict:
    """Build a private message request step whose target user identifier is substituted at run time."""
    if uid not in {"main_uid", "peer_uid"}:
        raise ValueError("UID must come from the current observed connection")
    body = (1 + len(fields)).to_bytes(2, "big").hex() + "00670002{" + uid + "}"
    length = 8
    for field, value in fields:
        body += (
            field.to_bytes(2, "big").hex()
            + len(value).to_bytes(2, "big").hex()
            + value.hex()
        )
        length += 4 + len(value)
    return send(packet(kind, identifier, bytes(length))[:40] + body, connection)


def settings(
    connection: str, identifier: int, name: bytes, options: int, auto: bytes = b""
) -> list[dict]:
    """Return the steps that set a connection's name and options, then wait for both connections to settle."""
    values = [(102, name), (104, b"\0\x01"), (113, options.to_bytes(2, "big"))]
    if auto:
        values.append((215, auto))
    return [send(packet(304, identifier, payload(values)), connection)] + barrier(
        identifier + 100
    )


def barrier(identifier: int) -> list[dict]:
    """Return the steps that make both connections answer a request and then go quiet."""
    steps = []
    for connection in ("main", "peer"):
        steps += request(connection, 500, identifier)
    return steps + [
        {"op": "expect_quiet", "connection": connection, "timeout": 2}
        for connection in ("main", "peer")
    ]


def observe() -> list[dict]:
    """Return the observe plan's steps: log in two connections and send the private message cases."""
    steps = login() + [
        send(packet(300, 10)),
        read(
            match_frame={"is_reply": 1, "id": 10},
            save={"name": "main_uid", "offset": 26, "size": 2},
        ),
    ]
    steps += [{**step, "connection": "peer"} for step in login()[:3]]
    steps += [
        authentication(b"admin", b"mothra19", name=PEER, connection="peer"),
        read("peer"),
        read("peer"),
        read("peer"),
        read("main", match_frame={"type": 301}, save_fields={"peer_uid": 103}),
    ]
    steps += settings("main", 20, MAIN, 0) + settings("peer", 21, PEER, 0)
    states = [(0, 0), (0, 1), (0, 4), (1, 1), (0, 0), (0, 0), (0, 0)]
    previous = (0, 0)
    for index, (label, case) in enumerate(CASES.items()):
        state = states[index]
        if state[0] != previous[0]:
            steps += settings("main", 30 + index, MAIN, state[0])
        if state[1] != previous[1]:
            steps += settings(
                "peer",
                40 + index,
                PEER,
                state[1],
                b"pm-a26-auto" if state[1] == 4 else b"",
            )
        previous = state
        fields = [(113, case.option.to_bytes(2, "big")), (101, case.text)]
        if case.quote:
            fields.append((214, case.quote))
        identifier = 60 + index
        sender = case.sender
        recipient = "peer" if sender == "main" else "main"
        uid = "peer_uid" if recipient == "peer" else "main_uid"
        steps += [variable_message(108, identifier, uid, fields, sender)]
        steps += [read(sender, match_frame={"is_reply": 1, "id": identifier})]
        steps += [
            read(sender, match_frame={"type": 104}) for _ in range(case.sender_push)
        ]
        steps += [
            read(recipient, match_frame={"type": 104})
            for _ in range(case.recipient_push)
        ]
        steps += barrier(160 + index)
    steps += settings("main", 90, MAIN, 0) + settings("peer", 91, PEER, 0)
    return steps + [close("peer"), close()]


def plans(runtime: dict, baseline_raw: bytes) -> dict[str, dict]:
    """Build the preflight, observe and postflight plans after checking the runtime against the baseline."""
    baseline = load_baseline(baseline_raw)
    identity = ("oracle_sha256", "emulator_pid", "emulator_sha256", "guest_pcap")
    if any(runtime.get(key) != baseline["environment"].get(key) for key in identity):
        raise ValueError("Runtime identity differs from immutable A7 baseline")
    observed = {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": "delegated A26 PM preparation; live lease required",
        "oracle_sha256": ORACLE_SHA256,
        "gap_ids": ["GAP-044"],
        "environment": runtime,
        "endpoints": {"control": {"host": "127.0.0.1", "port": 15500}},
        "steps": observe(),
        "expectation": {
            "case": "observe",
            "cases": list(CASES),
            "pm_request_count": len(CASES),
            "baseline_plan_sha256": BASELINE_SHA256,
        },
    }
    validate_plan(observed)
    return {"preflight": baseline, "observe": observed, "postflight": baseline}


def main() -> None:
    """Write the preflight, observe and postflight plans to the output directory."""
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
