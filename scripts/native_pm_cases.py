#!/usr/bin/env python3
"""Prepare bounded, two-session native private-message observations."""

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from native_auth_cases import authentication
from native_diagnostic_existing_cases import NAME as FIXTURE_NAME
from native_diagnostic_existing_cases import postflight
from native_live_account_cases import request
from native_plan import close, login, packet, payload, read, send
from protocol_capture import ORACLE_SHA256, validate_plan

MAIN = b"PM-Main-A26"
PEER = b"PM-Peer-A26"
QUOTE = b"quote-a26"


@dataclass(frozen=True)
class Case:
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
    values = [(102, name), (104, b"\0\x01"), (113, options.to_bytes(2, "big"))]
    if auto:
        values.append((215, auto))
    return [send(packet(304, identifier, payload(values)), connection)] + barrier(
        identifier + 100
    )


def barrier(identifier: int) -> list[dict]:
    steps = []
    for connection in ("main", "peer"):
        steps += request(connection, 500, identifier)
    return steps + [
        {"op": "expect_quiet", "connection": connection, "timeout": 2}
        for connection in ("main", "peer")
    ]


def observe() -> list[dict]:
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


def plans(runtime: dict) -> dict[str, dict]:
    plans = {}
    for label, steps in {
        "preflight": postflight(),
        "observe": observe(),
        "postflight": postflight(),
    }.items():
        plan = {
            "schema_version": 1,
            "profile": "native-mac-oracle",
            "operator": "delegated A26 PM preparation; live lease required",
            "oracle_sha256": ORACLE_SHA256,
            "gap_ids": ["GAP-044"],
            "environment": runtime,
            "endpoints": {"control": {"host": "127.0.0.1", "port": 15500}},
            "steps": steps,
            "expectation": {
                "case": label,
                "fixture_name_hex": FIXTURE_NAME.hex(),
                "cases": list(CASES) if label == "observe" else [],
                "pm_request_count": len(CASES) if label == "observe" else 0,
            },
        }
        validate_plan(plan)
        plans[label] = plan
    return plans


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-record", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Refusing existing output")
    prepared = plans(json.loads(args.runtime_record.read_text()))
    args.output.mkdir(parents=True)
    for label, plan in prepared.items():
        (args.output / f"{label}.json").write_text(json.dumps(plan, indent=2) + "\n")


if __name__ == "__main__":
    main()
