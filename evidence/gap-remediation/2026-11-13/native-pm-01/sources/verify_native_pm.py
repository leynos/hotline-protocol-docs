#!/usr/bin/env python3
"""Check bounded 108/104 PM routing without asserting unknown generated text."""

import argparse
import json
from pathlib import Path

import native_pm_cases as cases
from protocol_capture import decode_frame, verify_capture
from verify_native_auth import reply, roster
from verify_native_core import require
from verify_native_shx import fields


def check_variant(
    actual: dict[int, bytes],
    uid: bytes,
    name: bytes,
    option: int,
    text: bytes | None,
    quote: bytes | None = None,
) -> None:
    require(
        set(actual)
        == ({103, 102, 113, 101, 214} if quote is not None else {103, 102, 113, 101}),
        "PM 104 field set differs",
    )
    require(
        actual[103] == uid
        and actual[102] == name
        and actual[113] == option.to_bytes(2, "big"),
        "PM 104 identity/option differs",
    )
    if text is None:
        require(bool(actual[101]), "Generated PM text absent")
    else:
        require(actual[101] == text, "PM 104 text differs")
    if quote is not None:
        require(actual[214] == quote, "PM quoted field differs")


def semantic(report: dict, plan: dict) -> dict:
    require(report["status"] == "completed", "PM capture did not complete")
    require(plan["expectation"]["case"] == "observe", "Wrong PM case")
    first = roster(reply(report, 10))
    require(
        len(first) == 1 and bytes.fromhex(first[0]["name_hex"]) == b"framing-fixture",
        "Initial admin roster is ambiguous",
    )
    main_uid = first[0]["uid"].to_bytes(2, "big")
    saved = [
        index
        for index, step in enumerate(plan["steps"])
        if step.get("save_fields") == {"peer_uid": 103}
    ]
    require(len(saved) == 1, "Peer UID save step differs")
    announced = [
        f
        for f in report["frames"]
        if f["action"] == saved[0] and f["type"] == 301 and f["connection"] == "main"
    ]
    require(len(announced) == 1, "Peer announcement missing/ambiguous")
    peer_fields = fields(announced[0])
    require(
        peer_fields.get(102) == cases.PEER and len(peer_fields.get(103, b"")) == 2,
        "Peer identity announcement differs",
    )
    peer_uid = peer_fields[103]
    require(main_uid != peer_uid, "PM session UIDs collide")
    actions = [
        (index, step)
        for index, step in enumerate(plan["steps"])
        if step["op"] == "send" and int(step["hex"][4:8], 16) == 108
    ]
    require(len(actions) == len(cases.CASES), "PM action count differs")
    for offset, ((label, case), (start, step)) in enumerate(
        zip(cases.CASES.items(), actions, strict=True)
    ):
        end = (
            actions[offset + 1][0] if offset + 1 < len(actions) else len(plan["steps"])
        )
        sender = case.sender
        recipient = "peer" if sender == "main" else "main"
        sent = bytes.fromhex(
            "".join(
                event["hex"]
                for event in report["events"]
                if event["action"] == start and event["event"] == "send"
            )
        )
        require(
            fields(decode_frame(sent))[103]
            == (peer_uid if recipient == "peer" else main_uid),
            f"{label}: target UID differs",
        )
        identifier = 60 + offset
        ack = reply(report, identifier, sender)
        require(ack["error"] == 0 and not ack["fields"], "PM ACK is not empty success")
        window = [
            f
            for f in report["frames"]
            if start < f["action"] < end and f["type"] == 104 and not f["is_reply"]
        ]
        sender_events = [fields(f) for f in window if f["connection"] == sender]
        recipient_events = [fields(f) for f in window if f["connection"] == recipient]
        require(
            all(
                ack["action"] < frame["action"]
                for frame in window
                if frame["connection"] == sender
            ),
            f"{label}: sender feedback preceded ACK in recorded stream",
        )
        require(
            len(sender_events) == case.sender_push
            and len(recipient_events) == case.recipient_push,
            f"{label}: PM routing count differs",
        )
        sender_uid, sender_name = (
            (main_uid, cases.MAIN) if sender == "main" else (peer_uid, cases.PEER)
        )
        recipient_uid, recipient_name = (
            (peer_uid, cases.PEER) if sender == "main" else (main_uid, cases.MAIN)
        )
        if label == "direct-quoted":
            check_variant(
                recipient_events[0], sender_uid, sender_name, 1, case.text, cases.QUOTE
            )
        elif label == "recipient-refuses":
            check_variant(sender_events[0], recipient_uid, recipient_name, 2, None)
        elif label == "auto-and-original":
            check_variant(
                sender_events[0], recipient_uid, recipient_name, 4, b"pm-a26-auto"
            )
            check_variant(recipient_events[0], sender_uid, sender_name, 1, case.text)
        elif label in {"option-two", "option-three"}:
            check_variant(
                recipient_events[0], sender_uid, sender_name, case.option, None
            )
    require(
        sum(f["type"] == 104 and not f["is_reply"] for f in report["frames"])
        == sum(c.sender_push + c.recipient_push for c in cases.CASES.values()),
        "Unexpected 104 outside PM case windows",
    )
    return {
        "main_uid_hex": main_uid.hex(),
        "peer_uid_hex": peer_uid.hex(),
        "verified_cases": list(cases.CASES),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = verify_capture(args.capture)
    plan = json.loads((args.capture / "plan.json").read_text())
    result = semantic(report, plan)
    if args.output.exists():
        parser.error("Refusing existing output")
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
