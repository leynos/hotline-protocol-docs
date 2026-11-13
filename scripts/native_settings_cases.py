#!/usr/bin/env python3
"""Prepare ten bounded native 304/113 width, presence and duplicate probes."""

import argparse
import json
from pathlib import Path

from native_auth_cases import authentication
from native_plan import close, login, packet, payload, read, send
from protocol_capture import ORACLE_SHA256, validate_plan

CASES: dict[str, tuple[list[bytes] | None, int | None]] = {
    "absent": (None, 0),
    "empty": ([b""], 0),
    "zero-two": ([b"\0\0"], 0),
    "one-byte-refuse": ([b"\x01"], 1),
    "two-byte-auto": ([b"\0\x04"], 4),
    "three-byte-default": ([b"\0\0\x01"], 0),
    "four-byte-both": ([b"\0\0\0\x05"], 5),
    "five-byte-prefix": ([b"\0\0\0\x01\xff"], 1),
    "duplicate-refuse-auto": ([b"\0\x01", b"\0\x04"], None),
    "duplicate-auto-refuse": ([b"\0\x04", b"\0\x01"], None),
}


def pm_request(identifier: int, text: bytes) -> dict:
    """Substitute the saved native two-byte subject UID into an exact TLV."""
    fields = [(103, "{subject_uid}"), (113, b"\0\x01".hex()), (101, text.hex())]
    size = 2 + sum(
        4 + (2 if field == 103 else len(bytes.fromhex(value)))
        for field, value in fields
    )
    header = packet(108, identifier, bytes(size))[:40]
    body = "0003" + "".join(
        field.to_bytes(2, "big").hex()
        + (2 if field == 103 else len(bytes.fromhex(value))).to_bytes(2, "big").hex()
        + value
        for field, value in fields
    )
    return send(header + body)


def subject_login() -> list[dict]:
    steps = [{**step, "connection": "subject"} for step in login()[:3]]
    steps += [
        authentication(
            b"admin",
            b"mothra19",
            name=b"settings25",
            icon=b"\0\x07",
            connection="subject",
        )
    ]
    steps += [read("subject") for _ in range(3)]
    return steps


def barrier(connection: str, identifier: int) -> list[dict]:
    return [
        send(packet(500, identifier), connection),
        read(connection, match_frame={"is_reply": 1, "id": identifier}),
    ]


def cases() -> dict[str, tuple[list[dict], dict]]:
    result = {}
    for number, (name, (values, flags)) in enumerate(CASES.items(), 1):
        fields = [(102, b"settings25"), (104, b"\0\x07")]
        if values is not None:
            fields += [(113, values[0])]
            if len(values) == 2:
                # The second order also interleaves the known icon/name fields.
                if name == "duplicate-auto-refuse":
                    fields += [(104, b"\0\x07"), (102, b"settings25")]
                fields += [(113, values[1])]
        text = f"settings25-pm-{number:02d}".encode()
        steps = login() + subject_login()
        steps += [read(match_frame={"type": 301}, save_fields={"subject_uid": 103})]
        steps += [send(packet(304, 40, payload(fields)), "subject")]
        steps += [read(match_frame={"type": 301})] + barrier("main", 41)
        steps += [pm_request(70, text), read(match_frame={"is_reply": 1, "id": 70})]
        steps += barrier("main", 71) + barrier("subject", 72)
        steps += [
            send(
                packet(
                    304,
                    80,
                    payload([(102, b"settings25"), (104, b"\0\x07"), (113, b"\0\0")]),
                ),
                "subject",
            )
        ]
        steps += [read(match_frame={"type": 301})]
        steps += barrier("main", 81) + barrier("subject", 82)
        steps += [close("subject"), close()]
        result[name] = (
            steps,
            {
                "case": name,
                "expected_flags": flags,
                "duplicate": flags is None,
                "pm_text": text.hex(),
                "oracle_sha256": ORACLE_SHA256,
            },
        )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-record", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    environment = json.loads(args.runtime_record.read_text())
    args.output.mkdir(parents=True, exist_ok=False)
    for name, (steps, expectation) in cases().items():
        plan = {
            "schema_version": 1,
            "profile": "native-mac-oracle",
            "operator": "delegated native settings operator",
            "oracle_sha256": ORACLE_SHA256,
            "environment": environment,
            "gap_ids": ["GAP-015", "GAP-016", "GAP-017", "GAP-084"],
            "endpoints": {"control": {"host": "127.0.0.1", "port": 15500}},
            "expectation": expectation,
            "steps": steps,
        }
        validate_plan(plan)
        (args.output / f"{name}.json").write_text(json.dumps(plan, indent=2) + "\n")
    print(f"Prepared {len(CASES)} native settings cases")


if __name__ == "__main__":
    main()
