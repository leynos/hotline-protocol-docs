#!/usr/bin/env python3
"""Generate bounded read-only 303 load plans for the verified existing fixture."""

import argparse
import json
from pathlib import Path

from native_diagnostic_cases import diagnostic_request
from native_plan import close, packet, payload, read, send
from native_queue_cases import attach, cancel, session
from protocol_capture import ORACLE_SHA256, validate_plan

NAME = b"mothra-race-fixture"
MAX_REFERENCES = 16
MAX_DATA_SOCKETS = 8


def exchange(kind: int, identifier: int, fields: list[tuple[int, bytes]]) -> list[dict]:
    return [
        send(packet(kind, identifier, payload(fields)), "a"),
        read("a", match_frame={"is_reply": 1, "id": identifier}),
    ]


def roster(identifier: int) -> list[dict]:
    return [
        send(packet(300, identifier), "a"),
        read(
            "a",
            match_frame={"is_reply": 1, "id": identifier},
            save={"name": "admin_uid", "offset": 26, "size": 2},
        ),
    ]


def diagnostic(identifier: int, uid: str | bytes = "admin_uid") -> list[dict]:
    return [
        diagnostic_request("a", identifier, uid),
        read("a", match_frame={"is_reply": 1, "id": identifier}),
    ]


def request(identifier: int, variable: str) -> list[dict]:
    return [
        send(packet(202, identifier, payload([(201, NAME)])), "a"),
        read(
            "a",
            match_frame={"is_reply": 1, "id": identifier},
            save_fields={variable: 107, variable + "_size": 108},
        ),
    ]


def finish_active(variable: str, identifier: int) -> list[dict]:
    return cancel("a", identifier, variable) + [
        {"op": "read_eof", "connection": variable, "timeout": 30},
        close(variable),
    ]


def one_active_one_queued() -> list[dict]:
    """2/1 limits: require a same-session queued second reference."""
    steps = session("a") + roster(10)
    steps += request(11, "active") + attach("active")
    steps += request(12, "queued") + diagnostic(13)
    steps += diagnostic(14, b"\xff\xff")
    steps += cancel("a", 15, "queued") + finish_active("active", 16)
    return steps + diagnostic(17) + [close("a")]


def density() -> list[dict]:
    """8/8 limits: fixed 4+0, 8+4 and 8+8 points; never expand counts."""
    steps = session("a") + roster(10)
    for index in range(MAX_DATA_SOCKETS):
        variable = f"active{index}"
        steps += request(20 + index, variable) + attach(variable)
        if index == 3:
            steps += diagnostic(35)
    for index in range(MAX_REFERENCES - MAX_DATA_SOCKETS):
        steps += request(40 + index, f"queued{index}")
        if index in {3, 7}:
            steps += diagnostic(60 if index == 3 else 61)
    for index in reversed(range(MAX_REFERENCES - MAX_DATA_SOCKETS)):
        steps += cancel("a", 70 + index, f"queued{index}")
    for index in reversed(range(MAX_DATA_SOCKETS)):
        variable = f"active{index}"
        steps += cancel("a", 80 + index, variable) + [close(variable)]
    return steps + diagnostic(90) + [close("a")]


def postflight() -> list[dict]:
    """Read-only baseline after General Options have been restored and reopened."""
    steps = session("a")
    steps += exchange(348, 10, [])
    steps += exchange(200, 11, [(202, b"\0\0")])
    steps += exchange(206, 12, [(201, NAME)])
    return steps + roster(13) + diagnostic(14) + [close("a")]


CASES = {
    "one-active-one-queued": (one_active_one_queued, 2, 1),
    "density": (density, 8, 8),
    "postflight": (postflight, 100, 10),
}


def build(case: str, runtime: dict) -> dict:
    generator, global_limit, client_limit = CASES[case]
    steps = generator()
    plan = {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": "delegated A8 existing-fixture diagnostic operator",
        "oracle_sha256": ORACLE_SHA256,
        "gap_ids": ["GAP-037"],
        "environment": runtime,
        "endpoints": {
            "control": {"host": "127.0.0.1", "port": 15500},
            "data": {"host": "127.0.0.1", "port": 15501},
        },
        "expectation": {
            "case": case,
            "fixture_name_hex": NAME.hex(),
            "global_download_limit": global_limit,
            "per_client_download_limit": client_limit,
            "per_ip_limit": 5,
            "maximum_references": MAX_REFERENCES,
            "maximum_data_sockets": MAX_DATA_SOCKETS,
            "a7_required_preflight_commit": "66b406a3db343467491e9446634c1b9bf8475fcc",
        },
        "steps": steps,
    }
    validate_plan(plan)
    return plan


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=CASES)
    parser.add_argument("--runtime-record", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    runtime = json.loads(arguments.runtime_record.read_text())
    output = arguments.output
    if output.exists():
        raise SystemExit(f"Refusing existing output: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(build(arguments.case, runtime), indent=2) + "\n")
    print(output)


if __name__ == "__main__":
    main()
