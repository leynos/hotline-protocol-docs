"""Control-only plans for one configured-address ban application fixture."""

import hashlib
import json
from pathlib import Path

from native_auth_cases import authentication, complement
from native_ban_control_cases import A7_SHA, FILE, ZERO
from native_plan import close, eof, login, packet, payload, read, send
from protocol_capture import ORACLE_SHA256, validate_plan

KEY = b"m-ban-apply-only"
PASSWORD = b"apply-ban-pass"
NAME = b"Ban Apply Target"
ADDRESS = b"10.0.2.2"


def exchange(kind: int, identifier: int, values: list[tuple[int, bytes]]) -> list[dict]:
    """Return the steps that send one request and read its reply."""
    return [
        send(packet(kind, identifier, payload(values))),
        read(match_frame={"is_reply": 1, "id": identifier}),
    ]


def tail_eof(connection: str) -> dict:
    """Return the step that reads the connection's EOF without checking its bytes."""
    step = eof(connection)
    del step["expect_hex"]
    return step


def plans() -> dict[str, list[dict]]:
    """Return the readiness, guard, seed and held-apply plans of the configured-address ban capture."""
    ready = login()
    ready += exchange(348, 10, [])
    ready += exchange(200, 11, [(202, b"\0\0")])
    ready += exchange(206, 12, [(201, FILE)])
    ready += [
        send(packet(300, 13)),
        read(
            match_frame={"is_reply": 1, "id": 13},
            save={"name": "admin_uid", "offset": 26, "size": 2},
        ),
        send(packet(303, 14, payload([(103, b"\0\0")]))[:-4] + "{admin_uid}"),
        read(match_frame={"is_reply": 1, "id": 14}),
        close(),
    ]
    guard = login() + exchange(352, 30, [(105, KEY)]) + [close()]
    seed = login() + exchange(
        350,
        31,
        [(105, complement(KEY)), (106, complement(PASSWORD)), (102, NAME), (110, ZERO)],
    )
    seed += exchange(352, 32, [(105, KEY)]) + [close()]
    held = login()
    held += [{**step, "connection": "target"} for step in login()[:3]]
    held += [authentication(KEY, PASSWORD, name=NAME, connection="target")]
    held += [read("target"), read("target"), read("target")]
    held += [
        read(match_frame={"type": 301}, save_field={"name": "target_uid", "id": 103})
    ]
    held += exchange(300, 32, [])
    # The tail is part of this same source plan and resulting report.
    held += [
        read(match_frame={"type": 104}),
        read("target", match_frame={"type": 104}),
        tail_eof("main"),
        tail_eof("target"),
        close(),
        close("target"),
    ]
    return {"readiness": ready, "guard": guard, "seed": seed, "held-apply": held}


def write_plans(output: Path, environment: dict, port: int) -> dict[str, str]:
    """Write each plan for an owned lab port and return the plans' hashes."""
    if port in {15500, 15501} or not 1024 <= port <= 65534:
        raise ValueError("Control endpoint must be an owned lab port")
    if environment.get("source_a7_sha256") != A7_SHA:
        raise ValueError("Original A7 source-plan hash differs")
    output.mkdir(parents=True, exist_ok=False)
    result = {}
    for name, steps in plans().items():
        plan = {
            "schema_version": 1,
            "profile": "native-mac-oracle",
            "operator": "C64 configured-address ban application operator",
            "oracle_sha256": ORACLE_SHA256,
            "gap_ids": ["GAP-044"],
            "environment": {
                **environment,
                "fixture_profile": "control-only",
                "full_file_baseline": "not_exercised",
            },
            "endpoints": {"control": {"host": "127.0.0.1", "port": port}},
            "steps": steps,
            "expectation": {
                "case": name,
                "owned_key_hex": KEY.hex(),
                "address_hex": ADDRESS.hex(),
            },
        }
        validate_plan(plan)
        encoded = (json.dumps(plan, indent=2) + "\n").encode()
        (output / f"{name}.json").write_bytes(encoded)
        result[name] = hashlib.sha256(encoded).hexdigest()
    return result
