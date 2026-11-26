"""Plans for one isolated, control-only native permanent-ban observation."""

import hashlib
import json
from pathlib import Path

from native_auth_cases import authentication, complement
from native_plan import close, eof, login, packet, payload, read, send
from protocol_capture import ORACLE_SHA256, validate_plan

KEY = b"m-ban52-only"
PASSWORD = b"ban52-pass"
NAME = b"Ban52 Target"
ZERO = bytes(8)
FILE = b"mothra-race-fixture"
A7_SHA = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"


def exchange(kind: int, identifier: int, values: list[tuple[int, bytes]]) -> list[dict]:
    """Return the steps that send one request and read its reply."""
    return [
        send(packet(kind, identifier, payload(values))),
        read(match_frame={"is_reply": 1, "id": identifier}),
    ]


def plans() -> dict[str, list[dict]]:
    # 7 login + five correlated exchanges + close = 18. No 202/HTXF.
    """Build the ban control plans: the ready sequence and the probes that follow it."""
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
    ]
    ready += [
        send(packet(303, 14, payload([(103, b"\0\0")]))[:-4] + "{admin_uid}"),
        read(match_frame={"is_reply": 1, "id": 14}),
    ]
    ready += [close()]
    guard = login() + exchange(352, 30, [(105, KEY)]) + [close()]
    seed = login() + exchange(
        350,
        31,
        [(105, complement(KEY)), (106, complement(PASSWORD)), (102, NAME), (110, ZERO)],
    )
    seed += exchange(352, 32, [(105, KEY)]) + [close()]
    ban = login() + [{**step, "connection": "target"} for step in login()[:3]]
    ban += [authentication(KEY, PASSWORD, name=NAME, connection="target")]
    ban += [read("target"), read("target"), read("target")]
    ban += [
        read(match_frame={"type": 301}, save_field={"name": "target_uid", "id": 103})
    ]
    ban += exchange(300, 32, [])
    ban += [
        send(
            packet(110, 33, payload([(103, b"\0\0"), (113, b"\0\2")])).replace(
                "006700020000", "00670002{target_uid}"
            )
        )
    ]
    ban += [read("target", match_frame={"type": 104}), eof("target")]
    ban += [read(), read(), close("target")]
    ban += exchange(348, 40, [])
    ban += exchange(200, 41, [(202, b"\0\0")])
    ban += exchange(206, 42, [(201, FILE)])
    ban += exchange(300, 43, []) + [close()]
    probe = login()[:3] + [authentication(KEY, PASSWORD, name=NAME)]
    probe += [read(match_frame={"is_reply": 1, "id": 1}), close()]
    return {
        "readiness": ready,
        "guard": guard,
        "seed": seed,
        "ban": ban,
        "probe": probe,
    }


def write_plans(output: Path, environment: dict, port: int) -> dict:
    """Write the ban control plans for an owned lab port and return their identities."""
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
            "operator": "C52 isolated ban-control operator",
            "oracle_sha256": ORACLE_SHA256,
            "gap_ids": ["GAP-044"],
            "environment": {
                **environment,
                "fixture_profile": "control-only",
                "full_file_baseline": "not_exercised",
            },
            "endpoints": {"control": {"host": "127.0.0.1", "port": port}},
            "steps": steps,
            "expectation": {"case": name, "owned_key_hex": KEY.hex()},
        }
        validate_plan(plan)
        encoded = (json.dumps(plan, indent=2) + "\n").encode()
        (output / f"{name}.json").write_bytes(encoded)
        result[name] = hashlib.sha256(encoded).hexdigest()
    return result
