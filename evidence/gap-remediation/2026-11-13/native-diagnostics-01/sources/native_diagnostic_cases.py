#!/usr/bin/env python3
"""Generate bounded native 303 diagnostic observations for one owned account."""

import argparse
import json
from pathlib import Path

from native_auth_cases import complement
from native_live_account_cases import account_values, subject
from native_mkdir_cases import exchange
from native_plan import close, login, packet, read, send
from protocol_capture import ORACLE_SHA256, validate_plan

KEY = b"m-diag31-zero"
PASSWORD = b"diag-pass31"
NAME = b"Diag31-\x8e"
ACCESS = bytes(8)


def diagnostic_request(connection: str, identifier: int, uid: str | bytes) -> dict:
    """Build a 303 whose field 103 has the measured two-byte UID width."""
    if isinstance(uid, str):
        if uid not in {"target_uid", "admin_uid"}:
            raise ValueError("Only current-session UIDs may be substituted")
        content = "{" + uid + "}"
    elif len(uid) == 2:
        content = uid.hex()
    else:
        raise ValueError("A diagnostic UID must be exactly two bytes")
    return send(
        packet(303, identifier, bytes(8))[:40] + "000100670002" + content, connection
    )


def suites(stale_uid: bytes | None = None) -> dict[str, tuple[list[dict], dict]]:
    preflight = login() + exchange(348, 10, []) + exchange(352, 11, [(105, KEY)])
    preflight += exchange(300, 12, []) + [close()]
    seed = login() + exchange(350, 10, account_values(KEY, PASSWORD, NAME, ACCESS))
    seed += exchange(352, 11, [(105, KEY)]) + [close()]
    observe = login() + subject("zero", KEY, PASSWORD, 31)
    observe += [
        read("main", match_frame={"type": 301}, save_fields={"target_uid": 103}),
        diagnostic_request("main", 10, "target_uid"),
        read(match_frame={"is_reply": 1, "id": 10}),
        diagnostic_request("zero", 11, "target_uid"),
        read("zero", match_frame={"is_reply": 1, "id": 11}),
        diagnostic_request("main", 12, b"\xff\xff"),
        read(match_frame={"is_reply": 1, "id": 12}),
    ]
    if stale_uid is not None:
        observe += [
            diagnostic_request("main", 13, stale_uid),
            read(match_frame={"is_reply": 1, "id": 13}),
        ]
    observe += exchange(300, 20, []) + [close("zero"), close()]
    self_case = login() + [
        send(packet(300, 10)),
        read(
            match_frame={"is_reply": 1, "id": 10},
            save={"name": "admin_uid", "offset": 26, "size": 2},
        ),
        diagnostic_request("main", 11, "admin_uid"),
        read(match_frame={"is_reply": 1, "id": 11}),
        close(),
    ]
    cleanup = login() + exchange(351, 10, [(105, complement(KEY))])
    cleanup += exchange(352, 11, [(105, KEY)])
    cleanup += exchange(348, 12, []) + [close()]
    return {
        "preflight": (preflight, {"kind": "diagnostic-preflight"}),
        "seed": (seed, {"kind": "diagnostic-seed"}),
        "observe": (observe, {"kind": "diagnostic-observe"}),
        "self": (self_case, {"kind": "diagnostic-self"}),
        "cleanup": (cleanup, {"kind": "diagnostic-cleanup"}),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-record", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--stale-uid", type=lambda s: bytes.fromhex(s))
    args = parser.parse_args()
    if args.stale_uid is not None and len(args.stale_uid) != 2:
        parser.error("--stale-uid requires exactly two bytes")
    runtime = json.loads(args.runtime_record.read_text())
    args.output.mkdir(parents=True, exist_ok=False)
    for name, (steps, expectation) in suites(args.stale_uid).items():
        plan = {
            "schema_version": 1,
            "profile": "native-mac-oracle",
            "operator": "delegated native diagnostic operator",
            "oracle_sha256": ORACLE_SHA256,
            "gap_ids": ["GAP-037"],
            "environment": runtime,
            "endpoints": {"control": {"host": "127.0.0.1", "port": 15500}},
            "steps": steps,
            "expectation": expectation,
        }
        validate_plan(plan)
        (args.output / f"{name}.json").write_text(json.dumps(plan, indent=2) + "\n")


if __name__ == "__main__":
    main()
