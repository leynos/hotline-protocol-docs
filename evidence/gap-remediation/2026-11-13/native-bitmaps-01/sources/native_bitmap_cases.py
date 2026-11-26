#!/usr/bin/env python3
"""Generate bounded native field-110 account replacement/readback cases."""

import argparse
import json
from pathlib import Path

from native_auth_cases import complement
from native_live_account_cases import account_values, subject
from native_mkdir_cases import exchange
from native_plan import close, login
from protocol_capture import ORACLE_SHA256, validate_plan

KEY = b"m-bit32-owned"
PASSWORD = b"bitmap-pass32"
NAME = b"Bitmap32 owned"
ATTRIBUTE = b"bitmap32"
ZERO = bytes(8)
WIDTHS: dict[str, bytes | None] = {
    "absent": None,
    "empty": b"",
    "short-one": b"\xa5",
    "short-seven": bytes.fromhex("0123456789abcd"),
    "exact-eight": bytes.fromhex("1032547698badcfe"),
    "over-nine": bytes.fromhex("1032547698badcfe55"),
}


def walking_bit(bit: int) -> bytes:
    """Return the access bitmap with only the given bit set, most significant bit first."""
    if not 0 <= bit < 64:
        raise ValueError("Bit outside field-110 registry")
    result = bytearray(8)
    result[bit >> 3] = 0x80 >> (bit & 7)
    return bytes(result)


def replacement(access: bytes | None) -> list[tuple[int, bytes]]:
    """Return the account update fields, with the access bitmap when one is given."""
    values = [
        (105, complement(KEY)),
        (102, NAME),
        (106, b"\0"),
        (111, ATTRIBUTE),
    ]
    if access is not None:
        values.append((110, access))
    return values


def suites() -> dict[str, tuple[list[dict], dict]]:
    """Return the preflight, seed, walking-bit, width and cleanup plans of the bitmap capture."""
    plans = {}
    plans["preflight"] = (
        login() + exchange(348, 10, []) + exchange(352, 11, [(105, KEY)]) + [close()],
        {"kind": "bitmap-preflight"},
    )
    plans["seed"] = (
        login()
        + exchange(350, 10, account_values(KEY, PASSWORD, NAME, ZERO, ATTRIBUTE))
        + exchange(352, 11, [(105, KEY)])
        + [close()],
        {"kind": "bitmap-seed"},
    )
    for group in range(8):
        steps = login()
        for offset in range(8):
            bit = group * 8 + offset
            steps += exchange(353, 20 + offset * 2, replacement(walking_bit(bit)))
            steps += exchange(352, 21 + offset * 2, [(105, KEY)])
        plans[f"walk-{group:02d}"] = (
            steps + [close()],
            {"kind": "bitmap-walk", "first_bit": group * 8, "last_bit": group * 8 + 7},
        )
    steps = login()
    for offset, (label, value) in enumerate(WIDTHS.items()):
        steps += exchange(353, 40 + offset * 2, replacement(value))
        steps += exchange(352, 41 + offset * 2, [(105, KEY)])
    plans["widths"] = (
        steps + [close()],
        {"kind": "bitmap-widths", "labels": list(WIDTHS)},
    )
    plans["all-ones"] = (
        login()
        + exchange(353, 10, replacement(b"\xff" * 8))
        + exchange(352, 11, [(105, KEY)])
        + subject("owned", KEY, PASSWORD, 32)
        + [close("owned"), close()],
        {"kind": "bitmap-all-ones-login"},
    )
    plans["cleanup"] = (
        login()
        + exchange(351, 10, [(105, complement(KEY))])
        + exchange(352, 11, [(105, KEY)])
        + exchange(348, 12, [])
        + [close()],
        {"kind": "bitmap-cleanup"},
    )
    return plans


def main() -> None:
    """Write each bitmap plan to the output directory with the runtime record."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-record", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    runtime = json.loads(args.runtime_record.read_text())
    args.output.mkdir(parents=True, exist_ok=False)
    for name, (steps, expectation) in suites().items():
        plan = {
            "schema_version": 1,
            "profile": "native-mac-oracle",
            "operator": "delegated native bitmap operator",
            "oracle_sha256": ORACLE_SHA256,
            "gap_ids": ["GAP-031", "GAP-015", "GAP-016", "GAP-019"],
            "environment": runtime,
            "endpoints": {"control": {"host": "127.0.0.1", "port": 15500}},
            "steps": steps,
            "expectation": expectation,
        }
        validate_plan(plan)
        (args.output / f"{name}.json").write_text(json.dumps(plan, indent=2) + "\n")


if __name__ == "__main__":
    main()
