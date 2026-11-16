#!/usr/bin/env python3
"""Generate bounded native field-110 account replacement/readback cases."""

import json
import typing as typ
from pathlib import Path

from native_auth_cases import complement
from native_live_account_cases import account_values, subject
from native_mkdir_cases import exchange
from native_plan import Action, close, login
from native_wire_names import (
    ACCESS_BITMAP_BYTES,
    FIELD_ACCOUNT_ATTRIBUTE,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    TYPE_CREATE_ACCOUNT,
    TYPE_DELETE_ACCOUNT,
    TYPE_ENUMERATE_ACCOUNTS,
    TYPE_GET_ACCOUNT,
    TYPE_UPDATE_ACCOUNT,
)
from protocol_capture import ORACLE_SHA256, validate_plan
from script_cli import run

type Case = tuple[list[Action], dict[str, typ.Any]]
type Cases = dict[str, Case]

KEY = b"m-bit32-owned"
PASSWORD = b"bitmap-pass32"
NAME = b"Bitmap32 owned"
ATTRIBUTE = b"bitmap32"
ZERO = bytes(ACCESS_BITMAP_BYTES)
BITS_PER_BYTE = 8
ACCESS_BITS = ACCESS_BITMAP_BYTES * BITS_PER_BYTE
# The icon of the owned account in the all-ones login.
OWNED_ICON = 32
SCHEMA_VERSION = 1
CONTROL_PORT = 15500
WIDTHS: dict[str, bytes | None] = {
    "absent": None,
    "empty": b"",
    "short-one": b"\xa5",
    "short-seven": bytes.fromhex("0123456789abcd"),
    "exact-eight": bytes.fromhex("1032547698badcfe"),
    "over-nine": bytes.fromhex("1032547698badcfe55"),
}


class RegistryBitError(ValueError):
    """The requested bit is outside the field-110 registry."""

    def __init__(self) -> None:
        """Set the message of the refusal."""
        super().__init__("Bit outside field-110 registry")


def walking_bit(bit: int) -> bytes:
    """Return the field-110 bitmap with only ``bit`` set, most significant first.

    Returns
    -------
    bytes
        The eight-byte bitmap with the single bit set.

    Raises
    ------
    RegistryBitError
        If ``bit`` is outside the field-110 registry.
    """
    if not 0 <= bit < ACCESS_BITS:
        raise RegistryBitError
    result = bytearray(ACCESS_BITMAP_BYTES)
    result[bit >> 3] = 0x80 >> (bit & 7)
    return bytes(result)


def replacement(access: bytes | None) -> list[tuple[int, bytes]]:
    """Plan the account fields of a replacement, with the access bitmap if given.

    Returns
    -------
    list[tuple[int, bytes]]
        The field identifiers and values, in the order they are sent.
    """
    values = [
        (FIELD_LOGIN, complement(KEY)),
        (FIELD_NAME, NAME),
        (FIELD_PASSWORD, b"\0"),
        (FIELD_ACCOUNT_ATTRIBUTE, ATTRIBUTE),
    ]
    if access is not None:
        values.append((110, access))
    return values


def suites() -> Cases:
    """Plan the preflight, seeding, walks, widths, all-ones login and cleanup.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The steps and expectation of each suite, by its name, in order.
    """
    plans: Cases = {}
    plans["preflight"] = (
        login()
        + exchange(TYPE_ENUMERATE_ACCOUNTS, 10, [])
        + exchange(TYPE_GET_ACCOUNT, 11, [(FIELD_LOGIN, KEY)])
        + [close()],
        {"kind": "bitmap-preflight"},
    )
    plans["seed"] = (
        login()
        + exchange(
            TYPE_CREATE_ACCOUNT,
            10,
            account_values(KEY, PASSWORD, NAME, ZERO, ATTRIBUTE),
        )
        + exchange(TYPE_GET_ACCOUNT, 11, [(FIELD_LOGIN, KEY)])
        + [close()],
        {"kind": "bitmap-seed"},
    )
    for group in range(ACCESS_BITMAP_BYTES):
        steps = login()
        first_bit = group * BITS_PER_BYTE
        for offset in range(BITS_PER_BYTE):
            bit = first_bit + offset
            steps += exchange(
                TYPE_UPDATE_ACCOUNT, 20 + offset * 2, replacement(walking_bit(bit))
            )
            steps += exchange(TYPE_GET_ACCOUNT, 21 + offset * 2, [(FIELD_LOGIN, KEY)])
        plans[f"walk-{group:02d}"] = (
            [*steps, close()],
            {
                "kind": "bitmap-walk",
                "first_bit": first_bit,
                "last_bit": first_bit + BITS_PER_BYTE - 1,
            },
        )
    steps = login()
    for offset, value in enumerate(WIDTHS.values()):
        steps += exchange(TYPE_UPDATE_ACCOUNT, 40 + offset * 2, replacement(value))
        steps += exchange(TYPE_GET_ACCOUNT, 41 + offset * 2, [(FIELD_LOGIN, KEY)])
    plans["widths"] = (
        [*steps, close()],
        {"kind": "bitmap-widths", "labels": list(WIDTHS)},
    )
    plans["all-ones"] = (
        login()
        + exchange(
            TYPE_UPDATE_ACCOUNT,
            10,
            replacement(b"\xff" * ACCESS_BITMAP_BYTES),
        )
        + exchange(TYPE_GET_ACCOUNT, 11, [(FIELD_LOGIN, KEY)])
        + subject("owned", KEY, PASSWORD, OWNED_ICON)
        + [close("owned"), close()],
        {"kind": "bitmap-all-ones-login"},
    )
    plans["cleanup"] = (
        login()
        + exchange(TYPE_DELETE_ACCOUNT, 10, [(FIELD_LOGIN, complement(KEY))])
        + exchange(TYPE_GET_ACCOUNT, 11, [(FIELD_LOGIN, KEY)])
        + exchange(TYPE_ENUMERATE_ACCOUNTS, 12, [])
        + [close()],
        {"kind": "bitmap-cleanup"},
    )
    return plans


def write_plans(*, runtime_record: str, output: str) -> None:
    """Write one plan per suite into a new output directory.

    The runtime record is read first, then the output directory is created,
    which must not exist yet.
    """
    runtime = json.loads(Path(runtime_record).read_text(encoding="utf-8"))
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=False)
    for name, (steps, expectation) in suites().items():
        plan = {
            "schema_version": SCHEMA_VERSION,
            "profile": "native-mac-oracle",
            "operator": "delegated native bitmap operator",
            "oracle_sha256": ORACLE_SHA256,
            "gap_ids": ["GAP-031", "GAP-015", "GAP-016", "GAP-019"],
            "environment": runtime,
            "endpoints": {"control": {"host": "127.0.0.1", "port": CONTROL_PORT}},
            "steps": steps,
            "expectation": expectation,
        }
        validate_plan(plan)
        (directory / f"{name}.json").write_text(json.dumps(plan, indent=2) + "\n")


def main() -> None:
    """Generate the bounded native field-110 plans from the command line."""
    run(write_plans, __doc__)


if __name__ == "__main__":
    main()
