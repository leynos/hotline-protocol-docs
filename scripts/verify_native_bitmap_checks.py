"""Check the field-110 walking bits, width controls and account cleanup.

The order of the checks in each function is the order in which a corrupt case
is refused, so a function reads its evidence in the sequence that it always has.
"""

import typing as typ

import native_bitmap_cases as cases
from native_auth_cases import complement
from native_wire_names import (
    ACCESS_BITMAP_BYTES,
    FIELD_ACCESS_BITMAP,
    FIELD_ACCOUNT_ATTRIBUTE,
    FIELD_ERROR_TEXT,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    FRAME_HEADER_BYTES,
    TYPE_CREATE_ACCOUNT,
    TYPE_DELETE_ACCOUNT,
    TYPE_GET_ACCOUNT,
    TYPE_LOGIN,
    TYPE_PRIVILEGES_NOTIFICATION,
    TYPE_UPDATE_ACCOUNT,
)
from protocol_capture import decode_frame
from verify_native_account_updates import enumeration
from verify_native_auth import reply, selected
from verify_native_core import require
from verify_native_shx import fields

type Report = dict[str, typ.Any]

NAMES = tuple(cases.suites())
PRESENT_PASSWORD = b"x"  # a stand-in: the reply carries a password only as a flag
BLANK_PASSWORD = b"\0"  # the replacement sends a lone zero byte as the password
WALK_GROUPS = 8
BITS_PER_GROUP = 8
WALK_FIRST_ID = 20
WIDTH_FIRST_ID = 40
WIDTH_CASES = 6
BASELINE_ACCOUNTS = 2
ALL_ONES = b"\xff" * ACCESS_BITMAP_BYTES
WALKING_BITS = 64


def sent(
    report: Report, kind: int, identifier: int, connection: str = "main"
) -> Report:
    """Find the one request of a type and ID that a connection sent.

    Returns
    -------
    dict[str, typing.Any]
        The decoded request frame.
    """
    frames = []
    for event in report["events"]:
        if event["event"] != "send" or event["connection"] != connection:
            continue
        raw = bytes.fromhex(event["hex"])
        if len(raw) < FRAME_HEADER_BYTES:
            continue
        frame = decode_frame(raw)
        if frame["type"] == kind and frame["id"] == identifier:
            frames.append(frame)
    require(len(frames) == 1, "Missing/duplicate bitmap request")
    return frames[0]


def account(frame: Report, access: bytes) -> None:
    """Check a read of the owned account: its identity, password flag and bitmap."""
    require(
        frame["type"] == 0
        and frame["is_reply"] == 1
        and frame["error"] == 0
        and fields(frame)
        == {
            FIELD_NAME: cases.NAME,
            FIELD_LOGIN: complement(cases.KEY),
            FIELD_PASSWORD: PRESENT_PASSWORD,
            FIELD_ACCESS_BITMAP: access,
        },
        "Owned account identity/bitmap/password readback differs",
    )


def replacement(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # the callers' shape
    report: Report,
    update_id: int,
    read_id: int,
    submitted: bytes | None,
    observed: bytes,
) -> None:
    """Check a replacement of the owned account and its readback."""
    request = fields(sent(report, TYPE_UPDATE_ACCOUNT, update_id))
    expected = {
        FIELD_LOGIN: complement(cases.KEY),
        FIELD_NAME: cases.NAME,
        FIELD_PASSWORD: BLANK_PASSWORD,
        FIELD_ACCOUNT_ATTRIBUTE: cases.ATTRIBUTE,
    }
    if submitted is not None:
        expected[FIELD_ACCESS_BITMAP] = submitted
    require(request == expected, "Wrong submitted bitmap/owned replacement fields")
    require(reply(report, update_id)["error"] == 0, "Bitmap replacement failed")
    require(
        fields(sent(report, TYPE_GET_ACCOUNT, read_id)) == {FIELD_LOGIN: cases.KEY},
        "Account readback requested another identity",
    )
    account(reply(report, read_id), observed)


def ordered_replies(report: Report, identifiers: list[int]) -> None:
    """Check that the replies to the listed requests came in request order."""
    actual = [
        frame["id"]
        for frame in report["frames"]
        if frame["connection"] == "main"
        and frame["type"] == 0
        and frame["is_reply"]
        and frame["id"] in identifiers
    ]
    require(actual == identifiers, "Bitmap replacement/readback order differs")


def check_preflight(preflight: Report) -> tuple[list[str], Report]:
    """Check that the owned account was absent before the run.

    Returns
    -------
    tuple[list[str], dict[str, typing.Any]]
        The baseline enumeration and the reply that showed the account missing.
    """
    baseline = enumeration(reply(preflight, 10))
    require(len(baseline) == BASELINE_ACCOUNTS, "Preflight account inventory differs")
    missing = reply(preflight, 11)
    require(
        missing["error"] == 1
        and list(fields(missing)) == [FIELD_ERROR_TEXT]
        and fields(sent(preflight, TYPE_GET_ACCOUNT, 11)) == {FIELD_LOGIN: cases.KEY},
        "Owned account was not proven absent",
    )
    return baseline, missing


def check_seed(seed: Report) -> None:
    """Check the creation of the owned account with an empty bitmap."""
    require(
        fields(sent(seed, TYPE_CREATE_ACCOUNT, 10))
        == {
            FIELD_LOGIN: complement(cases.KEY),
            FIELD_PASSWORD: complement(cases.PASSWORD),
            FIELD_NAME: cases.NAME,
            FIELD_ACCESS_BITMAP: cases.ZERO,
            FIELD_ACCOUNT_ATTRIBUTE: cases.ATTRIBUTE,
        }
        and reply(seed, 10)["error"] == 0,
        "Owned account seed differs",
    )
    account(reply(seed, 11), cases.ZERO)


def check_walks(reports: dict[str, Report]) -> list[Report]:
    """Check each of the 64 single-bit replacements and their readbacks.

    Returns
    -------
    list[dict[str, typing.Any]]
        One row for each bit: the case, the request IDs and the bitmaps.
    """
    rows = []
    for group in range(WALK_GROUPS):
        report = reports[f"walk-{group:02d}"]
        ids = [
            identifier
            for offset in range(BITS_PER_GROUP)
            for identifier in (
                WALK_FIRST_ID + 2 * offset,
                WALK_FIRST_ID + 1 + 2 * offset,
            )
        ]
        ordered_replies(report, ids)
        for offset in range(BITS_PER_GROUP):
            bit = group * BITS_PER_GROUP + offset
            value = cases.walking_bit(bit)
            update_id = WALK_FIRST_ID + 2 * offset
            read_id = update_id + 1
            replacement(report, update_id, read_id, value, value)
            rows.append({
                "bit": bit,
                "case": f"walk-{group:02d}",
                "update_id": update_id,
                "read_id": read_id,
                "submitted_hex": value.hex(),
                "readback_hex": fields(reply(report, read_id))[
                    FIELD_ACCESS_BITMAP
                ].hex(),
            })
    return rows


def check_widths(widths: Report) -> dict[str, str]:
    """Check the input-width controls and what each read back.

    Returns
    -------
    dict[str, str]
        The readback of each control, in hexadecimal.
    """
    ordered_replies(
        widths,
        [
            identifier
            for offset in range(WIDTH_CASES)
            for identifier in (
                WIDTH_FIRST_ID + 2 * offset,
                WIDTH_FIRST_ID + 1 + 2 * offset,
            )
        ],
    )
    outcomes = {}
    for offset, (name, value) in enumerate(cases.WIDTHS.items()):
        observed = ((value or b"") + bytes(ACCESS_BITMAP_BYTES))[:ACCESS_BITMAP_BYTES]
        update_id = WIDTH_FIRST_ID + 2 * offset
        replacement(widths, update_id, update_id + 1, value, observed)
        outcomes[name] = observed.hex()
    return outcomes


def check_all_ones(all_ones: Report) -> None:
    """Check the all-ones replacement and the session that logged in with it."""
    replacement(all_ones, 10, 11, ALL_ONES, ALL_ONES)
    owned_login = fields(sent(all_ones, TYPE_LOGIN, 1, "owned"))
    require(
        owned_login.get(FIELD_LOGIN) == complement(cases.KEY)
        and owned_login.get(FIELD_PASSWORD) == complement(cases.PASSWORD),
        "All-ones subject used other credentials",
    )
    access = [
        f
        for f in selected(all_ones, "owned")
        if f["type"] == TYPE_PRIVILEGES_NOTIFICATION and not f["is_reply"]
    ]
    require(
        len(access) == 1 and fields(access[0]) == {FIELD_ACCESS_BITMAP: ALL_ONES},
        "All-ones effective session bitmap differs",
    )


def check_cleanup(cleanup: Report, baseline: list[str], missing: Report) -> None:
    """Check that the owned account was deleted and the baseline restored."""
    require(
        reply(cleanup, 10)["error"] == 0
        and fields(sent(cleanup, TYPE_DELETE_ACCOUNT, 10))
        == {FIELD_LOGIN: complement(cases.KEY)}
        and reply(cleanup, 11)["error"] == 1
        and fields(reply(cleanup, 11)) == fields(missing)
        and enumeration(reply(cleanup, 12)) == baseline,
        "Owned account cleanup/baseline differs",
    )


def semantic(reports: dict[str, Report]) -> Report:
    """Check every measured bit, input width, identity and observed ordering.

    Returns
    -------
    dict[str, typing.Any]
        The walking rows, the width readbacks and the baseline account count.
    """
    require(set(reports) == set(NAMES), "Bitmap case inventory differs")
    preflight, seed, widths, all_ones, cleanup = (
        reports[name] for name in ("preflight", "seed", "widths", "all-ones", "cleanup")
    )
    baseline, missing = check_preflight(preflight)
    check_seed(seed)
    rows = check_walks(reports)
    width_outcomes = check_widths(widths)
    check_all_ones(all_ones)
    check_cleanup(cleanup, baseline, missing)
    return {
        "walking_bits_verified": WALKING_BITS,
        "walking_rows": rows,
        "width_readbacks_hex": width_outcomes,
        "baseline_accounts": len(baseline),
    }
