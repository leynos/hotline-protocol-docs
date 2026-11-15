"""Check the account replies, enumerations and stored records of the account corpus."""

import json
import typing as typ

from native_auth_cases import complement
from native_wire_names import (
    ACCESS_BITMAP_BYTES,
    ACCOUNT_ACCESS_OFFSET,
    ACCOUNT_ATTRIBUTE_LENGTH_OFFSET,
    ACCOUNT_LOGIN_LENGTH_OFFSET,
    ACCOUNT_NAME_LENGTH_OFFSET,
    ACCOUNT_PASSWORD_LENGTH_OFFSET,
    ACCOUNT_RECORD_BYTES,
    FIELD_ACCESS_BITMAP,
    FIELD_DATA,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
)
from verify_native_core import require
from verify_native_shx import fields

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]
type Catalogue = dict[typ.Any, Report]

LABELS = [
    "preserve",
    "absent",
    "empty",
    "literal-x",
    "replace32",
    "preserve32",
    "sparse",
    "attribute65",
]
BASE_PASSWORD = b"account-base-26"
PASSWORDS = {
    "preserve": BASE_PASSWORD,
    "absent": b"",
    "empty": b"",
    "literal-x": b"\x87",
    "replace32": b"p" * 32,
    "preserve32": b"q" * 31,
    "sparse": BASE_PASSWORD,
    "attribute65": BASE_PASSWORD,
}
ACCESS = bytes.fromhex("2000000000000000")
# The two bytes that open each stored account record. No document fixes their
# meaning, so the corpus name is kept without an interpretation.
RECORD_HEADER = b"\0\1"
# The Trash objects that the cleanup observation found outside the owned set.
PRIOR_TRASH_OBJECTS = 5
# The stored records of the seed and final phases, and the catalogue sizes of
# the cleanup and publish phases.
SEED_RECORDS = 17
FINAL_RECORDS = 18
CLEANUP_RECORDS = 23
PUBLISHED_RECORDS = 24


def username(label: str) -> bytes:
    """Return the login of the owned account of ``label``.

    Returns
    -------
    bytes
        The login, ``m-au26-`` followed by the label.
    """
    return ("m-au26-" + label).encode()


def values(
    label: str,
    after: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers' shape
) -> tuple[bytes, bytes, bytes, bytes]:
    """Return what the account of ``label`` holds before or after the update.

    Returns
    -------
    tuple[bytes, bytes, bytes, bytes]
        The name, the attribute, the password and the access bitmap.
    """
    password = (
        PASSWORDS[label]
        if after
        else b"q" * 32
        if label == "preserve32"
        else BASE_PASSWORD
    )
    name = b"" if after and label == "sparse" else b"Account26-" + label.encode()
    attribute = (
        b""
        if after and label == "sparse"
        else b"X" * 64
        if after and label == "attribute65"
        else b"opaque26"
    )
    access = bytes(8) if after and label == "sparse" else ACCESS
    return name, attribute, password, access


def account_reply(
    frame: Report,
    label: str,
    after: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the public signature takes after positionally
) -> None:
    """Check the retrieval of the account of ``label`` in ``frame``."""
    name, _, password, access = values(label, after=after)
    expected = {FIELD_LOGIN: complement(username(label)), FIELD_ACCESS_BITMAP: access}
    if name:
        expected[FIELD_NAME] = name
    if password:
        expected[FIELD_PASSWORD] = b"x"
    require(
        frame["error"] == 0 and fields(frame) == expected,
        "Account retrieval/default/placeholder differs",
    )


def account_record(
    label: str,
    after: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers' shape
) -> bytes:
    """Return the 734-byte stored record of the account of ``label``.

    Returns
    -------
    bytes
        The record, with each length word and value at its wire offset.
    """
    name, attribute, password, access = values(label, after=after)
    result = bytearray(ACCOUNT_RECORD_BYTES)
    result[:2] = RECORD_HEADER
    result[ACCOUNT_ACCESS_OFFSET : ACCOUNT_ACCESS_OFFSET + ACCESS_BITMAP_BYTES] = access
    for offset, value in [
        (ACCOUNT_NAME_LENGTH_OFFSET, name),
        (ACCOUNT_ATTRIBUTE_LENGTH_OFFSET, attribute),
        (ACCOUNT_LOGIN_LENGTH_OFFSET, username(label)),
        (ACCOUNT_PASSWORD_LENGTH_OFFSET, complement(password)),
    ]:
        result[offset : offset + 2] = len(value).to_bytes(2, "big")
        result[offset + 2 : offset + 2 + len(value)] = value
    return bytes(result)


def enumeration(frame: Report) -> list[str]:
    """Check an account enumeration reply and sort its records.

    Returns
    -------
    list[str]
        The hexadecimal value of each record, sorted.
    """
    require(
        frame["error"] == 0 and all(f["id"] == FIELD_DATA for f in frame["fields"]),
        "Account enumeration failed",
    )
    return sorted(f["hex"] for f in frame["fields"])


def check_stored_record(
    base: Path, rows: list[Report], label: str, *, after: bool
) -> None:
    """Check the data and resource forks of the stored record of ``label``."""
    row = next(
        r
        for r in rows
        if r["path"] == "/Hotline19/Users/" + username(label).decode() + "/UserData"
    )
    data = (base / (row["key"] + ".data")).read_bytes()
    require(
        not row["directory"] and data == account_record(label, after=after),
        "Stored 734-byte account record differs",
    )
    require(
        (base / (row["key"] + ".rsrc")).read_bytes() == b"",
        "Account resource fork differs",
    )


def check_positive_phase(base: Path, *, after: bool, count: int) -> Catalogue:
    """Check the catalogue and the stored records of one positive phase.

    Returns
    -------
    dict[typing.Any, dict[str, typing.Any]]
        The catalogue records of the phase, by catalogue identifier.
    """
    rows = json.loads((base / "extraction.json").read_text())["records"]
    require(
        len(rows) == count and len({r["catalog"] for r in rows}) == count,
        "Account positive catalogue inventory differs",
    )
    catalogue = {r["catalog"]: r for r in rows}
    expected_paths = {
        "/Hotline19/Users/" + username(label).decode() + suffix
        for label in LABELS
        for suffix in ["", "/UserData"]
    } | {"/Hotline19/Files/m-au26-seed-flush"}
    if after:
        expected_paths.add("/Hotline19/Files/m-au26-final-flush")
    require({r["path"] for r in rows} == expected_paths, "Owned account paths differ")
    for label in LABELS:
        check_stored_record(base, rows, label, after=after)
    return catalogue


def check_trashed(directory: Path, base: Path, original: Report, row: Report) -> None:
    """Check that a cleanup moved an owned object to Trash without changing it."""
    path = (
        original["path"]
        .replace("/Hotline19/Users/", "/Trash/")
        .replace("/Hotline19/Files/", "/Trash/")
    )
    require(
        row["path"] == path and row["directory"] == original["directory"],
        "Account Trash identity/path differs",
    )
    if not row["directory"]:
        for fork in ["data", "rsrc"]:
            require(
                (
                    directory / "native-final" / (original["key"] + "." + fork)
                ).read_bytes()
                == (base / (row["key"] + "." + fork)).read_bytes(),
                "Account cleanup changed original fork",
            )


def check_moved_phase(
    directory: Path, phase: str, count: int, final: Catalogue
) -> None:
    """Check the Trash identities of one cleanup or publish phase."""
    base = directory / phase
    moved = {
        r["catalog"]: r
        for r in json.loads((base / "extraction.json").read_text())["records"]
    }
    require(
        len(moved) == count and set(final) < set(moved),
        "Positive account cleanup inventory differs",
    )
    for identifier, original in final.items():
        check_trashed(directory, base, original, moved[identifier])
    unrelated = [r for i, r in moved.items() if i not in final]
    if phase == "native-cleanup":
        require(
            len(unrelated) == PRIOR_TRASH_OBJECTS
            and all(r["path"].startswith("/Trash/") for r in unrelated),
            "Prior Trash observations differ",
        )
    else:
        require(
            len([
                r for r in unrelated if r["path"] == "/Hotline19/Files/m-au26-publish"
            ])
            == 1,
            "Separate account publisher differs",
        )


def storage(directory: Path) -> None:
    """Check the stored records and the Trash identities of the owned objects."""
    catalogues: dict[str, Catalogue] = {}
    for phase, after, count in [
        ("native-seed", False, SEED_RECORDS),
        ("native-final", True, FINAL_RECORDS),
    ]:
        catalogues[phase] = check_positive_phase(
            directory / phase, after=after, count=count
        )
    before, final = catalogues["native-seed"], catalogues["native-final"]
    require(
        set(before) < set(final)
        and all(final[i]["path"] == r["path"] for i, r in before.items()),
        "Account update changed catalogue identity",
    )
    for phase, count in [
        ("native-cleanup", CLEANUP_RECORDS),
        ("native-published", PUBLISHED_RECORDS),
    ]:
        check_moved_phase(directory, phase, count, final)
