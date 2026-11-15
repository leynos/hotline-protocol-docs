"""Verify the native account files and agreement text of the authentication corpus."""

import json
import typing as typ

from native_auth_cases import ACCOUNTS, KEY32, PASSWORD, complement
from native_wire_names import (
    ACCESS_BITMAP_BYTES,
    ACCOUNT_ACCESS_OFFSET,
    ACCOUNT_LOGIN_LENGTH_OFFSET,
    ACCOUNT_LOGIN_OFFSET,
    ACCOUNT_NAME_LENGTH_OFFSET,
    ACCOUNT_NAME_OFFSET,
    ACCOUNT_PASSWORD_LENGTH_OFFSET,
    ACCOUNT_PASSWORD_OFFSET,
    ACCOUNT_RECORD_BYTES,
)
from verify_native_core import ACCOUNT_VERSION, require

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

STORED_ACCOUNTS = 5  # four owned accounts that fit the key limit, and the guest
GUEST_NAME = b"Auth guest"


def stored_text(data: bytes, length_offset: int, offset: int) -> bytes:
    """Read a stored text field: a BE16 length, then that many bytes.

    Returns
    -------
    bytes
        The field value.
    """
    length = int.from_bytes(data[length_offset:offset], "big")
    return data[offset : offset + length]


def check_account_file(root: Path, record: Report) -> tuple[bytes, bytes]:
    """Check one extracted account file and its recorded path.

    Returns
    -------
    tuple[bytes, bytes]
        The stored login and the whole stored record.
    """
    require(
        record["attributes"]["data"]["exit_code"] == 0,
        "Account data extraction failed",
    )
    data = (root / (record["key"] + ".data")).read_bytes()
    require(
        len(data) == ACCOUNT_RECORD_BYTES
        and data[: len(ACCOUNT_VERSION)] == ACCOUNT_VERSION,
        "Native account record shape differs",
    )
    login = stored_text(data, ACCOUNT_LOGIN_LENGTH_OFFSET, ACCOUNT_LOGIN_OFFSET)
    require(
        "File Path: " + record["path"] + "\n"
        in (root / (record["key"] + ".stat.txt")).read_text()
        and record["path"].endswith("/UserData"),
        "Native account path differs",
    )
    return login, data


def check_stored_account(data: bytes, display: bytes, password: bytes) -> None:
    """Check the stored name and credential of one account."""
    require(
        stored_text(data, ACCOUNT_NAME_LENGTH_OFFSET, ACCOUNT_NAME_OFFSET) == display,
        "Stored account name differs",
    )
    require(
        stored_text(data, ACCOUNT_PASSWORD_LENGTH_OFFSET, ACCOUNT_PASSWORD_OFFSET)
        == complement(password),
        "Stored account credential control differs",
    )


def check_accounts(root: Path) -> None:
    """Check that the stored account records are the canonical, expected ones."""
    extraction = json.loads((root / "extraction.json").read_text())
    files = [r for r in extraction["records"] if not r["directory"]]
    expected = [
        (key, display, privileges, PASSWORD)
        for key, display, privileges in ACCOUNTS
        if key != KEY32
    ] + [(b"guest", GUEST_NAME, bytes(ACCESS_BITMAP_BYTES), b"")]
    require(len(files) == STORED_ACCOUNTS, "Native account snapshot inventory differs")
    found = dict(check_account_file(root, record) for record in files)
    require(
        set(found) == {key for key, _, _, _ in expected},
        "Stored canonical account keys differ",
    )
    for key, display, privileges, password in expected:
        data = found[key]
        require(
            data[ACCOUNT_ACCESS_OFFSET : ACCOUNT_ACCESS_OFFSET + ACCESS_BITMAP_BYTES]
            == privileges,
            "Stored account privileges differ",
        )
        check_stored_account(data, display, password)


def verify_accounts(directory: Path) -> bytes:
    """Verify the account snapshot and read the configured agreement text.

    Returns
    -------
    bytes
        The agreement text, with its line ends as the server sends them.
    """
    check_accounts(directory / "native-accounts")
    root = directory / "native-agreement"
    records = json.loads((root / "extraction.json").read_text())["records"]
    require(
        len(records) == 1
        and records[0]["path"] == "/Hotline19/Agreement.txt"
        and records[0]["attributes"]["data"]["exit_code"] == 0,
        "Native agreement path differs",
    )
    return (root / (records[0]["key"] + ".data")).read_bytes().replace(b"\r\n", b"\r")
