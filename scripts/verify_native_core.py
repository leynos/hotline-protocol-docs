#!/usr/bin/env python3
"""Verify specific native authentication, error and account-enumeration fixtures."""

import json
import typing as typ
from pathlib import Path

from native_wire_names import (
    ACCOUNT_ATTRIBUTE_LENGTH_OFFSET,
    ACCOUNT_ATTRIBUTE_OFFSET,
    ACCOUNT_PASSWORD_LENGTH_OFFSET,
    ACCOUNT_PASSWORD_OFFSET,
    ACCOUNT_RECORD_BYTES,
    FIELD_ACCESS_BITMAP,
    FIELD_ACCOUNT_ATTRIBUTE,
    FIELD_DATA,
    FIELD_ERROR_TEXT,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    FIELD_UNNAMED_WORD,
    FIELD_VERSION,
    FRAME_HEADER_BYTES,
    FRAME_SIZE_START,
    HANDSHAKE_REQUEST_HEX,
    TYPE_CREATE_ACCOUNT,
    TYPE_LOGIN,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRIVILEGES_NOTIFICATION,
    TYPE_UPDATE_ACCOUNT,
)
from protocol_capture import decode_frame, verify_capture
from script_cli import run

type Report = dict[str, typ.Any]
type Reports = dict[str, Report]
type Shapes = list[tuple[int, int, int]]  # (is_reply, type, error) per frame

COMPLEMENT_MASK = 0xFF
ACCOUNT_VERSION = b"\0\1"  # the stored record's leading BE16 version
# A reply header with a zero ID and error, up to the two BE32 size words.
REPLY_HEADER_PREFIX = bytes.fromhex("000100000000000000000000")
NESTED_ACCOUNT_FIELDS = 4  # name, login, password and access bitmap
ACCESS_BITMAP_BYTES = 8
FIXTURE_VERSION_REPLY = b"\x00\xbe"  # 190, as a successful login reports
FIXTURE_UNNAMED_WORD_REPLY = b"\x00\x00"
EARLY_LOGIN_REPLY_IDS = [1, 2, 3, 4, 5, 6]
MALFORMED_SIZE_FRAMES = 3  # the early login's three, and no reply to the bad size
NESTED_ACCOUNT_PLACEHOLDER = b"x"  # a password-presence placeholder, not a password
ENUMERATION_FIRST_FRAME = 3  # after the three login frames

# Each tuple is (is_reply, type, error) for one received frame.
ACK = (1, 0, 0)
PRIVILEGES = (0, TYPE_PRIVILEGES_NOTIFICATION, 0)
AGREEMENT = (0, TYPE_LOGIN_AGREEMENT, 0)
FAILURE = (1, 0, 1)
LOGIN_FRAMES = [ACK, PRIVILEGES, AGREEMENT]
FAILED_CAPTURES = {"wrong-password", "wrong-password-drain"}
NEGATIVE_LOGINS = ["wrong-password", "wrong-password-drain"]
REJECTED_LOGINS = ["old-password-rejected", "plaintext-password-rejected"]
MUTATION_REPLY_FRAME = 3  # the account write's reply follows the login frames
ACCOUNT_READ_FRAME = 4  # then the 352 reply (the first, complemented read failed)
STORED_111_CASES = [
    ("account111-absent", b""),
    ("account111-empty", b""),
    ("account111-value", b"opaque-c"),
]


def require(
    condition: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the public check shape
    message: str,
) -> None:
    """Keep checks active even when Python runs with optimization enabled.

    Raises
    ------
    ValueError
        With ``message``, when ``condition`` is false.
    """
    if not condition:
        raise ValueError(message)


def complement(value: bytes) -> bytes:
    """Return the byte complement in which logins and passwords are sent.

    Returns
    -------
    bytes
        ``value`` with every byte XORed with 255.
    """
    return bytes(x ^ COMPLEMENT_MASK for x in value)


def fields(frame: Report) -> dict[int, bytes]:
    """Map the field IDs of a decoded frame to their values.

    Returns
    -------
    dict[int, bytes]
        Each field's bytes, by ID.
    """
    return {f["id"]: bytes.fromhex(f["hex"]) for f in frame["fields"]}


def frames(reports: Reports, name: str) -> list[Report]:
    """List the decoded frames the named transcript received.

    Returns
    -------
    list[dict[str, typing.Any]]
        The frames, in order.
    """
    return reports[name]["frames"]


def requests(reports: Reports, name: str) -> list[Report]:
    """Decode every request the named transcript sent after its handshake.

    Returns
    -------
    list[dict[str, typing.Any]]
        The decoded requests, in order.
    """
    data = bytes.fromhex(reports[name]["streams"]["main"]["sent_hex"])
    handshake = bytes.fromhex(HANDSHAKE_REQUEST_HEX)
    require(data[: len(handshake)] == handshake, name + ": handshake changed")
    data = data[len(handshake) :]
    result = []
    while data:
        require(len(data) >= FRAME_HEADER_BYTES, name + ": truncated request")
        size = FRAME_HEADER_BYTES + int.from_bytes(
            data[FRAME_SIZE_START:FRAME_HEADER_BYTES], "big"
        )
        require(len(data) >= size, name + ": truncated payload")
        result.append(decode_frame(data[:size]))
        data = data[size:]
    return result


def sequence(reports: Reports, name: str, expected: Shapes) -> None:
    """Require the named transcript's frames to have the expected shapes."""
    observed = [(f["is_reply"], f["type"], f["error"]) for f in frames(reports, name)]
    require(observed == expected, name + ": reply/notification sequence changed")


def load_reports(directory: Path) -> Reports:
    """Verify every retained transcript and key its report by directory name.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        The reports, in sorted directory order.
    """
    reports = {}
    for path in sorted(directory.glob("*/report.json")):
        name = path.parent.name
        report = verify_capture(path.parent)
        require(report["profile"] == "native-mac-oracle", name + ": wrong profile")
        expected = "failed" if name in FAILED_CAPTURES else "completed"
        require(report["status"] == expected, name + ": unexpected capture status")
        reports[name] = report
    return reports


def check_credentials(reports: Reports) -> None:
    """Check the logins and the password mutations the transcripts sent."""
    for name, password in [
        ("created-password-success", complement(b"first-pass")),
        ("low-privilege-and-missing-room", complement(b"next-pass")),
        ("old-password-rejected", complement(b"first-pass")),
        ("plaintext-password-rejected", b"next-pass"),
    ]:
        login = requests(reports, name)[0]
        require(
            login["type"] == TYPE_LOGIN
            and fields(login)[FIELD_LOGIN] == complement(b"fixture-low")
            and fields(login)[FIELD_PASSWORD] == password,
            name + ": credential control changed",
        )
    for name, kind, password in [
        ("create-fixture-account", TYPE_CREATE_ACCOUNT, b"first-pass"),
        ("change-fixture-password", TYPE_UPDATE_ACCOUNT, b"next-pass"),
    ]:
        mutation = requests(reports, name)[1]
        require(
            mutation["type"] == kind
            and fields(mutation)[FIELD_PASSWORD] == complement(password),
            name + ": password mutation changed",
        )
    require(
        reports["created-password-success"]["recorded_at_utc"]
        < reports["change-fixture-password"]["recorded_at_utc"]
        < reports["old-password-rejected"]["recorded_at_utc"],
        "Password-change chronology changed",
    )


def check_login_replies(reports: Reports) -> None:
    """Check the reply and notification shapes of the login transcripts."""
    sequence(
        reports,
        "early-login-and-errors",
        [*LOGIN_FRAMES, ACK, ACK, FAILURE, FAILURE, FAILURE],
    )
    sequence(reports, "delayed-login", [ACK, AGREEMENT, ACK, PRIVILEGES, ACK])
    early = frames(reports, "early-login-and-errors")
    require(
        [f["id"] for f in early if f["is_reply"]] == EARLY_LOGIN_REPLY_IDS,
        "Direct reply correlation changed",
    )
    require(
        fields(early[0])
        == {
            FIELD_VERSION: FIXTURE_VERSION_REPLY,
            FIELD_UNNAMED_WORD: FIXTURE_UNNAMED_WORD_REPLY,
        },
        "Observed login extras changed",
    )
    for name in ["created-password-success", "low-privilege-and-missing-room"]:
        shapes = [
            (f["is_reply"], f["type"], f["error"])
            for f in frames(reports, name)[: len(LOGIN_FRAMES)]
        ]
        require(shapes == LOGIN_FRAMES, name + ": login did not succeed")
    sequence(
        reports,
        "low-privilege-and-missing-room",
        [*LOGIN_FRAMES, FAILURE, FAILURE, ACK],
    )


def check_failures(reports: Reports) -> None:
    """Check the rejected logins, the mutations and the malformed request."""
    for name in [*REJECTED_LOGINS, *NEGATIVE_LOGINS]:
        sequence(reports, name, [FAILURE])
        require(
            fields(frames(reports, name)[0]) == {FIELD_ERROR_TEXT: b"Incorrect login."},
            name + ": authentication outcome changed",
        )
    for name in ["create-fixture-account", "change-fixture-password"]:
        replies = frames(reports, name)
        require(replies[MUTATION_REPLY_FRAME]["error"] == 0, name + ": mutation failed")
        # The initial read attempt used complemented352 input and failed. Keep
        # that result rather than silently replacing it with the corrected case.
        require(
            replies[ACCOUNT_READ_FRAME]["error"] == 1,
            name + ": negative352 control changed",
        )
    sequence(reports, "missing-file-info", [*LOGIN_FRAMES, FAILURE])
    malformed = reports["malformed-zero-size"]
    require(
        any(e["event"] == "eof" for e in malformed["events"]),
        "Invalid size did not reach EOF",
    )
    require(
        len(malformed["frames"]) == MALFORMED_SIZE_FRAMES,
        "Invalid size unexpectedly produced a reply",
    )


def nested_account(item: Report) -> str:
    """Decode one enumerated account record and return its login name.

    Returns
    -------
    str
        The account's login, uncomplemented.
    """
    require(item["id"] == FIELD_DATA, "348 outer field changed")
    payload = bytes.fromhex(item["hex"])
    # Use the independently retained count/TLV representation, wrapping it
    # only for the existing physical-frame decoder.
    header = REPLY_HEADER_PREFIX + len(payload).to_bytes(4, "big") * 2
    nested = decode_frame(header + payload)
    require(
        not nested["unconsumed_hex"]
        and nested["declared_field_count"] == NESTED_ACCOUNT_FIELDS,
        "348 nested grammar changed",
    )
    value = fields(nested)
    require(
        set(value) == {FIELD_NAME, FIELD_LOGIN, FIELD_PASSWORD, FIELD_ACCESS_BITMAP}
        and value[FIELD_PASSWORD] == NESTED_ACCOUNT_PLACEHOLDER
        and len(value[FIELD_ACCESS_BITMAP]) == ACCESS_BITMAP_BYTES,
        "348 nested account schema changed",
    )
    return complement(value[FIELD_LOGIN]).decode("ascii")


def check_accounts(reports: Reports) -> None:
    """Check the plain 352 lookup and the 348 enumeration."""
    account_read, enumeration = frames(reports, "plain-account-read-and-enumerate")[
        ENUMERATION_FIRST_FRAME:
    ]
    require(account_read["error"] == enumeration["error"] == 0, "Account read failed")
    require(
        fields(account_read)
        == {
            FIELD_NAME: b"fixture-low",
            FIELD_LOGIN: complement(b"fixture-low"),
            FIELD_PASSWORD: NESTED_ACCOUNT_PLACEHOLDER,
            FIELD_ACCESS_BITMAP: bytes(ACCESS_BITMAP_BYTES),
        },
        "352 account schema changed",
    )
    accounts = [nested_account(item) for item in enumeration["fields"]]
    require(
        sorted(accounts) == ["admin", "fixture-low"], "348 account membership changed"
    )


def check_stored_records(directory: Path, reports: Reports) -> None:
    """Check the stored password record and the opaque 111 storage cases."""
    record = (directory / "fixture-account-after-update.bin").read_bytes()
    require(
        len(record) == ACCOUNT_RECORD_BYTES and record[:2] == ACCOUNT_VERSION,
        "Account record identity changed",
    )
    stored = b"next-pass"
    password_end = ACCOUNT_PASSWORD_OFFSET + len(stored)
    require(
        record[ACCOUNT_PASSWORD_LENGTH_OFFSET:ACCOUNT_PASSWORD_OFFSET]
        == len(stored).to_bytes(2, "big")
        and record[ACCOUNT_PASSWORD_OFFSET:password_end] == complement(stored),
        "Stored nonempty password changed",
    )
    for name, expected in STORED_111_CASES:
        data = (directory / name / "UserData.bin").read_bytes()
        length = int.from_bytes(
            data[ACCOUNT_ATTRIBUTE_LENGTH_OFFSET:ACCOUNT_ATTRIBUTE_OFFSET], "big"
        )
        require(
            len(data) == ACCOUNT_RECORD_BYTES
            and data[ACCOUNT_ATTRIBUTE_OFFSET : ACCOUNT_ATTRIBUTE_OFFSET + length]
            == expected,
            name + ": stored111 changed",
        )
        require(
            FIELD_ACCOUNT_ATTRIBUTE
            not in fields(frames(reports, name)[ACCOUNT_READ_FRAME]),
            name + ": 352 unexpectedly returned111",
        )


def verify(directory: Path) -> dict[str, typ.Any]:
    """Check retained transcripts against explicit, bounded native observations.

    Returns
    -------
    dict[str, typing.Any]
        The transcript count, the names of the checks and their scope.
    """
    reports = load_reports(directory)
    check_credentials(reports)
    check_login_replies(reports)
    check_failures(reports)
    check_accounts(reports)
    check_stored_records(directory, reports)
    return {
        "transcripts": len(reports),
        "checks": [
            "nonempty-password-create-change-login",
            "complement-vs-plaintext-negative",
            "early-and-delayed-login",
            "representative-errors-and-invalid-size-close",
            "plain352-lookup",
            "348-nested-success-and-permission-denial",
            "opaque111-absent-empty-value-storage",
        ],
        "scope": (
            "These fixtures only; no universal interoperability or timing certificate"
        ),
    }


def show(directory: str) -> None:
    """Verify a native-core fixture directory and print its summary as JSON."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify an immutable native-core fixture directory."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
