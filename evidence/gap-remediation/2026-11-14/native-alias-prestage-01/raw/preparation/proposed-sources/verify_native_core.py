#!/usr/bin/env python3
"""Verify specific native authentication, error and account-enumeration fixtures."""

import argparse
import json
from pathlib import Path

from protocol_capture import decode_frame, verify_capture


def require(condition: bool, message: str) -> None:
    """Keep checks active even when Python runs with optimization enabled."""
    if not condition:
        raise ValueError(message)


def verify(directory: Path) -> dict:
    """Check retained transcripts against explicit, bounded native observations."""
    reports = {}
    for path in sorted(directory.glob("*/report.json")):
        name = path.parent.name
        report = verify_capture(path.parent)
        require(report["profile"] == "native-mac-oracle", name + ": wrong profile")
        expected = (
            "failed"
            if name in {"wrong-password", "wrong-password-drain"}
            else "completed"
        )
        require(report["status"] == expected, name + ": unexpected capture status")
        reports[name] = report

    def frames(name: str) -> list[dict]:
        return reports[name]["frames"]

    def fields(frame: dict) -> dict[int, bytes]:
        return {f["id"]: bytes.fromhex(f["hex"]) for f in frame["fields"]}

    def requests(name: str) -> list[dict]:
        data = bytes.fromhex(reports[name]["streams"]["main"]["sent_hex"])
        require(
            data[:12] == bytes.fromhex("54525450484f544c00010002"),
            name + ": handshake changed",
        )
        data = data[12:]
        result = []
        while data:
            require(len(data) >= 20, name + ": truncated request")
            size = 20 + int.from_bytes(data[16:20], "big")
            require(len(data) >= size, name + ": truncated payload")
            result.append(decode_frame(data[:size]))
            data = data[size:]
        return result

    complement = lambda value: bytes(x ^ 255 for x in value)
    for name, password in [
        ("created-password-success", complement(b"first-pass")),
        ("low-privilege-and-missing-room", complement(b"next-pass")),
        ("old-password-rejected", complement(b"first-pass")),
        ("plaintext-password-rejected", b"next-pass"),
    ]:
        login = requests(name)[0]
        require(
            login["type"] == 107
            and fields(login)[105] == complement(b"fixture-low")
            and fields(login)[106] == password,
            name + ": credential control changed",
        )
    for name, kind, password in [
        ("create-fixture-account", 350, b"first-pass"),
        ("change-fixture-password", 353, b"next-pass"),
    ]:
        mutation = requests(name)[1]
        require(
            mutation["type"] == kind and fields(mutation)[106] == complement(password),
            name + ": password mutation changed",
        )
    require(
        reports["created-password-success"]["recorded_at_utc"]
        < reports["change-fixture-password"]["recorded_at_utc"]
        < reports["old-password-rejected"]["recorded_at_utc"],
        "Password-change chronology changed",
    )

    def sequence(name: str, expected: list[tuple[int, int, int]]) -> None:
        observed = [(f["is_reply"], f["type"], f["error"]) for f in frames(name)]
        require(observed == expected, name + ": reply/notification sequence changed")

    ack, privilege, agreement, failure = (1, 0, 0), (0, 354, 0), (0, 109, 0), (1, 0, 1)
    sequence(
        "early-login-and-errors",
        [ack, privilege, agreement, ack, ack, failure, failure, failure],
    )
    sequence("delayed-login", [ack, agreement, ack, privilege, ack])
    require(
        [f["id"] for f in frames("early-login-and-errors") if f["is_reply"]]
        == [1, 2, 3, 4, 5, 6],
        "Direct reply correlation changed",
    )
    require(
        fields(frames("early-login-and-errors")[0])
        == {160: b"\x00\xbe", 161: b"\x00\x00"},
        "Observed login extras changed",
    )
    for name in ["created-password-success", "low-privilege-and-missing-room"]:
        require(
            [(f["is_reply"], f["type"], f["error"]) for f in frames(name)[:3]]
            == [ack, privilege, agreement],
            name + ": login did not succeed",
        )
    sequence(
        "low-privilege-and-missing-room",
        [ack, privilege, agreement, failure, failure, ack],
    )
    for name in [
        "old-password-rejected",
        "plaintext-password-rejected",
        "wrong-password",
        "wrong-password-drain",
    ]:
        sequence(name, [failure])
        require(
            fields(frames(name)[0]) == {100: b"Incorrect login."},
            name + ": authentication outcome changed",
        )
    for name in ["create-fixture-account", "change-fixture-password"]:
        require(frames(name)[3]["error"] == 0, name + ": mutation failed")
        # The initial read attempt used complemented352 input and failed. Keep
        # that result rather than silently replacing it with the corrected case.
        require(frames(name)[4]["error"] == 1, name + ": negative352 control changed")
    sequence("missing-file-info", [ack, privilege, agreement, failure])
    malformed = reports["malformed-zero-size"]
    require(
        any(e["event"] == "eof" for e in malformed["events"]),
        "Invalid size did not reach EOF",
    )
    require(len(malformed["frames"]) == 3, "Invalid size unexpectedly produced a reply")
    account_read, enumeration = frames("plain-account-read-and-enumerate")[3:]
    require(account_read["error"] == enumeration["error"] == 0, "Account read failed")
    require(
        fields(account_read)
        == {
            102: b"fixture-low",
            105: bytes(x ^ 255 for x in b"fixture-low"),
            106: b"x",
            110: bytes(8),
        },
        "352 account schema changed",
    )
    accounts = []
    for item in enumeration["fields"]:
        require(item["id"] == 101, "348 outer field changed")
        payload = bytes.fromhex(item["hex"])
        # Use the independently retained count/TLV representation, wrapping it
        # only for the existing physical-frame decoder.
        header = (
            bytes.fromhex("000100000000000000000000")
            + len(payload).to_bytes(4, "big") * 2
        )
        nested = decode_frame(header + payload)
        require(
            not nested["unconsumed_hex"] and nested["declared_field_count"] == 4,
            "348 nested grammar changed",
        )
        value = fields(nested)
        require(
            set(value) == {102, 105, 106, 110}
            and value[106] == b"x"
            and len(value[110]) == 8,
            "348 nested account schema changed",
        )
        accounts.append(bytes(x ^ 255 for x in value[105]).decode("ascii"))
    require(
        sorted(accounts) == ["admin", "fixture-low"], "348 account membership changed"
    )
    record = (directory / "fixture-account-after-update.bin").read_bytes()
    require(
        len(record) == 734 and record[:2] == b"\0\1", "Account record identity changed"
    )
    require(
        record[0x2BC:0x2BE] == b"\0\x09"
        and record[0x2BE:0x2C7] == bytes(x ^ 255 for x in b"next-pass"),
        "Stored nonempty password changed",
    )
    for name, expected in [
        ("account111-absent", b""),
        ("account111-empty", b""),
        ("account111-value", b"opaque-c"),
    ]:
        data = (directory / name / "UserData.bin").read_bytes()
        length = int.from_bytes(data[0x254:0x256], "big")
        require(
            len(data) == 734 and data[0x256 : 0x256 + length] == expected,
            name + ": stored111 changed",
        )
        require(
            111 not in fields(frames(name)[4]), name + ": 352 unexpectedly returned111"
        )
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
        "scope": "These fixtures only; no universal interoperability or timing certificate",
    }


def main() -> None:
    """Verify an immutable native-core fixture directory."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == "__main__":
    main()
