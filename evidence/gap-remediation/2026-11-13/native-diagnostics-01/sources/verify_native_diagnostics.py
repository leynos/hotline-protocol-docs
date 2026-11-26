#!/usr/bin/env python3
"""Verify bounded 303 diagnostic examples against recorded native identities."""

import argparse
import json
from pathlib import Path

import native_diagnostic_cases as cases
from native_auth_cases import complement
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, decode_frame, verify_capture
from verify_native_account_updates import enumeration
from verify_native_auth import reply, roster, selected
from verify_native_core import require
from verify_native_shx import fields, sha

NAMES = ("preflight", "seed", "observe", "self", "cleanup")
DENIED = b"You are not allowed to get client information."
MISSING = b"Cannot get info for the specified client because it does not exist."
EMPTY_SECTIONS = (
    b"\r\r-------- File Downloads ---------\r\rNone.\r"
    b"\r------- Folder Downloads --------\r\rNone.\r"
    b"\r--------- File Uploads ----------\r\rNone.\r"
    b"\r-------- Folder Uploads ---------\r\rNone.\r"
    b"\r------- Waiting Downloads -------\r\rNone.\r"
)


def diagnostic_text(nickname: bytes, name: bytes, account: bytes) -> bytes:
    """A measured display snapshot, not a release parity requirement."""
    return (
        b"Nickname:   "
        + nickname
        + b"\rName:       "
        + name
        + b"\rAccount:    "
        + account
        + b"\rAddress:    10.0.2.2"
        + EMPTY_SECTIONS
    )


def sent(report: dict, kind: int, identifier: int, connection: str = "main") -> dict:
    """Return the single request of the given type and identifier that the report sent on a connection."""
    matches = [
        decode_frame(bytes.fromhex(event["hex"]))
        for event in report["events"]
        if event["event"] == "send"
        and event["connection"] == connection
        and len(bytes.fromhex(event["hex"])) >= 20
        and event["hex"][:8] != "54525450"
    ]
    matches = [f for f in matches if f["type"] == kind and f["id"] == identifier]
    require(len(matches) == 1, "Missing/duplicate diagnostic request")
    return matches[0]


def uid_field(frame: dict) -> bytes:
    """Return the two-byte user identifier of a diagnostic request."""
    values = fields(frame)
    require(set(values) == {103} and len(values[103]) == 2, "303 UID shape differs")
    return values[103]


def success(frame: dict, nickname: bytes, name: bytes, account: bytes) -> None:
    """Require a successful diagnostic reply with the expected text and nickname."""
    actual = fields(frame)
    expected = diagnostic_text(nickname, name, account)
    require(
        frame["type"] == 0
        and frame["error"] == 0
        and actual == {101: expected, 102: nickname},
        "303 success fields/bytes differ",
    )
    require(0x8E in expected if account == cases.KEY else True, "High byte lost")
    require(len(actual[101]) < 1024, "303 measured text exceeds source cap")


def failure(frame: dict, text: bytes) -> None:
    """Require a failed diagnostic reply with the expected text."""
    require(
        frame["type"] == 0 and frame["error"] == 1 and fields(frame) == {100: text},
        "303 failure fields/status differ",
    )


def semantic(reports: dict[str, dict]) -> dict:
    """Check provenance-sensitive 303 meanings independently of file hashes."""
    preflight, seed, observe, self_report, cleanup = (reports[name] for name in NAMES)
    baseline = enumeration(reply(preflight, 10))
    require(len(baseline) == 2, "Preflight account inventory differs")
    require(reply(preflight, 11)["error"] == 1, "Owned account existed before seed")
    first_roster = roster(reply(preflight, 12))
    require(
        len(first_roster) == 1
        and first_roster[0]["name_hex"] == b"framing-fixture".hex(),
        "Preflight admin roster ambiguous",
    )
    require(
        reply(seed, 10)["error"] == 0
        and fields(reply(seed, 11))
        == {
            102: cases.NAME,
            105: complement(cases.KEY),
            106: b"x",
            110: cases.ACCESS,
        },
        "Owned zero-access account seed differs",
    )
    require(
        fields(next(f for f in selected(observe, "zero") if f["type"] == 354))
        == {110: cases.ACCESS},
        "Subject effective privilege differs",
    )
    joined = [
        fields(f)
        for f in selected(observe, "main")
        if f["type"] == 301 and not f["is_reply"]
    ]
    require(
        len(joined) == 1 and joined[0].get(102) == cases.NAME,
        "Owned subject notification ambiguous",
    )
    target = joined[0][103]
    require(len(target) == 2, "Owned subject UID width differs")
    current = roster(reply(observe, 20))
    require(
        len(current) == 2
        and sum(row["name_hex"] == cases.NAME.hex() for row in current) == 1
        and any(row["uid"] == int.from_bytes(target, "big") for row in current),
        "Current owned subject identity differs",
    )
    current_admin = next(
        row["uid"] for row in current if row["name_hex"] != cases.NAME.hex()
    )
    ordered = [
        (frame["connection"], frame["id"])
        for frame in observe["frames"]
        if frame["type"] == 0
        and frame["is_reply"]
        and frame["id"] in {10, 11, 12, 13, 20}
    ]
    require(
        ordered
        == [("main", 10), ("zero", 11), ("main", 12), ("main", 13), ("main", 20)],
        "Diagnostic reply order differs",
    )
    require(
        uid_field(sent(observe, 303, 10)) == target,
        "Allowed 303 targeted another session",
    )
    success(reply(observe, 10), cases.NAME, cases.NAME, cases.KEY)
    require(
        uid_field(sent(observe, 303, 11, "zero")) == target, "Denied target differs"
    )
    failure(reply(observe, 11, "zero"), DENIED)
    require(
        uid_field(sent(observe, 303, 12)) == b"\xff\xff", "Missing UID control differs"
    )
    failure(reply(observe, 12), MISSING)
    stale = uid_field(sent(observe, 303, 13))
    require(
        stale == first_roster[0]["uid"].to_bytes(2, "big")
        and stale != current_admin.to_bytes(2, "big"),
        "Prior-session UID was relabelled current",
    )
    failure(reply(observe, 13), MISSING)
    own_rows = roster(reply(self_report, 10))
    require(
        len(own_rows) == 1 and own_rows[0]["name_hex"] == b"framing-fixture".hex(),
        "Same-connection self roster ambiguous",
    )
    own_uid = own_rows[0]["uid"].to_bytes(2, "big")
    require(uid_field(sent(self_report, 303, 11)) == own_uid, "Self 303 UID differs")
    success(reply(self_report, 11), b"framing-fixture", b"administrator", b"admin")
    require(
        reply(cleanup, 10)["error"] == 0
        and reply(cleanup, 11)["error"] == 1
        and enumeration(reply(cleanup, 12)) == baseline,
        "Owned account cleanup/baseline differs",
    )
    return {
        "subject_uid_hex": target.hex(),
        "current_admin_uid_hex": current_admin.to_bytes(2, "big").hex(),
        "stale_uid_hex": stale.hex(),
        "self_uid_hex": own_uid.hex(),
        "subject_text_bytes": len(fields(reply(observe, 10))[101]),
        "self_text_bytes": len(fields(reply(self_report, 11))[101]),
    }


def verify(directory: Path) -> dict:
    """Verify the diagnostic corpus (reports, runtime identity, packet captures and unread tails) and return the summary."""
    manifest = json.loads((directory / "manifest.json").read_text())
    require(
        manifest["reports"] == list(NAMES)
        and {p.parent.name for p in directory.glob("*/report.json")} == set(NAMES),
        "Diagnostic report inventory differs",
    )
    runtime = json.loads((directory / "runtime.json").read_text())
    require(
        runtime["emulator_pid"] == 1259319
        and runtime["running_executable_sha256"]
        == "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4",
        "Diagnostic runtime identity differs",
    )
    tails = json.loads((directory / "unread-tails.json").read_text())
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == 125
        and "0 packets dropped by kernel"
        in (directory / "host-capture-statistics.txt").read_text(),
        "Diagnostic host capture count/drop differs",
    )
    reports = {}
    paired = 0
    for name in NAMES:
        path = directory / name
        report = verify_capture(path)
        plan = json.loads((path / "plan.json").read_text())
        require(
            report["status"] == "completed"
            and report["profile"] == "native-mac-oracle"
            and report["oracle_sha256"] == ORACLE_SHA256
            and plan["environment"] == runtime
            and report["driver_sha256"] == manifest["driver_sha256"],
            "Diagnostic oracle/plan identity differs",
        )
        view_tails = tails.get(name, {})
        observations = reconcile(
            report,
            host,
            guest,
            unread_output={
                k: bytes.fromhex(v) for k, v in view_tails.get("host", {}).items()
            },
            guest_unread_output={
                k: bytes.fromhex(v) for k, v in view_tails.get("guest", {}).items()
            },
        )
        paired += len(observations)
        reports[name] = report
    tail = bytes.fromhex(tails["observe"]["host"]["main"])
    require(
        tails["observe"]["guest"]["main"] == tail.hex()
        and decode_frame(tail)["type"] == 302
        and decode_frame(tail)["fields"] == [{"id": 103, "hex": "0090"}],
        "Unread owned departure tail differs",
    )
    result = semantic(reports)
    require(paired == 6, "Diagnostic paired lifetime count differs")
    require(
        sha(directory / "sources/native_diagnostic_cases.initial.py.txt")
        == manifest["initial_generator_sha256"],
        "Initial generated plan source differs",
    )
    return {"completed_reports": len(reports), "paired_connections": paired, **result}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    print(json.dumps(verify(parser.parse_args().directory), indent=2))
