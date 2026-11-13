#!/usr/bin/env python3
"""Verify native account normalization, guest phases and configured login states."""

import argparse
import hashlib
import json
from pathlib import Path

from native_auth_cases import (
    ACCOUNTS,
    KEY32,
    PASSWORD,
    cleanup,
    complement,
    guest_create,
    lookup,
    reauthentication,
    seed,
    states,
)
from native_banner_cases import URL
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, decode_frame, verify_capture
from verify_native_banners import fields
from verify_native_core import require
from verify_native_framing import check_quiet

ADMIN = bytes.fromhex("fff3cfefff800000")
BYPASS = bytes.fromhex("0000003000000000")


def cases() -> dict:
    return (
        seed()
        | lookup(missing_guest=True)
        | guest_create()
        | lookup()
        | states()
        | reauthentication()
        | cleanup()
    )


def selected(report: dict, connection: str) -> list[dict]:
    return [f for f in report["frames"] if f["connection"] == connection]


def reply(report: dict, identifier: int, connection: str = "main") -> dict:
    matches = [
        f
        for f in selected(report, connection)
        if f["is_reply"] and f["id"] == identifier
    ]
    require(len(matches) == 1, "Missing/duplicate auth reply")
    return matches[0]


def roster(frame: dict) -> list[dict]:
    records = []
    for item in frame["fields"]:
        require(item["id"] == 300, "Unexpected roster parameter")
        raw = bytes.fromhex(item["hex"])
        require(
            len(raw) >= 8 and len(raw) == 8 + int.from_bytes(raw[6:8], "big"),
            "Roster record boundary differs",
        )
        records.append(
            {
                "uid": int.from_bytes(raw[:2], "big"),
                "icon": int.from_bytes(raw[2:4], "big"),
                "name_hex": raw[8:].hex(),
            }
        )
    require(len({r["uid"] for r in records}) == len(records), "Duplicate roster UID")
    return records


def check_lookup(report: dict, expected: dict, agreement: bytes) -> None:
    frames = report["frames"]
    if expected["success"]:
        require(
            [(f["type"], f["is_reply"], f["error"]) for f in frames]
            == [(0, 1, 0), (354, 0, 0), (109, 0, 0)],
            "Lookup success sequence differs",
        )
        require(
            fields(frames[0]) == {160: b"\0\xbe", 161: b"\0\0"},
            "Lookup login extras differ",
        )
        key = (
            bytes.fromhex(expected["key_hex"])
            if expected["key_hex"] is not None
            else b""
        )
        require(
            fields(frames[1]) == {110: ADMIN if key.lower() == b"admin" else bytes(8)},
            "Lookup effective privileges differ",
        )
        require(fields(frames[2]) == {101: agreement}, "Lookup agreement differs")
    else:
        key = (
            bytes.fromhex(expected["key_hex"])
            if expected["key_hex"] is not None
            else b""
        )
        text = (
            (
                b"Cannot read account \xd2"
                + KEY32
                + b"\xd3:\rA bad file or folder name was specified.\rID 4/119 [-37]"
            )
            if len(key) >= 32
            else b"Incorrect login."
        )
        require(
            len(frames) == 1
            and frames[0]["error"] == 1
            and frames[0]["is_reply"] == 1
            and fields(frames[0]) == {100: text},
            "Lookup failure/fallback differs",
        )


def check_state(name: str, report: dict, expected: dict, agreement: bytes) -> dict:
    subject = selected(report, "subject")
    views = {
        f["id"]: roster(f)
        for f in selected(report, "observer")
        if f["is_reply"] and f["id"] >= 10
    }
    require(
        all(f["error"] == 0 for f in selected(report, "observer") if f["is_reply"]),
        "Observer request failed",
    )
    require(len(views[10]) == 1, "Observer baseline visibility differs")
    observer_uid = views[10][0]["uid"]
    require(
        all(
            any(r["uid"] == observer_uid for r in records) for records in views.values()
        ),
        "Observer disappeared from roster",
    )
    updates = [f for f in selected(report, "observer") if f["type"] == 301]
    departures = [f for f in selected(report, "observer") if f["type"] == 302]
    if expected["kind"] == "login-state":
        early = expected["early"]
        shape = (
            [(0, 1, 0), (354, 0, 0), (109, 0, 0)]
            if early
            else [
                (0, 1, 0),
                (109, 0, 0),
                (0, 1, 0),
                (354, 0, 0),
                (122, 0, 0),
                (0, 1, 0),
            ]
        )
        shape += [(0, 1, 1), (0, 1, 1), (0, 1, 0)]
        require(
            [(f["type"], f["is_reply"], f["error"]) for f in subject] == shape,
            "Login state sequence differs",
        )
        require(
            [f["id"] for f in subject if f["is_reply"]]
            == ([1, 3, 4, 91] if early else [1, 2, 90, 3, 4, 91]),
            "Login state reply correlation differs",
        )
        require(
            fields(reply(report, 1, "subject")) == {160: b"\0\xbe", 161: b"\0\0"},
            "State login extras differ",
        )
        notice = next(f for f in subject if f["type"] == 109)
        require(
            fields(notice)
            == ({154: b"\0\1"} if expected["bypass"] else {101: agreement}),
            "Agreement bypass contents differ",
        )
        access = next(f for f in subject if f["type"] == 354)
        require(
            fields(access) == {110: BYPASS if expected["bypass"] else ADMIN},
            "State privilege bitmap differs",
        )
        if not early:
            banner = next(f for f in subject if f["type"] == 122)
            require(
                fields(banner) == {152: b"GIFf", 153: URL}, "Delayed banner differs"
            )
        for identifier in [3, 4]:
            require(
                fields(reply(report, identifier, "subject"))
                == {100: b"Unknown transaction type!"},
                "Online replay outcome differs",
            )
        require(
            [len(views[i]) for i in [10, 11, 12, 13, 14]]
            == [1, 1, 2 if early else 1, 2, 1],
            "Login visibility transition differs",
        )
        require(
            len(updates) == len(departures) == 1,
            "Login observer notification count differs",
        )
        uid = int.from_bytes(fields(updates[0])[103], "big")
        record = next(r for r in views[13] if r["uid"] == uid)
        require(
            record["icon"] == expected["icon"]
            and record["name_hex"]
            == (b"auth-visible" if early else b"auth-completed").hex(),
            "Visible identity differs",
        )
        require(
            int.from_bytes(fields(departures[0])[103], "big") == uid,
            "Departure UID differs",
        )
    elif expected["kind"] == "reauthentication" and not expected["preauth_acceptance"]:
        require(
            [(f["type"], f["is_reply"], f["error"]) for f in subject]
            == [(0, 1, 0), (109, 0, 0), (0, 1, 0), (354, 0, 0), (109, 0, 0)],
            "Waiting-state repeated login differs",
        )
        require(
            [len(views[i]) for i in [10, 11, 12, 13]] == [1, 1, 2, 2],
            "Repeated-login post-close snapshot differs",
        )
        require(
            len(updates) == 1 and not departures,
            "Repeated-login app-read notifications differ",
        )
    else:
        require(
            len(subject) == 1 and subject[0]["error"] == 1,
            "Preauth failure/retry silence differs",
        )
        require(
            all(len(v) == 1 for v in views.values()) and not updates,
            "Failed session became visible",
        )
        require(len(departures) == 1, "Missing unlisted-session departure")
        uid = int.from_bytes(fields(departures[0])[103], "big")
        require(
            all(uid not in {r["uid"] for r in v} for v in views.values()),
            "Failed session UID appeared in roster",
        )
    return {
        "case": name,
        "rosters": views,
        "observer_updates": len(updates),
        "read_departures": len(departures),
    }


def verify_accounts(directory: Path) -> bytes:
    root = directory / "native-accounts"
    extraction = json.loads((root / "extraction.json").read_text())
    files = [r for r in extraction["records"] if not r["directory"]]
    expected = [
        (key, display, privileges, PASSWORD)
        for key, display, privileges in ACCOUNTS
        if key != KEY32
    ] + [(b"guest", b"Auth guest", bytes(8), b"")]
    require(len(files) == 5, "Native account snapshot inventory differs")
    found = {}
    for record in files:
        require(
            record["attributes"]["data"]["exit_code"] == 0,
            "Account data extraction failed",
        )
        data = (root / (record["key"] + ".data")).read_bytes()
        require(
            len(data) == 734 and data[:2] == b"\0\1",
            "Native account record shape differs",
        )
        length = int.from_bytes(data[0x298:0x29A], "big")
        found[data[0x29A : 0x29A + length]] = data
        require(
            "File Path: " + record["path"] + "\n"
            in (root / (record["key"] + ".stat.txt")).read_text()
            and record["path"].endswith("/UserData"),
            "Native account path differs",
        )
    require(
        set(found) == {key for key, _, _, _ in expected},
        "Stored canonical account keys differ",
    )
    for key, display, privileges, password in expected:
        data = found[key]
        require(data[4:12] == privileges, "Stored account privileges differ")
        length = int.from_bytes(data[0x210:0x212], "big")
        require(data[0x212 : 0x212 + length] == display, "Stored account name differs")
        length = int.from_bytes(data[0x2BC:0x2BE], "big")
        require(
            data[0x2BE : 0x2BE + length] == complement(password),
            "Stored account credential control differs",
        )
    root = directory / "native-agreement"
    records = json.loads((root / "extraction.json").read_text())["records"]
    require(
        len(records) == 1
        and records[0]["path"] == "/Hotline19/Agreement.txt"
        and records[0]["attributes"]["data"]["exit_code"] == 0,
        "Native agreement path differs",
    )
    return (root / (records[0]["key"] + ".data")).read_bytes().replace(b"\r\n", b"\r")


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    expected = cases()
    require(
        set(manifest["cases"]) == set(expected) and len(expected) == 33,
        "Auth case inventory differs",
    )
    require(manifest["oracle_sha256"] == ORACLE_SHA256, "Auth oracle differs")
    agreement = verify_accounts(directory)
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    packets, reports, results = {}, {}, []
    driver = hashlib.sha256(
        (directory / "protocol_capture.py.as-run.txt").read_bytes()
    ).hexdigest()
    for name, (steps, expectation) in expected.items():
        path = directory / "transcripts" / name
        plan = json.loads((path / "plan.json").read_text())
        require(
            plan["steps"] == steps and plan["expectation"] == expectation,
            "Auth plan differs",
        )
        report = reports[name] = verify_capture(path)
        require(
            report["status"] == "completed" and report["driver_sha256"] == driver,
            "Auth capture status/source differs",
        )
        for connection, stream in report["streams"].items():
            require(
                stream["sent_hex"]
                == "".join(
                    step["hex"]
                    for step in steps
                    if step["op"] == "send" and step["connection"] == connection
                ),
                "Physical auth input differs",
            )
        packets[name] = reconcile(
            report,
            host,
            guest,
            {
                k: bytes.fromhex(v)
                for k, v in manifest["unread_output"].get(name, {}).items()
            },
        )
        check_quiet(report, plan)
        kind = expectation["kind"]
        if kind == "lookup":
            check_lookup(report, expectation, agreement)
        elif kind in {
            "login-state",
            "preauth-acceptance",
            "failed-password-acceptance",
            "reauthentication",
        }:
            results.append(check_state(name, report, expectation, agreement))
        elif kind == "account-seed":
            require(reply(report, 9)["error"] == 1, "Original guest was not absent")
            for identifier in range(10, 15):
                require(
                    reply(report, identifier)["error"] == (1 if identifier == 13 else 0)
                    and reply(report, identifier + 10)["error"]
                    == (1 if identifier == 13 else 0),
                    "Native account length/setup outcomes differ",
                )
        elif kind == "guest-create":
            require(
                reply(report, 10)["error"] == reply(report, 11)["error"] == 0
                and fields(reply(report, 11))[110] == bytes(8)
                and 106 not in fields(reply(report, 11)),
                "Temporary guest control differs",
            )
        elif kind == "account-cleanup":
            require(
                all(
                    reply(report, i)["error"] == 0
                    and reply(report, i + 10)["error"] == 1
                    for i in range(10, 15)
                ),
                "Owned account cleanup not verified",
            )
    require(
        set(manifest["initial_cases"])
        == {"login-after-premature-acceptance", "repeated-login-before-acceptance"},
        "Exploratory auth inventory differs",
    )
    for name in manifest["initial_cases"]:
        key = "initial/" + name
        report = verify_capture(directory / "initial" / name)
        require(
            report["status"]
            == (
                "failed" if name == "login-after-premature-acceptance" else "completed"
            ),
            "Initial recovery/overlap outcome differs",
        )
        packets[key] = reconcile(
            report,
            host,
            guest,
            {
                k: bytes.fromhex(v)
                for k, v in manifest["unread_output"].get(key, {}).items()
            },
        )
    tail = bytes.fromhex(
        manifest["unread_output"]["repeated-login-before-acceptance"]["observer"]
    )
    note = decode_frame(tail)
    require(
        note["type"] == 302 and note["is_reply"] == 0,
        "Unread delayed departure differs",
    )
    uid = int.from_bytes(fields(note)[103], "big")
    final_roster = roster(
        reply(reports["repeated-login-before-acceptance"], 13, "observer")
    )
    require(
        uid in {r["uid"] for r in final_roster},
        "Late departure was not the still-listed subject",
    )
    require(
        packets == json.loads((directory / "packet-reconciliation.json").read_text()),
        "Auth packet observations differ",
    )
    require(
        max(reports[n]["recorded_at_utc"] for n in lookup(missing_guest=True))
        < reports["create-temporary-guest"]["started_at_utc"]
        < min(reports[n]["started_at_utc"] for n in lookup()),
        "Guest phase chronology differs",
    )
    queries = json.loads((directory / "oracle-plan.json").read_text())
    require(
        len(queries) == 14 and len({q["id"] for q in queries}) == 14,
        "Auth query inventory differs",
    )
    for query in queries:
        record = json.loads(
            (directory / "oracle-queries" / (query["id"] + ".json")).read_text()
        )
        require(
            record["query"] == query
            and record["program"]["sha256"] == ORACLE_SHA256
            and not record["result"]["isError"],
            "Auth query identity/outcome differs",
        )
        data = record["result"]["structuredContent"]
        if "code" in data:
            require(
                data["code"]
                == (directory / "oracle-queries" / (query["id"] + ".c")).read_text(),
                "Auth oracle source differs",
            )
        if query["id"] == "AU-M-login-normalization":
            table = bytes.fromhex(data["hex"])
            require(
                data["address"] == "100946c8"
                and len(table) == 256
                and table[0] == 0
                and table[13] == 13
                and table[65:91] == bytes(range(97, 123))
                and table[128] == 138,
                "Native login normalization table differs",
            )
    return {
        "cases": len(reports),
        "initial_cases": 2,
        "state_observations": results,
        "packet_reconciliation": packets,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    result = verify(parser.parse_args().directory)
    print(
        f"Verified {result['cases']} native authentication cases and two retained exploratory reports"
    )


if __name__ == "__main__":
    main()
