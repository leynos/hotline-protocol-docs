#!/usr/bin/env python3
"""Verify configured agreement content, readiness and observer transitions."""

import argparse
import hashlib
import json
from pathlib import Path

from native_agreement_cases import (
    FILES,
    NON_TEXT_FILES,
    ORIGINAL_AGREEMENT_SHA256,
    phase,
)
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_auth import ADMIN, BYPASS, check_state, reply, roster, selected
from verify_native_banners import fields
from verify_native_core import require
from verify_native_framing import check_quiet

PHASE_NAMES = {
    "original",
    "absent",
    "text",
    "empty",
    "directory",
    "text-limit",
    "text-over-limit",
    "nontext",
    "nontext-over-limit",
    "nontext-field-over-limit",
    "restored",
}


def check_overflow(report: dict, expected: dict) -> dict:
    subject = selected(report, "subject")
    early = expected["early"]
    shape = [(0, 1, 0)]
    if early:
        shape += [(354, 0, 0), (0, 1, 0), (0, 1, 1), (0, 1, 1)]
    require(
        [(f["type"], f["is_reply"], f["error"]) for f in subject] == shape,
        "Field-overflow partial login sequence differs",
    )
    require(
        fields(subject[0]) == {160: b"\0\xbe", 161: b"\0\0"},
        "Overflow login ACK differs",
    )
    observer = selected(report, "observer")
    require(
        fields(observer[1]) == {110: BYPASS} and fields(observer[2]) == {154: b"\0\1"},
        "Overflow observer must use the independent bypass account",
    )
    views = {f["id"]: roster(f) for f in observer if f["is_reply"] and f["id"] >= 10}
    expected_views = {10: 1, 12: 2, 13: 2, 14: 1} if early else {10: 1, 12: 1, 13: 1}
    require(
        {k: len(v) for k, v in views.items()} == expected_views,
        "Overflow visibility differs",
    )
    updates = [f for f in observer if f["type"] == 301]
    departures = [f for f in observer if f["type"] == 302]
    require(
        len(updates) == int(early) and len(departures) == 1,
        "Overflow notifications differ",
    )
    uid = int.from_bytes(fields(departures[0])[103], "big")
    if early:
        require(fields(subject[1]) == {110: ADMIN}, "Overflow early privileges differ")
        require(
            fields(reply(report, 91, "subject")) == {},
            "Overflow online request500 failed",
        )
        for identifier in [2, 3]:
            require(
                fields(reply(report, identifier, "subject"))
                == {100: b"Unknown transaction type!"},
                "Overflow online replay differs",
            )
        require(
            int.from_bytes(fields(updates[0])[103], "big") == uid,
            "Overflow UID changed",
        )
        for identifier in [12, 13]:
            require(
                any(
                    r["uid"] == uid
                    and r["icon"] == 1
                    and r["name_hex"] == b"auth-visible".hex()
                    for r in views[identifier]
                ),
                "Overflow identity differs",
            )
    else:
        require(
            all(uid not in {r["uid"] for r in view} for view in views.values()),
            "Delayed overflow became roster-visible",
        )
        require(
            any(
                e["event"] == "eof" and e["connection"] == "subject"
                for e in report["events"]
            ),
            "Delayed overflow trigger did not reach EOF",
        )
    return {
        "early": early,
        "rosters": views,
        "observer_updates": len(updates),
        "read_departures": len(departures),
    }


def native_file(root: Path, expected_type: bytes, expected_data: bytes) -> None:
    extraction = json.loads((root / "extraction.json").read_text())
    matches = [
        r for r in extraction["records"] if r["path"] == "/Hotline19/Agreement.txt"
    ]
    require(len(matches) == 1, "Missing/duplicate positive native agreement path")
    record = matches[0]
    require(not record["directory"], "Expected agreement file, found directory")
    require(record["attributes"]["data"]["exit_code"] == 0, "Native fork read failed")
    require(
        (root / (record["key"] + ".data")).read_bytes() == expected_data,
        "Native agreement bytes differ",
    )
    stat = (root / (record["key"] + ".stat.txt")).read_text()
    require(
        "file type:\t" + expected_type.hex() + "  " in stat.lower(),
        "Native Finder type differs",
    )


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    require(
        manifest["oracle_sha256"] == ORACLE_SHA256, "Agreement oracle identity differs"
    )
    require(set(manifest["phases"]) == PHASE_NAMES, "Agreement phase inventory differs")
    host = read_packets(directory / "host.pcap")
    guest = read_packets(directory / "guest.pcap")
    for group, inventory in [("setup", "setup_cases"), ("initial", "initial_cases")]:
        require(
            {p.name for p in (directory / group).iterdir()} == set(manifest[inventory]),
            "Auxiliary transcript inventory differs",
        )
        for name in manifest[inventory]:
            root = directory / group / name
            verify_capture(root)
            report = json.loads((root / "report.json").read_text())
            if group == "setup":
                require(
                    report["status"] == "completed", "Setup/control did not complete"
                )
            if name != "absent-before-timer-recovery":
                tails = {
                    k: bytes.fromhex(v)
                    for k, v in manifest["other_unread_output"]
                    .get(group + "/" + name, {})
                    .items()
                }
                reconcile(report, host, guest, tails)
    cleanup = json.loads(
        (directory / "setup/remove-agreement-bypass-account/report.json").read_text()
    )
    require(
        [(f["id"], f["error"]) for f in cleanup["frames"] if f["is_reply"]]
        == [(1, 0), (10, 0), (11, 1)],
        "Owned agreement account cleanup/readback differs",
    )
    account = (directory / "native-seed/catalog-11296.data").read_bytes()
    require(
        len(account) == 734 and account[4:12] == BYPASS,
        "Native bypass account bitmap differs",
    )
    for root in (directory / "oracle-queries").glob("*.json"):
        query = json.loads(root.read_text())
        require(
            query["program"]["sha256"] == ORACLE_SHA256
            and not query["result"]["isError"],
            "Agreement oracle query failed or identity differs",
        )
    results = []
    all_cases = {}
    for name, setup in manifest["phases"].items():
        agreement = None
        if name in {"original", "restored"}:
            raw = (directory / "original-agreement.data").read_bytes()
            require(len(raw) == 245, "Original agreement length differs")
            require(
                hashlib.sha256(raw).hexdigest() == ORIGINAL_AGREEMENT_SHA256,
                "Original agreement identity differs",
            )
            agreement = raw.replace(b"\r\n", b"\r")
            native_file(directory / setup["snapshot"], b"TEXT", raw)
        elif name == "directory":
            extraction = json.loads(
                (directory / setup["snapshot"] / "extraction.json").read_text()
            )
            require(
                any(
                    r["path"] == "/Hotline19/Agreement.txt" and r["directory"]
                    for r in extraction["records"]
                ),
                "Unreadable path lacks a positive native directory record",
            )
        elif name != "absent":
            _, kind, raw = (FILES | NON_TEXT_FILES)[name]
            native_file(directory / setup["snapshot"], kind, raw)
            limit = 65535 if kind == b"TEXT" else 262140
            if 0 < len(raw) <= limit:
                agreement = raw.replace(b"\r\n", b"\r") if kind == b"TEXT" else raw
        for label, (steps, expected) in phase(name).items():
            root = directory / "captures" / label
            verify_capture(root)
            plan = json.loads((root / "plan.json").read_text())
            report = json.loads((root / "report.json").read_text())
            require(
                plan["steps"] == steps and plan["expectation"] == expected,
                "Agreement observation plan differs",
            )
            require(
                report["status"] == "completed",
                "Agreement observation did not complete",
            )
            check_quiet(report, plan)
            result = (
                check_overflow(report, expected)
                if expected["kind"] == "agreement-field-overflow"
                else check_state(label, report, expected, agreement)
            )
            for frame in report["frames"]:
                if frame["type"] == 109:
                    bypass = expected["kind"] == "agreement-field-overflow" or (
                        frame["connection"] == "subject" and expected["bypass"]
                    )
                    notice = (
                        {154: b"\0\1"}
                        if bypass
                        else {}
                        if agreement is None
                        else {101: agreement}
                    )
                    require(
                        fields(frame) == notice,
                        f"{label}: observer/subject agreement content differs",
                    )
            tails = {
                k: bytes.fromhex(v)
                for k, v in manifest.get("unread_output", {}).get(label, {}).items()
            }
            result["packets"] = reconcile(report, host, guest, tails)
            results.append(result)
            all_cases[label] = True
    require(
        set(manifest["cases"]) == set(all_cases), "Agreement case inventory differs"
    )
    return {
        "cases": len(results),
        "phases": len(manifest["phases"]),
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    result = verify(args.directory)
    print(
        f"Verified {result['cases']} configured agreement cases across {result['phases']} phases"
    )


if __name__ == "__main__":
    main()
