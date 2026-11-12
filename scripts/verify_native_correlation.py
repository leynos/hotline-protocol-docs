#!/usr/bin/env python3
"""Verify native ID collision/reuse and request/reply envelope observations."""

import argparse
import hashlib
import json
from pathlib import Path

from native_correlation_cases import correlation
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_banners import fields
from verify_native_core import require
from verify_native_framing import check_quiet


def check_outcome(report: dict, expected: dict, packets: dict) -> dict:
    frames = report["frames"]
    require(report["status"] == "completed", "Incomplete ID observation")
    require(
        [(f["type"], f["id"], f["is_reply"], f["error"]) for f in frames[:3]]
        == [(0, 1, 1, 0), (354, 1, 0, 0), (109, 2, 0, 0)],
        "ID bootstrap namespaces differ",
    )
    require(all(f["flags"] == 0 for f in frames), "Native emitted flags differ")
    remaining = frames[3:]
    replies = [f for f in remaining if f["is_reply"]]
    notifications = [f for f in remaining if not f["is_reply"]]
    if expected["kind"] == "close":
        require(
            not remaining and any(e["event"] == "eof" for e in report["events"]),
            "Missing unnumbered close",
        )
        require(
            (
                not packets["main"]["guest_server_initiated_close"]
                and packets["main"]["guest_server_close_kind"] == "FIN"
            )
            if any(e["event"] == "shutdown_write" for e in report["events"])
            else packets["main"]["guest_server_initiated_close"],
            "Missing native reply-size close",
        )
        return {
            "native_close_after_half_close": any(
                e["event"] == "shutdown_write" for e in report["events"]
            )
        }
    if expected["kind"] == "unsupported":
        require(
            len(replies) == 2 and not notifications,
            "Unsupported request outcomes differ",
        )
        error = replies[0]
        require(
            (error["type"], error["id"], error["is_reply"], error["error"])
            == (0, 10, 1, 1),
            "Unsupported error envelope differs",
        )
        require(
            fields(error) == {100: b"Unknown transaction type!"},
            "Unsupported error text differs",
        )
        replies = replies[1:]
        ids = [11]
    else:
        ids = expected["ids"]
    require(len(replies) == len(ids), "Direct reply count differs")
    for frame, identifier in zip(replies, ids, strict=True):
        require(
            (
                frame["type"],
                frame["id"],
                frame["is_reply"],
                frame["error"],
                frame["payload_hex"],
            )
            == (0, identifier, 1, 0, "0000"),
            "Direct reply correlation differs",
        )
    if expected["kind"] in {"notification", "collision-notification"}:
        require(len(notifications) == 1, "Notification count differs")
        frame = notifications[0]
        require(
            (frame["type"], frame["id"], frame["error"]) == (301, 3, 0),
            "Notification ID allocation differs",
        )
        values = fields(frame)
        require(
            values[102].hex() == expected["name_hex"]
            and int.from_bytes(values[104], "big") == expected["icon"],
            "Collision/notification settings differ",
        )
        require(
            [f["is_reply"] for f in remaining]
            == ([1, 0, 1] if expected["kind"] == "notification" else [0, 1]),
            "Notification/reply ordering differs",
        )
    else:
        require(not notifications, "Unexpected notification")
    return {
        "reply_ids": [f["id"] for f in replies],
        "notification_ids": [f["id"] for f in notifications],
    }


def verify_oracle(directory: Path) -> None:
    root = directory / "oracle-queries"
    queries = [
        q for p in directory.glob("oracle-*.json") for q in json.loads(p.read_text())
    ]
    require(
        len(queries) == 25 and len({q["id"] for q in queries}) == 25,
        "ID oracle query inventory differs",
    )
    for query in queries:
        record = json.loads((root / (query["id"] + ".json")).read_text())
        require(
            record["query"] == query and record["program"]["sha256"] == ORACLE_SHA256,
            "ID oracle identity differs",
        )
        require(
            record["result"]["isError"] == (query["id"] == "ID-D-10058960"),
            "Exploratory function-query outcome differs",
        )
        data = record["result"].get("structuredContent") or {}
        if "code" in data:
            require(
                data["code"] == (root / (query["id"] + ".c")).read_text(),
                "ID oracle code differs",
            )
    for address in [
        "10058090",
        "10058880",
        "100589b0",
        "10058df0",
        "10058ca0",
        "10058d70",
        "100590e0",
        "10058fd0",
        "10014640",
        "10079e30",
    ]:
        code = (root / ("ID-D-" + address + ".c")).read_text()
        require("FUN_" + address + "(" in code, "Lifecycle function identity differs")
    instructions = json.loads((root / "ID-A-10058d70.json").read_text())["result"][
        "structuredContent"
    ]
    require(
        not instructions["has_more"]
        and "".join(i["bytes"] for i in instructions["items"])
        == "8083000c340400019003000c4082000c380000019003000c8063000c4e800020",
        "32-bit increment/zero-skip instructions differ",
    )


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    cases = correlation()
    require(
        set(manifest["cases"]) == set(cases) and len(manifest["cases"]) == 24,
        "ID case inventory differs",
    )
    require(manifest["oracle_sha256"] == ORACLE_SHA256, "ID corpus identity differs")
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    source_hash = hashlib.sha256(
        (directory / "protocol_capture.py.as-run.txt").read_bytes()
    ).hexdigest()
    results, observations = {}, {}
    for name, (steps, expectation) in cases.items():
        path = directory / "transcripts" / name
        plan = json.loads((path / "plan.json").read_text())
        require(
            plan["steps"] == steps and plan["expectation"] == expectation,
            "ID preparation plan differs",
        )
        report = verify_capture(path)
        require(
            report["driver_sha256"] == source_hash, "Missing ID capture-driver source"
        )
        require(
            report["streams"]["main"]["sent_hex"]
            == "".join(s["hex"] for s in steps if s["op"] == "send"),
            "Physical ID input differs",
        )
        observations[name] = reconcile(report, host, guest)
        check_quiet(report, plan)
        for action, step in enumerate(steps):
            if step["op"] == "pause":
                event = next(
                    e
                    for e in report["events"]
                    if e["action"] == action and e["event"] == "pause"
                )
                before = max(
                    e["elapsed_ns"] for e in report["events"] if e["action"] < action
                )
                require(
                    event["elapsed_ns"] - before >= step["seconds"] * 1e9,
                    "Shortened dispatch pause",
                )
        results[name] = check_outcome(report, expectation, observations[name])
    require(
        observations
        == json.loads((directory / "packet-reconciliation.json").read_text()),
        "ID packet observations differ",
    )
    verify_oracle(directory)
    return {"cases": results, "packet_reconciliation": observations}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    result = verify(args.directory)
    print(
        f"Verified {len(result['cases'])} native ID/envelope cases and 25 oracle queries"
    )


if __name__ == "__main__":
    main()
