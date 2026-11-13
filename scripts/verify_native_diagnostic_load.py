#!/usr/bin/env python3
"""Verify a failed native 303 load attempt and exact owned-file cleanup."""

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path

from native_diagnostic_load_cases import NAME
from native_packet_evidence import reconcile
from pcap_tcp import direction, lifetime, read_packets, stream
from protocol_capture import ORACLE_SHA256, decode_frame, verify_capture
from verify_native_account_updates import enumeration
from verify_native_auth import roster
from verify_native_core import require
from verify_native_mkdir import listing
from verify_native_shx import fields

CASES = ("preflight", "seed", "cleanup")


def reply(report: dict, identifier: int) -> dict:
    matches = [
        f
        for f in report["frames"]
        if f["connection"] == "a" and f["is_reply"] == 1 and f["id"] == identifier
    ]
    require(len(matches) == 1, f"Reply {identifier} missing or duplicate")
    return matches[0]


def sent(report: dict, kind: int, identifier: int) -> dict:
    matches = [
        decode_frame(bytes.fromhex(e["hex"]))
        for e in report["events"]
        if e["event"] == "send"
        and e["connection"] == "a"
        and len(e["hex"]) >= 40
        and e["hex"][:8] != "54525450"
    ]
    selected = [f for f in matches if f["type"] == kind and f["id"] == identifier]
    require(len(selected) == 1, f"Request {kind}/{identifier} missing or duplicate")
    return selected[0]


def current_uid(report: dict, roster_id: int, diagnostic_id: int) -> str:
    rows = roster(reply(report, roster_id))
    require(
        len(rows) == 1 and rows[0]["name_hex"] == b"framing-fixture".hex(),
        "Current admin roster ambiguous",
    )
    uid = rows[0]["uid"].to_bytes(2, "big")
    require(
        fields(sent(report, 303, diagnostic_id)) == {103: uid},
        "303 did not target same-session UID",
    )
    return uid.hex()


def semantic(reports: dict[str, dict]) -> dict:
    preflight, seed, cleanup = (reports[name] for name in CASES)
    require(
        preflight["status"] == "completed" and preflight["completed_actions"] == 18,
        "Preflight incomplete",
    )
    require(
        seed["status"] == "failed"
        and seed["completed_actions"] == 11
        and seed["error"]
        == "ConnectionResetError: [Errno 104] Connection reset by peer",
        "Seed failure changed or was relabelled success",
    )
    require(
        cleanup["status"] == "completed"
        and cleanup["completed_actions"] == 24
        and cleanup.get("branch") == "present",
        "Conditional cleanup did not complete its positive branch",
    )
    baseline_accounts = enumeration(reply(preflight, 10))
    require(len(baseline_accounts) == 2, "Original account count differs")
    baseline_files = listing(reply(preflight, 11))
    require(NAME not in baseline_files, "Owned file existed before seed")
    require(reply(preflight, 12)["error"] == 1, "Owned preflight 206 was not absent")
    preflight_uid = current_uid(preflight, 14, 15)
    idle_before = fields(reply(preflight, 15))
    require(
        reply(preflight, 15)["error"] == 0
        and set(idle_before) == {101, 102}
        and idle_before[102] == b"framing-fixture"
        and NAME not in idle_before[101],
        "Preflight idle 303 differs",
    )
    require(
        reply(seed, 10)["error"] == 0 and len(fields(reply(seed, 10))[107]) == 4,
        "Seed 203 reference was not accepted",
    )
    require(
        not any(f["is_reply"] == 1 and f["id"] == 11 for f in seed["frames"]),
        "Failed seed was incorrectly treated as file-info verified",
    )
    initial_info = reply(cleanup, 10)
    initial_fields = fields(initial_info)
    require(
        initial_info["error"] == 0
        and initial_fields[201] == NAME
        and initial_fields[205] == b"Incomplete File",
        "Owned partial file identity/status differs",
    )
    initial_files = listing(reply(cleanup, 11))
    require(
        NAME in initial_files and set(initial_files) == set(baseline_files) | {NAME},
        "Partial file is not the sole added Files entry",
    )
    require(
        fields(sent(cleanup, 204, 17)) == {201: NAME}
        and reply(cleanup, 17)["error"] == 0,
        "204 deleted another path or failed",
    )
    require(reply(cleanup, 12)["error"] == 1, "Owned file remains after 204")
    require(
        listing(reply(cleanup, 13)) == baseline_files,
        "Full Files view was not restored",
    )
    require(
        enumeration(reply(cleanup, 14)) == baseline_accounts,
        "Original account enumeration was not restored",
    )
    cleanup_uid = current_uid(cleanup, 15, 16)
    idle_after = fields(reply(cleanup, 16))
    require(
        reply(cleanup, 16)["error"] == 0 and idle_after == idle_before,
        "Idle 303 was not restored",
    )
    plan = json.loads(cleanup["_plan_path"].read_text())
    deletes = [
        step
        for step in plan["steps"]
        if step["op"] == "send"
        and step["connection"] == "a"
        and step["hex"].startswith("000000cc")
    ]
    require(
        plan["expectation"]["branch"] == "present" and len(deletes) == 1,
        "Selected plan does not show one guarded deletion",
    )
    return {
        "preflight_uid": preflight_uid,
        "cleanup_uid": cleanup_uid,
        "baseline_file_entries": len(baseline_files),
        "partial_info_fields": {str(k): v.hex() for k, v in initial_fields.items()},
        "seed_error": seed["error"],
    }


def packet_evidence(directory: Path, reports: dict[str, dict]) -> dict:
    guest = read_packets(directory / "guest-after-cleanup.pcap")
    result = {}
    for name in ("preflight", "cleanup"):
        host = read_packets(directory / f"host-{name}.pcap")
        result[name] = reconcile(reports[name], host, guest)
    seed = reports["seed"]
    host = read_packets(directory / "host-seed.pcap")
    control = dict(seed)
    control["events"] = [e for e in seed["events"] if e["connection"] == "a"]
    control["streams"] = {"a": seed["streams"]["a"]}
    result["seed_control"] = reconcile(control, host, guest)
    connect = next(
        e
        for e in seed["events"]
        if e["event"] == "connect" and e["connection"] == "upload"
    )
    port = connect["local_address"][1]
    recorded = bytes.fromhex(seed["streams"]["upload"]["sent_hex"])
    lengths = {}
    for label, packets, client, server in (
        ("host", host, ("127.0.0.1", port), ("127.0.0.1", 15501)),
        ("guest", guest, ("10.0.2.2", port), ("10.0.2.15", 5501)),
    ):
        scoped = lifetime(
            packets,
            client,
            server,
            int(
                datetime.fromisoformat(seed["started_at_utc"]).timestamp() * 1e6
                + connect["elapsed_ns"] / 1000
            ),
        )
        prefix = stream(scoped, client, server)
        require(
            recorded.startswith(prefix) and len(prefix) < len(recorded),
            f"Seed {label} delivery was mislabelled complete",
        )
        require(stream(scoped, server, client) == b"", "Unexpected upload output")
        lengths[label] = len(prefix)
        if label == "host":
            resets = [p for p in direction(scoped, server, client) if p["flags"] & 4]
            require(len(resets) >= 1, "Host did not retain server-side reset")
    require(
        0 < lengths["guest"] < lengths["host"] < len(recorded),
        "Failure prefix ordering differs",
    )
    result["seed_upload"] = {
        "recorder_sent_bytes": len(recorded),
        "host_delivered_bytes": lengths["host"],
        "guest_delivered_bytes": lengths["guest"],
    }
    return result


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    require(manifest["oracle_sha256"] == ORACLE_SHA256, "Oracle identity differs")
    as_run = directory / "as-run-native_diagnostic_load_cases.py"
    require(
        hashlib.sha256(as_run.read_bytes()).hexdigest()
        == manifest["cleanup_driver_sha256"],
        "Captured cleanup coordinator source is missing or changed",
    )
    reports = {name: verify_capture(directory / name) for name in CASES}
    for name, report in reports.items():
        report["_plan_path"] = directory / name / "plan.json"
        require(report["profile"] == "native-mac-oracle", "Wrong capture profile")
    require(
        reports["cleanup"]["driver_sha256"] == manifest["cleanup_driver_sha256"],
        "Cleanup report does not identify its as-run source",
    )
    return {
        "semantic": semantic(reports),
        "packets": packet_evidence(directory, reports),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == "__main__":
    main()
