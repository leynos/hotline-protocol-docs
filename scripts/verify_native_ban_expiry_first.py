#!/usr/bin/env python3
"""Replay the frozen first native temporary-ban epoch without guest access."""

import argparse
import datetime as dt
import hashlib
import importlib
import json
import re
import sys
import tempfile
from pathlib import Path

SCHEMA = "native-ban-expiry-first-01"
CORPUS = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-14/native-ban-expiry-first-01"
)
FIRST = (
    "guard-zero",
    "guard-protected",
    "seed-zero",
    "seed-protected",
    "kick0",
    "kick0-probe",
    "protected",
    "tempban",
    "immediate-probe",
)
A7 = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"
ORACLE = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
EXE = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
PID, START, NS, INODE = 774195, "5983214", "net:[4026533397]", 3290756512
DEADLINE = "2026-11-14T05:56:51+00:00"
PROTECTED_UNREAD = bytes.fromhex(
    "0000012e00000004000000000000000800000008000100670002000a"
)


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def read(path: Path) -> dict:
    return json.loads(path.read_text())


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def when(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def inventory(corpus: Path) -> dict:
    manifest = read(corpus / "manifest.json")
    need(
        corpus.name == SCHEMA
        and manifest["schema"] == SCHEMA
        and manifest["profile"] == "control-only"
        and manifest["full_file_baseline"] == "not_exercised"
        and manifest["source_protocol_head"]
        == "e23c4e03102d04c8724d09bca715c74862134cb9"
        and manifest["source_controller_sha256"]
        == "f5e46930ec466030dca62ee12ca79f8af856aa29ef88de34afaac50f4b0f0210"
        and manifest["source_cases_sha256"]
        == "b55180ed77b4eb780e2a28decbb113db3442f939410a0c78e1ce9567296e3bc2"
        and manifest["guest_pcap_scope"].startswith("prefix snapshot"),
        "Corpus profile or source identity differs",
    )
    files = manifest["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(actual == set(files) and len(files) + 2 <= 250, "Corpus inventory differs")
    need(
        sum((corpus / name).stat().st_size for name in files) <= 60 * 1024 * 1024,
        "Corpus exceeds size bound",
    )
    for name, expected in files.items():
        need(sha(corpus / name) == expected, f"Corpus SHA differs: {name}")
    need(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{digest}  {name}" for name, digest in sorted(files.items())],
        "SHA256SUMS differs",
    )
    return manifest


def source_gate(corpus: Path, manifest: dict) -> None:
    sources = corpus / "sources/protocol"
    frozen = read(corpus / "sources/asrun-source-freeze.json")
    closure = read(corpus / "sources/dependency-closure.json")
    need(
        frozen["source_head"] == manifest["source_protocol_head"]
        and closure["hashes"]["native_ban_expiry_control.py"]
        == manifest["source_controller_sha256"]
        and closure["hashes"]["native_ban_expiry_cases.py"]
        == manifest["source_cases_sha256"]
        and closure["module_count"] == len(closure["hashes"])
        and set(frozen["hashes"]).issubset(closure["hashes"]),
        "Frozen as-run source set differs",
    )
    for name, digest in closure["hashes"].items():
        need(sha(sources / name) == digest, "Frozen source snapshot differs")
    for name, digest in frozen["hashes"].items():
        need(sha(sources / name) == digest, "As-run B68 source differs")
    prep = read(corpus / "preparation/preflight.json")
    need(
        prep["banned_absent"]
        and prep["owned_account_names_absent"]
        and prep["original_user_count"] == 2
        and prep["files"]["server-data"]["sha256"] == ORACLE
        and prep["working.dsk"]["inode"] == INODE,
        "Stopped preparation source or baseline differs",
    )


def frozen_modules(corpus: Path):
    sys.dont_write_bytecode = True
    path = str(corpus / "sources/protocol")
    if path not in sys.path:
        sys.path.insert(0, path)
    control = importlib.import_module("native_ban_expiry_control")
    base = importlib.import_module("native_control_readiness")
    capture = importlib.import_module("protocol_capture")
    tcp = importlib.import_module("pcap_tcp")
    return control, base, capture, tcp


def raw_gate(corpus: Path) -> Path:
    raw = corpus / "raw"
    frozen = read(corpus / "raw-freeze.json")
    need(
        frozen["snapshot_scope"].startswith("first epoch raw receipts")
        and set(frozen["files"])
        == {str(p.relative_to(raw)) for p in raw.rglob("*") if p.is_file()},
        "Raw freeze inventory differs",
    )
    for name, meta in frozen["files"].items():
        path = raw / name
        need(
            path.stat().st_size == meta["copied_size"]
            and sha(path) == meta["sha256"]
            and meta["copied_size"] <= meta["source_size_after"],
            f"Raw source snapshot differs: {name}",
        )
    need(
        frozen["files"]["lab-guest.pcap"]["copied_size"]
        == frozen["files"]["lab-guest.pcap"]["source_size_after"],
        "Guest snapshot was not stable at copy boundary",
    )
    return raw


def generic_report(folder: Path, capture) -> dict:
    """Adapt B68 case metadata only in a temporary generic replay view."""
    plan = read(folder / "plan.json")
    raw = read(folder / "report.json")
    need(
        raw["profile"] == "control-only"
        and raw["full_file_baseline"] == "not_exercised"
        and raw["oracle_sha256"] == plan["oracle_sha256"],
        "B68 raw case profile differs",
    )
    adapted = {
        **raw,
        "profile": plan["profile"],
        "native_conformance": False,
        "plan_sha256": sha(folder / "plan.json"),
    }
    with tempfile.TemporaryDirectory() as temporary:
        view = Path(temporary)
        (view / "plan.json").write_bytes((folder / "plan.json").read_bytes())
        (view / "report.json").write_text(json.dumps(adapted) + "\n")
        (view / "checksums.sha256").write_text(
            "".join(
                f"{sha(view / name)}  {name}\n" for name in ("plan.json", "report.json")
            )
        )
        capture.verify_capture(view)
    return raw


def identity_gate(corpus: Path, raw: Path) -> dict:
    receipt = read(raw / "capture-ready.json")
    runtime = read(raw / "runtime-asrun.json")
    preboot = read(raw / "preboot.json")
    terminal = read(raw / "first-terminal.json")
    need(
        receipt["fixture_profile"] == "control-only"
        and receipt["full_file_baseline"] == "not_exercised"
        and receipt["source_a7_sha256"] == A7
        and receipt["emulator_pid"] == PID
        and receipt["emulator_starttime"] == START
        and receipt["emulator_netns"] == NS
        and receipt["emulator_netns_inode"] == 4026533397
        and receipt["owned_working_image_inode"] == INODE
        and receipt["emulator_sha256"] == EXE
        and receipt["deadline_utc"] == DEADLINE
        and receipt["epoch_started_utc"] == "2026-11-14T05:44:51+00:00"
        and all(runtime[k] == receipt[k] for k in runtime)
        and preboot["image_inode"] == INODE
        and preboot["fixed_deadline_utc"] == DEADLINE,
        "Actual emulator identity, profile or deadline differs",
    )
    need(
        receipt["ns_routes"] == []
        and receipt["primary_syn_count"] == 0
        and receipt["host_recorder_pid"] == 773908
        and receipt["namespace_recorder_pid"] == 775272
        and receipt["managed_lock"]["pid"] == 772927
        and receipt["managed_lock"]["fd"] == 3
        and receipt["managed_lock"]["busy_exit"] == 1
        and receipt["managed_lock"]["lock_inode"] == 3512552451,
        "Managed recorder or lock receipt differs",
    )
    for label in ("host", "namespace"):
        meta = receipt["managed_capture"][label]
        need(
            meta["unit_properties"]["ActiveState"] == "active"
            and meta["unit_properties"]["KillMode"] == "control-group"
            and meta["unit_properties"]["RuntimeMaxUSec"] == "15min"
            and meta["deadline_utc"] == DEADLINE
            and meta["pid"] == receipt[f"{label}_recorder_pid"]
            and meta["header24"].startswith("d4c3b2a1"),
            f"{label} capture readiness differs",
        )
    need(
        terminal["first_exit"] == 0
        and terminal["actual_emulator_pid"] == PID
        and terminal["image_inode"] == INODE
        and terminal["vm_retained_for_idle"] is True
        and terminal["application_sockets_established"] is False
        and terminal["oracle_mutex_free"] is True
        and terminal["original_pids_stable"] is True
        and terminal["primary_syn_count"] == 0
        and when(terminal["utc"]) < when(DEADLINE)
        and (raw / "c77-first.exit").read_text() == "0\n",
        "First-epoch terminal receipt differs",
    )
    need(
        all(
            re.search(
                r"0 packets dropped by kernel",
                (raw / f"{name}-terminal-journal.log").read_text(),
            )
            for name in ("host", "namespace")
        )
        and "0 packets captured" in (raw / "host-terminal-journal.log").read_text()
        and all(
            f"Id=mothra-native-expiry-c75-{name}.service\nActiveState=inactive\nSubState=dead\nMainPID=0\nResult=success"
            in (raw / "c75-capture-lock-terminal.txt").read_text()
            for name in ("host", "namespace", "lease")
        ),
        "Capture drop or owned cleanup differs",
    )
    return receipt


def failed_launch_gate(corpus: Path, raw: Path) -> None:
    failed = read(raw / "results-first/summary.json")
    guard = read(raw / "results-first/guard-zero/report.json")
    c76 = (corpus / "operator/c76-unit-final.txt").read_text()
    c77 = (corpus / "operator/c77-unit-final.txt").read_text()
    need(
        failed["status"] == "failed"
        and "ConnectionRefusedError" in failed["error"]
        and set(failed["cases"]) == {"guard-zero"}
        and guard["status"] == "failed"
        and guard["completed_actions"] == 0
        and guard["events"] == guard["frames"] == []
        and (raw / "first.exit").read_text() == "1\n"
        and "NetworkNamespacePath=" in c76
        and "NetworkNamespacePath=/proc/774195/ns/net" not in c76
        and "Result=exit-code" in c76
        and "ExecMainStatus=1" in c76
        and "NetworkNamespacePath=/proc/774195/ns/net" in c77
        and "Result=success" in c77
        and "ExecMainStatus=0" in c77
        and (raw / "c77-runner-netns.txt").read_text() == NS + "\n"
        and read(raw / "c77-runner-ready.json")["netns"] == NS,
        "Failed C76 or corrected C77 launch identity differs",
    )


def reports_gate(
    corpus: Path, raw: Path, receipt: dict, control, base, capture
) -> dict:
    plans = raw / "plans"
    hashes = read(plans / "source-hashes.json")
    all_names = ("readiness", *FIRST, "pre-probe", "post-probe")
    need(set(hashes) == set(all_names), "Twelve-plan inventory differs")
    env = read(raw / "runtime-asrun.json")
    reports = {}
    for name in all_names:
        path = plans / f"{name}.json"
        plan = read(path)
        need(sha(path) == hashes[name], f"{name} source plan hash differs")
        need(
            plan == control.cases.plan(name, control.cases.plans()[name], env, 15800)
            and plan["endpoints"] == {"control": {"host": "127.0.0.1", "port": 15800}}
            and plan["environment"] == env,
            f"{name} source plan differs",
        )
    ready_path = raw / "captures/readiness"
    need(
        read(ready_path / "plan.json") == read(plans / "readiness.json"),
        "Readiness source plan differs",
    )
    ready = capture.verify_capture(ready_path)
    base.readiness(ready)
    reports["readiness"] = ready
    results = raw / "results-first-c77"
    summary = read(results / "summary.json")
    need(
        summary["status"] == "completed"
        and summary["phase"] == "first"
        and summary.get("error") is None
        and tuple(summary["cases"]) == FIRST
        and summary["post_readiness_settle"]["elapsed_seconds"] >= 35
        and summary["post_readiness_settle"]["runner_socket_actions_during_wait"] == 0,
        "First-epoch status, sequence or settle differs",
    )
    for name in FIRST:
        folder = results / name
        need(
            read(folder / "plan.json") == read(plans / f"{name}.json"),
            f"{name} as-run plan differs",
        )
        report = generic_report(folder, capture)
        control.outcome_gate(report, name)
        need(
            summary["cases"][name]
            == {"status": "completed", "error": "", "plan_sha256": hashes[name]},
            f"{name} summary differs",
        )
        reports[name] = report
    bound = control.ban_timing(reports["tempban"], receipt)
    need(
        bound.to_json() == read(results / "ban-clock.json")
        and bound.image_inode == INODE
        and bound.emulator_pid == PID
        and 0 <= (bound.ack_utc - bound.request_utc).total_seconds() <= 20,
        "Ban request/ACK bracket differs",
    )
    need(
        when(summary["post_readiness_settle"]["started_utc"])
        < when(summary["post_readiness_settle"]["completed_utc"])
        < when(reports["guard-zero"]["started_at_utc"])
        < bound.request_utc
        < bound.ack_utc
        < when(DEADLINE),
        "First-epoch timing order or deadline differs",
    )
    return reports


def packet_gate(corpus: Path, raw: Path, reports: dict, tcp) -> dict:
    namespace = tcp.read_packets(raw / "lab-namespace.pcap")
    guest = tcp.read_packets(raw / "lab-guest.pcap")
    need(not tcp.read_packets(raw / "primary-syn.pcap"), "Primary-port SYN observed")
    need(
        not any(
            p["src_port"] in {15500, 15501} or p["dst_port"] in {15500, 15501}
            for p in namespace
        ),
        "Fixed primary bridge was used",
    )
    settle = read(raw / "results-first-c77/summary.json")["post_readiness_settle"]
    start, end = (
        int(when(settle[k]).timestamp() * 1_000_000)
        for k in ("started_utc", "completed_utc")
    )
    need(
        not [p for p in namespace if start <= p["timestamp_us"] <= end],
        "Namespace traffic occurred during 35s settle",
    )
    ports = set()
    for name, report in reports.items():
        origin = when(report["started_at_utc"])
        for event in (e for e in report["events"] if e["event"] == "connect"):
            client_port = event["local_address"][1]
            need(client_port not in ports, "Repeated client TCP source port")
            ports.add(client_port)
            when_us = int(origin.timestamp() * 1_000_000) + event["elapsed_ns"] // 1000
            for label, source, client, server, target in (
                ("namespace", namespace, "127.0.0.1", "127.0.0.1", 15800),
                ("guest", guest, "10.0.2.2", "10.0.2.15", 5500),
            ):
                flow = tcp.lifetime(
                    source, (client, client_port), (server, target), when_us
                )
                sent = tcp.stream(flow, (client, client_port), (server, target))
                received = tcp.stream(flow, (server, target), (client, client_port))
                expected_received = bytes.fromhex(
                    report["streams"][event["connection"]]["received_hex"]
                )
                if name == "protected" and event["connection"] == "main":
                    expected_received += PROTECTED_UNREAD
                need(
                    bool(flow)
                    and sent.hex() == report["streams"][event["connection"]]["sent_hex"]
                    and received == expected_received
                    and flow[0]["flags"] & 2
                    and flow[-1]["timestamp_us"] >= flow[0]["timestamp_us"],
                    f"{name}/{event['connection']}/{label} paired TCP bytes differ",
                )
    need(
        len(ports) == 13
        and sum(p["dst_port"] == 15800 and p["flags"] == 2 for p in namespace) == 13
        and sum(p["dst_port"] == 5500 and p["flags"] == 2 for p in guest) == 13,
        "Thirteen SYN-scoped control lifetimes differ",
    )
    return {
        "connections": len(ports),
        "namespace_packets": len(namespace),
        "guest_packets": len(guest),
    }


def clock_gate(corpus: Path, raw: Path) -> None:
    value = read(corpus / "clock-observations.json")
    need(
        value["method"].startswith("manual transcription")
        and [v["visible_menubar_clock_transcription"] for v in value["observations"]]
        == ["Sat 5:49:09 AM", "Sat 5:51:09 AM", "Sat 5:55:26 AM"],
        "Visual guest clock transcription differs",
    )
    previous = None
    for row in value["observations"]:
        path = raw / row["screenshot"]
        need(
            sha(path) == row["screenshot_sha256"]
            and (raw / row["screenshot"].replace(".png", "-before.utc"))
            .read_text()
            .strip()
            == row["before_utc"]
            and (raw / row["screenshot"].replace(".png", "-after.utc"))
            .read_text()
            .strip()
            == row["after_utc"],
            "Clock screenshot or host brackets differ",
        )
        before, after = when(row["before_utc"]), when(row["after_utc"])
        need(
            before <= after and (after - before).total_seconds() < 3,
            "Clock host bracket differs",
        )
        if previous:
            need(previous < before, "Clock observation order differs")
        previous = after


def verify(corpus: Path = CORPUS) -> dict:
    manifest = inventory(corpus)
    source_gate(corpus, manifest)
    raw = raw_gate(corpus)
    control, base, capture, tcp = frozen_modules(corpus)
    receipt = identity_gate(corpus, raw)
    failed_launch_gate(corpus, raw)
    reports = reports_gate(corpus, raw, receipt, control, base, capture)
    packet = packet_gate(corpus, raw, reports, tcp)
    clock_gate(corpus, raw)
    return {
        "status": "verified_first_epoch_only",
        "full_file_baseline": "not_exercised",
        "cases": len(FIRST),
        **packet,
        "request_utc": read(raw / "results-first-c77/ban-clock.json")["request_utc"],
        "ack_utc": read(raw / "results-first-c77/ban-clock.json")["ack_utc"],
        "vm_retained_at_terminal": True,
        "expiry_proven": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", nargs="?", type=Path, default=CORPUS)
    args = parser.parse_args()
    print(json.dumps(verify(args.corpus), indent=2))


if __name__ == "__main__":
    main()
