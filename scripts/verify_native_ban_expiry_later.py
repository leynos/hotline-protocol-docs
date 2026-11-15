#!/usr/bin/env python3
"""Replay the stopped lab's later temporary-ban epoch without a VM."""

import argparse
import datetime as dt
import hashlib
import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

SCHEMA = "native-ban-expiry-later-01"
ROOT = Path(__file__).resolve().parents[1] / "evidence/gap-remediation/2026-11-14"
CORPUS = ROOT / SCHEMA
FIRST = ROOT / "native-ban-expiry-first-01"
PID, START, NS, INODE = 774195, "5983214", 4026533397, 3290756512
ROM = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
BASE = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
WORKING = "01e8621f16eb088a178d4e62c09259f8c470625d6fd35b6f34e22f0d894192bb"
DEADLINE = "2026-11-14T06:38:00+00:00"
HOST_PCAP_HEADER = bytes.fromhex("d4c3b2a10200040000000000000000000000040001000000")


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def read(path: Path) -> dict:
    return json.loads(path.read_text())


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def when(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def inventory(corpus: Path, first: Path) -> dict:
    m = read(corpus / "manifest.json")
    need(
        corpus.name == SCHEMA
        and m["schema"] == SCHEMA
        and m["profile"] == "control-only"
        and m["full_file_baseline"] == "not_exercised"
        and m["pre_window"] == "missed_no_probe"
        and m["exact_1800_boundary_proven"] is False
        and m["first_corpus_manifest_sha256"] == sha(first / "manifest.json")
        and m["first_corpus_sha256s_sha256"] == sha(first / "SHA256SUMS")
        and m["pre_controller_sha256"]
        == "6275f634be00487b7ba08415dea15b85aee0ed7218bc4f5ef99f3962971421b7"
        and m["post_controller_sha256"]
        == "7f58d3c6cf105bcd591910828000c24fca3110d90b9a0b08ba277b1d369b112d"
        and m["cleanup_sha256"]
        == "641a0c221b68bf1099df3e0f54e8fae51ccf649e176524a31f7d83dc9a315c40"
        and m["working_sha256"] == WORKING
        and m["immutable_base_sha256"] == BASE
        and m["rom_sha256"] == ROM,
        "Corpus profile, source or prior witness identity differs",
    )
    files = m["files"]
    actual = {
        str(p.relative_to(corpus))
        for p in corpus.rglob("*")
        if p.is_file() and p.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(actual == set(files) and len(files) + 2 <= 250, "Corpus inventory differs")
    need(
        sum((corpus / name).stat().st_size for name in files) <= 80 * 1024 * 1024,
        "Corpus size exceeds bound",
    )
    for name, digest in files.items():
        need(sha(corpus / name) == digest, f"Corpus SHA differs: {name}")
    need(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{digest}  {name}" for name, digest in sorted(files.items())],
        "SHA256SUMS differs",
    )
    first_result = json.loads(
        subprocess.run(
            [
                sys.executable,
                str(Path(__file__).with_name("verify_native_ban_expiry_first.py")),
                str(first),
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    need(
        first_result["status"] == "verified_first_epoch_only"
        and first_result["cases"] == 9
        and first_result["connections"] == 13
        and first_result["expiry_proven"] is False,
        "First-epoch witness differs",
    )
    return m


def source_gate(corpus: Path, manifest: dict) -> None:
    pre = corpus / "raw/pre"
    post = corpus / "raw/post"
    old = (pre / "controller-before-starttick-fix.py.as-run.txt").read_text()
    new = (post / "sources/native_ban_expiry_control.py").read_text()
    original = '                receipt["emulator_starttime"],'
    corrected = '                int(str(receipt["emulator_starttime"])), '
    need(
        old.count(original) == 1
        and old.replace(original, corrected.rstrip()) == new
        and sha(pre / "controller-before-starttick-fix.py.as-run.txt")
        == manifest["pre_controller_sha256"]
        and sha(post / "sources/native_ban_expiry_control.py")
        == manifest["post_controller_sha256"],
        "C80 one-line start-tick correction differs",
    )
    freeze = read(post / "source-freeze.json")
    need(
        freeze["source_head_at_freeze"] == manifest["post_source_protocol_head"]
        and freeze["hashes"]["native_ban_expiry_cleanup.py"]
        == manifest["cleanup_sha256"]
        and freeze["hashes"]["native_ban_expiry_control.py"]
        == manifest["post_controller_sha256"]
        and len(freeze["hashes"]) == 34,
        "Post source snapshot identity differs",
    )
    for name, digest in freeze["hashes"].items():
        need(sha(post / "sources" / name) == digest, f"Post source differs: {name}")
    need(
        'receipt | {"emulator_starttime": "111"}'
        in (post / "sources/test_native_ban_expiry.py").read_text()
        and 'receipt | {"emulator_starttime": "112"}'
        in (post / "sources/test_native_ban_expiry.py").read_text(),
        "Start-tick regression source differs",
    )


def frozen(corpus: Path):
    sys.dont_write_bytecode = True
    source = str(corpus / "raw/post/sources")
    if source not in sys.path:
        sys.path.insert(0, source)
    control = importlib.import_module("native_ban_expiry_control")
    cleanup = importlib.import_module("native_ban_expiry_cleanup")
    readiness = importlib.import_module("native_control_readiness")
    capture = importlib.import_module("protocol_capture")
    tcp = importlib.import_module("pcap_tcp")
    return control, cleanup, readiness, capture, tcp


def generic_post(folder: Path, capture) -> dict:
    plan = read(folder / "plan.json")
    report = read(folder / "report.json")
    need(
        report["profile"] == "control-only"
        and report["full_file_baseline"] == "not_exercised",
        "Raw post report profile differs",
    )
    adapted = {
        **report,
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
    return report


def clock_gate(raw: Path) -> None:
    rows = (
        ("pre", "Sat 6:20:05 AM", "clock-before.utc", "clock-after.utc", None),
        ("post", "Sat 6:27:48 AM", "clock-before.utc", "clock-after.utc", None),
        (
            "post",
            "Sat 6:29:36 AM",
            "clock-after-probe-before.utc",
            "clock-after-probe-after.utc",
            "post_probe",
        ),
    )
    previous = None
    for location, visible, before_name, after_name, nested in rows:
        folder = raw / location
        value = read(folder / "clock-witness.json")
        data = value[nested] if nested else value
        before, after = when(data["host_before_utc"]), when(data["host_after_utc"])
        need(
            data["visible_guest_menubar_clock"] == visible
            and data["ui_action"] == "none"
            and sha(folder / data["screenshot"]) == data["sha256"]
            and (folder / before_name).read_text().strip() == data["host_before_utc"]
            and (folder / after_name).read_text().strip() == data["host_after_utc"]
            and before <= after
            and (after - before).total_seconds() < 3
            and (previous is None or previous < before),
            "Guest clock screenshot, host bracket or order differs",
        )
        previous = after
    need("Login successful" in data["server_log_observation"], "Post UI log differs")


def pre_gate(raw: Path) -> None:
    pre = raw / "pre"
    ready = read(pre / "capture-ready.json")
    need(
        ready["emulator_pid"] == PID
        and ready["emulator_starttime"] == START
        and ready["emulator_netns_inode"] == NS
        and ready["owned_working_image_inode"] == INODE
        and ready["deadline_utc"] == "2026-11-14T06:24:00+00:00"
        and ready["epoch_started_utc"] == "2026-11-14T06:19:10Z"
        and ready["managed_lock"]["busy_exit"] == 1
        and ready["managed_lock"]["fd"] == 3,
        "Missed pre-epoch readiness differs",
    )
    for label in ("host", "namespace"):
        need(
            (
                pre / ("primary-syn.pcap" if label == "host" else "lab-namespace.pcap")
            ).read_bytes()
            == HOST_PCAP_HEADER
            and read(pre / f"{label}-ready.json")["pid"]
            == ready[f"{label}_recorder_pid"]
            and "0 packets captured"
            in (pre / f"{label}-terminal-journal.log").read_text()
            and "0 packets dropped by kernel"
            in (pre / f"{label}-terminal-journal.log").read_text(),
            "Pre-epoch capture was not empty and controlled",
        )
    unit = (pre / "c80-failed-unit.txt").read_text()
    journal = (pre / "c80-failed-journal.log").read_text()
    need(
        "Result=exit-code" in unit
        and "ExecMainStatus=1" in unit
        and "NetworkNamespacePath=/proc/774195/ns/net" in unit
        and "ValueError: Guest/image identity changed during idle" in journal
        and not (pre / "results").exists()
        and when((pre / "terminal.utc").read_text().strip())
        < when(ready["deadline_utc"])
        and "ActiveState=inactive" in (pre / "c79-terminal-units.txt").read_text(),
        "C80 failed-before-socket receipt differs",
    )
    need(
        read(pre / "route4.json") == read(pre / "route6.json") == []
        and [link["ifname"] for link in read(pre / "links.json")] == ["lo"],
        "Pre-epoch namespace containment differs",
    )


def post_receipt_gate(raw: Path) -> dict:
    post = raw / "post"
    receipt = read(post / "capture-ready.json")
    first = read(raw / "pre/capture-ready.json")
    for key in (
        "emulator_pid",
        "emulator_starttime",
        "emulator_sha256",
        "emulator_netns_inode",
        "owned_working_image_inode",
        "owned_working_image",
        "guest_pcap",
    ):
        need(receipt[key] == first[key], f"Live emulator continuity differs: {key}")
    need(
        receipt["emulator_pid"] == PID
        and receipt["emulator_starttime"] == START
        and receipt["emulator_netns_inode"] == NS
        and receipt["owned_working_image_inode"] == INODE
        and receipt["deadline_utc"] == DEADLINE
        and receipt["epoch_started_utc"] == "2026-11-14T06:27:04Z"
        and receipt["managed_lock"]["busy_exit"] == 1
        and receipt["managed_lock"]["fd"] == 3
        and receipt["managed_lock"]["unit"] == "mothra-native-expiry-c81-lease.service"
        and receipt["ns_routes"] == []
        and receipt["primary_syn_count"] == 0,
        "Post-epoch emulator, lease or deadline differs",
    )
    for label in ("host", "namespace"):
        meta = read(post / f"{label}-ready.json")
        need(
            meta == receipt["managed_capture"][label]
            and meta["deadline_utc"] == DEADLINE
            and meta["unit_properties"]["ActiveState"] == "active"
            and meta["unit_properties"]["RuntimeMaxUSec"] == "15min"
            and meta["unit_properties"]["KillMode"] == "control-group"
            and meta["header24"] == HOST_PCAP_HEADER.hex(),
            f"Post-epoch {label} capture readiness differs",
        )
    need(
        read(post / "route4.json") == read(post / "route6.json") == []
        and [link["ifname"] for link in read(post / "links.json")] == ["lo"],
        "Post-epoch namespace containment differs",
    )
    return receipt


def unit_gate(post: Path, unit: str) -> None:
    result = (post / f"{unit}-final-unit.txt").read_text()
    journal = (post / f"{unit}-journal.log").read_text()
    required = (
        "ActiveState=active",
        "SubState=exited",
        "MainPID=0",
        "Result=success",
        "ExecMainStatus=0",
        "NetworkNamespacePath=/proc/774195/ns/net",
    )
    need(
        all(value in result for value in required) and "completed" in journal,
        f"{unit} managed completion differs",
    )


def reports_gate(corpus: Path, first: Path, receipt: dict, modules: tuple) -> dict:
    control, cleanup, readiness, capture, _ = modules
    post = corpus / "raw/post"
    first_raw = first / "raw"
    env = read(first_raw / "runtime-asrun.json")
    plan = read(first_raw / "plans/post-probe.json")
    need(
        plan
        == control.cases.plan(
            "post-probe", control.cases.plans()["post-probe"], env, 15800
        )
        and plan == read(post / "results/post-probe/plan.json")
        and receipt["emulator_starttime"] == env["emulator_starttime"],
        "Immutable post plan or runtime differs",
    )
    report = generic_post(post / "results/post-probe", capture)
    control.outcome_gate(report, "post-probe")
    summary = read(post / "results/summary.json")
    ban_clock = read(first_raw / "results-first-c77/ban-clock.json")
    bound = control.TimingBounds.from_json(ban_clock)
    # The run's preflight timing gate happened before its first socket.
    gate = summary["timing_gate"]
    need(
        summary["phase"] == "post"
        and summary["status"] == "completed"
        and summary["full_file_baseline"] == "not_exercised"
        and summary["capture_receipt_sha256"] == sha(post / "capture-ready.json")
        and summary["readiness_report_sha256"] is None
        and summary["preprobe_baseline"] == "not_exercised_preserve_first_lookup"
        and summary["cases"]
        == {
            "post-probe": {
                "status": "completed",
                "error": "",
                "plan_sha256": sha(first_raw / "plans/post-probe.json"),
            }
        }
        and gate["phase"] == "post"
        and gate["host_window"] == [1900, 2400]
        and gate["native_getdatetime_seconds_proven"] is False
        and 1900 <= gate["host_elapsed_seconds"] < 2400
        and abs((bound.ack_utc - bound.request_utc).total_seconds() - 0.015954)
        < 0.000001
        and bound.emulator_pid == PID
        and bound.image_inode == INODE
        and bound.namespace_inode == NS,
        "Post first lookup, timing bracket or no-readiness scope differs",
    )
    need(
        when(report["started_at_utc"]) > bound.ack_utc + dt.timedelta(seconds=1900)
        and when(report["started_at_utc"]) < bound.ack_utc + dt.timedelta(seconds=2400)
        and when(report["recorded_at_utc"]) < when(DEADLINE),
        "Post capture is outside host-relative window",
    )
    parent = read(post / "parent-post-acceptance.json")
    need(
        parent["status"] == "parent_post_probe_semantics_and_paired_bytes_accepted"
        and parent["missed_pre_window"] is True
        and parent["exact_native1800_boundary_measured"] is False
        and parent["connections"] == 1
        and parent["cleanup_not_started"] is True,
        "Parent post-scope receipt differs",
    )
    unit_gate(post, "post")
    guard_source = read(post / "cleanup-guard-plan/plan.json")
    post_sha = sha(post / "results/post-probe/report.json")
    need(
        guard_source == cleanup.make_plan("guard", env, post_sha, None)
        and guard_source == read(post / "cleanup-guard/plan.json"),
        "Owned guard source plan differs",
    )
    guard = capture.verify_capture(post / "cleanup-guard")
    cleanup.semantic(guard, "guard")
    parent = read(post / "parent-guard-acceptance.json")
    need(
        parent["status"] == "parent_exact_owned_guard_accepted"
        and parent["completed_actions"] == 12
        and parent["original_accounts_not_selected"] is True
        and parent["delete_not_started"] is True,
        "Parent guard approval scope differs",
    )
    unit_gate(post, "guard")
    delete_source = read(post / "cleanup-delete-plan/plan.json")
    need(
        delete_source
        == cleanup.make_plan(
            "delete", env, post_sha, sha(post / "cleanup-guard/report.json")
        )
        and delete_source == read(post / "cleanup-delete/plan.json")
        and [
            step["op"] for step in delete_source["steps"] if step["op"] == "send"
        ].count("send")
        == 7,
        "Owned delete/readback source plan differs",
    )
    deleted = capture.verify_capture(post / "cleanup-delete")
    cleanup.semantic(deleted, "delete")
    unit_gate(post, "delete")
    need(
        read(post / "postflight/plan.json") == read(first_raw / "plans/readiness.json"),
        "Control-only postflight source differs",
    )
    after = capture.verify_capture(post / "postflight")
    readiness.readiness(after)
    unit_gate(post, "postflight")
    need(
        len(report["events"]) == 14
        and guard["completed_actions"] == 12
        and deleted["completed_actions"] == 18
        and after["completed_actions"] == 18
        and when(report["recorded_at_utc"])
        < when(guard["started_at_utc"])
        < when(deleted["started_at_utc"])
        < when(after["started_at_utc"]),
        "Post, guard, delete, postflight chronology differs",
    )
    return {
        "post": report,
        "guard": guard,
        "delete": deleted,
        "postflight": after,
    }


def packet_gate(corpus: Path, first: Path, reports: dict, tcp) -> dict:
    post = corpus / "raw/post"
    pre = corpus / "raw/pre"
    guest_file = post / "lab-guest-final.pcap"
    namespace_file = post / "lab-namespace.pcap"
    guest_bytes = guest_file.read_bytes()
    first_prefix = (first / "raw/lab-guest.pcap").read_bytes()
    need(
        guest_bytes.startswith(first_prefix)
        and (pre / "primary-syn.pcap").read_bytes() == HOST_PCAP_HEADER
        and (pre / "lab-namespace.pcap").read_bytes() == HOST_PCAP_HEADER
        and (post / "primary-syn.pcap").read_bytes() == HOST_PCAP_HEADER,
        "First-to-later guest continuity or primary silence differs",
    )
    guest = tcp.read_packets(guest_file)
    namespace = tcp.read_packets(namespace_file)
    first_guest = tcp.read_packets(first / "raw/lab-guest.pcap")
    first_syns = [
        p
        for p in first_guest
        if p["dst_port"] == 5500 and p["flags"] & 2 and not p["flags"] & 16
    ]
    guest_syns = [
        p
        for p in guest
        if p["dst_port"] == 5500 and p["flags"] & 2 and not p["flags"] & 16
    ]
    ns_syns = [
        p
        for p in namespace
        if p["dst_port"] == 15800 and p["flags"] & 2 and not p["flags"] & 16
    ]
    need(
        len(first_syns) == 13
        and len(guest_syns) == 17
        and len(ns_syns) == 4
        and [p["src_port"] for p in guest_syns[:13]]
        == [p["src_port"] for p in first_syns]
        and not any(
            p["src_port"] in {15500, 15501} or p["dst_port"] in {15500, 15501}
            for p in namespace
        ),
        "Unexpected SYN or primary bridge use during unobserved idle gap",
    )
    ports = []
    counts = {}
    for name, report in reports.items():
        connects = [event for event in report["events"] if event["event"] == "connect"]
        need(len(connects) == 1, f"{name} connection count differs")
        event = connects[0]
        port = event["local_address"][1]
        ports.append(port)
        now_us = (
            int(when(report["started_at_utc"]).timestamp() * 1_000_000)
            + event["elapsed_ns"] // 1000
        )
        values = []
        for label, packets, client, server, target in (
            ("namespace", namespace, "127.0.0.1", "127.0.0.1", 15800),
            ("guest", guest, "10.0.2.2", "10.0.2.15", 5500),
        ):
            flow = tcp.lifetime(packets, (client, port), (server, target), now_us)
            sent = tcp.stream(flow, (client, port), (server, target))
            received = tcp.stream(flow, (server, target), (client, port))
            expected = report["streams"][event["connection"]]
            need(
                len(flow) > 0
                and flow[0]["flags"] & 2
                and sent.hex() == expected["sent_hex"]
                and received.hex() == expected["received_hex"],
                f"{name}/{label} paired TCP bytes or tail differs",
            )
            values.append((len(flow), len(sent), len(received)))
        need(values[0][1:] == values[1][1:], f"{name} paired view differs")
        counts[name] = {
            "namespace_packets": values[0][0],
            "guest_packets": values[1][0],
            "sent_bytes": values[0][1],
            "received_bytes": values[0][2],
        }
    need(
        len(set(ports)) == 4
        and [p["src_port"] for p in guest_syns[-4:]] == ports
        and [p["src_port"] for p in ns_syns] == ports,
        "Four later lifetimes or ordering differ",
    )
    return counts


def stopped_gate(corpus: Path, first: Path, manifest: dict) -> dict:
    post = corpus / "raw/post"
    gate = read(post / "stopped-read-gate.json")
    terminal = read(post / "terminal.json")
    need(
        gate["image_inode"] == INODE
        and gate["image_fd_owners"] == []
        and gate["emulator_pid_absent"] is True
        and gate["source_start_ticks"] == int(START)
        and terminal["emulator_absent"] is True
        and terminal["sheep_wrapper_absent"] is True
        and terminal["bridge_pids_absent"] is True
        and terminal["stopped_image_inode"] == INODE
        and "not orderly OS shutdown" in terminal["retirement"]
        and when(terminal["utc"]) < when(DEADLINE),
        "Stopped and FD-free extraction boundary differs",
    )
    for key, name in (
        ("guest_pcap", "lab-guest-final.pcap"),
        ("namespace_pcap", "lab-namespace.pcap"),
        ("primary_pcap", "primary-syn.pcap"),
    ):
        path = post / name
        need(
            terminal[key] == {"bytes": path.stat().st_size, "sha256": sha(path)},
            f"Final {key} bytes differ",
        )
    for name in (
        "c81-terminal-units.txt",
        "lab-terminal-units.txt",
        "bridge-terminal-units.txt",
    ):
        data = (post / name).read_text()
        expected = {
            "c81-terminal-units.txt": 3,
            "lab-terminal-units.txt": 2,
            "bridge-terminal-units.txt": 2,
        }[name]
        need(
            data.count("ActiveState=inactive") == expected
            and data.count("MainPID=0") == expected
            and data.count("Result=success") == expected,
            f"Owned terminal units differ: {name}",
        )
    for label in ("host", "namespace"):
        data = (post / f"{label}-terminal-journal.log").read_text()
        need("0 packets dropped by kernel" in data, f"{label} capture drops differ")
    need(
        "0 packets captured" in (post / "host-terminal-journal.log").read_text()
        and (post / "primary-syn.pcap").read_bytes() == HOST_PCAP_HEADER,
        "Primary SYN isolation differs",
    )
    hashes = {}
    for line in (post / "stopped-assets.sha256").read_text().splitlines():
        digest, path = line.split("  ", 1)
        hashes[Path(path).name] = digest
    need(
        hashes == {"working.dsk": WORKING, "base.dsk": BASE, "rom": ROM},
        "Stopped working/base/ROM hash receipt differs",
    )
    prep = read(first / "preparation/preflight.json")
    need(
        prep["working.dsk"]["inode"] == INODE
        and prep["working.dsk"]["sha256"] == BASE
        and prep["base.dsk"]["sha256"] == BASE
        and prep["rom"]["sha256"] == ROM
        and prep["banned_absent"] is True
        and prep["original_user_count"] == 2,
        "Original immutable preparation baseline differs",
    )
    filenames = {
        "admin": (11193, 734),
        "fixture-low": (11201, 734),
        "Prefs": (11202, 175),
        "server-data": ("11183-4352-0", 616821),
        "server-rsrc": ("11183-4353-1", 38460),
    }
    catalog = (post / "stopped-catalog.txt").read_text()
    need("Banned" not in catalog, "Banned file appeared after temporary expiry")
    for name, (identifier, size) in filenames.items():
        path = post / "stopped-hfs" / f"{name}.bin"
        need(
            path.stat().st_size == size
            and sha(path) == prep["files"][name]["sha256"]
            and prep["files"][name]["catalog"] == str(identifier),
            f"Original stopped fork changed: {name}",
        )
    allocated = (post / "stopped-allocated-catalog.txt").read_text()
    deleted = (post / "stopped-deleted-catalog.txt").read_text()
    for name, directory, data_id, digest in (
        (
            "m-expiry-zero",
            11754,
            11755,
            "d7c4f728b21c6f1c060cc94ff2d0151f5ee6e29929774a4e026bf59b1ef04ae6",
        ),
        (
            "m-expiry-protected",
            11756,
            11757,
            "ea68398dd65a2bd0d955f155a3265dcc64fc9f0a7607ef02e61d2641a4d956a8",
        ),
    ):
        path = (
            post
            / "stopped-hfs"
            / f"owned-{'zero' if directory == 11754 else 'protected'}.bin"
        )
        need(
            f"d/d {directory}:\tTrash/{name}" in allocated
            and f"-/r {data_id}:\tTrash/{name}/UserData" in allocated
            and name not in deleted
            and sha(path) == digest
            and path.stat().st_size == 734
            and all(
                "Allocated" in (post / "stopped-hfs" / f"istat-{i}.txt").read_text()
                and f"File Path: /Trash/{name}"
                in (post / "stopped-hfs" / f"istat-{i}.txt").read_text()
                for i in (directory, data_id)
            ),
            f"Owned {name} allocated Trash footprint differs",
        )
    return {"working_sha256": WORKING, "owned_folders_allocated_in_trash": 2}


def verify(corpus: Path = CORPUS, first: Path = FIRST) -> dict:
    manifest = inventory(corpus, first)
    source_gate(corpus, manifest)
    raw = corpus / "raw"
    clock_gate(raw)
    pre_gate(raw)
    modules = frozen(corpus)
    receipt = post_receipt_gate(raw)
    reports = reports_gate(corpus, first, receipt, modules)
    flows = packet_gate(corpus, first, reports, modules[4])
    stopped = stopped_gate(corpus, first, manifest)
    return {
        "status": "verified_later_epoch_only",
        "pre_window": "missed_no_probe",
        "post_host_elapsed_seconds": read(raw / "post/results/summary.json")[
            "timing_gate"
        ]["host_elapsed_seconds"],
        "later_flows": flows,
        "cleanup": "owned_delete_and_control_postflight_passed",
        "stopped": stopped,
        "exact_1800_boundary_proven": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", nargs="?", type=Path, default=CORPUS)
    parser.add_argument("--first", type=Path, default=FIRST)
    args = parser.parse_args()
    print(json.dumps(verify(args.corpus, args.first), indent=2))


if __name__ == "__main__":
    main()
