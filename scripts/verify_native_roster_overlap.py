#!/usr/bin/env python3
"""Replay the frozen two-session native roster overlap without a VM."""

import argparse
import datetime as dt
import hashlib
import importlib
import json
import sys
from pathlib import Path

SCHEMA = "native-roster-overlap-01"
CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-14/native-roster-overlap-01"
)
PID, START, NS, INODE = 953125, "6421050", "net:[4026532547]", 5973041789
DEADLINE = "2026-11-14T07:09:57.615913+00:00"
SOURCE_HEAD = "58494d779b319853cfb543c9f0c5c06997da07f2"
ORACLE = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
RSRC = "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12"
EXE = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
BASE = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
ROM = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
A7 = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def read(path: Path) -> dict:
    return json.loads(path.read_text())


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def frozen(corpus: Path):
    sys.dont_write_bytecode = True
    path = str(corpus / "raw/sources")
    if path not in sys.path:
        sys.path.insert(0, path)
    return (
        importlib.import_module("native_roster_overlap_control"),
        importlib.import_module("native_roster_overlap_cases"),
        importlib.import_module("native_control_readiness"),
        importlib.import_module("protocol_capture"),
        importlib.import_module("pcap_tcp"),
    )


def inventory(corpus: Path) -> dict:
    manifest = read(corpus / "manifest.json")
    need(
        corpus.name == SCHEMA
        and manifest["schema"] == SCHEMA
        and manifest["source_head"] == SOURCE_HEAD
        and manifest["profile"] == "control-only"
        and manifest["full_file_baseline"] == "not_exercised"
        and manifest["actual_runner_proc_netns"]
        == "not_observed_before_two_second_exit",
        "Corpus identity or profile differs",
    )
    files = manifest["files"]
    actual = {
        str(p.relative_to(corpus))
        for p in corpus.rglob("*")
        if p.is_file() and p.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(actual == set(files) and len(files) + 2 <= 250, "Corpus inventory differs")
    need(
        sum((corpus / name).stat().st_size for name in files) <= 80 * 1024 * 1024,
        "Corpus size bound exceeded",
    )
    for name, expected in files.items():
        need(sha(corpus / name) == expected, f"Corpus SHA differs: {name}")
    need(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{digest}  {name}" for name, digest in sorted(files.items())],
        "SHA256SUMS differs",
    )
    return manifest


def source_gate(corpus: Path, manifest: dict, modules) -> None:
    raw = corpus / "raw"
    freeze = read(raw / "source-freeze.json")
    need(freeze["source_head"] == SOURCE_HEAD, "As-run source HEAD differs")
    need(
        {name: sha(raw / "sources" / name) for name in freeze["files"]}
        == freeze["files"],
        "Frozen source snapshot differs",
    )
    need(
        freeze["files"]["native_roster_overlap_cases.py"] == manifest["cases_sha256"]
        and freeze["files"]["native_roster_overlap_control.py"]
        == manifest["controller_sha256"]
        and freeze["files"]["native_control_readiness.py"]
        == manifest["readiness_sha256"]
        and (raw / "b71-source.sha256").read_text().splitlines()
        == [
            f"{freeze['files'][name]}  /data/leynos/Projects/hotline-protocol-docs/scripts/{name}"
            for name in (
                "native_roster_overlap_cases.py",
                "native_roster_overlap_control.py",
            )
        ],
        "B71 source hash record differs",
    )
    control, cases, _, capture, _ = modules
    plan = control.prepared(raw / "roster-plan")
    need(
        sha(raw / "roster-plan/plan.json") == manifest["plan_sha256"]
        and plan == cases.source_plan(plan["environment"], cases.MAX_PORT)
        and plan["oracle_sha256"] == capture.ORACLE_SHA256 == ORACLE,
        "Prepared source plan differs",
    )


def identity(corpus: Path) -> dict:
    raw = corpus / "raw"
    prep = read(corpus / "preparation/preflight.json")
    proof = read(raw / "runtime-proof.json")
    receipt = read(raw / "capture-ready.json")
    runtime = read(raw / "runtime-asrun.json")
    need(
        prep["base.dsk"]["sha256"] == BASE
        and prep["working.dsk"]["sha256"] == BASE
        and prep["working.dsk"]["inode"] == INODE
        and prep["rom"]["sha256"] == ROM
        and prep["files"]["server-data"]["sha256"] == ORACLE
        and prep["files"]["server-rsrc"]["sha256"] == RSRC
        and prep["banned_absent"]
        and len(prep["active_users_catalog_lines"]) == 2,
        "Stopped preparation differs",
    )
    need(
        (
            proof["actual_pid"],
            proof["start_ticks"],
            proof["netns"],
            proof["image_inode"],
        )
        == (PID, START, NS, INODE)
        and proof["exe_sha256"] == EXE
        and proof["deadline_utc"] == DEADLINE
        and proof["fd6"].endswith("native-roster-overlap-01/working.dsk")
        and proof["fd16"].endswith("native-roster-overlap-01/lab-guest.pcap")
        and proof["original_pids"] == {"1099659": "767842", "1012834": "2357813"},
        "Actual emulator or original-service identity differs",
    )
    need(
        receipt["emulator_pid"] == PID
        and str(receipt["emulator_starttime"]) == START
        and receipt["emulator_netns"] == NS
        and receipt["emulator_sha256"] == EXE
        and receipt["owned_working_image_inode"] == INODE
        and receipt["deadline_utc"] == DEADLINE
        and receipt["fixture_profile"] == "control-only"
        and receipt["full_file_baseline"] == "not_exercised"
        and receipt["source_a7_sha256"] == A7
        and receipt["ns_routes"] == []
        and receipt["primary_syn_count"] == 0
        and all(runtime[k] == receipt[k] for k in runtime),
        "Runtime/capture receipt identity differs",
    )
    for label in ("host", "namespace"):
        ready = read(raw / f"{label}-ready.json")
        need(
            ready["deadline_utc"] == DEADLINE
            and ready["unit_properties"]["ActiveState"] == "active"
            and ready["unit_properties"]["KillMode"] == "control-group"
            and ready["header24"].startswith("d4c3b2a1"),
            f"{label} recorder readiness differs",
        )
    need(
        read(raw / "route4.json") == [] and read(raw / "route6.json") == [],
        "Routes differ",
    )
    return receipt


def report_gate(corpus: Path, modules) -> dict:
    raw = corpus / "raw"
    control, _, readiness, capture, _ = modules
    preflight = read(raw / "parent-preflight.json")
    need(
        preflight["status"] == "parent_runtime_source_and18_readiness_pass"
        and preflight["initial_parent_replay_path_error"].startswith(
            "parent first used nonexistent captures/readiness"
        )
        and preflight["overlap_socket_actions"] == 0
        and preflight["pid"] == PID
        and preflight["deadline_utc"] == DEADLINE,
        "Parent readiness path correction differs",
    )
    for label in ("readiness", "postflight"):
        folder = raw / label
        report = capture.verify_capture(folder)
        need(
            report["status"] == "completed" and report["completed_actions"] == 18,
            f"{label} generic capture differs",
        )
        readiness.readiness(report)
        need(
            sha(folder / "plan.json") == sha(raw / "control-plans/readiness.json"),
            f"{label} source readiness plan differs",
        )
    result = read(raw / "results/report.json")
    plan = read(raw / "results/plan.json")
    need(plan == control.prepared(raw / "roster-plan"), "As-run roster plan differs")
    need(
        result["status"] == result["overlap_status"] == "completed"
        and result["teardown_status"] == "completed"
        and result["old_or_new_snapshot"] == "old"
        and result["error"] == ""
        and result["late_observations"] == []
        and result["unparsed_hex"] == {"a": "", "b": ""}
        and result["completed_actions"] == 35
        and len(result["frames"]) == 16,
        "Native overlap outcome differs",
    )
    need(
        result["plan_sha256"] == sha(raw / "results/plan.json")
        and result["receipt_sha256"] == sha(raw / "capture-ready.json")
        and result["oracle_sha256"] == ORACLE,
        "As-run result identity differs",
    )
    control.verify_operation_map(plan, result)
    entries = {entry["label"]: entry for entry in result["operation_map"]}
    setup = result["frames"][: entries["setup"]["frame_range"][1]]
    recorder = type("FrozenSetup", (), {"frames": setup, "variables": {}})()
    b_update = next(f for f in setup if f["connection"] == "a" and f["type"] == 301)
    from verify_native_shx import fields

    recorder.variables["b_uid"] = fields(b_update)[103]
    a_uid, b_uid = control.check_setup(recorder)
    start, end = entries["overlap-drain"]["frame_range"]
    need(
        control.check_overlap(result["frames"][start:end], a_uid, b_uid) == "old",
        "Old overlap snapshot or five required frames differ",
    )
    stable = entries["stable-drain"]["frame_range"]
    control.exact_rows(
        control.one(result["frames"][slice(*stable)], "a", 0, 13, 1),
        a_uid,
        b_uid,
        b_new=True,
    )
    need(
        not any(f["is_reply"] and f["id"] == 20 for f in result["frames"]),
        "Unobserved direct 304 ACK was invented",
    )
    for f in result["frames"]:
        if f.get("raw_hex"):
            decoded = capture.decode_frame(bytes.fromhex(f["raw_hex"]))
            need(
                all(
                    decoded[key] == f[key]
                    for key in ("flags", "is_reply", "type", "id", "error", "fields")
                ),
                "Decoded drain frame differs from retained raw bytes",
            )
    parent = read(raw / "parent-case-acceptance.json")
    need(
        parent["asrun_plan_equal"] is True
        and parent["status"].startswith(
            "parent_custom_schedule_and_completed_outcome_accepted"
        )
        and parent["packet_pairing_pending"] is True
        and parent["frames"] == 16
        and parent["events"] == 51,
        "Parent overlap receipt differs",
    )
    return result


def streams(corpus: Path, modules, report: dict) -> None:
    raw = corpus / "raw"
    _, _, _, tcp = modules[0], modules[1], modules[3], modules[4]
    host = tcp.read_packets(raw / "primary-syn.pcap")
    namespace = tcp.read_packets(raw / "lab-namespace.pcap")
    guest = tcp.read_packets(raw / "lab-guest.pcap")
    need(not host, "Primary ports received a SYN")
    expected = [
        ("readiness", "main", 58390),
        ("results", "a", 57748),
        ("results", "b", 57750),
        ("postflight", "main", 41566),
    ]
    syn_ports = [
        p["src_port"] for p in namespace if p["flags"] & 2 and not p["flags"] & 16
    ]
    need(
        syn_ports == [port for _, _, port in expected],
        "Four SYN-scoped lifetimes differ",
    )
    need(
        all(
            p["src_port"] not in (15500, 15501) and p["dst_port"] not in (15500, 15501)
            for p in namespace
        ),
        "Namespace capture contacted primary bridge",
    )
    for folder, label, port in expected:
        source = report if folder == "results" else read(raw / folder / "report.json")
        observed = source["streams"][label]
        n_client = ("127.0.0.1", port)
        n_server = ("127.0.0.1", 15820)
        g_client = ("10.0.2.2", port)
        g_server = ("10.0.2.15", 5500)
        for direction, a, b, c, d, key in (
            ("sent", n_client, n_server, g_client, g_server, "sent_hex"),
            ("received", n_server, n_client, g_server, g_client, "received_hex"),
        ):
            n = tcp.stream(namespace, a, b)
            g = tcp.stream(guest, c, d)
            need(
                n == g == bytes.fromhex(observed[key]),
                f"{folder}/{label} {direction} paired bytes or tails differ",
            )
        for name, packets in (("namespace", namespace), ("guest", guest)):
            selected = [
                p for p in packets if p["src_port"] == port or p["dst_port"] == port
            ]
            need(
                len([p for p in selected if p["flags"] & 1]) == 2
                and not any(p["flags"] & 4 for p in selected)
                and selected[-1]["flags"] & 16,
                f"{folder}/{label} {name} TCP close or tail differs",
            )
    need(
        {p["src_port"] for p in guest if p["flags"] & 2 and not p["flags"] & 16}
        == {port for _, _, port in expected},
        "Guest SYN scope has another connection",
    )


def terminal(corpus: Path) -> None:
    raw = corpus / "raw"
    forks = read(raw / "stopped-forks-corrected.json")
    prep = read(corpus / "preparation/preflight.json")
    need(
        forks["stopped_pid_absent"]
        and all(
            item["exit"] == 0
            and item["matches_preflight"]
            and item["sha256"] == prep["files"][name]["sha256"]
            for name, item in forks["files"].items()
        )
        and set(forks["files"]) == set(prep["files"]),
        "Stopped named forks differ",
    )
    first = read(raw / "stopped-forks-and-assets.json")
    need(
        all(item["exit"] == 127 for item in first["files"].values())
        and first["base.dsk"]["matches_preflight"]
        and first["rom"]["matches_preflight"]
        and not first["working.dsk"]["matches_preflight"],
        "Retained initial TSK tool failure or stopped assets differ",
    )
    system = (raw / "terminal-system-units.txt").read_text()
    user = (raw / "terminal-user-units.txt").read_text()
    need(
        "mothra-native-roster-c86-host.service\nActiveState=inactive" in system
        and "mothra-native-roster-c86-namespace.service\nActiveState=inactive" in system
        and "mothra-native-roster-c86-lease.service\nActiveState=inactive" in system
        and "NetworkNamespacePath=/proc/953125/ns/net" in system
        and "mothra-sheep-ee4b4d810c5b.service\nActiveState=inactive" in user
        and "mothra-display-ed0dd3f6ab3e.service\nActiveState=inactive" in user,
        "Owned unit retirement differs",
    )
    journal = (raw / "c86-recorder-journal.log").read_text()
    need(
        journal.count("0 packets dropped by kernel") == 2
        and "0 packets captured" in journal
        and "114 packets captured" in journal,
        "Capture drop or packet count differs",
    )
    need(
        (raw / "c87-run.exit").read_text().strip() == "0"
        and (raw / "c88-postflight.exit").read_text().strip() == "0"
        and "ExecMainStatus=0" in (raw / "c87-unit-final.txt").read_text()
        and "ExecMainStatus=0" in (raw / "c88-unit-final.txt").read_text(),
        "Managed case/postflight result differs",
    )
    need(
        dt.datetime.fromisoformat(forks["recorded_at_utc"])
        < dt.datetime.fromisoformat(DEADLINE),
        "Stopped-fork check exceeded fixed deadline",
    )
    final = read(raw / "terminal-network-lock.json")
    need(
        final["emulator_953125_absent"]
        and final["original_start_ticks"] == {"1099659": "767842", "1012834": "2357813"}
        and final["ss_exit"] == 0
        and final["listeners_ss"].splitlines()
        == ["State Recv-Q Send-Q Local Address:Port Peer Address:Port"]
        and final["image_fuser_stdout"] == ""
        and final["image_fuser_exit"] == 1
        and final["lock_exit"] == 0
        and final["primary_syn_pcap_bytes"] == 24,
        "Post-retirement process, ports, image FD or lock differs",
    )


def verify(corpus: Path = CORPUS) -> None:
    manifest = inventory(corpus)
    modules = frozen(corpus)
    source_gate(corpus, manifest, modules)
    identity(corpus)
    result = report_gate(corpus, modules)
    streams(corpus, modules, result)
    terminal(corpus)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    args = parser.parse_args()
    verify(args.corpus)
    print("native roster overlap: offline replay PASS")


if __name__ == "__main__":
    main()
