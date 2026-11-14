#!/usr/bin/env python3
"""Replay the frozen Hotline 1.9 field-212/325 native case offline."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib
import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-14/native-path-fields-01"
)
PREFIX = "evidence/gap-remediation/2026-11-14/native-path-fields-01/"
PLAN = "dac0a99b766855d07005195c279f34396ea6c966308ba0bb7ee00fb725c0f947"
CASES = "eeca1a3b9c150c25de4c6e3e0d1cef9ff2f187c3dc112f6b1d4025bc5ce4f5b3"
CONTROL = "6d7dbe35c919b648b8e0ae6370c3414ab577b949e38a3fd8224e1cb4f60b1371"
SOURCE_APPROVAL = "f59977429992350607fa9ddcc7a56774577030a2f0f706624cdc8350a7e02760"
HELPER_APPROVAL = "65b56c87f306dd31521056eca22085e711071d6698b52fd9bba3d17f3431dd45"
DATA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
BASE = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
ROM = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
EXE = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
PID, START, NS, INODE = 1058709, "8937287", 4026533805, 5999397982
DEADLINE = "2026-11-14T14:09:46.041564+00:00"
PORTS = {"readiness": 52304, "case": 39238}
FORKS = {
    "admin": "26612ad46cd91b90050feacf517d32a9e56d4a4aa92fbe6618eaf6e9e5ac60a3",
    "fixture-low": "fce81359d0efcfc6c2dbf42852db66b0fb7a404b2889162b8f8fad81361ce2d5",
    "Prefs": "4ed2b3e14e6e8a6cf246d16f7d1b98f0b91d1b09f6ab5497de1056a6f617d196",
    "server-data": DATA,
    "server-rsrc": "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12",
}


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: Path) -> dict:
    return json.loads(path.read_text())


def pins(path: Path) -> dict[str, str]:
    lines = path.read_text().splitlines()
    entries = [line.split("  ") for line in lines]
    need(
        all(len(entry) == 2 and len(entry[0]) == 64 for entry in entries),
        "Pin syntax differs",
    )
    result = {name: digest for digest, name in entries}
    need(len(result) == len(lines), "Duplicate pinned path")
    return result


def inventory(corpus: Path) -> dict:
    need(corpus.is_dir() and not corpus.is_symlink(), "Corpus root is a symlink")
    for root, dirs, files in os.walk(corpus, followlinks=False):
        for name in (*dirs, *files):
            need(
                not (Path(root) / name).is_symlink(),
                f"Corpus symlink is not portable: {Path(root) / name}",
            )
    manifest = read(corpus / "manifest.json")
    need(
        manifest["case_status"] == "completed"
        and manifest["readiness_status"] == "completed"
        and manifest["readiness_actions"] == 18
        and manifest["case_request_count"] == 82
        and manifest["mutation_count"] == 20
        and manifest["case_frames"] == 84
        and manifest["case_views"] == 31,
        "Corpus scope differs",
    )
    files = manifest["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(actual == set(files), "Corpus inventory differs")
    for name, digest in files.items():
        need(
            not Path(name).is_absolute()
            and ".." not in Path(name).parts
            and sha(corpus / name) == digest,
            f"Corpus file differs: {name}",
        )
    expected = {**files, "manifest.json": sha(corpus / "manifest.json")}
    lines = (corpus / "SHA256SUMS").read_text().splitlines()
    need(
        len(lines) == len(expected)
        and set(lines)
        == {f"{digest}  {PREFIX}{name}" for name, digest in expected.items()},
        "Root-relative SHA inventory differs",
    )
    return manifest


def trusted_sources(corpus: Path) -> None:
    """Authenticate approved names and bytes before importing retained Python."""
    prep, epoch = corpus / "raw/preparation", corpus / "raw/epoch"
    source_pin = prep / "approved-source-closure.sha256"
    helper_pin = prep / "approved-helpers.sha256"
    need(
        sha(source_pin) == SOURCE_APPROVAL and sha(helper_pin) == HELPER_APPROVAL,
        "Trusted source approval changed before import",
    )
    approved, helpers = pins(source_pin), pins(helper_pin)
    need(
        len(approved) == 37
        and len(helpers) == 3
        and all(
            name.startswith("scripts/")
            and len(Path(name).parts) == 2
            and Path(name).suffix == ".py"
            for name in (*approved, *helpers)
        )
        and approved["scripts/native_path_fields_cases.py"] == CASES
        and approved["scripts/native_path_fields_control.py"] == CONTROL,
        "Trusted source names/ownership differ",
    )
    for folder, expected in (
        (epoch / "sources", set(approved)),
        (epoch / "helper-sources", set(helpers)),
        (prep / "proposed-sources", set(approved) | set(helpers)),
    ):
        need(
            folder.is_dir()
            and not folder.is_symlink()
            and {f"scripts/{path.name}" for path in folder.iterdir()} == expected
            and all(
                path.is_file() and not path.is_symlink() for path in folder.iterdir()
            ),
            "Frozen source directory inventory differs",
        )
    freeze = read(epoch / "source-freeze.json")
    proposed = read(prep / "proposed-source-closure.json")["hashes"]
    need(
        freeze["hashes"]
        == proposed
        == {Path(name).name: digest for name, digest in approved.items()}
        and freeze["helper_hashes"]
        == {Path(name).name: digest for name, digest in helpers.items()},
        "Frozen closure differs from trusted approval",
    )
    for name, digest in (*approved.items(), *helpers.items()):
        basename = Path(name).name
        need(
            sha(epoch / "sources" / basename) == digest
            if name in approved
            else sha(epoch / "helper-sources" / basename) == digest,
            f"Approved frozen byte differs: {name}",
        )
        need(
            sha(prep / "proposed-sources" / basename) == digest,
            f"Approved proposed byte differs: {name}",
        )


@contextmanager
def frozen(raw: Path):
    before_modules = sys.modules.copy()
    before_path = sys.path.copy()
    before_bytecode = sys.dont_write_bytecode
    freeze = read(raw / "source-freeze.json")
    root = raw / "sources"
    try:
        sys.dont_write_bytecode = True
        for name, digest in freeze["hashes"].items():
            need(sha(root / name) == digest, f"Frozen source differs: {name}")
            sys.modules.pop(Path(name).stem, None)
        sys.path.insert(0, str(root))
        modules = tuple(
            importlib.import_module(name)
            for name in (
                "native_path_fields_control",
                "native_path_fields_cases",
                "native_control_readiness",
                "protocol_capture",
                "pcap_tcp",
            )
        )
        for module in modules:
            source_path = module.__file__
            need(isinstance(source_path, str), "Frozen module lacks source path")
            assert isinstance(source_path, str)
            name = Path(source_path).name
            need(
                sha(Path(source_path)) == freeze["hashes"][name],
                "Loaded source differs",
            )
        yield modules
    finally:
        for name in set(sys.modules) - before_modules.keys():
            del sys.modules[name]
        sys.modules.update(before_modules)
        sys.path[:] = before_path
        sys.dont_write_bytecode = before_bytecode


def source_identity(corpus: Path, modules) -> dict:
    control, cases, _, _, _ = modules
    epoch, prep = corpus / "raw/epoch", corpus / "raw/preparation"
    freeze = read(epoch / "source-freeze.json")
    proposed = read(prep / "proposed-source-closure.json")["hashes"]
    approved = pins(prep / "approved-source-closure.sha256")
    need(
        len(proposed) == len(freeze["hashes"]) == len(approved) == 37
        and approved == {f"scripts/{name}": digest for name, digest in proposed.items()}
        and freeze["hashes"] == proposed,
        "Approved 37-module closure differs",
    )
    for name, digest in proposed.items():
        need(
            sha(epoch / "sources" / name) == digest
            and sha(prep / "proposed-sources" / name) == digest,
            f"Frozen/proposed source differs: {name}",
        )
    helpers = pins(prep / "approved-helpers.sha256")
    need(
        len(helpers) == 3
        and freeze["helper_hashes"]
        == {Path(name).name: digest for name, digest in helpers.items()},
        "Helper approval differs",
    )
    for name, digest in freeze["helper_hashes"].items():
        need(
            sha(epoch / "helper-sources" / name) == digest
            and sha(prep / "proposed-sources" / name) == digest,
            f"Frozen helper differs: {name}",
        )
    owned = pins(prep / "approved-path-fields-sources.sha256")
    need(
        owned
        == {
            "scripts/native_path_fields_cases.py": CASES,
            "scripts/native_path_fields_control.py": CONTROL,
        }
        and sha(Path(control.__file__)) == CONTROL
        and sha(Path(cases.__file__)) == CASES,
        "Approved path source differs",
    )
    scripts = pins(prep / "script-SHA256SUMS")
    need(len(scripts) == 8, "Prewritten script inventory differs")
    for name, digest in scripts.items():
        need(
            name.startswith("state/native-sessions/native-path-fields-preparation-01/")
            and sha(prep / "scripts" / Path(name).name) == digest,
            "Prewritten script differs",
        )
    plan_path = epoch / "path-fields-plan/plan.json"
    plan = read(plan_path)
    need(
        sha(plan_path) == PLAN
        and plan == cases.source_plan(plan["environment"], 15900)
        and read(epoch / "path-fields-plan/source-hashes.json")
        == {
            "plan.json": PLAN,
            "native_path_fields_cases.py": CASES,
            "native_path_fields_control.py": CONTROL,
        }
        and sha(epoch / "coordinator/plan.json") == PLAN
        and sha(epoch / "parent-regenerated-plan/plan.json") == PLAN,
        "As-run plan/source differs",
    )
    need(
        read(epoch / "source-prerun-check.json")["status"]
        == "all_frozen_sources_match_current",
        "Pre-run source check missing",
    )
    return plan


def identity(corpus: Path, plan: dict) -> None:
    epoch, prep = corpus / "raw/epoch", corpus / "raw/preparation"
    runtime, receipt = read(epoch / "runtime.json"), read(epoch / "capture-ready.json")
    disk, capture = (
        read(epoch / "disk-ready.json"),
        read(epoch / "guest-capture-ready.json"),
    )
    need(
        runtime == plan["environment"]
        and runtime["fixture_profile"] == "control-only"
        and runtime["emulator_pid"] == receipt["emulator_pid"] == PID
        and str(runtime["emulator_starttime"])
        == str(receipt["emulator_starttime"])
        == START
        and runtime["emulator_netns_inode"] == receipt["emulator_netns_inode"] == NS
        and runtime["owned_working_image_inode"]
        == receipt["owned_working_image_inode"]
        == INODE
        and runtime["emulator_sha256"] == receipt["emulator_sha256"] == EXE
        and runtime["native_data_sha256"] == receipt["native_data_sha256"] == DATA
        and runtime["source_base_sha256"] == BASE
        and runtime["rom_sha256"] == ROM
        and receipt["deadline_utc"]
        == (epoch / "case-deadline.utc").read_text().strip()
        == DEADLINE,
        "Runtime/receipt identity differs",
    )
    for value in (disk, capture):
        need(
            value["pid"] == PID
            and str(value["start_ticks"]) == START
            and value["uid"] == 1000
            and value["netns_inode"] == NS
            and value["working_inode"] == INODE
            and value["exe_sha256"] == EXE,
            "Disk/capture identity differs",
        )
    need(
        disk["phase"] == "disk"
        and capture["phase"] == "capture"
        and capture["guest_fd"] == 16,
        "Guest capture boundary differs",
    )
    prepared = read(prep / "preflight.json")["prepared"]
    need(
        prepared["base.dsk"]["sha256"] == BASE
        and prepared["working.dsk"]["sha256"] == BASE
        and prepared["rom"]["sha256"] == ROM
        and prepared["working.dsk"]["inode"] == INODE,
        "Stopped prepared asset differs",
    )
    epoch_start = dt.datetime.fromisoformat(
        (epoch / "epoch-start.utc").read_text().strip()
    )
    deadline = dt.datetime.fromisoformat(DEADLINE)
    case_start = dt.datetime.fromisoformat(
        read(epoch / "coordinator/report.json")["started_at_utc"]
    )
    need(
        719 <= (deadline - epoch_start).total_seconds() <= 721
        and (deadline - case_start).total_seconds() >= 390,
        "Fixed epoch or case margin differs",
    )
    need(
        read(epoch / "source-freeze.json")["docs_head"] != ""
        and receipt["managed_lock"]["unit"]
        == "mothra-native-path-fields-01-lease.service",
        "Managed source/lock receipt differs",
    )
    lock = receipt["managed_lock"]
    need(
        lock["pid"] > 0
        and lock["fd"] >= 0
        and lock["lock_inode"] > 0
        and lock["busy_exit"] == 1
        and lock["unit_properties"]["MainPID"] == str(lock["pid"])
        and lock["unit_properties"]["ActiveState"] == "active",
        "Managed oracle lease proof differs",
    )
    for view, expected_ns, filename in (
        ("host", 4026531840, "primary-syn.pcap"),
        ("namespace", NS, "lab-namespace.pcap"),
    ):
        ready = read(epoch / f"{view}-ready.json")
        managed = receipt["managed_capture"][view]
        need(
            ready == managed
            and ready["unit"] == f"mothra-native-path-fields-01-{view}.service"
            and ready["pid"] > 0
            and ready["fd"] >= 0
            and ready["netns_inode"] == expected_ns
            and ready["deadline_utc"] == DEADLINE
            and ready["capture"].endswith("/" + filename)
            and ready["header24"] == (epoch / filename).read_bytes()[:24].hex()
            and ready["unit_properties"]["ActiveState"] == "active"
            and ready["unit_properties"]["MainPID"] == str(ready["pid"]),
            f"{view} managed capture receipt differs",
        )
    need(
        capture["header24"] == (epoch / "lab-guest.pcap").read_bytes()[:24].hex()
        and capture["guest_pcap"].endswith("/lab-guest.pcap")
        and receipt["guest_pcap"] == capture["guest_pcap"],
        "Guest capture receipt differs",
    )


def outcomes(corpus: Path, plan: dict, report: dict, modules) -> None:
    control, cases, _, _, _ = modules
    need(
        report["status"] == "completed"
        and report["error"] == ""
        and report["request_count"] == 82
        and report["mutation_count"] == 20
        and len(report["actions"]) == 82
        and len(report["frames"]) == 84
        and len(report["events"]) == 173
        and len(report["views"]) == 31
        and len(report["results"]) == 12
        and len(report["progress"]) == 81
        and report["terminals"] == {"main": "eof"}
        and report["unparsed_hex"] == {"main": ""}
        and report["oracle_sha256"] == DATA,
        "Case count/status/tail differs",
    )
    control.verify_report(plan, report)
    need(
        report["own_uid"]
        == next(v["uid"] for v in report["views"] if v["label"] == "initial-roster")
        and report["current_case_index"] is None,
        "Dynamic UID/progress differs",
    )
    for index, result in enumerate(report["results"]):
        cell = cases.cells()[index]
        need(
            result["index"] == index
            and result["field"] == cell["field"]
            and result["value_hex"] == cell["value_hex"]
            and result["status"] == 0
            and result["selected_parent"] == ("H" if index < 6 else "news-high"),
            f"Observed cell {index} differs",
        )
        if index < 6:
            need(
                result["after_info_parent_hex"] == cases.HIGH.hex()
                and result["error_fields"] == [],
                f"Move location/error {index} differs",
            )
        else:
            need(
                result["names"]
                == [{"field": 323, "kind": 3, "name_hex": cases.CATEGORY.hex()}],
                f"News folder {index} differs",
            )
    manifest = read(corpus / "manifest.json")
    summaries = [
        {key: value for key, value in result.items() if key != "same_parent_noop"}
        for result in report["results"]
    ]
    need(
        manifest["twelve_tested_values_and_observations"] == summaries,
        "Manifest outcome summary differs",
    )


def paired(corpus: Path, report: dict, modules) -> dict:
    epoch = corpus / "raw/epoch"
    _, _, readiness, capture, tcp = modules
    pre = capture.verify_capture(epoch / "readiness")
    readiness.readiness(pre)
    need(
        pre["status"] == "completed" and pre["completed_actions"] == 18,
        "Readiness differs",
    )
    host = tcp.read_packets(epoch / "primary-syn.pcap")
    need(
        host == [] and (epoch / "primary-syn.pcap").stat().st_size == 24,
        "Primary SYN capture differs",
    )
    expected_reports = {"readiness": pre, "case": report}
    derived = read(corpus / "derived/flows.json")
    need(len(derived["flows"]) == 2, "Derived flow count differs")
    measured = {}
    for view, client_ip, server_ip, server_port in (
        ("namespace", "127.0.0.1", "127.0.0.1", 15900),
        ("guest", "10.0.2.2", "10.0.2.15", 5500),
    ):
        packets = tcp.read_packets(epoch / f"lab-{view}.pcap")
        syns = [p for p in packets if p["flags"] & 2 and not p["flags"] & 16]
        need(
            len(syns) == 2
            and {p["src_port"] for p in syns} == set(PORTS.values())
            and all(
                (p["src_ip"], p["dst_ip"], p["dst_port"])
                == (client_ip, server_ip, server_port)
                for p in syns
            ),
            f"{view} SYN/endpoint differs",
        )
        need(
            all(
                (p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"])
                in {
                    (client_ip, port, server_ip, server_port) for port in PORTS.values()
                }
                | {(server_ip, server_port, client_ip, port) for port in PORTS.values()}
                for p in packets
            ),
            f"{view} unexpected TCP lifetime",
        )
        for label, port in PORTS.items():
            sent = tcp.stream(packets, (client_ip, port), (server_ip, server_port))
            received = tcp.stream(packets, (server_ip, server_port), (client_ip, port))
            expected = expected_reports[label]["streams"]["main"]
            need(
                sent.hex() == expected["sent_hex"]
                and received.hex() == expected["received_hex"],
                f"{view}/{label} PCAP/report byte mismatch",
            )
            item = next(f for f in derived["flows"] if f["label"] == label)
            details = item["views"][view]
            need(
                details["client"] == [client_ip, port]
                and details["server"] == [server_ip, server_port]
                and details["sent"]["bytes"] == len(sent)
                and details["received"]["bytes"] == len(received)
                and details["sent"]["sha256"] == hashlib.sha256(sent).hexdigest()
                and details["received"]["sha256"]
                == hashlib.sha256(received).hexdigest()
                and (corpus / details["sent"]["file"]).read_bytes() == sent
                and (corpus / details["received"]["file"]).read_bytes() == received,
                f"{view}/{label} derived stream differs",
            )
            selected = [
                p
                for p in packets
                if p["src_port"] in {port, server_port}
                and p["dst_port"] in {port, server_port}
            ]
            terminals = [
                {
                    "index": p["index"],
                    "flags": p["flags"],
                    "timestamp_us": p["timestamp_us"],
                    "payload_hex": p["payload_hex"],
                }
                for p in selected
                if p["flags"] & 5
            ]
            need(
                details["terminal_flags"] == terminals
                and details["packet_count"] == len(selected),
                f"{view}/{label} complete TCP lifetime differs",
            )
            measured[f"{view}/{label}"] = (len(sent), len(received))
    need(
        set(measured.values()) == {(231, 2759), (11529, 8295)},
        "Readiness/case stream lengths differ",
    )
    return measured


def stopped(corpus: Path) -> None:
    epoch, prep = corpus / "raw/epoch", corpus / "raw/preparation"
    hfs, retire = (
        read(epoch / "stopped-hfs-summary.json"),
        read(epoch / "emulator-retire.json"),
    )
    need(
        hfs["pid_gone"] is True
        and hfs["root_fuser_exit"] == 1
        and hfs["working_inode"] == INODE
        and hfs["original_ticks"] == {"1099659": "767842", "1012834": "2357813"}
        and retire["pid"] == PID
        and retire["start_ticks"] == int(START)
        and retire["gone_final"] is True
        and "forced emulator TERM" in retire["reason"],
        "Stopped owner/retirement differs",
    )
    need(
        dt.datetime.fromisoformat(retire["utc"]) < dt.datetime.fromisoformat(DEADLINE)
        and dt.datetime.fromisoformat((epoch / "units-stopped.utc").read_text().strip())
        < dt.datetime.fromisoformat(DEADLINE),
        "Retirement missed fixed deadline",
    )
    need(
        (epoch / "working-fuser-after.exit").read_text().strip() == "1"
        and (epoch / "working-fuser-after.stdout").read_bytes() == b""
        and (epoch / "working-fuser-after.stderr").read_bytes() == b"",
        "Stopped image still held",
    )
    for key, filename in (
        ("fls-full", "stopped-fls-full.stdout"),
        ("fls-allocated", "stopped-fls-allocated.stdout"),
    ):
        result = hfs["results"][key]
        need(
            result["exit"] == 0 and result["sha256"] == sha(epoch / filename),
            "Stopped catalogue differs",
        )
    full = (epoch / "stopped-fls-full.stdout").read_text().splitlines()
    allocated = (epoch / "stopped-fls-allocated.stdout").read_text().splitlines()
    need(full == allocated and len(full) >= 5000, "Allocated/full HFS differs")
    marker = read(corpus / "derived/stopped-marker-catalogue.json")
    need(
        marker["catalogue"] == "raw/epoch/stopped-fls-allocated.stdout"
        and marker["entries"]
        == [
            {"line_number": i + 1, "line": line}
            for i, line in enumerate(allocated)
            if "m-path47" in line or "m-n47" in line or "m-cat47" in line
        ],
        "Stopped marker catalogue differs",
    )
    names = [row["line"] for row in marker["entries"]]
    baseline_catalogue = read(prep / "files-news-catalog.json")["entries"]
    need(
        all(
            [
                line
                for line in hfs["files_news"]
                if f"Hotline19/{kind}" in line
                and "m-path47" not in line
                and "m-n47" not in line
                and "m-cat47" not in line
            ]
            == baseline_catalogue[kind]
            for kind in ("Files", "News")
        ),
        "Original Files/News catalogue differs",
    )
    need(
        len(names) == 11
        and sum(
            "Trash/m-path47/H-" in line and line.endswith(f"/p{i}")
            for i in range(6)
            for line in names
        )
        == 6
        and any("Trash/m-cat47" in line for line in names)
        and any("Trash/m-n47" in line for line in names)
        and not any(
            "Hotline19/Files/m-path47" in line or "Hotline19/News/m-n47" in line
            for line in allocated
        ),
        "Owned cleanup/Trash path differs",
    )
    prepared = read(prep / "preflight.json")
    need(
        hfs["active_users"]
        == [
            "-/r 11193:\tHotline19/Users/admin/UserData",
            "-/r 11201:\tHotline19/Users/fixture-low/UserData",
        ]
        and not hfs["banned_lines"]
        and all(line in allocated for line in hfs["active_users"]),
        "Original users/Banned state differs",
    )
    for name, digest in FORKS.items():
        item = hfs["results"][f"icat-{name}"]
        need(
            item["exit"] == 0
            and item["sha256"] == digest
            and (item["size"] == prepared["forks"][name]["size"]),
            f"Stopped {name} fork differs",
        )
        # No copyrighted fork bytes are packaged; retained command receipt is
        # evidence of a stopped read, not an independently rehashed fork here.
    need(
        hfs["results"]["istat-board"]["exit"] == 0
        and hfs["results"]["istat-board"]["sha256"]
        == sha(epoch / "stopped-istat-board.stdout"),
        "Stopped board stat differs",
    )
    supplement = epoch / "stopped-marker-forks"
    fd_free = read(supplement / "fd-free-before-read.json")
    need(
        fd_free["pid"] == PID
        and fd_free["pid_gone"] is True
        and fd_free["working_inode"] == INODE
        and fd_free["root_fuser_exit"] == 1
        and fd_free["root_fuser_stdout"] == fd_free["root_fuser_stderr"] == "",
        "Supplement owner-free gate differs",
    )
    commands = read(supplement / "commands.json")
    need(len(commands) == 12, "Supplement marker command count differs")
    for item in commands:
        path = supplement / item["stdout_file"]
        need(
            item["exit"] == 0
            and path.stat().st_size == item["size"]
            and sha(path) == item["sha256"],
            "Stopped marker command bytes differ",
        )
    for identifier in range(11747, 11759):
        if identifier == 11748:
            continue
        text = (supplement / f"istat-{identifier}.stdout").read_text()
        matching = [
            line for line in names if line.split(":", 1)[0].endswith(f" {identifier}")
        ]
        need(
            len(matching) == 1
            and f"File Path: /{matching[0].split(chr(9), 1)[1]}" in text
            and f"Catalog Record: {identifier}" in text
            and "File Path: /Trash/" in text
            and ("Type:\tFile" if identifier == 11758 else "Type:\tFolder") in text,
            "Stopped marker type/catalogue differs",
        )
    category = (supplement / "istat-11758.stdout").read_text()
    need(
        "Resource fork size:\t0" in category
        and "File type:\t484c4e5a  HLNZ" in category
        and "File creator:\t48544c53  HTLS" in category
        and sha(supplement / "category-data.bin")
        == "7d82b5826175ca1971249907692fa51823998e11d77dbd577226ee2bde97cd1a",
        "Stopped News category fork differs",
    )
    journal = (epoch / "capture-journal-terminal.txt").read_text()
    need(
        "0 packets captured" in journal
        and "252 packets captured" in journal
        and journal.count("0 packets dropped by kernel") == 2,
        "Managed recorder journal differs",
    )
    units = (epoch / "units-after-stop.txt").read_text()
    need(
        units.count("ActiveState=inactive") == 5
        and units.count("MainPID=0") == 5
        and units.count("Result=success") == 5
        and "ActiveState=active" not in units
        and (epoch / "coordinator.exit").read_text().strip() == "0",
        "Owned unit/case terminal differs",
    )


def verify(corpus: Path = CORPUS) -> dict:
    manifest = inventory(corpus)
    raw = corpus / "raw/epoch"
    trusted_sources(corpus)
    with frozen(raw) as modules:
        plan = source_identity(corpus, modules)
        identity(corpus, plan)
        report = read(raw / "coordinator/report.json")
        outcomes(corpus, plan, report, modules)
        flows = paired(corpus, report, modules)
    stopped(corpus)
    need(
        manifest["retirement"]["forced_term_after_app_quit"] is True,
        "Retirement provenance differs",
    )
    return {"status": "PASS", "case_status": "completed", "flows": flows}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    args = parser.parse_args()
    print(json.dumps(verify(args.corpus), indent=2))


if __name__ == "__main__":
    main()
