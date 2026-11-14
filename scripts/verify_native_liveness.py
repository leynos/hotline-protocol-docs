#!/usr/bin/env python3
"""Replay the frozen native preonline liveness witness without a guest."""

import argparse
import datetime as dt
import hashlib
import importlib
import json
import sys
from contextlib import contextmanager
from pathlib import Path

SCHEMA = "native-liveness-01"
CORPUS = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-14/native-liveness-01"
)
PID, START, NS, INODE = 1221811, "6825819", "net:[4026533605]", 71221932
DEADLINE = "2026-11-14T08:17:11.974963+00:00"
BASE = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
ROM = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
EXE = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
DATA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
RSRC = "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12"
A7 = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"
CASES = "6c475a226bb0a294727fe2d3c3ed01c09e364ac5801ba71913940203cb240633"
RUNNER = "ad939bae0f3355c1e680fb3cc4d25d25f8fb730eb4deb8facff899db01408269"
PLAN = "b196ed191fdc61cea65d4c600e97fb332f74e23f7a8e2029bcb0d49a51270ca5"
FLOWS = ("o", "a", "b", "f", "s35", "s75", "s120")
PORTS = (
    ("readiness", "main", 58728),
    ("coordinator", "o", 50122),
    ("coordinator", "a", 50132),
    ("coordinator", "b", 50144),
    ("coordinator", "f", 50148),
    ("coordinator", "s35", 36346),
    ("coordinator", "s75", 39636),
    ("coordinator", "s120", 45508),
    ("postflight", "main", 49674),
)
EXPECTED_302 = ("0005", "0006", "0003", "0007", "0004", "0008")


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def read(path: Path) -> dict:
    return json.loads(path.read_text())


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


@contextmanager
def frozen(corpus: Path):
    original_modules = sys.modules.copy()
    original_path = sys.path.copy()
    original_bytecode = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        path = str(corpus / "sources/protocol")
        closure = read(corpus / "sources/dependency-closure.json")
        for name in closure["hashes"]:
            sys.modules.pop(name, None)
        if path in sys.path:
            sys.path.remove(path)
        sys.path.insert(0, path)
        yield (
            importlib.import_module("native_liveness_control"),
            importlib.import_module("native_liveness_cases"),
            importlib.import_module("native_control_readiness"),
            importlib.import_module("protocol_capture"),
            importlib.import_module("pcap_tcp"),
        )
    finally:
        for name in set(sys.modules) - original_modules.keys():
            del sys.modules[name]
        sys.modules.update(original_modules)
        sys.path[:] = original_path
        sys.dont_write_bytecode = original_bytecode


def inventory(corpus: Path) -> dict:
    manifest = read(corpus / "manifest.json")
    need(
        corpus.name == SCHEMA
        and manifest["schema"] == SCHEMA
        and manifest["profile"] == "control-only"
        and manifest["full_file_baseline"] == "not_exercised"
        and manifest["runner_sha256"] == RUNNER
        and manifest["cases_sha256"] == CASES
        and manifest["plan_sha256"] == PLAN
        and manifest["actual_pid"] == PID
        and manifest["fixed_deadline_utc"] == DEADLINE,
        "Corpus profile, source or deadline differs",
    )
    files = manifest["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
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


def source_gate(corpus: Path, modules) -> dict:
    raw = corpus / "raw"
    _, cases, _, capture, _ = modules
    freeze = read(raw / "source-freeze.json")
    closure = read(corpus / "sources/dependency-closure.json")
    need(
        closure["module_count"] == len(closure["hashes"])
        and set(freeze["hashes"]).issubset(
            {f"{name}.py" for name in closure["hashes"]}
        ),
        "Frozen source closure differs",
    )
    for name, digest in closure["hashes"].items():
        need(
            sha(corpus / "sources/protocol" / f"{name}.py") == digest,
            f"Frozen dependency differs: {name}",
        )
    for name, digest in freeze["hashes"].items():
        need(
            sha(raw / "sources" / name) == digest
            and sha(corpus / "sources/protocol" / name) == digest,
            f"As-run source differs: {name}",
        )
    need(
        sha(corpus / "sources/protocol/native_liveness_cases.py") == CASES
        and sha(corpus / "sources/protocol/native_liveness_control.py") == RUNNER
        and sha(raw / "liveness-plan/plan.json") == PLAN
        and read(raw / "liveness-plan/source-hashes.json") == {"plan.json": PLAN},
        "B75 producer, runner or plan differs",
    )
    plan = read(raw / "liveness-plan/plan.json")
    need(
        plan == cases.source_plan(plan["environment"], cases.PORT)
        and plan["oracle_sha256"] == capture.ORACLE_SHA256 == DATA
        and plan["schedule"]["duration_seconds"] == 135
        and len(plan["schedule"]["operations"]) == 47,
        "Generated finite schedule differs",
    )
    need(
        read(raw / "coordinator/plan.json") == plan,
        "As-run coordinator plan differs",
    )
    return plan


def identity(corpus: Path) -> dict:
    raw = corpus / "raw"
    prep = read(corpus / "preparation/final-preflight.json")
    hfs = read(corpus / "preparation/hfs-preflight.json")
    proof = read(raw / "actual-emulator-proof.json")
    runtime = read(raw / "runtime.json")
    receipt = read(raw / "capture-ready.json")
    need(
        prep["prepared"]["base.dsk"]["sha256"] == BASE
        and prep["prepared"]["working.dsk"]["sha256"] == BASE
        and prep["prepared"]["working.dsk"]["inode"] == INODE
        and prep["prepared"]["rom"]["sha256"] == ROM
        and prep["source_hashes_unchanged"]
        and hfs["banned_absent"]
        and len(hfs["allocated_active_users"]) == 2
        and all(item["matches"] and item["exit"] == 0 for item in hfs["files"].values())
        and hfs["files"]["server-data"]["sha256"] == DATA
        and hfs["files"]["server-rsrc"]["sha256"] == RSRC,
        "Stopped preparation or immutable source differs",
    )
    need(
        (proof["pid"], proof["starttime"], proof["netns"], proof["working_image_inode"])
        == (PID, START, NS, INODE)
        and proof["exe_sha256"] == EXE
        and proof["fd6"] == runtime["owned_working_image"]
        and proof["fd16"].endswith("native-liveness-epoch-01/lab-guest.pcap")
        and proof["original_startticks"] == {"1099659": "767842", "1012834": "2357813"},
        "Actual emulator/guest capture or originals differ",
    )
    need(
        runtime["emulator_pid"] == receipt["emulator_pid"] == PID
        and runtime["emulator_starttime"] == receipt["emulator_starttime"] == START
        and runtime["emulator_sha256"] == receipt["emulator_sha256"] == EXE
        and runtime["emulator_netns"] == receipt["emulator_netns"] == NS
        and runtime["owned_working_image_inode"] == INODE
        and receipt["deadline_utc"] == DEADLINE
        and receipt["fixture_profile"] == "control-only"
        and receipt["full_file_baseline"] == "not_exercised"
        and receipt["source_a7_sha256"] == A7
        and receipt["ns_routes"] == []
        and receipt["primary_syn_count"] == 0
        and all(runtime[key] == receipt[key] for key in runtime),
        "As-run runtime or fixed deadline differs",
    )
    failure = read(raw / "capture-readiness-operator-error.json")
    need(
        failure["native_socket_actions"] == 0
        and "PermissionError" in failure["failure"]
        and (raw / "host-ready.uid1000-failed.stdout").stat().st_size == 0
        and (raw / "namespace-ready.uid1000-failed.stdout").stat().st_size == 0,
        "Retained unprivileged observer failure differs",
    )
    for label in ("host", "namespace"):
        ready = read(raw / f"{label}-ready.json")
        meta = receipt["managed_capture"][label]
        need(
            ready == meta
            and ready["header24"].startswith("d4c3b2a1")
            and ready["pid"] == receipt[f"{label}_recorder_pid"]
            and ready["start_ticks"] == receipt[f"{label}_recorder_starttime"]
            and ready["fd"] >= 0
            and ready["inode"] > 0
            and ready["netns_inode"] == (4026531840 if label == "host" else 4026533605)
            and ready["capture"] == receipt[f"{label}_pcap"]
            and ready["deadline_utc"] == DEADLINE
            and ready["unit_properties"]["ActiveState"] == "active"
            and ready["unit_properties"]["MainPID"] == str(ready["pid"])
            and ready["unit_properties"]["RuntimeMaxUSec"] == "15min"
            and ready["unit_properties"]["KillMode"] == "control-group",
            f"{label} managed recorder differs",
        )
    coverage = read(raw / "independent-plus5-coverage.json")
    need(
        all(
            item["covers_plus5"]
            and utc(item["earliest_runtime_end_utc"])
            > utc(DEADLINE) + dt.timedelta(seconds=5)
            for item in coverage.values()
        )
        and receipt["managed_lock"]["busy_exit"] == 1
        and receipt["managed_lock"]["fd"] == 3
        and receipt["managed_lock"]["lock_inode"] > 0
        and receipt["managed_lock"]["unit_properties"]["MainPID"]
        == str(receipt["managed_lock"]["pid"])
        and receipt["managed_lock"]["unit_properties"]["ActiveState"] == "active",
        "Managed lease or +5 capture coverage differs",
    )
    return receipt


def report_gate(corpus: Path, modules, plan: dict) -> dict:
    raw = corpus / "raw"
    control, _, readiness, capture, _ = modules
    for label in ("readiness", "postflight"):
        folder = raw / label
        report = capture.verify_capture(folder)
        need(
            report["status"] == "completed"
            and report["completed_actions"] == 18
            and sha(folder / "plan.json") == sha(raw / "control-plans/readiness.json"),
            f"{label} generic 18-action control differs",
        )
        readiness.readiness(report)
    report = read(raw / "coordinator/report.json")
    need(
        report["status"] == "completed"
        and report["error"] == ""
        and report["window_completed"] is True
        and len(report["operations"]) == 48
        and len(report["frames"]) == 39
        and len(report["events"]) == 103
        and report["window_frame_count"] == 39
        and report["plan_sha256"] == PLAN
        and report["receipt_sha256"] == sha(raw / "capture-ready.json")
        and report["source_sha256"] == RUNNER
        and report["cases_sha256"] == CASES,
        "Complete custom case identity or counts differ",
    )
    control.verify_report(plan, report)
    t0 = report["operations"][0]["elapsed_ns"]
    need(
        report["window_elapsed_ns"] - t0 == 135_000_159_328
        and report["window_status"]["o"] == "bounded_no_eof_through_window"
        and report["terminals"]["o"] == "eof"
        and report["window_status"]["a"] == "eof"
        and report["window_status"]["b"] == "eof"
        and report["window_status"]["f"] == "eof",
        "Measured finite window or EOF labels differ",
    )
    for name, target in (
        ("f", 35.138506),
        ("a", 65.116360),
        ("b", 110.017097),
        ("o", 135.008015),
    ):
        events = [
            event
            for event in report["events"]
            if event["connection"] == name and event["event"] == "eof"
        ]
        need(
            len(events) == 1
            and abs((events[0]["elapsed_ns"] - t0) / 1e9 - target) < 0.000001,
            f"{name} EOF timing differs",
        )
    departure = [
        frame
        for frame in report["frames"]
        if frame["connection"] == "o" and frame["type"] == 302
    ]
    need(
        len(departure) == 6
        and all(
            (
                frame["flags"],
                frame["is_reply"],
                frame["error"],
                len(bytes.fromhex(frame["raw_hex"])),
            )
            == (0, 0, 0, 28)
            and len(frame["fields"]) == 1
            and frame["fields"][0]["id"] == 103
            for frame in departure
        )
        and tuple(frame["fields"][0]["hex"] for frame in departure) == EXPECTED_302,
        "Observer 302 UID, header or raw length differs",
    )
    need(
        not any(frame["type"] == 301 for frame in report["frames"]),
        "Unexpected observer 301 was inserted",
    )
    return report


def packet_gate(corpus: Path, modules, report: dict) -> list[dict]:
    raw = corpus / "raw"
    tcp = modules[4]
    host = tcp.read_packets(raw / "primary-syn.pcap")
    namespace = tcp.read_packets(raw / "lab-namespace.pcap")
    guest = tcp.read_packets(raw / "lab-guest.pcap")
    need(not host, "Primary-port SYN capture is not empty")
    need(
        all(
            p["src_port"] not in (15500, 15501) and p["dst_port"] not in (15500, 15501)
            for p in namespace
        ),
        "Namespace capture contacted primary bridge",
    )
    expected = [port for _, _, port in PORTS]
    ns_syn = [p for p in namespace if p["flags"] & 2 and not p["flags"] & 16]
    guest_syn = [p for p in guest if p["flags"] & 2 and not p["flags"] & 16]
    need(
        len(ns_syn) == 9
        and [p["src_port"] for p in ns_syn] == expected
        and len(guest_syn) == 10
        and {p["src_port"] for p in guest_syn} == set(expected)
        and len([p for p in guest_syn if p["src_port"] == 45508]) == 2
        and len({p["sequence"] for p in guest_syn if p["src_port"] == 45508}) == 1,
        "Nine SYN lifetimes or S120 retransmission differs",
    )
    summary = []
    for folder, name, port in PORTS:
        source = (
            report if folder == "coordinator" else read(raw / folder / "report.json")
        )
        connect = [
            e
            for e in source["events"]
            if e["connection"] == name and e["event"] == "connect"
        ]
        need(
            len(connect) == 1
            and connect[0]["local_address"] == ["127.0.0.1", port]
            and connect[0]["peer_address"] == ["127.0.0.1", 15840],
            f"{folder}/{name} connection identity differs",
        )
        connect_us = int(
            utc(source["started_at_utc"]).timestamp() * 1_000_000
            + connect[0]["elapsed_ns"] / 1000
        )
        n_client = ("127.0.0.1", port)
        n_server = ("127.0.0.1", 15840)
        g_client = ("10.0.2.2", port)
        g_server = ("10.0.2.15", 5500)
        n = tcp.lifetime(namespace, n_client, n_server, connect_us)
        g = tcp.lifetime(guest, g_client, g_server, connect_us)
        item = {"folder": folder, "connection": name, "port": port}
        for direction, a, b, c, d, key in (
            ("sent", n_client, n_server, g_client, g_server, "sent_hex"),
            ("received", n_server, n_client, g_server, g_client, "received_hex"),
        ):
            ns_bytes = tcp.stream(n, a, b)
            guest_bytes = tcp.stream(g, c, d)
            recorded = bytes.fromhex(source["streams"][name][key])
            need(
                ns_bytes == guest_bytes == recorded,
                f"{folder}/{name} {direction} packet/report bytes or tail differ",
            )
            item[direction] = len(recorded)
        item["namespace_packets"] = len(n)
        item["guest_packets"] = len(g)
        item["namespace_fin"] = sum(bool(p["flags"] & 1) for p in n)
        item["namespace_rst"] = sum(bool(p["flags"] & 4) for p in n)
        item["guest_fin"] = sum(bool(p["flags"] & 1) for p in g)
        item["guest_rst"] = sum(bool(p["flags"] & 4) for p in g)
        if name in {"a", "b", "f"}:
            need(
                item["guest_rst"] >= 1 and item["guest_fin"] == 0,
                f"{name} guest reset/relay EOF distinction differs",
            )
        if name in {"o", "s35", "s75", "s120"}:
            need(item["guest_fin"] == 2, f"{name} guest FIN pair differs")
        summary.append(item)
    review = read(raw / "parent-paired-stream-review.json")
    need(
        review["status"] == "PASS"
        and len(review["flows"]) == 9
        and all(
            (
                item["report"],
                item["connection"],
                item["port"],
                item["sent"],
                item["received"],
            )
            == (
                other["folder"],
                other["connection"],
                other["port"],
                other["sent"],
                other["received"],
            )
            for item, other in zip(review["flows"], summary, strict=True)
        ),
        "Independent paired-stream review differs",
    )
    return summary


def terminal(corpus: Path) -> None:
    raw = corpus / "raw"
    receipt = read(raw / "terminal.json")
    stopped = read(raw / "stopped-forks.json")
    preflight = read(corpus / "preparation/hfs-preflight.json")
    need(
        receipt["actual_emulator_gone"]
        and receipt["original_ticks"] == {"1099659": "767842", "1012834": "2357813"}
        and receipt["port_exit"] == 0
        and receipt["ports_ss"].splitlines()
        == ["State Recv-Q Send-Q Local Address:Port Peer Address:Port"]
        and receipt["lock_exit"] == 0
        and receipt["fuser_exit"] == 1
        and receipt["fuser_stdout"] == ""
        and receipt["primary_pcap_size"] == 24
        and "Mac OS not shut down orderly" in receipt["retirement_kind"]
        and utc(receipt["recorded_at_utc"]) < utc(DEADLINE),
        "Retired process, original services, ports, lock or deadline differ",
    )
    need(
        stopped["stopped_pid_gone"]
        and stopped["fd_free"]
        and set(stopped["files"]) == set(preflight["files"])
        and all(
            item["exit"] == 0
            and item["matches_preflight"]
            and item["sha256"] == preflight["files"][name]["sha256"]
            for name, item in stopped["files"].items()
        ),
        "Stopped named fork bytes differ",
    )
    system = (raw / "terminal-system-units.txt").read_text()
    user = (raw / "terminal-user-units.txt").read_text()
    need(
        all(
            f"{unit}\nActiveState=inactive" in system
            for unit in (
                "mothra-native-liveness-c92-lease.service",
                "mothra-native-liveness-c92-host.service",
                "mothra-native-liveness-c92-namespace.service",
                "mothra-native-liveness-c92-readiness.service",
                "mothra-native-liveness-c93-case.service",
                "mothra-native-liveness-c93-postflight.service",
            )
        )
        and all(
            f"{unit}\nActiveState=inactive" in user
            for unit in (
                "mothra-sheep-b2ee689a7fcc.service",
                "mothra-bridge-72798e9e3497.service",
                "mothra-xbridge-72798e9e3497.service",
                "mothra-display-25fab252cbac.service",
            )
        ),
        "Owned unit retirement differs",
    )
    journal = (raw / "c92-recorder-terminal-journal.log").read_text()
    need(
        journal.count("0 packets dropped by kernel") == 2
        and "0 packets captured" in journal
        and "269 packets captured" in journal,
        "Recorder drops or packet counts differ",
    )
    need(
        (raw / "readiness.exit").read_text().strip() == "0"
        and (raw / "c93-run.exit").read_text().strip() == "0"
        and (raw / "postflight.exit").read_text().strip() == "0"
        and "ExecMainStatus=0" in (raw / "c93-unit-final.txt").read_text()
        and "semantic postflight PASS"
        in (raw / "c93-postflight-journal.log").read_text(),
        "Managed case, preflight or postflight exit differs",
    )


def verify(corpus: Path = CORPUS) -> None:
    inventory(corpus)
    with frozen(corpus) as modules:
        plan = source_gate(corpus, modules)
        identity(corpus)
        report = report_gate(corpus, modules, plan)
        packet_gate(corpus, modules, report)
        terminal(corpus)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    args = parser.parse_args()
    verify(args.corpus)
    print("native liveness: offline replay PASS")


if __name__ == "__main__":
    main()
