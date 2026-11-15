#!/usr/bin/env python3
"""Replay the frozen Hotline 1.9 board fixture without a VM or live server."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib
import json
import sys
from contextlib import contextmanager
from pathlib import Path

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-14/native-board-01"
)
SCHEMA = "native-board-01"
PID, START, NS, INODE = 1441133, "7213582", "net:[4026532471]", 1678261667
DEADLINE = "2026-11-14T09:22:28.893022+00:00"
BASE = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
ROM = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
EXE = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
DATA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
RSRC = "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12"
CASES = "19e699317afd769c4a4b483e6094337fe92a5baaed279ae6ab98c18b7b554344"
RUNNER = "da343b8d39f35c18bc267f301fdac316c720c0d5d4334eaec1d389ef381d1f6c"
PLAN = "95270ece3efe4da57cabd07ecf0a99ddb35cc11c3d353b69b7df3ae429b577ed"
BOARD = "a676c6349bb500411c0e0d73f29763a092cc1d9471809636c93433c5b430c4e0"
PORTS = (
    ("readiness", "main", 44446),
    ("coordinator", "sender", 52838),
    ("coordinator", "eligible", 52852),
    ("coordinator", "denied", 52854),
    ("coordinator", "waiting", 46468),
    ("postflight", "main", 47550),
)
FORKS = {
    "admin": "26612ad46cd91b90050feacf517d32a9e56d4a4aa92fbe6618eaf6e9e5ac60a3",
    "fixture-low": "fce81359d0efcfc6c2dbf42852db66b0fb7a404b2889162b8f8fad81361ce2d5",
    "Prefs": "4ed2b3e14e6e8a6cf246d16f7d1b98f0b91d1b09f6ab5497de1056a6f617d196",
    "server-data": DATA,
    "server-rsrc": RSRC,
}


def need(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def read(path: Path) -> dict:
    return json.loads(path.read_text())


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def inventory(corpus: Path) -> dict:
    manifest = read(corpus / "manifest.json")
    need(
        corpus.name == SCHEMA
        and manifest["schema"] == SCHEMA
        and manifest["profile"] == "control-only"
        and manifest["full_file_baseline"] == "not_exercised"
        and manifest["actual_pid"] == PID
        and manifest["runner_sha256"] == RUNNER
        and manifest["cases_sha256"] == CASES
        and manifest["plan_sha256"] == PLAN
        and manifest["fixed_deadline_utc"] == DEADLINE,
        "Corpus schema, source or fixed deadline differs",
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
        "Corpus size exceeds approved bound",
    )
    for name, digest in files.items():
        need(sha(corpus / name) == digest, f"Corpus SHA differs: {name}")
    need(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{digest}  {name}" for name, digest in sorted(files.items())],
        "SHA256SUMS differs",
    )
    return manifest


@contextmanager
def frozen(corpus: Path):
    original_modules = sys.modules.copy()
    original_path = sys.path.copy()
    original_bytecode = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        root = corpus / "sources/protocol"
        closure = read(corpus / "sources/dependency-closure.json")
        need(
            closure["module_count"] == len(closure["hashes"]), "Source closure differs"
        )
        for name, digest in closure["hashes"].items():
            need(sha(root / f"{name}.py") == digest, f"Frozen source differs: {name}")
            sys.modules.pop(name, None)
        path = str(root)
        if path in sys.path:
            sys.path.remove(path)
        sys.path.insert(0, path)
        yield (
            importlib.import_module("native_board_control"),
            importlib.import_module("native_board_cases"),
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


def source_and_plan(corpus: Path, modules) -> dict:
    raw = corpus / "raw"
    control, cases, _, capture, _ = modules
    freeze = read(raw / "source-freeze.json")
    closure = read(corpus / "sources/dependency-closure.json")["hashes"]
    need(
        freeze["hashes"]["native_board_cases.py"] == CASES
        and freeze["hashes"]["native_board_control.py"] == RUNNER
        and set(freeze["hashes"]).issubset({f"{name}.py" for name in closure}),
        "As-run board source identity differs",
    )
    for name, digest in freeze["hashes"].items():
        need(
            sha(raw / "sources" / name) == digest
            and sha(corpus / "sources/protocol" / name) == digest,
            f"As-run source differs: {name}",
        )
    need(
        sha(corpus / "sources/helpers/native_capture_receipt.py")
        == (corpus / "preparation/approved-helper.sha256").read_text().split()[0]
        and sha(corpus / "sources/protocol/native_board_control.py") == RUNNER
        and sha(corpus / "sources/protocol/native_board_cases.py") == CASES,
        "Approved receipt helper or B80 source differs",
    )
    plan = read(raw / "board-plan/plan.json")
    need(
        sha(raw / "board-plan/plan.json") == PLAN
        and read(raw / "board-plan/source-hashes.json")
        == {
            "plan.json": PLAN,
            "native_board_cases.py": CASES,
            "native_board_control.py": RUNNER,
        }
        and plan == cases.source_plan(plan["environment"], 15860)
        and plan["oracle_sha256"] == capture.ORACLE_SHA256 == DATA,
        "Generated board plan, endpoint or oracle differs",
    )
    need(
        read(raw / "runtime.json")["stopped_board_baseline"]
        == {
            "path": "Hotline19/MessageBoard.txt",
            "catalog_id": 11191,
            "data_size": 0,
            "resource_size": 0,
            "finder_type": "TEXT",
            "finder_creator": "ttxt",
        },
        "Empty stopped board baseline differs",
    )
    need(
        control.sha((json.dumps(plan, indent=2) + "\n").encode()) == PLAN,
        "Plan encoding differs",
    )
    return plan


def identity(corpus: Path) -> dict:
    raw = corpus / "raw"
    prep = read(corpus / "preparation/preflight.json")
    proof = read(raw / "actual-emulator-proof.json")
    runtime = read(raw / "runtime.json")
    receipt = read(raw / "capture-ready.json")
    need(
        prep["status"] == "prepared_stopped"
        and prep["prepared"]["base.dsk"]["sha256"] == BASE
        and prep["prepared"]["working.dsk"]["sha256"] == BASE
        and prep["prepared"]["working.dsk"]["inode"] == INODE
        and prep["prepared"]["rom"]["sha256"] == ROM
        and prep["source_before"]["base"] == prep["source_after"]["base"]
        and prep["source_before"]["rom"] == prep["source_after"]["rom"]
        and prep["catalog"]["banned_absent"]
        and len(prep["catalog"]["active_users"]) == 2,
        "Stopped preparation, immutable source or accounts differ",
    )
    need(
        (proof["pid"], proof["starttime"], proof["netns"], proof["working_image_inode"])
        == (PID, START, NS, INODE)
        and proof["exe_sha256"] == EXE
        and proof["fd6"] == runtime["owned_working_image"]
        and proof["fd16"] == receipt["guest_pcap"]
        and receipt["emulator_pid"] == runtime["emulator_pid"] == PID
        and receipt["emulator_starttime"] == runtime["emulator_starttime"] == START
        and receipt["emulator_netns"] == runtime["emulator_netns"] == NS
        and receipt["emulator_sha256"] == runtime["emulator_sha256"] == EXE
        and receipt["owned_working_image_inode"] == INODE
        and receipt["source_base_sha256"] == BASE
        and receipt["rom_sha256"] == ROM
        and receipt["native_data_sha256"] == DATA
        and receipt["fixture_profile"] == "control-only"
        and receipt["full_file_baseline"] == "not_exercised"
        and receipt["deadline_utc"] == DEADLINE
        and receipt["ns_routes"] == []
        and receipt["primary_syn_count"] == 0
        and all(runtime[key] == receipt[key] for key in runtime),
        "Actual emulator, capture receipt or profile differs",
    )
    for name, inode in (("host", 4026531840), ("namespace", 4026532471)):
        ready = read(raw / f"{name}-ready.json")
        meta = receipt["managed_capture"][name]
        need(
            ready == meta
            and ready["netns_inode"] == inode
            and ready["header24"].startswith("d4c3b2a1")
            and ready["pid"] == receipt[f"{name}_recorder_pid"]
            and ready["start_ticks"] == receipt[f"{name}_recorder_starttime"]
            and ready["unit_properties"]["ActiveState"] == "active"
            and ready["unit_properties"]["MainPID"] == str(ready["pid"])
            and ready["unit_properties"]["RuntimeMaxUSec"] == "15min"
            and ready["deadline_utc"] == DEADLINE,
            f"Managed {name} recorder differs",
        )
    lock = receipt["managed_lock"]
    need(
        lock["unit"] == "mothra-native-board02-c100-lease.service"
        and lock["busy_exit"] == 1
        and lock["fd"] == 3
        and lock["lock_inode"] > 0
        and lock["unit_properties"]["MainPID"] == str(lock["pid"])
        and lock["unit_properties"]["ActiveState"] == "active"
        and (raw / "lock-free.exit").read_text().strip() == "0",
        "Managed oracle lease or release differs",
    )
    need(
        utc(receipt["epoch_started_utc"]) + dt.timedelta(minutes=12) == utc(DEADLINE)
        and utc(receipt["utc"]) < utc(DEADLINE)
        and (raw / "primary-syn.pcap").stat().st_size == 24,
        "Fixed twelve-minute epoch or primary capture differs",
    )
    return receipt


def reports(corpus: Path, modules, plan: dict) -> dict:
    raw = corpus / "raw"
    board, _, readiness, capture, _ = modules
    for phase in ("readiness", "postflight"):
        folder = raw / phase
        report = capture.verify_capture(folder)
        need(
            report["status"] == "completed"
            and report["completed_actions"] == 18
            and sha(folder / "plan.json") == sha(raw / "control-plans/readiness.json")
            and (raw / f"{phase}.exit").read_text().strip() == "0",
            f"{phase} generic control differs",
        )
        readiness.readiness(report)
    report = read(raw / "coordinator/report.json")
    need(
        report["status"] == "completed"
        and report["error"] == ""
        and report["plan_sha256"] == PLAN
        and report["capture_receipt_sha256"] == sha(raw / "capture-ready.json")
        and report["native_source_sha256"] == DATA
        and report["runner_sha256"] == RUNNER
        and report["producer_sha256"] == CASES
        and (raw / "coordinator.exit").read_text().strip() == "0"
        and len(report["frames"]) == 71
        and len(report["events"]) == 429
        and report["byte_count"] == 463467,
        "Finite custom board case or source binding differs",
    )
    board.verify_report(plan, report)
    counts = {107: 0, 101: 0, 103: 0, 500: 0}
    for stream in report["streams"].values():
        sent = bytes.fromhex(stream["sent_hex"])
        need(sent[:12] == bytes.fromhex(plan["hello_hex"]), "Board greeting differs")
        pending = sent[12:]
        while pending:
            need(len(pending) >= 20, "Short numbered request")
            size = int.from_bytes(pending[16:20], "big")
            need(len(pending) >= 20 + size, "Truncated numbered request")
            kind = int.from_bytes(pending[:4], "big")
            need(kind in counts, "Unexpected numbered request kind")
            counts[kind] += 1
            pending = pending[20 + size :]
    need(counts == {107: 4, 101: 9, 103: 13, 500: 6}, "32-request composition differs")
    need(
        utc(report["started_utc"])
        >= utc(read(raw / "capture-ready.json")["epoch_started_utc"])
        and utc(report["ended_utc"]) < utc(DEADLINE),
        "Board case ran outside fixed epoch",
    )
    need(
        len(report["segments_hex"]) == 12
        and len(report["post_data_hex"]) == 13
        and [len(bytes.fromhex(x)) for x in report["post_data_hex"]]
        == [0, 7, 7, 8191, 8192, 8192, 8192, 8192, 8192, 8192, 7155, 1, 8193]
        and report["reads"]["12"] == report["reads"]["11"]
        and report["whole_board_sha256"] == BOARD,
        "Post boundaries, rejected 8193 or stored prefix differs",
    )
    return report


def packets(corpus: Path, modules, report: dict) -> list[dict]:
    raw = corpus / "raw"
    tcp = modules[4]
    host = tcp.read_packets(raw / "primary-syn.pcap")
    namespace = tcp.read_packets(raw / "lab-namespace.pcap")
    guest = tcp.read_packets(raw / "lab-guest.pcap")
    need(not host, "Primary-port SYN capture is not empty")
    need(
        len(namespace) == 830
        and len(guest) == 915
        and all(
            item["src_port"] not in (15500, 15501)
            and item["dst_port"] not in (15500, 15501)
            for item in namespace
        ),
        "Namespace packet count or primary bridge contact differs",
    )
    expected = [port for _, _, port in PORTS]
    for view, name in ((namespace, "namespace"), (guest, "guest")):
        syn = [item for item in view if item["flags"] & 2 and not item["flags"] & 16]
        need(
            len(syn) == 6 and [item["src_port"] for item in syn] == expected,
            f"{name} six SYN lifetimes differ",
        )
    summary = []
    for phase, name, port in PORTS:
        source = report if phase == "coordinator" else read(raw / phase / "report.json")
        connect = [
            event
            for event in source["events"]
            if event["connection"] == name and event["event"] == "connect"
        ]
        need(
            len(connect) == 1
            and connect[0]["local_address"] == ["127.0.0.1", port]
            and connect[0]["peer_address"] == ["127.0.0.1", 15860],
            f"{phase}/{name} socket identity differs",
        )
        started = source.get("started_at_utc", source.get("started_utc"))
        connect_us = int(
            utc(started).timestamp() * 1_000_000 + connect[0]["elapsed_ns"] / 1000
        )
        n_client = ("127.0.0.1", port)
        n_server = ("127.0.0.1", 15860)
        g_client = ("10.0.2.2", port)
        g_server = ("10.0.2.15", 5500)
        n = tcp.lifetime(namespace, n_client, n_server, connect_us)
        g = tcp.lifetime(guest, g_client, g_server, connect_us)
        item = {"report": phase, "connection": name, "port": port}
        for label, a, b, c, d, key in (
            ("sent", n_client, n_server, g_client, g_server, "sent_hex"),
            ("received", n_server, n_client, g_server, g_client, "received_hex"),
        ):
            ns_data = tcp.stream(n, a, b)
            guest_data = tcp.stream(g, c, d)
            recorded = bytes.fromhex(source["streams"][name][key])
            need(
                ns_data == guest_data == recorded,
                f"{phase}/{name} {label} PCAP/report bytes or tail differ",
            )
            item[label] = len(recorded)
        item["namespace_packets"] = len(n)
        item["guest_packets"] = len(g)
        summary.append(item)
    review = read(raw / "parent-paired-stream-review.json")
    need(
        review["status"] == "PASS"
        and len(review["flows"]) == 6
        and all(
            all(
                item[key] == other[key]
                for key in ("report", "connection", "port", "sent", "received")
            )
            and item["namespace_packets"] == other["namespace_packets"]
            and item["guest_packets"] == other["guest_packets"]
            for item, other in zip(summary, review["flows"], strict=True)
        ),
        "Independent paired-stream review differs",
    )
    return summary


def terminal(corpus: Path, report: dict) -> None:
    raw = corpus / "raw"
    stopped = raw / "stopped"
    proof = read(raw / "parent-terminal-proof.json")
    need(
        proof["lab_pid_gone"]
        and proof["original_ticks_unchanged"]
        and proof["lock_free"]
        and proof["working_fd_hits"] == []
        and proof["no_working_image_bytes_read"]
        and utc(proof["recorded_at_utc"]) < utc(DEADLINE),
        "Independent retired-process or FD-free proof differs",
    )
    need(
        (stopped / "fuser.exit").read_text().strip() == "1"
        and not (stopped / "fuser.stdout").read_bytes()
        and (raw / "lock-free.exit").read_text().strip() == "0"
        and "15860" not in (raw / "ports-terminal.txt").read_text()
        and "15861" not in (raw / "ports-terminal.txt").read_text()
        and "15862" not in (raw / "ports-terminal.txt").read_text()
        and "15863" not in (raw / "ports-terminal.txt").read_text(),
        "Stopped image holder, lease or ports differ",
    )
    system = (raw / "units-terminal.txt").read_text()
    user = (raw / "user-units-terminal.txt").read_text()
    need(
        all(
            f"Id={unit}\nActiveState=inactive" in system
            for unit in (
                "mothra-native-board02-c100-host.service",
                "mothra-native-board02-c100-namespace.service",
                "mothra-native-board02-c100-lease.service",
            )
        )
        and all(
            f"Id={unit}\nActiveState=inactive" in user
            for unit in (
                "mothra-sheep-8eca68cab7b1.service",
                "mothra-bridge-fd5e17ac00f6.service",
                "mothra-xbridge-fd5e17ac00f6.service",
                "mothra-display-364ae329a9c8.service",
            )
        ),
        "Owned service retirement differs",
    )
    journal = (raw / "capture-journal.txt").read_text()
    need(
        journal.count("0 packets dropped by kernel") == 2
        and "0 packets captured" in journal
        and "830 packets captured" in journal,
        "Recorder zero-drop or primary quiet evidence differs",
    )
    need(
        "ExecMainStatus=0" in (raw / "units-terminal.txt").read_text()
        and "ActiveState=inactive" in (raw / "case-units-stopped.txt").read_text()
        and (raw / "postflight.exit").read_text().strip() == "0",
        "Managed case/postflight terminal result differs",
    )
    hashes = dict(
        line.split(maxsplit=1)
        for line in (stopped / "image-sha256.txt").read_text().splitlines()
    )
    need(
        hashes[BASE] == "state/mac-runtime/native-board-02/base.dsk"
        and hashes[ROM] == "state/mac-runtime/native-board-02/rom"
        and hashes["a1b2f48093cc6dc622c5d4bcffb3c14409eedbd67af0f40f559e318b18d185b9"]
        == "state/mac-runtime/native-board-02/working.dsk",
        "Stopped base, ROM or quarantined working image hash differs",
    )
    board = (stopped / "MessageBoard.data").read_bytes()
    expected = b"".join(
        bytes.fromhex(value) for value in reversed(report["segments_hex"])
    )
    need(
        len(board) == 65629
        and board == expected
        and sha(stopped / "MessageBoard.data") == BOARD
        and (stopped / "MessageBoard.rsrc").stat().st_size == 0,
        "Stopped board DATA bytes or resource fork differ",
    )
    meta = (stopped / "board-istat.txt").read_text()
    catalog = (stopped / "catalog-allocated.txt").read_text()
    need(
        "File Path: /Hotline19/MessageBoard.txt" in meta
        and "Size:\t65629" in meta
        and "Resource fork size:\t0" in meta
        and "File type:\t54455854  TEXT" in meta
        and "File creator:\t74747874  ttxt" in meta
        and "-/r 11191:\tHotline19/MessageBoard.txt" in catalog
        and catalog.count("/Users/admin/UserData") == 1
        and catalog.count("/Users/fixture-low/UserData") == 1,
        "Stopped board HFS path, Finder metadata or active users differ",
    )
    prep = read(corpus / "preparation/preflight.json")
    for name, digest in FORKS.items():
        need(
            prep["forks"][name]["sha256"] == digest
            and dict(
                line.split(maxsplit=1)
                for line in (stopped / "fork-sha256.txt").read_text().splitlines()
            )
            .get(digest, "")
            .endswith(f"/{name}.bin"),
            f"Unchanged stopped named fork differs: {name}",
        )


def verify(corpus: Path = CORPUS) -> dict:
    inventory(corpus)
    with frozen(corpus) as modules:
        plan = source_and_plan(corpus, modules)
        identity(corpus)
        report = reports(corpus, modules, plan)
        flows = packets(corpus, modules, report)
        terminal(corpus, report)
    return {
        "status": "PASS",
        "corpus": str(corpus),
        "board_sha256": BOARD,
        "board_bytes": 65629,
        "flows": flows,
        "full_file_baseline": "not_exercised",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    args = parser.parse_args()
    print(json.dumps(verify(args.corpus), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
