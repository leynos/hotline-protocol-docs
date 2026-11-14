#!/usr/bin/env python3
"""Replay the frozen, failed Hotline 1.9 rate304 sequence offline."""

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
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-14/native-rate304-sequence-01"
)
SCHEMA = "native-rate304-sequence-01"
PID, START, NS, INODE = 3125063, "8100939", 4026533665, 1687370702
DEADLINE = "2026-11-14T11:50:21.652926+00:00"
PLAN = "6c0089f101ab4b99c41a6a548866d14e1460d6beaadb5f4c95ea91a5098c0d49"
CASES = "1c95329cfb361ae5322738e6644aa933d95ea6d01feed012dd629f6dca52a2c1"
RUNNER = "9c25e60bdd382c2768954547220fc1a7d5c78b118fc7d006e42bc6a5a41618f6"
BASE = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
ROM = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
EXE = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
DATA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
FORKS = {
    "admin": "26612ad46cd91b90050feacf517d32a9e56d4a4aa92fbe6618eaf6e9e5ac60a3",
    "fixture-low": "fce81359d0efcfc6c2dbf42852db66b0fb7a404b2889162b8f8fad81361ce2d5",
    "Prefs": "4ed2b3e14e6e8a6cf246d16f7d1b98f0b91d1b09f6ab5497de1056a6f617d196",
    "server-data": DATA,
    "server-rsrc": "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12",
}
PORTS = {
    "readiness": 36960,
    "observer": 59848,
    "paced": 34152,
    "burst": 38334,
    "probe": 38344,
}
TEMP_ERROR = b"You are temporarily banned on this server."
MISSING_CLIENT = b"Cannot get info for the specified client because it does not exist."


def need(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: Path) -> dict:
    return json.loads(path.read_text())


def pin(path: Path) -> dict[str, str]:
    lines = path.read_text().splitlines()
    entries = [line.split() for line in lines]
    need(all(len(item) == 2 for item in entries), "Approved pin syntax differs")
    result = {name: digest for digest, name in entries}
    need(len(lines) == len(result), "Approved pin duplicates path")
    return result


def inventory(corpus: Path) -> dict:
    manifest = read(corpus / "manifest.json")
    need(
        manifest["schema"] == SCHEMA
        and manifest["case_status"] == "failed"
        and manifest["plan_sha256"] == PLAN,
        "Corpus scope/status differs",
    )
    files = manifest["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(actual == set(files), "Corpus file inventory differs")
    for name, digest in files.items():
        need(sha(corpus / name) == digest, f"Corpus file SHA differs: {name}")
    prefix = "evidence/gap-remediation/2026-11-14/native-rate304-sequence-01/"
    need(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{digest}  {prefix}{name}" for name, digest in sorted(files.items())],
        "Root-relative SHA256SUMS differs",
    )
    return manifest


@contextmanager
def frozen(raw: Path):
    original_modules = sys.modules.copy()
    original_path = sys.path.copy()
    original_bytecode = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        freeze = read(raw / "source-freeze.json")
        root = raw / "sources"
        for filename, digest in freeze["hashes"].items():
            need(sha(root / filename) == digest, f"Frozen module differs: {filename}")
            sys.modules.pop(Path(filename).stem, None)
        sys.path.insert(0, str(root))
        yield (
            importlib.import_module("native_rate304_control"),
            importlib.import_module("native_rate304_cases"),
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


def source_identity(corpus: Path, modules) -> dict:
    raw, prep = corpus / "raw/epoch", corpus / "raw/preparation"
    control, cases, _, _, _ = modules
    freeze = read(raw / "source-freeze.json")
    proposed = read(prep / "proposed-source-closure.json")["hashes"]
    closure = pin(prep / "approved-source-closure.sha256")
    need(
        len(closure) == len(freeze["hashes"]) == len(proposed) == 35
        and closure == {f"scripts/{name}": digest for name, digest in proposed.items()}
        and freeze["hashes"] == proposed,
        "Approved 35-module closure differs",
    )
    for name, digest in proposed.items():
        need(
            sha(raw / "sources" / name) == digest
            and sha(prep / "proposed-sources" / name) == digest,
            f"Approved source byte differs: {name}",
        )
    helpers = pin(prep / "approved-helpers.sha256")
    need(
        len(helpers) == 3
        and freeze["helper_hashes"]
        == {Path(name).name: digest for name, digest in helpers.items()},
        "Three helper pins differ",
    )
    for name, digest in freeze["helper_hashes"].items():
        need(
            sha(raw / "helper-sources" / name) == digest
            and sha(prep / "proposed-sources" / name) == digest,
            f"Approved helper byte differs: {name}",
        )
    two = pin(prep / "approved-rate304-sources.sha256")
    need(
        two
        == {
            "scripts/native_rate304_cases.py": CASES,
            "scripts/native_rate304_control.py": RUNNER,
        }
        and sha(raw / "sources/native_rate304_cases.py") == CASES
        and sha(raw / "sources/native_rate304_control.py") == RUNNER,
        "Rate304 producer/runner pins differ",
    )
    need(
        sha(Path(cases.__file__)) == CASES and sha(Path(control.__file__)) == RUNNER,
        "Loaded frozen implementation differs",
    )
    script_pin = pin(prep / "script-SHA256SUMS")
    need(len(script_pin) == 8, "Prewritten script set differs")
    for name, digest in script_pin.items():
        need(
            name.startswith("state/native-sessions/native-rate304-preparation-03/")
            and sha(prep / Path(name).name) == digest,
            "Prewritten script byte differs",
        )
    plan = read(raw / "rate304-plan/plan.json")
    need(
        sha(raw / "rate304-plan/plan.json") == PLAN
        and plan == cases.source_plan(plan["environment"], 15880)
        and read(raw / "rate304-plan/source-hashes.json")["plan.json"] == PLAN,
        "Prepared plan/source differs",
    )
    return plan


def identity(corpus: Path) -> None:
    raw, prep = corpus / "raw/epoch", corpus / "raw/preparation"
    prepared = read(prep / "preflight.json")
    runtime, receipt = read(raw / "runtime.json"), read(raw / "capture-ready.json")
    proof = read(raw / "actual-emulator-proof.json")
    need(
        prepared["status"] == "prepared_stopped"
        and prepared["prepared"]["working.dsk"]["inode"] == INODE
        and prepared["prepared"]["base.dsk"]["sha256"] == BASE
        and prepared["prepared"]["working.dsk"]["sha256"] == BASE
        and prepared["prepared"]["rom"]["sha256"] == ROM
        and all(
            prepared["source_before"][name] == prepared["source_after"][name]
            for name in ("base", "rom")
        )
        and prepared["catalog"]["banned_absent"]
        and len(prepared["catalog"]["active_users"]) == 2,
        "Stopped preparation identity differs",
    )
    for name, record in (
        ("disk", "disk-ready.json"),
        ("capture", "guest-capture-ready.json"),
        ("capture", "guest-capture-resume-ready.json"),
    ):
        item = read(raw / record)
        need(
            item["phase"] == name
            and item["pid"] == PID
            and item["start_ticks"] == int(START)
            and item["working_inode"] == INODE
            and item["netns_inode"] == NS
            and item["exe_sha256"] == EXE
            and item["deadline_utc"] == DEADLINE,
            "Staged readiness identity differs",
        )
    need(
        runtime["emulator_pid"] == receipt["emulator_pid"] == proof["pid"] == PID
        and runtime["emulator_starttime"]
        == receipt["emulator_starttime"]
        == proof["starttime"]
        == START
        and runtime["emulator_netns_inode"] == receipt["emulator_netns_inode"] == NS
        and runtime["owned_working_image_inode"]
        == receipt["owned_working_image_inode"]
        == proof["working_image_inode"]
        == INODE
        and runtime["emulator_sha256"] == receipt["emulator_sha256"] == EXE
        and runtime["native_data_sha256"] == receipt["native_data_sha256"] == DATA
        and runtime["full_file_baseline"]
        == receipt["full_file_baseline"]
        == "not_exercised"
        and receipt["deadline_utc"] == DEADLINE,
        "Runtime/receipt identity or fixed deadline differs",
    )
    need(
        (raw / "complete-asrun.exit").read_text().strip() == "1"
        and "git" in (raw / "complete-asrun.stderr").read_text()
        and "exit status 128" in (raw / "complete-asrun.stderr").read_text()
        and (raw / "resume-asrun.exit").read_text().strip() == "0"
        and (raw / "partial-runtime-builder-01/runtime.json").is_file()
        and (
            raw / "partial-runtime-builder-01/sources/native_rate304_control.py"
        ).is_file()
        and (raw / "readiness.exit").read_text().strip() == "0"
        and (raw / "case-launch-asrun.exit").read_text().strip() == "0"
        and (raw / "coordinator.exit").read_text().strip() == "1",
        "Retained procedural failure or case status differs",
    )


def events_and_actions(report: dict, plan: dict, modules) -> None:
    control, cases, _, capture, _ = modules
    need(
        report["status"] == "failed"
        and report["error"] == "ValueError: Reply is not direct success"
        and report["timing"] == {}
        and report["phase_receipts"] == {}
        and report["phase_progress"] == {"paced": 26, "burst": 26}
        and report["native_clock_calibrated"] is False
        and report["plan_sha256"] == PLAN
        and report["cases_sha256"] == CASES
        and report["source_sha256"] == RUNNER
        and report["oracle_sha256"] == DATA
        and report["terminals"] == dict.fromkeys(plan["schedule"]["flows"], "eof"),
        "Failed case status/timing/source differs",
    )
    events, actions, frames = report["events"], report["actions"], report["frames"]
    need(
        len(events) == 210 and len(actions) == 133 and len(frames) == 195,
        "Raw event/action/frame boundary differs",
    )
    idle_count = sum(a["label"].startswith("observer-idle500-") for a in actions)
    need(idle_count == 14, "Observed idle control count differs")
    need(
        [(a["label"], a["connection"], a["hex"]) for a in actions]
        == control.expected_actions(plan, idle_count),
        "As-run request schedule/bytes differ",
    )
    rebuilt: dict[str, dict[str, str]] = {}
    last = -1
    for event in events:
        need(event["elapsed_ns"] >= last, "Event time regressed")
        last = event["elapsed_ns"]
        stream = rebuilt.setdefault(
            event["connection"], {"sent_hex": "", "received_hex": ""}
        )
        if event["event"] == "send":
            stream["sent_hex"] += event["hex"]
        elif event["event"] == "receive":
            stream["received_hex"] += event["hex"]
    need(rebuilt == report["streams"], "Recorder event/stream bytes differ")
    expected = {name: cases.HELLO for name in plan["schedule"]["flows"]}
    for action in actions:
        first, end = action["event_range"]
        need(first < end <= len(events), "Action event range differs")
        sent = "".join(e["hex"] for e in events[first:end] if e["event"] == "send")
        need(sent == action["hex"], "Action/send event bytes differ")
        expected[action["connection"]] += action["hex"]
    for name, stream in report["streams"].items():
        need(stream["sent_hex"] == expected[name], "Injected request bytes differ")
        need(
            stream["received_hex"].startswith(cases.HELLO_REPLY),
            "TRTP response differs",
        )
        parsed = "".join(f["raw_hex"] for f in frames if f["connection"] == name)
        need(
            stream["received_hex"]
            == cases.HELLO_REPLY + parsed + report["unparsed_hex"][name]
            and report["unparsed_hex"][name] == "",
            "Received frame/tail bytes differ",
        )
    for frame in frames:
        decoded = capture.decode_frame(bytes.fromhex(frame["raw_hex"]))
        need(
            all(frame.get(k) == v for k, v in decoded.items()),
            "Raw frame decode differs",
        )
    for name in plan["schedule"]["flows"]:
        terminal = [
            e["event"]
            for e in events
            if e["connection"] == name and e["event"] in {"eof", "rst"}
        ]
        need(terminal == [report["terminals"][name]], "Socket terminal/event differs")


def observed_prefix(report: dict, plan: dict, modules) -> dict:
    control, cases, _, _, _ = modules
    frames = report["frames"]
    control.login_identity(frames, "observer", control.ADMIN)
    paced_uid = control.subject_identity(frames, "paced")
    burst_uid = control.subject_identity(frames, "burst")
    need(
        (paced_uid, burst_uid) == (3, 4)
        and report["identities"] == {"paced_uid": 3, "burst_uid": 4},
        "Dynamic roster UID differs",
    )
    counts = {
        name: sum(f["type"] == 301 and f["connection"] == name for f in frames)
        for name in ("observer", "paced", "burst")
    }
    need(
        counts == {"observer": 55, "paced": 27, "burst": 26},
        "301 recipient inventory differs",
    )
    actions = {a["label"]: a["elapsed_ns"] for a in report["actions"]}
    timing = {}
    for name, uid, bars in (("paced", paced_uid, 2000), ("burst", burst_uid, 4000)):
        first = actions[f"{name}-304-00"]
        arrivals = []
        for icon in range(2, 28):
            for receiver in (name, "observer"):
                matches = [
                    f
                    for f in frames
                    if f["connection"] == receiver
                    and f["type"] == 301
                    and control.exact_fields(f).get(103) == uid.to_bytes(2, "big")
                    and control.exact_fields(f).get(104) == icon.to_bytes(2, "big")
                ]
                need(
                    len(matches) == 1, f"{name}/{receiver} update301 icon{icon} differs"
                )
                control.update_frame(matches[0], uid, icon)
                need(
                    control.exact_fields(matches[0])[112] == b"\x00\x20",
                    "Update301 status differs",
                )
                arrivals.append(matches[0]["arrival_elapsed_ns"])
            ack = control.one(frames, name, 0, bars + icon - 2, 1)
            control.successful(ack)
            need(control.exact_fields(ack) == {}, "Numbered500 ACK fields differ")
            arrivals.append(ack["arrival_elapsed_ns"])
        last = max(arrivals)
        need(0 <= last - first <= 20_000_000_000, f"{name} host trial bound differs")
        timing[f"{name}_trial_ns"] = last - first
    quiet_start = max(
        f["arrival_elapsed_ns"]
        for f in frames
        if f["connection"] in {"observer", "paced"}
        and (
            f["type"] == 301
            and control.exact_fields(f).get(103) == b"\x00\x03"
            and control.exact_fields(f).get(104) == b"\x00\x1b"
            or f["type"] == 0
            and f["id"] == 2025
        )
    )
    quiet_end = actions["paced-304-after-quiet"]
    need(
        70_000_000_000 <= quiet_end - quiet_start < 80_000_000_000,
        "70-second host quiet bracket differs",
    )
    need(
        not any(
            a["connection"] == "paced" and quiet_start < a["elapsed_ns"] < quiet_end
            for a in report["actions"]
        ),
        "Subject request inside quiet bracket",
    )
    for receiver in ("observer", "paced"):
        late = [
            f
            for f in frames
            if f["connection"] == receiver
            and f["type"] == 301
            and control.exact_fields(f).get(103) == b"\x00\x03"
            and control.exact_fields(f).get(104) == b"\x00\x1c"
        ]
        need(len(late) == 1, "Post-quiet icon28 update differs")
        control.update_frame(late[0], paced_uid, 28)
    control.successful(control.one(frames, "paced", 0, 2026, 1))
    need(
        not any(
            f["type"] == 301
            and control.exact_fields(f).get(103) == b"\x00\x04"
            and control.exact_fields(f).get(104) == b"\x00\x1c"
            for f in frames
        ),
        "Burst terminal icon28 unexpectedly delivered",
    )
    need(
        not any(f["connection"] == "burst" and f["id"] == 4026 for f in frames),
        "Burst terminal barrier unexpectedly replied",
    )
    need(not any(f["type"] == 104 for f in frames), "Unexpected ban notice104")
    probe = control.one(frames, "probe", 0, 1, 1)
    need(
        (probe["flags"], probe["error"]) == (0, 1)
        and control.exact_fields(probe) == {100: TEMP_ERROR},
        "Fresh107 temporary-ban response differs",
    )
    need(
        not any(f["connection"] == "probe" and f["type"] == 354 for f in frames),
        "Banned probe gained access",
    )
    for kind, identifier in ((348, 6000), (200, 6001), (206, 6002), (300, 6003)):
        reply = control.one(frames, "observer", 0, identifier, 1)
        control.successful(reply)
        if kind in (348, 200):
            need(
                control.field_digest(reply) == control.BASELINE_FIELDS[kind],
                f"Observer {kind} baseline differs",
            )
        if kind == 300:
            rows = control.roster(reply)
            need(
                len(rows) == 1 and bytes.fromhex(rows[0]["name_hex"]) == cases.OBS_NAME,
                "Retained roster differs",
            )
    final = control.one(frames, "observer", 0, 6004, 1)
    need(
        (final["flags"], final["error"]) == (0, 1)
        and control.exact_fields(final) == {100: MISSING_CLIENT},
        "Final303 error differs",
    )
    raw = bytes.fromhex(
        next(a["hex"] for a in report["actions"] if a["label"] == "observer-303")
    )
    need(
        len(raw) == 22
        and int.from_bytes(raw[:4], "big") == 303
        and raw[-2:] == b"\x00\x00",
        "Final303 was not fieldless",
    )
    need(
        report["terminals"] == {name: "eof" for name in plan["schedule"]["flows"]},
        "Socket EOF labels differ",
    )
    timing["subject_quiet_ns"] = quiet_end - quiet_start
    return timing


def paired_packets(corpus: Path, report: dict, modules) -> dict:
    raw = corpus / "raw/epoch"
    _, _, _, _, tcp = modules
    host = tcp.read_packets(raw / "primary-syn.pcap")
    ns = tcp.read_packets(raw / "lab-namespace.pcap")
    guest = tcp.read_packets(raw / "lab-guest.pcap")
    need(
        len(host) == 0 and len(ns) == 206 and len(guest) == 227,
        "Capture packet inventory differs",
    )
    streams = {
        "readiness": read(raw / "readiness/report.json")["streams"]["main"]
    } | report["streams"]
    result = {}
    for view, client_ip, server_ip, server_port in (
        (ns, "127.0.0.1", "127.0.0.1", 15880),
        (guest, "10.0.2.2", "10.0.2.15", 5500),
    ):
        syns = [p for p in view if p["flags"] & 2 and not p["flags"] & 16]
        need(
            len(syns) == 5 and {p["src_port"] for p in syns} == set(PORTS.values()),
            "Five SYN lifetimes differ",
        )
        need(
            all(
                p["src_ip"] == client_ip
                and p["dst_ip"] == server_ip
                and p["dst_port"] == server_port
                for p in syns
            ),
            "Capture endpoint differs",
        )
        need(
            all(
                (p["src_port"] in PORTS.values() and p["dst_port"] == server_port)
                or (p["src_port"] == server_port and p["dst_port"] in PORTS.values())
                for p in view
            ),
            "Unexpected TCP lifetime",
        )
        for name, port in PORTS.items():
            sent = tcp.stream(view, (client_ip, port), (server_ip, server_port))
            received = tcp.stream(view, (server_ip, server_port), (client_ip, port))
            need(
                sent.hex() == streams[name]["sent_hex"]
                and received.hex() == streams[name]["received_hex"],
                f"{name} PCAP/Recorder bytes or tail differ",
            )
            result[name] = {"sent": len(sent), "received": len(received)}
    burst_guest_rst = [
        p
        for p in guest
        if p["src_port"] == 5500 and p["dst_port"] == PORTS["burst"] and p["flags"] & 4
    ]
    burst_ns_fin = [
        p
        for p in ns
        if p["src_port"] == 15880 and p["dst_port"] == PORTS["burst"] and p["flags"] & 1
    ]
    need(
        len(burst_guest_rst) == len(burst_ns_fin) == 1
        and bytes.fromhex(burst_guest_rst[0]["payload_hex"]) == b"tcp_disconnect",
        "Guest RST versus relay FIN differs",
    )
    need(
        result
        == {
            "readiness": {"sent": 231, "received": 2759},
            "observer": {"sent": 526, "received": 5897},
            "paced": {"sent": 1459, "received": 2495},
            "burst": {"sent": 1437, "received": 2418},
            "probe": {"sent": 91, "received": 76},
        },
        "Five stream lengths differ",
    )
    return result


def stopped_and_capture(corpus: Path) -> None:
    raw = corpus / "raw/epoch"
    terminal, hfs = (
        read(raw / "terminal-identity.json"),
        read(raw / "stopped-hfs-summary.json"),
    )
    need(
        terminal["actual_pid_gone"]
        and terminal["oracle_lock_free"]
        and terminal["ports_absent"]
        and terminal["original_ticks"] == {"1099659": "767842", "1012834": "2357813"},
        "Retirement/original identity differs",
    )
    need(
        all(
            v["exit"] == 1 and not v["stdout"] and not v["stderr"]
            for v in terminal["fuser"].values()
        ),
        "Owned image/ROM still held",
    )
    need(
        hfs["image_inode"] == INODE
        and hfs["fuser_exit"] == 1
        and hfs["full_lines"] == hfs["allocated_lines"] == 5504
        and not hfs["banned_entries"]
        and len(hfs["active_users"]) == 2,
        "Stopped HFS state differs",
    )
    allocated = (raw / "stopped-fls-allocated.stdout").read_text().splitlines()
    users = [
        line
        for line in allocated
        if "Hotline19/Users/" in line and line.endswith("/UserData")
    ]
    need(
        users == hfs["active_users"]
        and not any("Hotline19/Banned" in line for line in allocated)
        and any(
            "11191:" in line and "Hotline19/MessageBoard.txt" in line
            for line in allocated
        ),
        "Stopped allocated HFS catalogue differs",
    )
    istat = (raw / "stopped-istat-board.stdout").read_text()
    need(
        "Catalog Record: 11191" in istat
        and "Size:\t0" in istat
        and "Resource fork size:\t0" in istat
        and "TEXT" in istat
        and "ttxt" in istat,
        "Stopped board fork/Finder metadata differs",
    )
    for name, digest in FORKS.items():
        need(
            hfs["forks"][name]["sha256"] == digest
            and sha(raw / f"stopped-icat-{name}.stdout") == digest
            if name in {"admin", "fixture-low", "Prefs"}
            else hfs["forks"][name]["sha256"] == digest,
            f"Stopped {name} fork differs",
        )
    need(
        hfs["forks"]["board"]["bytes"] == 0
        and (raw / "stopped-icat-board.stdout").read_bytes() == b"",
        "Stopped board differs",
    )
    unit = (raw / "units-after-stop.txt").read_text()
    need(
        unit.count("ActiveState=inactive") == 7
        and "ActiveState=failed" in unit
        and "ExecMainStatus=1" in unit,
        "Owned unit terminal state differs",
    )
    need(
        read(raw / "owned-pid-term.json")["action"]
        == "SIGTERM after native app Quit; not orderly OS shutdown",
        "Forced retirement provenance differs",
    )
    need(
        dt.datetime.fromisoformat((raw / "units-stopped.utc").read_text().strip())
        < dt.datetime.fromisoformat(DEADLINE),
        "Retirement missed fixed deadline",
    )
    journal = (raw / "capture-journal-terminal.txt").read_text()
    need(
        (raw / "capture-journal-terminal.exit").read_text().strip() == "0"
        and "206 packets captured" in journal
        and "0 packets captured" in journal
        and journal.count("0 packets dropped by kernel") == 2,
        "Capture drops/counts differ",
    )
    need(
        (raw / "primary-syn.pcap").stat().st_size == 24,
        "Primary-port SYN capture differs",
    )
    need(
        (raw / "root-git-ownership-check.exit").read_text().strip() == "0"
        and (raw / "root-git-nested-sudo.exit").read_text().strip() == "128"
        and "dubious ownership" in (raw / "root-git-nested-sudo.stderr").read_text(),
        "Post-event nested-sudo Git reproduction differs",
    )


def verify(corpus: Path = CORPUS) -> dict:
    inventory(corpus)
    identity(corpus)
    raw = corpus / "raw/epoch"
    with frozen(raw) as modules:
        plan = source_identity(corpus, modules)
        _, _, readiness, capture, _ = modules
        pre = capture.verify_capture(raw / "readiness")
        readiness.readiness(pre)
        report = read(raw / "coordinator/report.json")
        events_and_actions(report, plan, modules)
        timing = observed_prefix(report, plan, modules)
        flows = paired_packets(corpus, report, modules)
    stopped_and_capture(corpus)
    return {
        "status": "PASS",
        "case_status": "failed",
        "flows": flows,
        "host_timing_ns": timing,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    args = parser.parse_args()
    print(json.dumps(verify(args.corpus), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
