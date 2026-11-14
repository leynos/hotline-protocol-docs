#!/usr/bin/env python3
"""Replay one native persisted-ban UI and Login107 witness offline."""

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path

from native_control_readiness import probe
from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import verify_capture
from verify_native_ban_control import verify as verify_control

CORPUS = "native-ban-reload-01"
C56_MANIFEST = "8e8497212614ae32b1b03a8c27b8aa28fcf595ef1704f056420ac18fd7cc9629"
DATA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
RSRC = "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12"
BASE = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
ROM = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
EMULATOR = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
IMAGE_BEFORE = "3717cd5e044bf63eb1e68d131290172a30777743ea073d12ab5b880a0ec4a6b9"
IMAGE_AFTER = "1a0f7ede44b2261ca0e2d264d25833337a5f0780bdf02b7f228b678233f00b64"
BAN = "53bec37683dc9bab6cc812f38fa465724085e9c35fc5b7bdf72e25dd09b727d4"
PREPARED = "3d1c69bb2c03625df891c44370ad3f8dd90c2d907d4808a6469b644f2e0ef0dc"
UI_IMAGE = "10bce764a04be6479dd17a9409d544d5f0107ba8781cf26386be4887c6322c3d"
INPUT = "b07976522f664a05ef5e3df33e2719b70c49d86ef7f99c8a892344284a07cd9e"
PID, START, NS = 415512, "5324681", "net:[4026533397]"
NOTICE = b"You are permanently banned on this server."


def require(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def read(path: Path) -> dict:
    return json.loads(path.read_text())


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(corpus: Path) -> None:
    m = read(corpus / "manifest.json")
    require(
        corpus.name == CORPUS
        and m["schema"] == CORPUS
        and m["profile"] == "persisted-ban-reload-readonly"
        and m["full_file_baseline"] == "not_exercised"
        and m["failed_full_A7"] == ["C35", "C45", "C50"]
        and m["source_native_data_sha256"] == DATA
        and m["source_native_rsrc_sha256"] == RSRC
        and m["source_c56_manifest_sha256"] == C56_MANIFEST
        and m["source_c56_corpus"] == "../native-ban-control-01",
        "Profile or source manifest differs",
    )
    files = m["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    require(actual == set(files), "Corpus inventory differs")
    for path, digest in files.items():
        require(sha(corpus / path) == digest, f"Corpus SHA differs: {path}")
    require(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{digest}  {path}" for path, digest in sorted(files.items())],
        "SHA256SUMS differs",
    )
    c56 = corpus.parent / "native-ban-control-01"
    require(sha(c56 / "manifest.json") == C56_MANIFEST, "C56 source manifest differs")
    require(
        verify_control(c56)["status"]
        == "verified_control_only_option_two_notice_and_login_rejection",
        "C56 control corpus differs",
    )
    require(
        all(
            sha(corpus / "sources" / name) == sha(c56 / "sources" / name)
            for name in (
                "protocol_capture.py",
                "pcap_tcp.py",
                "native_control_readiness.py",
                "native_ban_control_cases.py",
            )
        )
        and sha(corpus / "sources/capture_readiness.py")
        == "7a75f4b78f1255f4486ced44fc5fb8882d6008c7de6844a82f4c107e7299d678",
        "Captured source snapshot differs",
    )


def preflight(corpus: Path) -> None:
    root = corpus / "c61"
    p = read(root / "preflight.json")
    require(
        p["source_sha256"]
        == {
            "working": IMAGE_BEFORE,
            "base": BASE,
            "rom": ROM,
            "emulator": EMULATOR,
            "server_data": DATA,
        }
        and p["working_fd_holders"] == []
        and p["ports_15750_15753_free"] is True
        and p["full_file_baseline"] == "not_exercised"
        and p["existing_ban_state_preserved"] is True,
        "Preboot source or scope differs",
    )
    require(
        sha(root / "preboot-fls.txt") == p["fls_sha256"]
        and all(
            item in (root / "preboot-fls.txt").read_text()
            for item in (
                "Hotline19/Banned",
                "Hotline19/Users/admin/UserData",
                "Hotline19/Users/fixture-low/UserData",
                "Hotline19/Users/m-ban52-only/UserData",
            )
        ),
        "Preboot HFS paths differ",
    )
    users = p["hfs_user_data_and_ban"]
    require(
        users
        == {
            "admin": {
                "bytes": 734,
                "sha256": "26612ad46cd91b90050feacf517d32a9e56d4a4aa92fbe6618eaf6e9e5ac60a3",
            },
            "fixture-low": {
                "bytes": 734,
                "sha256": "fce81359d0efcfc6c2dbf42852db66b0fb7a404b2889162b8f8fad81361ce2d5",
            },
            "m-ban52-only": {
                "bytes": 734,
                "sha256": "0df7dd5ad9c2c992ddefa4aa30af069c27d1e0d793ea19d112d0520e9fcc3e86",
            },
            "Banned": {"bytes": 49, "sha256": BAN},
        }
        and sha(corpus / "c56-reference/Banned.data.bin") == BAN
        and sha(root / "Banned-postprobe.data.bin") == BAN
        and (root / "Banned-postprobe.data.bin").read_bytes()
        == (corpus / "c56-reference/Banned.data.bin").read_bytes(),
        "Stored ban or account bytes differ",
    )
    c56 = read(corpus / "c56-reference/terminal.json")
    require(
        c56["stopped_image_sha256"] == IMAGE_BEFORE
        and c56["ban_file"]["data_sha256"] == BAN,
        "C56 stopped-image origin differs",
    )


def ready_and_ui(corpus: Path) -> dict:
    root = corpus / "c61"
    ready = read(root / "ui-ready.json")
    em = ready["actual_emulator"]
    require(
        (em["pid"], em["starttime"], em["netns"]) == (PID, START, NS)
        and em["exe"].endswith(EMULATOR)
        and em["fd6"].endswith("native-eventlab-one-01/working.dsk")
        and em["fd16"].endswith("native-configured-ban-ui-c61/lab-guest.pcap")
        and em["uid"].split()[0] == "1000"
        and ready["ns_route"] == ""
        and ready["primary_syn_pcap_bytes"] == 24
        and ready["namespace_pcap_bytes"] == 24
        and ready["probe_executed"] is False
        and ready["options_cancelled"] is True
        and ready["probe_prepared_sha256"] == PREPARED,
        "Read-only UI boot identity differs",
    )
    for label in ("host", "namespace"):
        first = ready[f"{label}_recorder"]
        before = read(root / f"{label}-ready-preprobe.json")
        require(
            first["pid"] == before["pid"]
            and first["start_ticks"] == before["start_ticks"]
            and first["fd"] == before["fd"]
            and first["unit_properties"]["ActiveState"] == "active"
            and before["unit_properties"]["ActiveState"] == "active"
            and before["header24"].startswith("d4c3b2a1")
            and before["deadline_utc"] == first["deadline_utc"]
            and before["unit_properties"]["RuntimeMaxUSec"] == "15min",
            f"{label} recorder identity or deadline differs",
        )
    ui = read(root / "ui-observation.json")
    tab = ui["ban_tab"]
    require(
        tab["checked_row"] == tab["ip_field"] == "10.0.2.2"
        and tab["info_field"] == ""
        and tab["edited"] is False
        and tab["saved"] is False
        and tab["actions_taken"] == ["open Options", "select Ban tab", "Cancel"]
        and ui["resource_mapping"]["ban_control_ids"].startswith("unresolved")
        and ui["probe_executed"] is False
        and ui["no_primary_contact_before_probe"] is True
        and sha(root / "options-ban.png") == UI_IMAGE
        and all(
            sha(root / image) == digest
            for image, digest in ui["screenshots_sha256"].items()
        ),
        "Read-only Ban UI row or Cancel claim differs",
    )
    actions = [
        json.loads(line)
        for line in (root / "ui-actions.jsonl").read_text().splitlines()
    ]
    require(
        len(actions) == 8
        and [(x["x"], x["y"]) for x in actions[3:6]]
        == [(936, 85), (490, 247), (583, 541)]
        and "Cancel" in actions[5]["reason"]
        and all("Save" not in x["reason"] for x in actions)
        and sha(root / "input.py") == INPUT,
        "UI action scope or input source differs",
    )
    return ready


def check_probe(corpus: Path, ready: dict) -> dict:
    root = corpus / "c61"
    prepared = read(root / "probe-prepared.json")
    asrun = read(root / "probe-asrun.json")
    launch = read(root / "probe-launch.json")
    require(
        sha(root / "probe-prepared.json") == launch["prepared_sha256"] == PREPARED
        and sha(root / "probe-asrun.json") == launch["asrun_sha256"]
        and launch["steps_unchanged"] is True
        and prepared["steps"] == asrun["steps"]
        and prepared["environment"] == asrun["environment"]
        and prepared["endpoints"] == asrun["endpoints"]
        and asrun["gap_ids"] == ["GAP-044", "GAP-074"]
        and len(asrun["steps"]) == 6
        and asrun["environment"]["emulator_pid"] == PID
        and asrun["environment"]["fixture_profile"] == "persisted-ban-reload-readonly"
        and asrun["environment"]["full_file_baseline"] == "not_exercised"
        and asrun["endpoints"] == {"control": {"host": "127.0.0.1", "port": 15750}},
        "Prepared/as-run one-probe vector differs",
    )
    steps = asrun["steps"]
    require(
        [s["op"] for s in steps]
        == ["connect", "send", "read", "send", "read_frame", "close"]
        and steps[1]["hex"] == "54525450484f544c00010002"
        and steps[2]["expect_hex"] == "5452545000000000"
        and steps[3]["hex"].startswith("0000006b00000001")
        and steps[4]["match_frame"] == {"is_reply": 1, "id": 1}
        and not any("0000006e" in s.get("hex", "") for s in steps),
        "Fresh TRTP/107 vector or no-110 scope differs",
    )
    argv = launch["argv"]
    require(
        "--property=User=0" in argv
        and "--property=Group=0" in argv
        and f"--property=NetworkNamespacePath=/proc/{PID}/ns/net" in argv
        and "--property=RuntimeMaxSec=60" in argv
        and "--property=Type=oneshot" in argv
        and "--property=RemainAfterExit=yes" in argv
        and argv[argv.index("capture") + 1].endswith("probe-asrun.json")
        and read(root / "probe-launch-result.json")["returncode"] == 0
        and "completed; 6 actions" in (root / "probe-unit.log").read_text(),
        "Managed root/namespace probe or exit differs",
    )
    require(
        sha(root / "probe-asrun.json") == sha(root / "probe-capture/plan.json"),
        "Captured plan differs from as-run vector",
    )
    report = verify_capture(root / "probe-capture")
    require(
        report["status"] == "completed"
        and report["completed_actions"] == 6
        and report["oracle_sha256"] == DATA
        and report["driver_sha256"] == sha(corpus / "sources/protocol_capture.py")
        and report["profile"] == "native-mac-oracle",
        "One-probe capture incomplete",
    )
    probe(report)
    return report


def packets(corpus: Path, report: dict) -> dict:
    root = corpus / "c61"
    host = read_packets(root / "primary-syn.pcap")
    ns = read_packets(root / "lab-namespace.pcap")
    guest = read_packets(root / "lab-guest.pcap")
    require(not host, "Primary SYN capture is nonempty")
    require(
        not [
            p
            for p in ns
            if p["src_port"] in {15500, 15501} or p["dst_port"] in {15500, 15501}
        ],
        "Fixed primary bridge was contacted",
    )
    for label, count in (("host", 0), ("namespace", 13)):
        log = (root / f"{label}-recorder.log").read_text()
        require(
            f"{count} packets captured" in log and "0 packets dropped by kernel" in log,
            f"{label} recorder count/drop differs",
        )
    view = read(corpus / "packet-views.json")
    connect = [e for e in report["events"] if e["event"] == "connect"]
    require(
        len(connect) == 1 and connect[0]["connection"] == "main",
        "Fresh socket count differs",
    )
    event = connect[0]
    port = event["local_address"][1]
    started = int(
        dt.datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1_000_000
    )
    start = started + event["elapsed_ns"] // 1000
    require(
        view["local_port"] == port and view["connection"] == "main",
        "TCP flow identity differs",
    )
    for label, source, client, server, target in (
        ("namespace", ns, "127.0.0.1", "127.0.0.1", 15750),
        ("guest", guest, "10.0.2.2", "10.0.2.15", 5500),
    ):
        life = lifetime(source, (client, port), (server, target), start)
        require(bool(life), f"{label} TCP lifetime missing")
        sent = stream(life, (client, port), (server, target))
        received = stream(life, (server, target), (client, port))
        saved = view["views"][label]
        require(
            saved["packet_indices"] == [p["index"] for p in life]
            and saved["packet_count"] == len(life)
            and saved["first_us"] == life[0]["timestamp_us"]
            and saved["last_us"] == life[-1]["timestamp_us"]
            and saved["fin_packets"] == [p["index"] for p in life if p["flags"] & 1]
            and saved["rst_packets"] == [p["index"] for p in life if p["flags"] & 4]
            and saved["sent_len"] == len(sent)
            and saved["sent_sha256"] == hashlib.sha256(sent).hexdigest()
            and saved["sent_hex"] == sent.hex() == report["streams"]["main"]["sent_hex"]
            and saved["received_len"] == len(received)
            and saved["received_sha256"] == hashlib.sha256(received).hexdigest()
            and saved["received_hex"]
            == received.hex()
            == report["streams"]["main"]["received_hex"]
            and saved["received_tail_hex"] == received[-96:].hex(),
            f"{label} complete scoped TCP stream differs",
        )
    require(len(ns) == 13 and len(guest) == 12, "Unexpected TCP packet count")
    return {"namespace_packets": len(ns), "guest_packets": len(guest)}


def terminal(corpus: Path, ready: dict) -> None:
    root = corpus / "c61"
    t = read(root / "terminal.json")
    signals = read(root / "cleanup-signals.json")
    require(
        t["profile"] == "persisted-ban-reload-readonly"
        and t["full_file_baseline"] == "not_exercised"
        and t["actual_emulator_pid"] == PID
        and t["actual_pid_gone"] is True
        and t["server_quit_normal"] is True
        and t["guest_emulator_forced_term"] is True
        and t["working_fd_holders"] == []
        and t["stopped_image_sha256"] == IMAGE_AFTER
        and t["Banned"] == {"bytes": 49, "sha256": BAN}
        and t["owned_ports_absent"] is True
        and t["probe_reruns"] == 0
        and t["account_or_ban_mutations"] is False,
        "Terminal profile, forced retirement or ban bytes differ",
    )
    require(
        signals["pid_gone"] is True
        and signals["observed"]["starttime"] == START
        and signals["observed"]["netns"] == NS
        and [e["action"] for e in signals["events"]] == ["TERM"]
        and len(t["units"]) == 7
        and all(
            "ActiveState=inactive" in v and "MainPID=0" in v
            for v in t["units"].values()
        )
        and all(
            "0 packets dropped by kernel" in v[-1]
            for v in (t["host_recorder_log_tail"], t["namespace_recorder_log_tail"])
        ),
        "Cleanup PID, managed units or packet drops differ",
    )
    for label, pid, start in (
        ("primary", 1099659, "767842"),
        ("client", 1012834, "2357813"),
    ):
        original = t["original"][label]
        require(
            original["pid"] == pid
            and original["starttime"] == start
            and original["fd6"] == ready["original"][label]["fd6"]
            and original["fd16"] == ready["original"][label]["fd16"],
            f"Original {label} identity changed",
        )


def verify(corpus: Path) -> dict:
    corpus = corpus.resolve()
    inventory(corpus)
    preflight(corpus)
    ready = ready_and_ui(corpus)
    report = check_probe(corpus, ready)
    packet_counts = packets(corpus, report)
    terminal(corpus, ready)
    return {
        "status": "verified_one_persisted_ban_reload_ui_and_login107",
        "full_file_baseline": "not_exercised",
        "connected_session_application_104": "not_exercised",
        "login_error_bytes": len(NOTICE),
        "primary_syn_packets": 0,
        **packet_counts,
        "lab_retired": True,
        "guest_emulator_forced_term": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    print(json.dumps(verify(parser.parse_args().corpus), indent=2))


if __name__ == "__main__":
    main()
