#!/usr/bin/env python3
"""Replay the isolated native option-two control witness from frozen bytes."""

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path

import native_control_readiness as gates
from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import decode_frame, verify_capture

EXPECTED = {
    "source_a7": "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e",
    "controller": "afb2dcbabae9765b9708efa21e4e3d7ff74ad33e90bee0f03d953cfa95d1c1da",
    "base": "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910",
    "rom": "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd",
    "emulator": "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4",
    "data": "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b",
    "rsrc": "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12",
    "stopped": "3717cd5e044bf63eb1e68d131290172a30777743ea073d12ab5b880a0ec4a6b9",
    "banned": "53bec37683dc9bab6cc812f38fa465724085e9c35fc5b7bdf72e25dd09b727d4",
}
PHASES = {"readiness": 18, "guard": 10, "seed": 12, "ban": 32, "probe": 6}
PID = 4127848
START = "5026815"
NS = "net:[4026532619]"


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def loaded(path: Path) -> dict:
    return json.loads(path.read_text())


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(corpus: Path) -> dict:
    manifest = loaded(corpus / "manifest.json")
    need(manifest["schema"] == "native-ban-control-01", "Corpus schema differs")
    files = manifest["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(actual == set(files), "Corpus inventory differs")
    for name, sha in files.items():
        need(digest(corpus / name) == sha, f"Corpus SHA differs: {name}")
    need(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{sha}  {name}" for name, sha in sorted(files.items())],
        "SHA256SUMS differs",
    )
    need(
        manifest["full_file_baseline"] == "not_exercised"
        and manifest["failed_full_A7"] == ["C35", "C45", "C50"]
        and manifest["root_controller_source_sha256"] == EXPECTED["controller"]
        and manifest["source_a7_sha256"] == EXPECTED["source_a7"]
        and manifest["native_data_sha256"] == EXPECTED["data"]
        and manifest["native_rsrc_sha256"] == EXPECTED["rsrc"],
        "Evidence profile or source identity differs",
    )
    need(
        digest(corpus / "sources/native_control_readiness.py")
        == EXPECTED["controller"],
        "Controller source differs",
    )
    return manifest


def boot(corpus: Path) -> dict:
    old = loaded(corpus / "boot-c53/terminal.json")
    need(
        old["actual_pid_gone"] is True
        and old["primary_syn_pcap_bytes"] == 24
        and old["namespace_pcap_bytes"] == 24,
        "C53 no-contact retirement differs",
    )
    for label in ("primary-syn", "lab-namespace"):
        need(
            not read_packets(corpus / "boot-c53" / f"{label}.pcap"),
            "C53 no-contact capture has packets",
        )
    ready = loaded(corpus / "boot-c55/readiness.json")
    emulator = ready["actual_emulator"]
    need(
        ready["purpose"]
        == "control-only boot readiness; full_file_baseline=not_exercised"
        and ready["no_frontend_contact"] is True
        and ready["root_controller_required_for_case"] is True
        and (emulator["pid"], emulator["starttime"], emulator["netns"])
        == (PID, START, NS)
        and emulator["uid"].split()[1] == "1000"
        and emulator["cap_eff"].split()[1] == "0000000000020000"
        and emulator["fd6"].endswith("native-eventlab-one-01/working.dsk")
        and emulator["fd16"].endswith("native-ban-control-c55/lab-guest.pcap")
        and emulator["exe"].endswith(EXPECTED["emulator"]),
        "Boot emulator identity differs",
    )
    source = ready["source_hashes"]
    need(
        source
        == {
            "base": EXPECTED["base"],
            "rom": EXPECTED["rom"],
            "emulator": EXPECTED["emulator"],
            "server_data": EXPECTED["data"],
            "server_rsrc": EXPECTED["rsrc"],
        },
        "Preboot source hashes differ",
    )
    need(
        ready["recorder_remaining_seconds"]["host"] >= 360
        and ready["recorder_remaining_seconds"]["namespace"] >= 360
        and ready["namespace"]["routes"] == ""
        and all(
            f"127.0.0.1:{port}" in ready["namespace"]["listeners"]
            for port in (15750, 15751, 15752, 15753)
        )
        and ready["primary_syn_pcap_bytes"] == 24,
        "Boot recorder deadline, isolation or listener differs",
    )
    need(
        digest(corpus / "boot-c55/server-ready.png") == ready["screenshot_sha256"],
        "Boot screenshot identity differs",
    )
    for label in ("host", "namespace"):
        witness = loaded(corpus / "boot-c55" / f"{label}-ready-final.json")
        need(
            witness == ready["recorders"][label]
            and witness["unit_properties"]["ActiveState"] == "active"
            and witness["unit_properties"]["KillMode"] == "control-group"
            and witness["header24"].startswith("d4c3b2a1")
            and witness["deadline_utc"] == ready["case_deadline_utc"],
            f"{label} managed recorder differs",
        )
    return ready


def case(corpus: Path, ready: dict) -> dict[str, dict]:
    base = corpus / "case-c56"
    capture = loaded(base / "capture-ready.json")
    need(
        capture["emulator_pid"] == PID
        and capture["emulator_starttime"] == START
        and capture["emulator_netns"] == NS
        and capture["emulator_sha256"] == EXPECTED["emulator"]
        and capture["owned_working_image"].endswith(
            "native-eventlab-one-01/working.dsk"
        )
        and capture["host_recorder_pid"] == ready["recorders"]["host"]["pid"]
        and capture["namespace_recorder_pid"] == ready["recorders"]["namespace"]["pid"]
        and capture["ns_routes"] == []
        and capture["primary_syn_count"] == 0
        and capture["fixture_profile"] == "control-only"
        and capture["full_file_baseline"] == "not_exercised",
        "As-run capture identity or scope differs",
    )
    launch = loaded(base / "controller-launch.json")
    argv = launch["argv"]
    need(
        launch["source_sha256"] == EXPECTED["controller"]
        and "--property=User=0" in argv
        and f"--property=NetworkNamespacePath=/proc/{PID}/ns/net" in argv
        and "--property=Type=oneshot" in argv
        and "--property=RuntimeMaxSec=180s" in argv
        and argv[argv.index("--plans") + 1].endswith("native-ban-control-c56/plans")
        and argv[argv.index("--binary") + 1].endswith("HLserver19.pef"),
        "Controller root/namespace/source launch differs",
    )
    unit = (base / "controller-unit-terminal.txt").read_text()
    need(
        all(
            item in unit
            for item in (
                "Type=oneshot",
                "RemainAfterExit=yes",
                "MainPID=0",
                "Result=success",
                "ExecMainStatus=0",
            )
        ),
        "Controller managed exit differs",
    )
    hashes = loaded(base / "plans/source-hashes.json")
    need(set(hashes) == set(PHASES), "As-run plan inventory differs")
    reports = {}
    for name, count in PHASES.items():
        plan = base / "plans" / f"{name}.json"
        need(digest(plan) == hashes[name], f"{name} as-run source plan differs")
        prepared = loaded(plan)
        need(
            prepared["environment"]["emulator_pid"] == PID
            and prepared["environment"]["source_a7_sha256"] == EXPECTED["source_a7"]
            and prepared["environment"]["fixture_profile"] == "control-only"
            and prepared["environment"]["full_file_baseline"] == "not_exercised"
            and prepared["endpoints"]
            == {"control": {"host": "127.0.0.1", "port": 15750}},
            f"{name} plan profile/endpoint differs",
        )
        folder = base / "captures" / name
        need(
            digest(folder / "plan.json") == hashes[name], "Capture plan/source differs"
        )
        report = verify_capture(folder)
        need(
            report["status"] == "completed" and report["completed_actions"] == count,
            f"{name} capture incomplete",
        )
        reports[name] = report
    need(reports["ban"].get("controller_uid") == 0, "Guarded controller was not root")
    gates.readiness(reports["readiness"])
    gates.guarded_account(reports["guard"], absent=True)
    gates.guarded_account(reports["seed"], absent=False)
    target_uid = gates.target_gate(reports["ban"]["frames"])
    gates.outcome(reports["ban"])
    gates.probe(reports["probe"])
    sends = [
        decode_frame(bytes.fromhex(e["hex"]))
        for report in reports.values()
        for e in report["events"]
        if e["event"] == "send" and len(e["hex"]) >= 40 and e["hex"][:8] != "54525450"
    ]
    bans = [item for item in sends if item["type"] == 110]
    need(
        len(bans) == 1
        and bans[0]["id"] == 33
        and gates.fields(bans[0]) == {103: target_uid, 113: b"\0\2"}
        and all(item["type"] not in {202, 203, 214} for item in sends),
        "Control-only request or one-ban scope differs",
    )
    return reports


def packets(corpus: Path, reports: dict[str, dict]) -> dict:
    boot = corpus / "boot-c55"
    need(not read_packets(boot / "primary-syn.pcap"), "Primary SYN capture is nonempty")
    namespace = read_packets(boot / "lab-namespace.pcap")
    guest = read_packets(boot / "lab-guest.pcap")
    need(
        not [
            packet
            for packet in namespace
            if packet["src_port"] in {15500, 15501}
            or packet["dst_port"] in {15500, 15501}
        ],
        "Lab touched fixed primary bridge",
    )
    for label in ("host", "namespace"):
        log = (boot / f"{label}-recorder.log").read_text()
        need("0 packets dropped by kernel" in log, f"{label} packet drops differ")
    need(
        "0 packets captured" in (boot / "host-recorder.log").read_text(),
        "Primary SYN count differs",
    )
    views = loaded(corpus / "packet-views.json")
    need(set(views) == set(PHASES), "Packet phase inventory differs")
    observed = set()
    for phase, report in reports.items():
        started = int(
            dt.datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1_000_000
        )
        connections = [
            event for event in report["events"] if event["event"] == "connect"
        ]
        need(
            set(views[phase]) == {e["connection"] for e in connections},
            "Packet socket inventory differs",
        )
        for event in connections:
            name = event["connection"]
            port = event["local_address"][1]
            need(port not in observed, "Repeated client TCP source port")
            observed.add(port)
            start = started + event["elapsed_ns"] // 1000
            for label, source, client, server, target in (
                ("namespace", namespace, "127.0.0.1", "127.0.0.1", 15750),
                ("guest", guest, "10.0.2.2", "10.0.2.15", 5500),
            ):
                lifetime_packets = lifetime(
                    source, (client, port), (server, target), start
                )
                need(
                    bool(lifetime_packets),
                    f"{phase}/{name}/{label} TCP lifetime missing",
                )
                sent = stream(lifetime_packets, (client, port), (server, target))
                received = stream(lifetime_packets, (server, target), (client, port))
                saved = views[phase][name][label]
                need(
                    saved["packet_indices"] == [p["index"] for p in lifetime_packets]
                    and saved["packet_count"] == len(lifetime_packets)
                    and saved["first_us"] == lifetime_packets[0]["timestamp_us"]
                    and saved["last_us"] == lifetime_packets[-1]["timestamp_us"]
                    and saved["fin_packets"]
                    == [p["index"] for p in lifetime_packets if p["flags"] & 1]
                    and saved["rst_packets"]
                    == [p["index"] for p in lifetime_packets if p["flags"] & 4]
                    and saved["sent_len"] == len(sent)
                    and saved["received_len"] == len(received)
                    and saved["sent_sha256"] == hashlib.sha256(sent).hexdigest()
                    and saved["received_sha256"] == hashlib.sha256(received).hexdigest()
                    and saved["sent_hex"] == sent.hex()
                    and saved["received_hex"] == received.hex()
                    and saved["received_tail_hex"] == received[-96:].hex()
                    and sent.hex() == report["streams"][name]["sent_hex"]
                    and received.hex() == report["streams"][name]["received_hex"],
                    f"{phase}/{name}/{label} scoped stream differs",
                )
                if phase == "ban" and name == "target" and label == "namespace":
                    need(
                        any(
                            p["src_port"] == target and p["flags"] & 1
                            for p in lifetime_packets
                        ),
                        "Target server FIN missing",
                    )
    need(
        len(observed) == 6
        and sum(p["dst_port"] == 15750 and p["flags"] == 2 for p in namespace) == 6,
        "Unexpected namespace TCP connection count",
    )
    return {
        "connections": len(observed),
        "namespace_packets": len(namespace),
        "guest_packets": len(guest),
    }


def terminal(corpus: Path) -> dict:
    base = corpus / "case-c56"
    result = loaded(base / "terminal.json")
    need(
        result["profile"] == "control-only"
        and result["full_file_baseline"] == "not_exercised"
        and result["actual_emulator_pid"] == PID
        and result["actual_pid_gone"] is True,
        "Terminal profile differs",
    )
    need(
        result["pcap"]["primary_syn_bytes"] == 24
        and result["pcap"]["host_terminal_log_tail"][-1]
        == "0 packets dropped by kernel"
        and result["pcap"]["namespace_terminal_log_tail"][-1]
        == "0 packets dropped by kernel"
        and result["original"]["primary_fd6"]["stdout"]
        .strip()
        .endswith("hotline22-recovery/working.dsk")
        and result["original"]["client_fd6"]["stdout"]
        .strip()
        .endswith("hotline-client-isolated-01/working.dsk"),
        "Terminal original or capture proof differs",
    )
    need(
        len(result["units"]) == 7
        and all(
            "ActiveState=inactive" in item["stdout"] and "MainPID=0" in item["stdout"]
            for item in result["units"].values()
        )
        and loaded(base / "cleanup-signals.json")["pid_gone"] is True
        and result["no_case_retry"] is True
        and result["no_restart_unban_or_full_A7"] is True,
        "Lab cleanup or no-retry proof differs",
    )
    raw = base / "Banned.data.bin"
    ban = result["ban_file"]
    need(
        ban["catalog"] == 11771
        and ban["path"] == "/Hotline19/Banned"
        and ban["data_bytes"] == raw.stat().st_size == 49
        and ban["data_sha256"] == digest(raw) == EXPECTED["banned"]
        and ban["resource_bytes"] == 0
        and ban["bak_absent"] is True
        and "Catalog Record: 11771" in (base / "Banned.stat.txt").read_text()
        and "Resource fork size:\t0" in (base / "Banned.stat.txt").read_text()
        and result["stopped_image_sha256"] == EXPECTED["stopped"]
        and (base / "stopped-image.sha256").read_text().split()[0]
        == EXPECTED["stopped"]
        and result["image_fd_free_before_hash"] is True,
        "Stopped persisted ban bytes or image proof differs",
    )
    return {"ban_bytes": raw.stat().st_size, "ban_sha256": digest(raw)}


def failed_full_baselines(corpus: Path) -> None:
    for label in ("c35", "c45", "c50"):
        base = corpus / "failed-full-A7" / label
        report = verify_capture(base / "a7-capture")
        need(
            report["status"] == "failed"
            and report["completed_actions"] == 21
            and report["error"] == "TimeoutError: timed out"
            and len(bytes.fromhex(report["streams"]["download"]["received_hex"]))
            == 98_304
            and digest(base / "a7-capture/plan.json")
            == digest(base / "a7-as-run-plan.json"),
            f"{label} failed full-file baseline differs",
        )
        if (base / "a7-original-plan.json").exists():
            need(
                digest(base / "a7-original-plan.json") == EXPECTED["source_a7"],
                f"{label} original A7 source differs",
            )


def verify(corpus: Path) -> dict:
    corpus = corpus.resolve()
    inventory(corpus)
    ready = boot(corpus)
    reports = case(corpus, ready)
    packet_result = packets(corpus, reports)
    stopped = terminal(corpus)
    failed_full_baselines(corpus)
    return {
        "status": "verified_control_only_option_two_notice_and_login_rejection",
        "full_file_baseline": "not_exercised",
        **packet_result,
        **stopped,
        "primary_syn": 0,
        "lab_retired": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    print(json.dumps(verify(parser.parse_args().corpus), indent=2))


if __name__ == "__main__":
    main()
