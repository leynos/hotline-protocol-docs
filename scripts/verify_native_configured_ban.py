#!/usr/bin/env python3
"""Replay the control-only native Options-ban application witness offline."""

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path

import native_configured_ban_control as control
import native_control_readiness as base
from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import decode_frame, verify_capture

SCHEMA = "native-configured-ban-01"
BASE = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
ROM = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
EXE = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
DATA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
RSRC = "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12"
CASES = "23fbb968f1d692b8d7cfeb5937d56dc1cb35d75f102efa18fa6f97173b56ccc4"
CONTROLLER = "ee9648248618269aa20572362f54af25b157fed6586265874e1964c1ebd6f13a"
STOPPED = "bd8ddf219f75118eda91cbfd0e2dd5dc133534840bd587a58b483e4e6410f499"
BANNED = "671c8164c116d26cf5bb863ba87b93174f81b1a59abb208491b57f9d41a87aa1"
ADMIN = "26612ad46cd91b90050feacf517d32a9e56d4a4aa92fbe6618eaf6e9e5ac60a3"
LOW = "fce81359d0efcfc6c2dbf42852db66b0fb7a404b2889162b8f8fad81361ce2d5"
PREFS = "4ed2b3e14e6e8a6cf246d16f7d1b98f0b91d1b09f6ab5497de1056a6f617d196"
PID, START, NS = 600782, "5595993", "net:[4026533397]"
PHASES = {"readiness": 18, "guard": 10, "seed": 12, "held-apply": 23}


def need(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def read(path: Path) -> dict:
    return json.loads(path.read_text())


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def instant(path: Path) -> dt.datetime:
    return dt.datetime.fromisoformat(path.read_text().strip().replace(",", "."))


def inventory(corpus: Path) -> dict:
    manifest = read(corpus / "manifest.json")
    need(
        corpus.name == SCHEMA
        and manifest["schema"] == SCHEMA
        and manifest["profile"] == "control-only"
        and manifest["full_file_baseline"] == "not_exercised"
        and manifest["failed_full_A7"] == ["C35", "C45", "C50"]
        and manifest["source_heads"]["protocol"]
        == "91f8e0a8c4bbeba719d008ee569f7427737a6cd4"
        and manifest["source_sha256"]
        == {"cases": CASES, "controller": CONTROLLER, "data": DATA, "rsrc": RSRC},
        "Corpus profile or source identity differs",
    )
    files = manifest["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(actual == set(files), "Corpus inventory differs")
    for name, expected in files.items():
        need(sha(corpus / name) == expected, f"Corpus SHA differs: {name}")
    need(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{value}  {name}" for name, value in sorted(files.items())],
        "SHA256SUMS differs",
    )
    need(
        sha(corpus / "sources/protocol/native_configured_ban_cases.py") == CASES
        and sha(corpus / "sources/protocol/native_configured_ban_control.py")
        == CONTROLLER,
        "Controller source snapshot differs",
    )
    need(
        len(files) <= 160
        and sum(
            (corpus / name).stat().st_size
            for name in files
            if not name.endswith(".pcap")
        )
        <= 24 * 1024 * 1024
        and sum(
            (corpus / name).stat().st_size for name in files if name.endswith(".pcap")
        )
        <= 2 * 1024 * 1024,
        "Corpus size bound exceeded",
    )
    return manifest


def failed_c65(corpus: Path) -> None:
    root = corpus / "native-configured-apply-c65"
    failure = read(root / "terminal.json")
    need(
        failure["owned_runtime_fd_processes"] == []
        and failure["guest_pcap_present"] is False
        and failure["working_disk_open"] is False
        and failure["host_primary_pcap_size"] == 24
        and failure["display114_socket_present"] is False,
        "C65 failed-boot status differs",
    )
    need(not read_packets(root / "primary-syn.pcap"), "C65 primary SYN differs")
    need(
        "0 packets dropped by kernel" in (root / "host-recorder.log").read_text()
        and "status=1/FAILURE" in (root / "sheep-journal.log").read_text()
        and "Result=success" in (root / "system-units-terminal.txt").read_text()
        and "ActiveState=inactive" in (root / "user-units-terminal.txt").read_text(),
        "C65 failure or cleanup record differs",
    )
    note = (corpus / "c65-launch-failure-operator-note.md").read_text()
    need(
        "FileExistsError" in note
        and "not a native-server protocol observation" in note,
        "C65 operator failure classification missing",
    )


def preboot(corpus: Path) -> None:
    asset = corpus / "assets"
    proof, hfs, source = (
        read(asset / name)
        for name in ("asset-proof.json", "preflight.json", "assets.json")
    )
    need(
        all(
            proof[name]["sha256"] == BASE
            for name in ("source_base", "prepared_base", "prepared_working")
        )
        and all(proof[name]["sha256"] == ROM for name in ("source_rom", "prepared_rom"))
        and source["base_disk_sha256"] == BASE
        and source["rom_sha256"] == ROM
        and hfs["app"]["app_data"]["sha256"] == DATA
        and hfs["app"]["app_rsrc"]["sha256"] == RSRC
        and hfs["app"]["prefs"] == {"catalog": "11202", "size": 175, "sha256": PREFS}
        and hfs["app"]["admin"]["sha256"] == ADMIN
        and hfs["app"]["fixture_low"]["sha256"] == LOW
        and hfs["original_user_count"] == 2
        and hfs["banned_absent"] is True
        and hfs["owned_account_absent"] is True,
        "Immutable preboot assets or two-account state differ",
    )
    need(
        all(value == "free-at-preparation" for value in proof["ports"].values())
        and proof["display114_socket_absent"] is True
        and "Hotline19/Banned" not in "\n".join(hfs["catalog_entries"]),
        "Preboot port or Banned state differs",
    )
    old = read(asset / "plans-prepared/source-hashes.json")
    need(set(old) == set(PHASES), "Prepared plan inventory differs")
    for name in PHASES:
        plan = asset / "plans-prepared" / f"{name}.json"
        need(sha(plan) == old[name], "Original prepared plan SHA differs")
        need(
            read(plan)["environment"]["emulator_pid"] is None,
            "Prepared plan unexpectedly live",
        )


def boot_and_ui(corpus: Path) -> dict:
    root = corpus / "native-configured-apply-c66"
    ready, processes = read(root / "readiness.json"), read(root / "process-ready.json")
    lab = processes["lab"]
    need(
        ready["actual_emulator"] == lab
        and (lab["pid"], lab["starttime"], lab["netns"]) == (PID, START, NS)
        and lab["exe_sha256"] == EXE
        and lab["exe"].endswith(EXE)
        and lab["fd6"].endswith("native-configured-apply-01/working.dsk")
        and lab["fd16"].endswith("native-configured-apply-c66/lab-guest.pcap")
        and lab["uid"].split()[1] == "1000"
        and lab["cap_eff"].split()[1] == "0000000000020000"
        and processes["primary"]["pid"] == 1099659
        and processes["client"]["pid"] == 1012834
        and len(
            {lab["netns"], processes["primary"]["netns"], processes["client"]["netns"]}
        )
        == 3,
        "Actual lab emulator or original identity differs",
    )
    lease = read(root / "lease-ready.json")
    need(
        lease["main_pid"] == 599355
        and lease["lock_inode"] == 3512552451
        and lease["busy_flock_exit"] == 1
        and lease["uid"].split()[1] == "1000",
        "Managed oracle lockholder differs",
    )
    deadline = read(root / "deadline.json")
    fixed = dt.datetime.fromisoformat(deadline["fixed_deadline_utc"])
    plus = dt.datetime.fromisoformat(deadline["capture_deadline_utc"])
    need(
        (plus - fixed).total_seconds() == 5
        and ready["fixed_deadline_utc"] == deadline["fixed_deadline_utc"]
        and ready["remaining_seconds"] >= 300
        and ready["namespace_established_connections"] == 0
        and ready["namespace_routes"] == []
        and read(root / "namespace-routes.json") == []
        and (root / "namespace-established.txt").read_text() == "",
        "Boot deadline, route or no-contact UI readiness differs",
    )
    for label in ("host", "namespace"):
        first = read(root / f"{label}-ready.json")
        final = read(root / f"{label}-ready-final.json")
        case = read(root / f"{label}-ready-case.json")
        need(
            first["pid"] == final["pid"] == case["pid"]
            and first["start_ticks"] == final["start_ticks"] == case["start_ticks"]
            and first["header24"] == final["header24"] == case["header24"]
            and all(
                x["deadline_utc"] == deadline["capture_deadline_utc"]
                for x in (first, final, case)
            )
            and all(
                x["unit_properties"]["ActiveState"] == "active"
                for x in (first, final, case)
            )
            and all(
                x["unit_properties"]["KillMode"] == "control-group"
                for x in (first, final, case)
            ),
            f"{label} recorder identity or deadline differs",
        )
    for name, expected in ready["screenshots_sha256"].items():
        need(sha(root / name) == expected, f"{name} UI screenshot differs")
    need(
        ready["ban_ui_empty_before_entry"] is True
        and ready["typed_ip"] == "10.0.2.2"
        and ready["info_empty"] is True
        and ready["clicked_cancel_without_add_save"] is True
        and ready["host_primary_pcap_bytes"] == 24
        and (root / "options-cancel.utc").exists(),
        "Unsaved UI rehearsal differs",
    )
    return ready


def case(corpus: Path, ready: dict) -> dict[str, dict]:
    root = corpus / "native-configured-apply-c66"
    capture = read(root / "capture-ready.json")
    need(
        capture["emulator_pid"] == PID
        and capture["emulator_starttime"] == START
        and capture["emulator_netns"] == NS
        and capture["emulator_sha256"] == EXE
        and capture["owned_working_image"].endswith(
            "native-configured-apply-01/working.dsk"
        )
        and capture["host_recorder_pid"] == ready["capture_pids"]["host"]
        and capture["namespace_recorder_pid"] == ready["capture_pids"]["namespace"]
        and capture["ns_routes"] == []
        and capture["primary_syn_count"] == 0,
        "Actual case capture identity differs",
    )
    hashes = read(root / "plans-asrun/source-hashes.json")
    need(set(hashes) == set(PHASES), "Actual plan inventory differs")
    reports = {}
    for phase, actions in PHASES.items():
        path = root / "plans-asrun" / f"{phase}.json"
        plan = read(path)
        need(
            sha(path) == hashes[phase]
            and plan["environment"]["emulator_pid"] == PID
            and plan["environment"]["emulator_starttime"] == START
            and plan["environment"]["source_a7_sha256"]
            == "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"
            and plan["environment"]["fixture_profile"] == "control-only"
            and plan["environment"]["full_file_baseline"] == "not_exercised"
            and plan["endpoints"] == {"control": {"host": "127.0.0.1", "port": 15770}}
            and len(plan["steps"]) == actions
            and sha(root / "captures" / phase / "plan.json") == hashes[phase],
            f"{phase} source plan identity or profile differs",
        )
        report = verify_capture(root / "captures" / phase)
        need(
            report["status"] == "completed"
            and report["completed_actions"] == actions
            and report.get("controller_uid", 0) == 0,
            f"{phase} capture incomplete or not root",
        )
        reports[phase] = report
    base.readiness(reports["readiness"])
    control.account_gate(reports["guard"], absent=True)
    control.account_gate(reports["seed"], absent=False)
    held = reports["held-apply"]
    gate = read(root / "captures/held-apply/held-ready.json")
    need(
        gate
        == {
            "source_plan_sha256": hashes["held-apply"],
            "completed_actions": 17,
            "target_uid_hex": "0005",
            "controller_uid": 0,
        }
        and control.identity_gate(held["frames"]) == b"\0\5",
        "Held current target UID, access or roster differs",
    )
    control.outcome(held, read(root / "plans-asrun/held-apply.json"))
    need(
        (root / "reviewed-save.trigger").read_bytes() == b"reviewed-save\n",
        "Reviewed Save trigger bytes differ",
    )
    requests = [
        decode_frame(bytes.fromhex(e["hex"]))
        for report in reports.values()
        for e in report["events"]
        if e["event"] == "send"
        and len(e["hex"]) >= 40
        and not e["hex"].startswith("54525450")
    ]
    need(
        not any(f["type"] in {110, 202, 203, 214} for f in requests),
        "Forbidden ban request or full-file operation observed",
    )
    return reports


def timeline(corpus: Path, reports: dict[str, dict]) -> None:
    root = corpus / "native-configured-apply-c66"
    held = reports["held-apply"]
    started = dt.datetime.fromisoformat(held["started_at_utc"])
    last_gate = max(
        started + dt.timedelta(microseconds=e["elapsed_ns"] // 1000)
        for e in held["events"]
        if e["action"] == 16
    )
    first_notice = min(
        started + dt.timedelta(microseconds=e["elapsed_ns"] // 1000)
        for e in held["events"]
        if e["action"] in {17, 18} and e["event"] == "receive"
    )
    add, trigger, save_return = (
        instant(root / name)
        for name in ("add-click.utc", "save-trigger.utc", "save-click-return.utc")
    )
    need(
        last_gate < add < trigger < first_notice < save_return
        and 0 < (trigger - add).total_seconds() < 120
        and 0 < (save_return - trigger).total_seconds() < 2
        and not any(
            e["action"] >= 17
            for e in held["events"]
            if e["event"] == "receive"
            and started + dt.timedelta(microseconds=e["elapsed_ns"] // 1000) < trigger
        ),
        "Add, reviewed Save or early-data timing differs",
    )
    deadline = dt.datetime.fromisoformat(
        read(root / "deadline.json")["fixed_deadline_utc"]
    )
    need(
        save_return < instant(root / "server-quit.utc") < deadline,
        "Global case deadline or retirement order differs",
    )
    need(
        sha(root / "after-one-add.png")
        == "630fdd66396cb7a9774ff8864de7256e8d133001b222e91e1cd43ed3e5d6acee"
        and sha(root / "held-ip-before-add.png")
        == "b22f350ac4a3b47b57ddf699ea662287553561ebd75cd4c56ded25eb49bc6522",
        "Checked row or pre-Add UI screenshot differs",
    )


def packets(corpus: Path, reports: dict[str, dict]) -> dict:
    first = corpus / "native-configured-apply-c65"
    root = corpus / "native-configured-apply-c66"
    need(not read_packets(first / "primary-syn.pcap"), "C65 primary SYN exists")
    need(not read_packets(root / "primary-syn.pcap"), "Primary SYN capture is nonempty")
    namespace = read_packets(root / "lab-namespace.pcap")
    guest = read_packets(root / "lab-guest.pcap")
    need(
        not any(
            p["src_port"] in {15500, 15501} or p["dst_port"] in {15500, 15501}
            for p in namespace
        )
        and {p["src_port"] for p in namespace if p["dst_port"] == 15770}
        == {53240, 53250, 53262, 44898, 44902},
        "Primary bridge contact or five-client scope differs",
    )
    for label in ("host", "namespace"):
        log = (root / f"{label}-recorder.log").read_text()
        need("0 packets dropped by kernel" in log, f"{label} capture drops differ")
    need(
        "0 packets captured" in (root / "host-recorder.log").read_text(),
        "Primary SYN counter differs",
    )
    views = read(corpus / "packet-views.json")
    need(set(views) == set(PHASES), "Packet phase inventory differs")
    observed = set()
    for phase, report in reports.items():
        started = int(
            dt.datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1_000_000
        )
        connects = [e for e in report["events"] if e["event"] == "connect"]
        need(
            set(views[phase]) == {e["connection"] for e in connects},
            "Packet socket inventory differs",
        )
        for event in connects:
            name, port = event["connection"], event["local_address"][1]
            need(port not in observed, "Repeated client TCP source port")
            observed.add(port)
            when = started + event["elapsed_ns"] // 1000
            for label, source, client, server, target in (
                ("namespace", namespace, "127.0.0.1", "127.0.0.1", 15770),
                ("guest", guest, "10.0.2.2", "10.0.2.15", 5500),
            ):
                scoped = lifetime(source, (client, port), (server, target), when)
                sent = stream(scoped, (client, port), (server, target))
                received = stream(scoped, (server, target), (client, port))
                saved = views[phase][name][label]
                need(
                    bool(scoped)
                    and saved["client_port"] == port
                    and saved["packet_indices"] == [p["index"] for p in scoped]
                    and saved["packet_count"] == len(scoped)
                    and saved["first_us"] == scoped[0]["timestamp_us"]
                    and saved["last_us"] == scoped[-1]["timestamp_us"]
                    and saved["fin_packets"]
                    == [p["index"] for p in scoped if p["flags"] & 1]
                    and saved["rst_packets"]
                    == [p["index"] for p in scoped if p["flags"] & 4]
                    and saved["sent_len"] == len(sent)
                    and saved["received_len"] == len(received)
                    and saved["sent_sha256"] == hashlib.sha256(sent).hexdigest()
                    and saved["received_sha256"] == hashlib.sha256(received).hexdigest()
                    and saved["sent_hex"]
                    == sent.hex()
                    == report["streams"][name]["sent_hex"]
                    and saved["received_hex"]
                    == received.hex()
                    == report["streams"][name]["received_hex"]
                    and saved["received_tail_hex"] == received[-96:].hex(),
                    f"{phase}/{name}/{label} paired TCP bytes differ",
                )
                if phase == "held-apply":
                    need(
                        any(p["src_port"] == target and p["flags"] & 1 for p in scoped),
                        f"{name}/{label} server FIN missing",
                    )
    need(
        len(observed) == 5
        and sum(p["dst_port"] == 15770 and p["flags"] == 2 for p in namespace) == 5,
        "Five complete SYN lifetimes differ",
    )
    return {
        "connections": len(observed),
        "namespace_packets": len(namespace),
        "guest_packets": len(guest),
    }


def terminal(corpus: Path) -> dict:
    root = corpus / "native-configured-apply-c66"
    unit = (root / "c67-unit-retained.txt").read_text()
    need(
        all(
            item in unit
            for item in (
                "Type=oneshot",
                "User=0",
                "Group=0",
                f"NetworkNamespacePath=/proc/{PID}/ns/net",
                "TimeoutStartUSec=3min",
                "RuntimeMaxUSec=3min",
                "RemainAfterExit=yes",
                "ActiveState=active",
                "SubState=exited",
                "MainPID=0",
                "Result=success",
                "ExecMainStatus=0",
                "status=0",
                "native_configured_ban_control.py execute",
            )
        )
        and "ActiveState=inactive" in (root / "c67-unit-cleanup.txt").read_text()
        and "MainPID=0" in (root / "c67-unit-cleanup.txt").read_text(),
        "Retained terminal oneshot or cleanup differs",
    )
    done = read(root / "terminal.json")
    need(
        done["actual_lab_pid_gone"] is True
        and done["host_primary_syn_pcap_bytes"] == 24
        and done["host_drop_count"] == done["namespace_drop_count"] == 0
        and done["display114_absent"] is True
        and done["owned_ports_absent"] is True
        and done["oracle_lease_released"] is True
        and done["originals"]["primary"]["starttime"] == "767842"
        and done["originals"]["client"]["starttime"] == "2357813",
        "Lab retirement, zero contact or original processes differ",
    )
    hashes = read(root / "stopped-files/summary.json")
    need(
        set(hashes)
        == {
            "Hotline19/Banned",
            "Hotline19/Prefs",
            "Hotline19/Users/admin/UserData",
            "Hotline19/Users/fixture-low/UserData",
            "Hotline19/Users/m-ban-apply-only/UserData",
        }
        and hashes["Hotline19/Banned"]["size"] == 49
        and hashes["Hotline19/Banned"]["sha256"] == BANNED
        and hashes["Hotline19/Prefs"]["size"] == 175
        and hashes["Hotline19/Prefs"]["sha256"] == PREFS
        and hashes["Hotline19/Users/admin/UserData"]["sha256"] == ADMIN
        and hashes["Hotline19/Users/fixture-low/UserData"]["sha256"] == LOW
        and hashes["Hotline19/Users/m-ban-apply-only/UserData"]["size"] == 734
        and (root / "stopped-working.sha256").read_text().split()[0] == STOPPED,
        "Stopped Banned, Prefs, UserData or image bytes differ",
    )
    for item in hashes.values():
        need(
            sha(root / "stopped-files" / item["file"]) == item["sha256"],
            "Stopped stored file bytes differ",
        )
    need(
        "Banned.bak" not in (root / "stopped-files/catalog.txt").read_text(),
        "Unexpected Banned.bak evidence",
    )
    return {"ban_bytes": 49, "ban_sha256": BANNED, "stopped_image_sha256": STOPPED}


def verify(corpus: Path) -> dict:
    corpus = corpus.resolve()
    inventory(corpus)
    failed_c65(corpus)
    preboot(corpus)
    ready = boot_and_ui(corpus)
    reports = case(corpus, ready)
    timeline(corpus, reports)
    traffic = packets(corpus, reports)
    stored = terminal(corpus)
    return {
        "status": "verified_control_only_connected_configured_ban_notice",
        "full_file_baseline": "not_exercised",
        "primary_syn": 0,
        "lab_retired": True,
        **traffic,
        **stored,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    print(json.dumps(verify(parser.parse_args().corpus), indent=2))


if __name__ == "__main__":
    main()
