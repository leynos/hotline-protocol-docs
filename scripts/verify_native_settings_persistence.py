#!/usr/bin/env python3
"""Replay the A46 legacy and A48 planned-EOF control-only persistence corpus."""

import argparse
import importlib.util
import json
import re
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import native_settings_persistence as current_runner
from native_control_readiness import readiness
from pcap_tcp import read_packets, stream
from pinned_source import pinned_bytes
from protocol_capture import ORACLE_SHA256, digest, verify_capture

A46_SOURCES = {
    "native_settings_persistence_cases.py": "ecd3bba43abcefc31ad5f0aecd2c27f3d5c127e2d3ca7292e95cf05b4d344fe7",
    "native_settings_persistence.py": "9122c142d515811b9485c3fe728618152271a5adb85e547f0c3022e549d23c92",
}
A48_SOURCES = {
    "native_settings_persistence_cases.py": "29ad770ab95dd9035b46dd3a1616448efd8a987520f59567320db2a92c200229",
    "native_settings_persistence.py": "a2474c41ef7098f8fd00535712cb6e139497bdce269c176d0013865fa3cba23a",
}
FORKS = {
    11193: (
        "/Hotline19/Users/admin/UserData",
        734,
        "26612ad46cd91b90050feacf517d32a9e56d4a4aa92fbe6618eaf6e9e5ac60a3",
    ),
    11201: (
        "/Hotline19/Users/fixture-low/UserData",
        734,
        "fce81359d0efcfc6c2dbf42852db66b0fb7a404b2889162b8f8fad81361ce2d5",
    ),
    11202: (
        "/Hotline19/Prefs",
        175,
        "4ed2b3e14e6e8a6cf246d16f7d1b98f0b91d1b09f6ab5497de1056a6f617d196",
    ),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def load_frozen(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("Frozen source loader missing")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def inventory(corpus: Path) -> dict:
    manifest = read_json(corpus / "manifest.json")
    require(manifest["schema_version"] == 1, "Corpus schema differs")
    require(manifest["corpus"] == "native-settings-persistence-01", "Wrong corpus")
    require(
        manifest["profile"] == "control-only"
        and manifest["full_file_baseline"] == "not_exercised",
        "Control-only scope differs",
    )
    require(
        "did not hold canonical oracle.lock"
        in manifest["phase2_oracle_lock_deviation"],
        "A48 lock deviation missing",
    )
    actual = {str(p.relative_to(corpus)) for p in corpus.rglob("*") if p.is_file()}
    declared = set(manifest["files"])
    require(
        actual == declared | {"manifest.json", "SHA256SUMS"},
        "Corpus file inventory differs",
    )
    for name, record in manifest["files"].items():
        path = corpus / name
        require(
            path.is_file() and path.stat().st_size == record["bytes"],
            f"Corpus size differs: {name}",
        )
        require(
            digest(path.read_bytes()) == record["sha256"],
            f"Corpus hash differs: {name}",
        )
    lines = (corpus / "SHA256SUMS").read_text().splitlines()
    expected = {
        f"{digest((corpus / name).read_bytes())}  {name}"
        for name in declared | {"manifest.json"}
    }
    require(
        set(lines) == expected and len(lines) == len(expected), "SHA256SUMS differs"
    )
    return manifest


def source_identity(corpus: Path) -> None:
    for phase, expected in (("a46", A46_SOURCES), ("a48", A48_SOURCES)):
        for name, value in expected.items():
            require(
                digest((corpus / "source" / phase / name).read_bytes()) == value,
                f"{phase} source differs: {name}",
            )
    shared = (
        "native_control_readiness.py",
        "native_ban_control_cases.py",
        "pcap_tcp.py",
        "protocol_capture.py",
    )
    for name in shared:
        require(
            digest((corpus / "source/a48" / name).read_bytes())
            == digest(pinned_bytes(name)),
            f"Shared verifier source differs: {name}",
        )
    for phase in (1, 2):
        directory = corpus / f"phase{phase}"
        planned = read_json(directory / "plans/source-code-sha256.json")
        for name, value in planned.items():
            source = (
                corpus
                / "source"
                / ("a46" if phase == 1 and name in A46_SOURCES else "a48")
                / name
            )
            require(
                digest(source.read_bytes()) == value,
                f"Phase {phase} source pin differs: {name}",
            )
        plan_hashes = read_json(directory / "plans/source-hashes.json")
        for case, value in plan_hashes.items():
            require(
                digest((directory / "plans" / f"{case}.json").read_bytes()) == value,
                f"Phase {phase} plan pin differs: {case}",
            )


def legacy_report(corpus: Path) -> tuple[dict, dict, dict]:
    directory = corpus / "phase1/phase1"
    plan_raw = (directory / "plan.json").read_bytes()
    report_raw = (directory / "report.json").read_bytes()
    checks = (directory / "checksums.sha256").read_text()
    require(
        checks == f"{digest(plan_raw)}  plan.json\n{digest(report_raw)}  report.json\n",
        "A46 raw checksums differ",
    )
    plan, report = json.loads(plan_raw), json.loads(report_raw)
    require(
        plan == read_json(corpus / "phase1/plans/phase1.json"),
        "A46 as-run plan differs",
    )
    require(
        len(plan["steps"]) == 64
        and report["completed_actions"] == 66
        and report["status"] == "completed",
        "A46 legacy 64+2 count differs",
    )
    require(
        report["plan_sha256"] == digest(plan_raw)
        and report["driver_sha256"] == A46_SOURCES["native_settings_persistence.py"],
        "A46 raw provenance differs",
    )
    require(
        report["oracle_sha256"] == plan["oracle_sha256"] == ORACLE_SHA256,
        "A46 oracle differs",
    )
    eof = [
        (event["action"], event["connection"])
        for event in report["events"]
        if event["event"] == "eof"
    ]
    require(eof == [(64, "subject"), (65, "main")], "A46 legacy EOF actions differ")
    try:
        verify_capture(directory)
    except ValueError as error:
        require(
            str(error) == "Incomplete plan reported as completed",
            "A46 generic rejection changed",
        )
    else:
        raise ValueError("A46 raw legacy plan must remain generically rejected")
    old_cases = load_frozen(
        "a46_cases", corpus / "source/a46/native_settings_persistence_cases.py"
    )
    old_runner = load_frozen(
        "a46_runner", corpus / "source/a46/native_settings_persistence.py"
    )
    old_runner.cases = old_cases
    require(
        plan
        == old_cases.plans(plan["environment"], plan["endpoints"]["control"]["port"])[
            "phase1"
        ],
        "A46 frozen generator differs",
    )
    # Temporary normalized analysis only. The retained as-run plan/report stay untouched.
    normal_plan = json.loads(plan_raw)
    normal_plan["steps"] += [
        {"op": "read_eof", "connection": name, "timeout": 720}
        for name in ("subject", "main")
    ]
    normal_report = json.loads(report_raw)
    with tempfile.TemporaryDirectory() as temporary:
        derived = Path(temporary)
        normal_raw = (json.dumps(normal_plan) + "\n").encode()
        normal_report["plan_sha256"] = digest(normal_raw)
        normal_report_raw = (json.dumps(normal_report) + "\n").encode()
        (derived / "plan.json").write_bytes(normal_raw)
        (derived / "report.json").write_bytes(normal_report_raw)
        (derived / "checksums.sha256").write_text(
            f"{digest(normal_raw)}  plan.json\n{digest(normal_report_raw)}  report.json\n"
        )
        replay = verify_capture(derived)
    require(
        replay["frames"] == report["frames"] and replay["streams"] == report["streams"],
        "A46 raw frame/stream replay differs",
    )
    semantic = old_runner.semantic(report, plan)
    require(
        semantic["status"] == "verified_phase_only" and len(semantic["gates"]) == 15,
        "A46 legacy semantic gates differ",
    )
    parent = read_json(corpus / "baseline/a46-parent-verification.json")
    require(
        parent["raw_checksums_frames_streams_verified"]
        and parent["gates"] == semantic["gates"],
        "A46 independent replay differs",
    )
    return plan, report, semantic


def planned_report(corpus: Path) -> tuple[dict, dict, dict]:
    directory = corpus / "phase2/phase2"
    plan = read_json(directory / "plan.json")
    report = verify_capture(directory)
    require(
        plan == read_json(corpus / "phase2/plans/phase2.json"),
        "A48 as-run plan differs",
    )
    require(
        len(plan["steps"]) == report["completed_actions"] == 28,
        "A48 planned EOF count differs",
    )
    require(
        plan["expectation"]["observation_actions"] == 26,
        "A48 observation boundary differs",
    )
    require(
        report["driver_sha256"] == A48_SOURCES["native_settings_persistence.py"],
        "A48 driver differs",
    )
    semantic = current_runner.semantic(report, plan)
    require(
        semantic["status"] == "verified_phase_only"
        and semantic["gates"] == ["identity", "baseline-delivery", "baseline-pm"],
        "A48 semantic gates differ",
    )
    return plan, report, semantic


def controls(corpus: Path) -> None:
    for phase in (1, 2):
        directory = corpus / f"phase{phase}"
        report = verify_capture(directory / "readiness")
        readiness(report)
        plan = read_json(directory / "readiness/plan.json")
        require(
            plan == read_json(directory / "plans/readiness.json"),
            "Readiness as-run plan differs",
        )


def login_vectors(first: dict, second: dict) -> None:
    def sent(plan: dict) -> list[str]:
        return [
            step["hex"]
            for step in plan["steps"]
            if step["op"] == "send" and step["hex"].startswith("0000006b")
        ]

    require(
        len(sent(first)) == 2 and sent(first) == sent(second),
        "Fixed login 107 vectors differ",
    )


def paired_packets(corpus: Path, phase: int) -> list[dict]:
    directory = corpus / f"phase{phase}"
    recorded = read_json(directory / "paired-streams.json")
    require(
        recorded["paired_complete"] and recorded["lifetime_count"] == 3,
        "Paired packet claim differs",
    )
    primary = directory / "primary-syn.pcap"
    require(
        primary.stat().st_size == 24 and read_packets(primary) == [],
        "Primary SYN capture is nonempty",
    )
    host = read_packets(directory / "namespace.pcap")
    guest = read_packets(directory / "guest.pcap")
    host_ports = [p["src_port"] for p in host if p["flags"] & 2 and not p["flags"] & 16]
    gports = [p["src_port"] for p in guest if p["flags"] & 2 and not p["flags"] & 16]
    require(
        len(host_ports) == 3 and len(set(host_ports)) == 3 and host_ports == gports,
        "SYN lifetimes differ",
    )
    ready = read_json(directory / "readiness/report.json")
    observed = read_json(
        directory / ("phase1" if phase == 1 else "phase2") / "report.json"
    )
    for port, case, report, row in zip(
        host_ports,
        ("readiness", "main", "subject"),
        (ready, observed, observed),
        recorded["flows"],
        strict=True,
    ):
        require(
            row["port"] == port and row["case"] == case, "Paired flow identity differs"
        )
        for label, packets, server in (
            ("namespace", host, ("127.0.0.1", 15760)),
            ("guest", guest, ("10.0.2.15", 5500)),
        ):
            client = ("127.0.0.1", port) if label == "namespace" else ("10.0.2.2", port)
            for direction, src, dst in (
                ("sent", client, server),
                ("received", server, client),
            ):
                data = stream(packets, src, dst)
                require(
                    len(data) == row[f"{label}_{direction}_bytes"]
                    and digest(data) == row[f"{label}_{direction}_sha256"],
                    "Paired packet stream differs",
                )
                recorder = bytes.fromhex(
                    report["streams"]["main" if case == "readiness" else case][
                        direction + "_hex"
                    ]
                )
                require(data == recorder, "Recorder/packet application bytes differ")
    for name in ("primary-syn.pcap", "namespace.pcap", "guest.pcap"):
        path = directory / name
        require(
            recorded["pcaps"][name]
            == {"bytes": path.stat().st_size, "sha256": digest(path.read_bytes())},
            "PCAP provenance differs",
        )
    return recorded["flows"]


def stopped_storage(corpus: Path) -> dict:
    base = read_json(corpus / "baseline/a41-assets.json")
    require(
        base["profile"] == "control-only" and not base["booted"],
        "A41 baseline identity differs",
    )
    path = base["target_working"]["path"]
    inode = base["target_working"]["inode"]
    first_hash = "e7ff40564780c0eb4b3e5bfdb24f8c4d37c3d1dbb7b4a77216d71c7be616aafa"
    final_hash = "be0b2c95c1ddd06e678bc31941bb01fb744d70fee50e28c82f2a71910c8f7d0a"
    for phase, image_hash in ((1, first_hash), (2, final_hash)):
        directory = corpus / f"phase{phase}"
        paths = dict(
            line.split("\t", 1)
            for line in (directory / "stopped-path-ids.txt").read_text().splitlines()
        )
        for catalog, (name, size, value) in FORKS.items():
            fork = directory / f"stopped-fork-{catalog}.bin"
            require(paths[name] == str(catalog), f"Phase {phase} HFS path differs")
            require(
                fork.stat().st_size == size and digest(fork.read_bytes()) == value,
                f"Phase {phase} stored fork differs",
            )
            require(
                base["objects"][name]
                == {"catalog": catalog, "data_size": size, "data_sha256": value},
                "A41 stored fork baseline differs",
            )
        hashes = (directory / "stopped-image-hashes.txt").read_text()
        require(
            f"{image_hash}  state/mac-runtime/native-settings-persistence-01/working.dsk"
            in hashes,
            f"Phase {phase} stopped image hash differs",
        )
        require(
            f"{base['target_base']['sha256']}  state/mac-runtime/native-settings-persistence-01/base.dsk"
            in hashes,
            "Immutable base hash differs",
        )
        stat = (directory / "stopped-assets-stat.txt").read_text()
        require(
            path.endswith(
                "/state/mac-runtime/native-settings-persistence-01/working.dsk"
            )
            and re.search(
                rf"state/mac-runtime/native-settings-persistence-01/working\.dsk \d+ {inode} 8388608000",
                stat,
            )
            is not None,
            "Same working image inode differs",
        )
    preboot = (corpus / "phase2/preboot-hashes.txt").read_text()
    require(
        first_hash in preboot and base["target_base"]["sha256"] in preboot,
        "A48 preboot was not A46 stopped image",
    )
    return {
        "same_working_inode": inode,
        "phase1_image_sha256": first_hash,
        "phase2_image_sha256": final_hash,
        "forks_unchanged": True,
    }


def lifecycle(corpus: Path) -> None:
    timeline = read_json(corpus / "baseline/operator-timeline.json")
    boot_journal = (corpus / "baseline/user-sheep-journal.txt").read_text()
    scope = timeline["scope"]
    require("not a machine exit attestation" in scope, "Shutdown proof scope differs")
    for phase, count in ((1, 66), (2, 28)):
        directory = corpus / f"phase{phase}"
        events = timeline["phases"][f"phase{phase}"]
        require(
            events["journal_start_utc"] in boot_journal, "Boot journal start missing"
        )
        status = events["machine_journal_exit_status"]
        require(status.startswith("not recorded"), "Missing exit-status caveat")
        keys = "quit_prompt_image after_quit_image special_menu_image shutdown_image"
        shots = [events["screenshots"][key] for key in keys.split()]
        require(
            all(
                digest((corpus / shot["path"]).read_bytes()) == shot["sha256"]
                for shot in shots
            ),
            "Shutdown screen binding differs",
        )
        stamps = [
            events["journal_start_utc"],
            events["hold_ready_utc"],
            *(shot["source_mtime_utc"] for shot in shots),
            events["operator_pid_absent_by_utc"],
            events["capture_stop_utc"],
            events["fork_extraction_completed_utc"],
        ]
        times = [datetime.fromisoformat(stamp) for stamp in stamps]
        require(times == sorted(times), "Operator shutdown chronology differs")
        parse = datetime.fromisoformat
        deadline_text = (directory / "deadline.txt").read_text().strip()
        deadline = parse(deadline_text.replace("Z", "+00:00"))
        case = directory / f"phase{phase}"
        hold = read_json(case / "hold-ready.json")
        observed = read_json(case / "report.json")
        require(events["hold_ready_utc"] == hold["utc"], "Hold-ready timeline differs")
        require(
            parse(stamps[2]) < parse(observed["recorded_at_utc"]) < parse(stamps[3]),
            "Quit/EOF timeline differs",
        )
        require(
            hold["sockets"] == ["main", "subject"]
            and datetime.fromisoformat(hold["utc"]) < deadline,
            "Owned sockets/deadline differ",
        )
        require(
            observed["completed_actions"] == count
            and datetime.fromisoformat(observed["recorded_at_utc"]) < deadline,
            "Phase report exceeded deadline",
        )
        gates = "host-ready-boot host-ready-readiness host-ready-phase namespace-ready-readiness namespace-ready-phase"
        for name in (f"{gate}.json" for gate in gates.split()):
            gate = read_json(directory / name)
            target = (
                observed
                if name.endswith("-phase.json")
                else read_json(directory / "readiness/report.json")
            )
            require(
                datetime.fromisoformat(gate["utc"]) < deadline
                and datetime.fromisoformat(gate["utc"])
                < datetime.fromisoformat(target["started_at_utc"])
                and gate["deadline_utc"] == deadline.isoformat(),
                "Capture gate readiness/deadline differs",
            )
        journal = (directory / "capture-journal.txt").read_text()
        require(
            journal.count("0 packets dropped by kernel") == 2
            and "0 packets captured" in journal,
            "Capture drops/primary zero differ",
        )
        units = (directory / "system-units-terminal.txt").read_text()
        require(
            units.count("MainPID=0") == 4 and units.count("Result=success") == 4,
            "Managed system unit terminal state differs",
        )
        user = (directory / "user-units-terminal.txt").read_text()
        require(user.count("MainPID=0") == 4, "User unit terminal state differs")
        identity = read_json(directory / "emulator-identity.json")
        require(
            identity["uid"] == 1000
            and identity["exe_sha256"]
            == "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4",
            "Emulator identity differs",
        )
        require(
            identity["working_image_fd6"].endswith(
                "native-settings-persistence-01/working.dsk"
            )
            and identity["guest_pcap_fd16"].endswith(
                f"native-settings-persistence-a{45 if phase == 1 else 48}/guest.pcap"
            ),
            "Emulator FD identity differs",
        )
        require(
            (directory / "screenshots" / "special-menu-hold2.png").is_file()
            and (directory / "screenshots" / "after-quit-confirm.png").is_file(),
            "Shutdown/quit screen missing",
        )
    first = read_json(corpus / "phase1/emulator-identity.json")
    second = read_json(corpus / "phase2/emulator-identity.json")
    require(
        (first["pid"], first["start_ticks"], first["netns"])
        != (second["pid"], second["start_ticks"], second["netns"]),
        "Same emulator instance reused",
    )


def verify(corpus: Path) -> dict:
    inventory(corpus)
    source_identity(corpus)
    controls(corpus)
    first, _first_report, first_semantic = legacy_report(corpus)
    second, _second_report, second_semantic = planned_report(corpus)
    login_vectors(first, second)
    flows = {f"phase{phase}": paired_packets(corpus, phase) for phase in (1, 2)}
    storage = stopped_storage(corpus)
    lifecycle(corpus)
    return {
        "status": "verified_control_only",
        "legacy_phase1": "verified_original_64_plus_2_not_generic_capture",
        "planned_phase2": "generic_and_semantic_verified_28",
        "gates": {
            "phase1": first_semantic["gates"],
            "phase2": second_semantic["gates"],
        },
        "paired_flows": {name: len(value) for name, value in flows.items()},
        "stored": storage,
        "operational_deviation": "A48 oracle.lock was not held; exclusive lease and zero primary SYN independently retained",
        "persistence_scope": "same-image operator-observed orderly shutdown and fresh-login control; no power-loss or all-storage claim",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.corpus), indent=2))


if __name__ == "__main__":
    main()
