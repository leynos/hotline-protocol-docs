"""Replay B62's finite Classic roster-115 experiment from portable evidence."""

import argparse
import hashlib
import json
from pathlib import Path

from pcap_tcp import read_packets
from verify_classic_native_baseline import flow, verify_a7
from verify_mac_peer_first_session import field_map, parse_frames

PROXY_SHA = "cbea168a5b77fdf7ab1c7cacf5119b36149723d0725748b592f2768e22664379"
PARSER_SHA = "04c4fda2e62ccab35ed306c036dac6b1878af58adbfaccc6312a2805dd6897d7"
RAW_ACK_SHA = "814b733a82d15dd7250cb0e8b7ed0c6c09a7a02d7169ab70ebaa359fb18eb6d0"
RAW_ROSTER_SHA = "9652ca8dee63462016f49e25c4e8cfe80900ed665e0b93d3386fd9d3016a4f90"
FORWARDED_ROSTER_SHA = (
    "6a094bcad87575dfd2df90589b6a5165ab5a7cdd3bed7ee2f07869f3b3d1c549"
)
AGREEMENT_SHA = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
FILP_SHA = "7d1f5bf5e2b69b8a18906633ce2ef550876b78252c0639e7d36eb61142787ab8"
CAPTURE_GATE_SHA = "7a75f4b78f1255f4486ced44fc5fb8882d6008c7de6844a82f4c107e7299d678"
HEADER = bytes.fromhex("d4c3b2a10200040000000000000000000000040001000000")
ROUTES = (
    "client-guest-post.pcap",
    "namespace.pcap",
    "namespace.pcap",
    "host.pcap",
    "server-guest-post.pcap",
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def inventory(base: Path) -> int:
    root = base.resolve().parents[3]
    found = set()
    for line in (base / "SHA256SUMS").read_text().splitlines():
        expected, rel = line.split("  ", 1)
        path = root / rel
        need(path.is_file() and path.resolve().is_relative_to(base), "inventory path")
        need(sha(path.read_bytes()) == expected, "SHA inventory mismatch")
        need(rel not in found, "duplicate inventory entry")
        found.add(rel)
    actual = {
        str(p.relative_to(root))
        for p in base.rglob("*")
        if p.is_file() and p.name != "SHA256SUMS"
    }
    need(found == actual, "SHA inventory file set")
    return len(found)


def source_check(base: Path, manifest: dict) -> None:
    source = manifest["source"]
    for name, revision, expected, key in (
        (
            "classic_login_proxy.py",
            "73681b1b06d58ede021a7440c1173595e8e78a0d",
            PROXY_SHA,
            "proxy",
        ),
        (
            "pcap_tcp.py",
            "31fd33efaa778eabcaed4195cccad4e2d7e89094",
            PARSER_SHA,
            "parser",
        ),
    ):
        need(
            source[f"{key}_path"] == f"../hotline-protocol-docs/scripts/{name}",
            "source path",
        )
        need(
            source[f"{key}_revision"] == revision
            and source[f"{key}_sha256"] == expected,
            "source revision/hash",
        )
        need(
            source[f"{key}_snapshot_path"] == f"as-run/{name}.txt",
            "source snapshot path",
        )
        need(
            sha((base / source[f"{key}_snapshot_path"]).read_bytes()) == expected,
            "frozen source changed",
        )
    need(
        source["client_data_sha256"]
        == "7f286e3f8941c2261fc9c32b2d1d03acef32bdea567362a1c64abd5d64fe5315",
        "client DATA",
    )
    need(
        source["client_resource_sha256"]
        == "f762cfdedcc39758f841f720a4586dbbb88a7b74ec9e83db1793791b7c3f318b",
        "client RSRC",
    )
    need(
        source["client_vers_short"] == "1.9.1.0"
        and source["vendor_authenticity"] == "unproved",
        "client identity limits",
    )
    need(
        source["native_oracle_sha256"]
        == "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b",
        "oracle identity",
    )
    need(manifest["capture_gate_sha256"] == CAPTURE_GATE_SHA, "capture gate source")


def a7_check(base: Path) -> dict:
    result = verify_a7(base / "run")
    need(
        result
        == {"actions_each": 29, "accounts": 2, "files": 41, "filp_sha256": FILP_SHA},
        "full A7",
    )
    for phase in ("a7-preflight", "a7-postflight"):
        report = load(base / "run" / phase / "report.json")
        agreement = next(f for f in report["frames"] if f["action"] == 6)
        text = bytes.fromhex(agreement["fields"][0]["hex"])
        need(len(text) == 242 and sha(text) == AGREEMENT_SHA, "known agreement")
    return result


def capture_check(base: Path, manifest: dict) -> dict:
    run = base / "run"
    need(
        manifest["group_deadline_utc"] == "2026-11-14T04:25:15+00:00", "group deadline"
    )
    result = {}
    for label, ns, unit in (
        ("host", 4026531840, "mothra-b62-host-capture.service"),
        ("ns", 4026532479, "mothra-b62-ns-capture.service"),
    ):
        receipts = [
            load(run / f"{label}-ready-{phase}.json")
            for phase in ("launch", "before-a7", "before-connect")
        ]
        first = receipts[0]
        need(
            first["pid"] > 0 and first["fd"] >= 0 and first["header24"] == HEADER.hex(),
            "capture PID/FD/header",
        )
        need(
            all(
                r["unit"] == unit
                and r["pid"] == first["pid"]
                and r["start_ticks"] == first["start_ticks"]
                and r["fd"] == first["fd"]
                and (r["dev"], r["inode"]) == (first["dev"], first["inode"])
                and r["netns_inode"] == ns
                and r["deadline_utc"] == manifest["group_deadline_utc"]
                and r["header24"] == HEADER.hex()
                and r["unit_properties"]["ActiveState"] == "active"
                and r["unit_properties"]["SubState"] == "running"
                and r["unit_properties"]["MainPID"] == str(first["pid"])
                and r["unit_properties"]["RuntimeMaxUSec"] == "15min"
                and r["unit_properties"]["KillMode"] == "control-group"
                for r in receipts
            ),
            "capture readiness drift",
        )
        need(
            all(
                r["capture"]
                == str(
                    Path(
                        "/data/leynos/Projects/mothra/state/native-sessions/native-proxy-roster-115-01"
                    )
                    / ("host.pcap" if label == "host" else "namespace.pcap")
                )
                for r in receipts
            ),
            "capture path",
        )
        journal = (run / f"{label}-capture-journal.txt").read_text()
        need(
            f"tcpdump[{first['pid']}]" in journal
            and "packets captured" in journal
            and "0 packets dropped by kernel" in journal,
            "capture drop/owner",
        )
        units = (run / "units-terminal.txt").read_text()
        need(
            f"Id={unit}\nActiveState=inactive\nMainPID=0\nResult=success" in units,
            "capture cleanup",
        )
        result[label] = first["pid"]
    return result


def selection_check(base: Path, manifest: dict, packets: dict) -> None:
    need(
        set(manifest["selection"])
        == {
            "client-guest-post.pcap",
            "namespace.pcap",
            "host.pcap",
            "server-guest-post.pcap",
        },
        "selected view set",
    )
    for name, spec in manifest["selection"].items():
        chosen = base / "pcaps" / name
        need(
            chosen.stat().st_size == spec["selected_bytes"]
            and sha(chosen.read_bytes()) == spec["selected_sha256"],
            "selected PCAP identity",
        )
        need(
            len(packets["pcaps/" + name]) == len(spec["selected_record_indexes"]),
            "selected record count",
        )
        for entry in spec["routes"]:
            src, port, dst, target = entry["route"]
            selected = [
                p
                for p in packets["pcaps/" + name]
                if (p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"])
                in ((src, port, dst, target), (dst, target, src, port))
            ]
            syns = [
                p
                for p in selected
                if (p["src_ip"], p["src_port"]) == (src, port)
                and p["flags"] & 2
                and not p["flags"] & 16
            ]
            need(
                len(selected) == entry["packet_count"]
                and len(syns) == 1
                and entry["syn_index"] in spec["selected_record_indexes"]
                and syns[0]["timestamp_us"] == entry["syn_timestamp_us"],
                "selected SYN lifetime",
            )
            need(
                [p["flags"] for p in selected if p["flags"] & 5]
                == entry["terminal_flags"]
                and bool(entry["terminal_flags"]),
                "selected tail",
            )


def split_frames(data: bytes) -> list[bytes]:
    result = []
    while data:
        need(len(data) >= 20, "split frame header")
        size = int.from_bytes(data[16:20], "big")
        need(len(data) >= 20 + size, "split frame body")
        result.append(data[: 20 + size])
        data = data[20 + size :]
    return result


def wire_check(base: Path, manifest: dict, packets: dict) -> dict:
    pairs = {}
    for kind in ("control", "data"):
        routes = manifest["routes"][kind]
        need(
            [r[0].removeprefix("pcaps/") for r in routes] == list(ROUTES),
            "five route views",
        )
        streams = [flow(packets[r[0]], r) for r in routes]
        need(len({client for client, _ in streams}) == 1, "client request parity")
        need(streams[0][1] == streams[1][1], "forwarded reply parity")
        need(streams[2][1] == streams[3][1] == streams[4][1], "raw reply parity")
        pairs[kind] = streams
    control = pairs["control"]
    client, downstream = control[0]
    raw = control[2][1]
    need(
        client[:12] == bytes.fromhex("54525450484f544c00010002")
        and raw[:8] == downstream[:8] == b"TRTP\0\0\0\0",
        "handshake",
    )
    requests = parse_frames(client[12:])
    replies = parse_frames(downstream[8:])
    raw_replies = parse_frames(raw[8:])
    need(
        [(f["type"], f["id"], f["flags"], f["is_reply"], f["error"]) for f in requests]
        == [(x, i, 0, 0, 0) for i, x in enumerate((107, 121, 300, 212), 1)],
        "client request sequence",
    )
    need(
        [(f["type"], f["id"], f["flags"], f["is_reply"], f["error"]) for f in replies]
        == [
            (0, 1, 0, 1, 0),
            (109, 1, 0, 0, 0),
            (0, 2, 0, 1, 0),
            (354, 2, 0, 0, 0),
            (122, 3, 0, 0, 0),
            (0, 3, 0, 1, 0),
            (0, 4, 0, 1, 0),
        ],
        "server reply sequence",
    )
    need(
        [
            (f["type"], f["id"], f["flags"], f["is_reply"], f["error"])
            for f in raw_replies
        ]
        == [
            (f["type"], f["id"], f["flags"], f["is_reply"], f["error"]) for f in replies
        ],
        "reply header identity",
    )
    need(
        raw_replies[0] == replies[0]
        and sha(raw[8:42]) == RAW_ACK_SHA
        and field_map(replies[0]) == {160: b"\0\xbe", 161: b"\0\0"},
        "unchanged login ACK",
    )
    need(
        sha(field_map(replies[1])[101]) == AGREEMENT_SHA
        and field_map(requests[1])[102] == b"unnamed",
        "agreement/name",
    )
    raw_roster, forwarded_roster = raw_replies[5], replies[5]
    raw_frames, forwarded_frames = split_frames(raw[8:]), split_frames(downstream[8:])
    need(
        sha(raw_frames[5]) == RAW_ROSTER_SHA
        and sha(forwarded_frames[5]) == FORWARDED_ROSTER_SHA,
        "roster frame hashes",
    )
    original = raw_frames[5]
    rewritten = forwarded_frames[5]
    expected = (
        original[:12]
        + (int.from_bytes(original[12:16], "big") + 19).to_bytes(4, "big") * 2
        + (int.from_bytes(original[20:22], "big") + 1).to_bytes(2, "big")
        + original[22:]
        + b"\0s\0\x0ffixture-subject"
    )
    need(
        rewritten == expected and len(original) == 41 and len(rewritten) == 60,
        "sole roster TLV append",
    )
    need(
        300 in field_map(raw_roster)
        and 115 not in field_map(raw_roster)
        and field_map(forwarded_roster)[115] == b"fixture-subject",
        "roster fields",
    )
    packed = field_map(raw_roster)[300]
    need(
        len(packed) >= 8
        and len(packed) == 8 + int.from_bytes(packed[6:8], "big")
        and len(packed) > 8,
        "packed roster record",
    )
    need(raw[:8] + b"".join(raw_frames) == raw, "raw frame reconstruction")
    need(
        downstream[:8] + b"".join(forwarded_frames) == downstream,
        "forwarded frame reconstruction",
    )
    need(
        all(a == b for i, (a, b) in enumerate(zip(raw_replies, replies)) if i != 5),
        "other replies unchanged",
    )
    reference = field_map(replies[6])[107]
    data = pairs["data"]
    need(
        len(data[0][0]) == 16
        and data[0][0][:4] == b"HTXF"
        and data[0][0][4:8] == reference
        and len(data[0][1]) == 58
        and data[0][1][:6] == b"GIF89a",
        "banner data/reference",
    )
    report = load(base / "run/proxy/report.json")
    entries = report["entries"]
    need(
        len(entries) == 15
        and sum(e["raw_hex"] != e["forwarded_hex"] for e in entries) == 1,
        "single proxy audit mutation",
    )
    need(
        [e["event"] for e in entries]
        == [
            "client-handshake",
            "server-handshake",
            "login-request",
            "server",
            "server",
            "client",
            "server",
            "server",
            "server",
            "client",
            "client",
            "server",
            "server",
            "data-client",
            "data-server",
        ],
        "proxy audit order",
    )
    logged = lambda events, key: b"".join(
        bytes.fromhex(e[key]) for e in entries if e["event"] in events
    )
    need(
        logged({"client-handshake", "login-request", "client"}, "raw_hex") == client
        and logged({"server-handshake", "server"}, "raw_hex") == raw
        and logged({"server-handshake", "server"}, "forwarded_hex") == downstream,
        "proxy audit/control bytes",
    )
    need(
        logged({"data-client"}, "raw_hex") == data[0][0]
        and logged({"data-server"}, "raw_hex") == data[0][1],
        "proxy audit/data bytes",
    )
    obs = report["observation"]
    elapsed = obs["relay_teardown_ns"] - obs["ack_sent_monotonic_ns"]
    need(
        report["status"] == "intentional-observation-cutoff"
        and report["variant"] == "roster-subject-115"
        and not report["errors"]
        and obs["state"] == "fired"
        and obs["valid_30_seconds"] is True,
        "watchdog outcome",
    )
    need(
        obs["cutoff_due_ns"] - obs["ack_sent_monotonic_ns"] == 28_000_000_000
        and elapsed == 28_129_110_855
        and elapsed < 30_000_000_000,
        "watchdog timing",
    )
    need(
        obs["raw_ack_sha256"] == obs["forwarded_ack_sha256"] == RAW_ACK_SHA,
        "watchdog login identity",
    )
    need(
        manifest["raw_roster_sha256"] == RAW_ROSTER_SHA
        and manifest["forwarded_roster_sha256"] == FORWARDED_ROSTER_SHA,
        "manifest roster hashes",
    )
    return {
        "requests": [f["type"] for f in requests],
        "replies": [f["type"] for f in replies],
        "roster_id": raw_roster["id"],
        "roster_bytes": [len(original), len(rewritten)],
        "watchdog_seconds": elapsed / 1e9,
    }


def ui_check(base: Path, packets: dict) -> dict:
    receipt = load(base / "ui-timing.json")
    screenshot = base / receipt["screenshot"]
    need(
        screenshot.is_file()
        and sha(screenshot.read_bytes()) == receipt["screenshot_sha256"],
        "UI screenshot identity",
    )
    need(
        receipt["screenshot"] == "run/after-agree-1s.png"
        and receipt["screenshot_sha256"]
        == "d2b9c17e3176044ab981f4c1bee036bfc8eb38dfafd4180f46e1422f500751bc",
        "UI image provenance",
    )
    need(
        receipt["source_file_mtime_ns"] == 1_794_629_906_672_474_509,
        "UI host mtime receipt",
    )
    arrivals = [
        p
        for p in packets["pcaps/client-guest-post.pcap"]
        if b"fixture-subject" in bytes.fromhex(p["payload_hex"])
        and p["dst_ip"] == "10.0.2.15"
    ]
    need(
        len(arrivals) == 1
        and arrivals[0]["timestamp_us"] == receipt["guest_delivery_packet_timestamp_us"]
        and receipt["guest_delivery_packet_index"] == 478,
        "guest roster delivery packet",
    )
    need(
        receipt["guest_delivery_packet_timestamp_us"] == 1_794_629_905_744_557
        and receipt["source_file_mtime_ns"] // 1000
        > receipt["guest_delivery_packet_timestamp_us"],
        "UI after delivery",
    )
    need(
        receipt["proxy_audit_timestamp_us"]
        <= receipt["guest_delivery_packet_timestamp_us"],
        "UI proxy packet sequence",
    )
    # The visual assertion was reviewed from this exact image; timestamp is retained
    # source-host metadata and does not independently prove client rendering time.
    return {
        "screenshot": receipt["screenshot"],
        "delivery_to_snapshot_seconds": (
            receipt["source_file_mtime_ns"] // 1000
            - receipt["guest_delivery_packet_timestamp_us"]
        )
        / 1e6,
    }


def cleanup_check(base: Path) -> dict:
    run = base / "run"
    units = (run / "units-terminal.txt").read_text()
    for unit in (
        "mothra-classic-proxy-b62.service",
        "mothra-b62-host-capture.service",
        "mothra-b62-ns-capture.service",
        "mothra-b62-oracle-lease.service",
    ):
        need(
            f"Id={unit}\nActiveState=inactive\nMainPID=0\nResult=success" in units,
            "owned service cleanup",
        )
    need(
        "15652" not in (run / "listeners-terminal.txt").read_text()
        and "15653" not in (run / "listeners-terminal.txt").read_text(),
        "proxy listener cleanup",
    )
    need(
        (run / "ns-v4-routes-terminal.txt").read_text().strip() == ""
        and (run / "ns-v6-routes-terminal.txt").read_text().strip() == ""
        and "lo" in (run / "ns-addresses-terminal.txt").read_text(),
        "isolated namespace routes",
    )
    emulator = (run / "emulators-terminal.txt").read_text()
    need(
        emulator.count(
            "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
        )
        == 2,
        "emulator executable postflight",
    )
    fds = (run / "original-fds-terminal.txt").read_text()
    need(
        "/proc/1012834/fd/6" in fds
        and "/proc/1099659/fd/6" in fds
        and "/proc/1012834/fd/16" in fds
        and "/proc/1099659/fd/16" in fds,
        "original disk/PCAP FD owners",
    )
    lock = load(base / "lock-receipt.json")
    need(
        lock["pid"] == 492350
        and lock["lock_dev"] == 2097
        and lock["lock_inode"] == 3512552451
        and lock["proc_fd3_before"].endswith("/state/delegation/oracle.lock"),
        "managed lock identity",
    )
    need(
        lock["active_state_before"] == "active"
        and lock["independent_flock_n_before_exit"] == 1
        and lock["after_stop_state"] == "inactive"
        and lock["after_stop_main_pid"] == 0
        and lock["independent_flock_n_after_exit"] == 0,
        "managed lock busy/free",
    )
    need(
        "operator tool-output transcription" in lock["evidence_status"],
        "lock proof limitation",
    )
    journal = (run / "oracle-lease-journal.txt").read_text()
    need(
        "mothra-b62-oracle-lease.service" in journal
        and "/usr/bin/flock --exclusive --nonblock" in journal
        and "Deactivated successfully" in journal,
        "managed lock journal",
    )
    return {
        "owned_units_stopped": 4,
        "lock": "transcribed busy/free plus retained service journal",
    }


def verify(base: Path) -> dict:
    base = base.resolve()
    count = inventory(base)
    manifest = load(base / "manifest.json")
    need(manifest["schema_version"] == 1, "manifest schema")
    need(
        manifest["verifier_budget"]["approved_source_lines"] == 620
        and manifest["verifier_budget"]["original_source_lines"] == 470,
        "approved verifier budget",
    )
    source_check(base, manifest)
    packets = {
        "pcaps/" + p.name: read_packets(p) for p in (base / "pcaps").glob("*.pcap")
    }
    need(len(packets) == 4, "four selected PCAPs")
    selection_check(base, manifest, packets)
    return {
        "inventory_files": count,
        "a7": a7_check(base),
        "capture": capture_check(base, manifest),
        "wire": wire_check(base, manifest, packets),
        "ui": ui_check(base, packets),
        "cleanup": cleanup_check(base),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    print(json.dumps(verify(parser.parse_args().corpus), indent=2))


if __name__ == "__main__":
    main()
