"""Replay the finite B56/B57 Classic server-name field-162 evidence offline."""

import argparse
import hashlib
import json
from pathlib import Path

from pcap_tcp import read_packets
from verify_classic_native_baseline import flow, verify_a7
from verify_mac_peer_first_session import field_map, parse_frames

RAW_ACK = bytes.fromhex(
    "0001000000000001000000000000000e0000000e000200a0000200be00a100020000"
)
FORWARDED_ACK = bytes.fromhex(
    "0001000000000001000000000000002000000020000300a0000200be00a100020000"
    "00a2000e666978747572652d6e6174697665"
)
PROXY_SHA = "586d31f204ea1f2782a63346f7a4069d5e6f8f6112bba931488a4e687c25ccea"
PARSER_SHA = "04c4fda2e62ccab35ed306c036dac6b1878af58adbfaccc6312a2805dd6897d7"
AGREEMENT_SHA = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
FILP_SHA = "7d1f5bf5e2b69b8a18906633ce2ef550876b78252c0639e7d36eb61142787ab8"
CLIENT_HELLO = bytes.fromhex("54525450484f544c00010002")
SERVER_HELLO = bytes.fromhex("5452545000000000")
FIELDS = {160: bytes.fromhex("00be"), 161: b"\0\0", 162: b"fixture-native"}
ROUTES = (
    "client-guest-post.pcap",
    "namespace.pcap",
    "namespace.pcap",
    "host.pcap",
    "server-guest-post.pcap",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def inventory(base: Path) -> int:
    root = base.resolve().parents[3]
    names: set[str] = set()
    for line in (base / "SHA256SUMS").read_text().splitlines():
        expected, relative = line.split("  ", 1)
        path = root / relative
        require(
            path.is_file() and path.resolve().is_relative_to(base), "inventory path"
        )
        require(relative not in names, "duplicate inventory path")
        names.add(relative)
        require(digest(path.read_bytes()) == expected, f"SHA inventory {relative}")
    actual = {
        str(p.relative_to(root))
        for p in base.rglob("*")
        if p.is_file() and p.name != "SHA256SUMS"
    }
    require(names == actual, "SHA inventory file set")
    return len(names)


def check_source(base: Path, source: dict) -> None:
    for key, name, revision, expected in (
        (
            "proxy",
            "classic_login_proxy.py",
            "12b51a2d8271ffa06cd1589501f0ca1d36bb37fe",
            PROXY_SHA,
        ),
        (
            "parser",
            "pcap_tcp.py",
            "79d867dc80c0aea50ad77569aae89e1d0bf37915",
            PARSER_SHA,
        ),
    ):
        require(
            source[f"{key}_path"] == f"../hotline-protocol-docs/scripts/{name}"
            and source[f"{key}_revision"] == revision
            and source[f"{key}_snapshot_path"] == f"as-run/{name}.txt"
            and source[f"{key}_sha256"] == expected,
            f"{key} provenance",
        )
        require(
            digest((base / source[f"{key}_snapshot_path"]).read_bytes()) == expected,
            f"{key} source snapshot",
        )
    require(
        source["client_data_sha256"]
        == "7f286e3f8941c2261fc9c32b2d1d03acef32bdea567362a1c64abd5d64fe5315"
        and source["client_resource_sha256"]
        == "f762cfdedcc39758f841f720a4586dbbb88a7b74ec9e83db1793791b7c3f318b"
        and source["client_vers_short"] == "1.9.1.0"
        and source["vendor_authenticity"] == "unproved",
        "Classic client identity record",
    )


def check_a7(base: Path, label: str) -> dict:
    directory = base / label
    result = verify_a7(directory)
    require(
        result
        == {"actions_each": 29, "accounts": 2, "files": 41, "filp_sha256": FILP_SHA},
        f"{label} A7 fixture",
    )
    for name in ("a7-preflight", "a7-postflight"):
        report = load(directory / name / "report.json")
        agreement = next(f for f in report["frames"] if f["action"] == 6)
        data = bytes.fromhex(agreement["fields"][0]["hex"])
        require(
            len(data) == 242 and digest(data) == AGREEMENT_SHA, f"{label} agreement"
        )
    return result


def check_capture(base: Path, label: str, manifest: dict) -> dict:
    directory = base / label
    deadline = (
        "2026-11-14T03:26:00+00:00" if label == "b56" else "2026-11-14T03:33:30+00:00"
    )
    for kind, inode, pid, unit in (
        (
            "host",
            4026531840,
            88855 if label == "b56" else 231986,
            f"mothra-{label}-host-capture.service",
        ),
        (
            "ns",
            4026532479,
            88897 if label == "b56" else 232035,
            f"mothra-{label}-ns-capture.service",
        ),
    ):
        starts = set()
        fd_ids = set()
        for phase in ("launch", "before-a7", "before-connect"):
            receipt = load(directory / f"{kind}-ready-{phase}.json")
            props = receipt["unit_properties"]
            require(
                receipt["unit"] == unit
                and receipt["pid"] == pid
                and receipt["netns_inode"] == inode
                and receipt["fd"] == 5
                and receipt["deadline_utc"] == deadline
                and receipt["header24"]
                == "d4c3b2a10200040000000000000000000000040001000000"
                and props["MainPID"] == str(pid)
                and props["ActiveState"] == "active"
                and props["SubState"] == "running"
                and props["RuntimeMaxUSec"] == "15min"
                and props["KillMode"] == "control-group",
                f"{label} {kind} recorder readiness",
            )
            starts.add(receipt["start_ticks"])
            fd_ids.add((receipt["dev"], receipt["inode"]))
        require(
            len(starts) == len(fd_ids) == 1, f"{label} {kind} recorder identity drift"
        )
        journal_name = (
            f"{unit.removesuffix('.service')}-journal.txt"
            if label == "b57"
            else f"{kind if kind == 'host' else 'ns'}-recorder-journal.txt"
        )
        journal = (directory / journal_name).read_text()
        require(
            f"tcpdump[{pid}]" in journal
            and "packets captured" in journal
            and "0 packets dropped by kernel" in journal,
            f"{label} {kind} recorder drops/ownership",
        )
    units = (directory / "units-terminal.txt").read_text()
    for kind in ("host", "ns"):
        require(
            f"Id=mothra-{label}-{kind}-capture.service\nActiveState=inactive\nMainPID=0\nResult=success"
            in units,
            f"{label} {kind} recorder cleanup",
        )
    require(
        manifest["capture_gate_sha256"]
        == "7a75f4b78f1255f4486ced44fc5fb8882d6008c7de6844a82f4c107e7299d678",
        "capture gate source identity",
    )
    return {
        "recorder_pids": [88855, 88897] if label == "b56" else [231986, 232035],
        "drops": 0,
    }


def check_b56(base: Path) -> dict:
    directory = base / "b56"
    terminal = load(directory / "terminal.json")
    require(
        terminal["outcome"] == "infrastructure-stop-before-connect"
        and terminal["client_connect_activated"] is False
        and terminal["proxy_ready"] is False,
        "B56 failure label",
    )
    require(
        (directory / "namespace.pcap").read_bytes()
        == bytes.fromhex("d4c3b2a10200040000000000000000000000040001000000"),
        "B56 namespace zero-contact capture",
    )
    pre = (directory / "client-guest-pre.pcap").read_bytes()
    post = (directory / "client-guest-post.pcap").read_bytes()
    require(
        pre == post
        and digest(pre)
        == terminal["client_guest_pre_sha256"]
        == terminal["client_guest_post_sha256"],
        "B56 client guest no contact",
    )
    journal = (directory / "proxy-journal.txt").read_text()
    require(
        "FileExistsError" in journal and "classic-proxy-b56.service" in journal,
        "B56 output leaf failure",
    )
    units = (directory / "units-terminal.txt").read_text()
    require(
        "Id=mothra-classic-proxy-b56.service\nActiveState=failed\nMainPID=0\nResult=exit-code"
        in units
        and "15652" not in (directory / "listeners-terminal.txt").read_text(),
        "B56 failed setup cleanup",
    )
    return {"outcome": "infrastructure-stop-before-connect", "namespace_packets": 0}


def check_selection(base: Path, selection: dict, packets: dict) -> None:
    for name, spec in selection.items():
        chosen = base / "pcaps" / name
        require(
            chosen.stat().st_size == spec["selected_bytes"]
            and digest(chosen.read_bytes()) == spec["selected_sha256"]
            and len(packets["pcaps/" + name]) == len(spec["selected_record_indexes"]),
            f"selected PCAP identity {name}",
        )
        for route in spec["routes"]:
            src, port, dst, target = route["route"]
            selected = [
                p
                for p in packets["pcaps/" + name]
                if (p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"])
                in ((src, port, dst, target), (dst, target, src, port))
            ]
            syns = [
                p
                for p in selected
                if p["src_ip"] == src
                and p["src_port"] == port
                and p["flags"] & 2
                and not p["flags"] & 16
            ]
            require(
                len(selected) == route["packet_count"]
                and len(syns) == 1
                and [p["flags"] for p in selected if p["flags"] & 5]
                == route["terminal_flags"]
                and bool(route["terminal_flags"]),
                f"selected SYN lifetime/tails {name}",
            )


def check_b57(base: Path, manifest: dict, packets: dict) -> dict:
    routes = manifest["b57"]["routes"]
    require(set(routes) == {"control", "data"}, "B57 route kinds")
    pairs = {}
    for kind in ("control", "data"):
        require(
            [r[0].removeprefix("pcaps/") for r in routes[kind]] == list(ROUTES),
            f"B57 {kind} five views",
        )
        streams = [flow(packets[r[0]], r) for r in routes[kind]]
        require(
            len({client for client, _ in streams}) == 1, f"B57 {kind} upstream parity"
        )
        require(streams[0][1] == streams[1][1], f"B57 {kind} downstream parity")
        require(
            streams[2][1] == streams[3][1] == streams[4][1], f"B57 {kind} raw parity"
        )
        pairs[kind] = streams
    control = pairs["control"]
    raw = control[2][1]
    downstream = control[0][1]
    require(
        raw[:8] == SERVER_HELLO and control[0][0][:12] == CLIENT_HELLO,
        "TRTP/HOTL handshake",
    )
    require(
        raw[8 : 8 + len(RAW_ACK)] == RAW_ACK
        and digest(RAW_ACK) == manifest["original_ack_sha256"]
        and digest(FORWARDED_ACK) == manifest["forwarded_ack_sha256"]
        and downstream == SERVER_HELLO + FORWARDED_ACK + raw[8 + len(RAW_ACK) :],
        "B57 sole ACK rewrite",
    )
    requests = parse_frames(control[0][0][12:])
    replies = parse_frames(downstream[8:])
    raw_replies = parse_frames(raw[8:])
    require(
        [f["type"] for f in requests] == [107, 121, 300, 212]
        and [f["id"] for f in requests] == [1, 2, 3, 4]
        and [f["type"] for f in replies] == [0, 109, 0, 354, 122, 0, 0]
        and [f["id"] for f in replies] == [1, 1, 2, 2, 3, 3, 4]
        and [(f["flags"], f["is_reply"], f["error"]) for f in requests]
        == [(0, 0, 0)] * 4
        and [(f["flags"], f["is_reply"], f["error"]) for f in replies]
        == [(0, x, 0) for x in (1, 0, 1, 0, 0, 1, 1)]
        and [
            (f["flags"], f["is_reply"], f["error"], f["id"], f["type"])
            for f in raw_replies
        ]
        == [
            (f["flags"], f["is_reply"], f["error"], f["id"], f["type"]) for f in replies
        ],
        "B57 control sequence/IDs/flags",
    )
    require(
        field_map(raw_replies[0]) == {160: b"\0\xbe", 161: b"\0\0"}
        and field_map(replies[0]) == FIELDS,
        "B57 162 fields",
    )
    require(digest(field_map(replies[1])[101]) == AGREEMENT_SHA, "B57 known agreement")
    require(field_map(requests[1])[102] == b"unnamed", "B57 unnamed roster request")
    reference = field_map(replies[6])[107]
    data = pairs["data"]
    require(
        len(data[0][0]) == 16
        and data[0][0][:4] == b"HTXF"
        and data[0][0][4:8] == reference
        and len(data[0][1]) == 58
        and data[0][1][:6] == b"GIF89a"
        and data[0][1] == data[2][1],
        "B57 banner reference/data parity",
    )
    report = load(base / "b57/proxy/report.json")
    entries = report["entries"]
    events = [e["event"] for e in entries]
    require(
        events[:5]
        == ["client-handshake", "server-handshake", "login-request", "server", "server"]
        and len(events) == 15
        and events.count("server") == 7
        and events.count("client") == 3
        and events.count("data-client") == events.count("data-server") == 1,
        "B57 proxy audit events",
    )

    def logged(events: set[str], key: str) -> bytes:
        return b"".join(bytes.fromhex(e[key]) for e in entries if e["event"] in events)

    require(
        logged({"client-handshake", "login-request", "client"}, "raw_hex")
        == control[0][0]
        and logged({"server-handshake", "server"}, "raw_hex") == raw
        and logged({"server-handshake", "server"}, "forwarded_hex") == downstream
        and logged({"data-client"}, "raw_hex") == data[0][0]
        and logged({"data-server"}, "raw_hex") == data[0][1]
        and all(
            e["raw_hex"] == e["forwarded_hex"] for i, e in enumerate(entries) if i != 3
        ),
        "B57 proxy audit/wire and sole mutation",
    )
    obs = report["observation"]
    require(
        report["variant"] == "server-name-162"
        and report["status"] == "intentional-observation-cutoff"
        and not report["errors"]
        and obs["state"] == "fired"
        and obs["valid_30_seconds"] is True
        and obs["raw_ack_sha256"] == digest(RAW_ACK)
        and obs["forwarded_ack_sha256"] == digest(FORWARDED_ACK),
        "B57 proxy cutoff status",
    )
    elapsed = obs["relay_teardown_ns"] - obs["ack_sent_monotonic_ns"]
    require(
        obs["cutoff_due_ns"] - obs["ack_sent_monotonic_ns"] == 28_000_000_000
        and elapsed == 28_195_908_139
        and elapsed < 30_000_000_000,
        "B57 cutoff timing",
    )
    require(
        "Id=mothra-classic-proxy-b57.service\nActiveState=inactive\nMainPID=0\nResult=success"
        in (base / "b57/units-terminal.txt").read_text()
        and "15652" not in (base / "b57/listeners-terminal.txt").read_text()
        and (base / "b57/active-native-terminal.txt")
        .read_text()
        .strip()
        .startswith("State"),
        "B57 proxy/socket cleanup",
    )
    return {
        "fields": {str(k): v.hex() for k, v in FIELDS.items()},
        "requests": [f["type"] for f in requests],
        "replies": [f["type"] for f in replies],
        "banner_bytes": [len(data[0][0]), len(data[0][1])],
        "teardown_seconds": elapsed / 1e9,
    }


def verify(base: Path) -> dict:
    base = base.resolve()
    count = inventory(base)
    manifest = load(base / "manifest.json")
    require(manifest["schema_version"] == 1, "manifest schema")
    require(
        manifest["b56"]["outcome"] == "infrastructure-stop-before-connect"
        and manifest["b57"]["outcome"] == "intentional-observation-cutoff",
        "run outcomes",
    )
    require(
        bytes.fromhex(manifest["original_ack_hex"]) == RAW_ACK, "original ACK manifest"
    )
    check_source(base, manifest["source"])
    packets = {
        "pcaps/" + p.name: read_packets(p) for p in (base / "pcaps").glob("*.pcap")
    }
    require(len(packets) == 4, "four selected PCAP views")
    check_selection(base, manifest["selection"], packets)
    return {
        "inventory_files": count,
        "b56": {
            **check_b56(base),
            "a7": check_a7(base, "b56"),
            "capture": check_capture(base, "b56", manifest),
        },
        "b57": {
            **check_b57(base, manifest, packets),
            "a7": check_a7(base, "b57"),
            "capture": check_capture(base, "b57", manifest),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.corpus), indent=2))


if __name__ == "__main__":
    main()
