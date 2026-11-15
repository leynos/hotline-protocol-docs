"""Replay the finite B52 Classic field-161 matrix from portable PCAPs."""

import argparse
import hashlib
import json
from pathlib import Path

from classic_login_proxy import transform_ack
from mothra_root import mothra_root
from pcap_tcp import read_packets
from verify_classic_native_baseline import flow, verify_a7
from verify_mac_peer_first_session import field_map, parse_frames

SOURCE_ACK_SHA = "814b733a82d15dd7250cb0e8b7ed0c6c09a7a02d7169ab70ebaa359fb18eb6d0"
SOURCE_ACK_HEX = "0001000000000001000000000000000e0000000e000200a0000200be00a100020000"
AGREEMENT_SHA = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
VARIANTS = ("omit-161", "one-byte-161", "four-byte-161")
SOURCE_SHAS = {
    "proxy": "44bb68fe0bc464874aa455e823ca08b00704b88f5064d776119fcaf0682a5c7e",
    "parser": "04c4fda2e62ccab35ed306c036dac6b1878af58adbfaccc6312a2805dd6897d7",
}
EXPECTED_FIELDS = {
    "omit-161": {160: bytes.fromhex("00be")},
    "one-byte-161": {160: bytes.fromhex("00be"), 161: b"\0"},
    "four-byte-161": {160: bytes.fromhex("00be"), 161: bytes(4)},
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def inventory(base: Path) -> None:
    root = base.resolve().parents[3]
    names = set()
    for line in (base / "SHA256SUMS").read_text().splitlines():
        expected, relative = line.split("  ", 1)
        path = root / relative
        require(
            path.is_file() and path.resolve().is_relative_to(base),
            "inventory path escapes corpus",
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


def check_source_snapshot(base: Path, source: dict, key: str) -> None:
    names = {"proxy": "classic_login_proxy.py", "parser": "pcap_tcp.py"}
    require(key in names, "unknown source snapshot")
    name = names[key]
    require(
        source[f"{key}_path"] == f"../hotline-protocol-docs/scripts/{name}"
        and source[f"{key}_revision"] == "79d867dc80c0aea50ad77569aae89e1d0bf37915"
        and source[f"{key}_snapshot_path"] == f"as-run/{name}.txt"
        and source[f"{key}_sha256"] == SOURCE_SHAS[key],
        f"{key} source provenance",
    )
    require(
        digest((base / source[f"{key}_snapshot_path"]).read_bytes())
        == source[f"{key}_sha256"],
        f"{key} source snapshot",
    )


def check_readiness(base: Path, manifest: dict) -> dict:
    terminal = json.loads((base / "terminal.json").read_text())
    require(
        terminal["fixed_group_deadline_utc"] == "2026-11-14T02:23:00Z",
        "fixed group deadline",
    )
    require(
        terminal["live_start_utc"] == "2026-11-14T02:11:00Z"
        and terminal["live_end_utc"] == "2026-11-14T02:22:15Z",
        "group bound",
    )
    require(
        manifest["capture_gate_sha256"] == terminal["sources"]["capture_gate_sha256"],
        "capture gate identity",
    )
    for label, pid, netns in (
        ("host", 3394965, 4026531840),
        ("ns", 3394975, 4026532479),
    ):
        names = [f"{label}-ready-launch.json", f"{label}-ready-before-a7.json"]
        names += [f"{case}/{label}-ready-before-connect.json" for case in VARIANTS]
        starts = set()
        inodes = set()
        for name in names:
            receipt = json.loads((base / name).read_text())
            properties = receipt["unit_properties"]
            require(
                receipt["pid"] == pid
                and receipt["fd"] == 5
                and receipt["netns_inode"] == netns,
                f"capture owner {name}",
            )
            require(
                properties["ActiveState"] == "active"
                and properties["SubState"] == "running"
                and properties["MainPID"] == str(pid)
                and properties["RuntimeMaxUSec"] == "15min"
                and properties["KillMode"] == "control-group",
                f"unit ready {name}",
            )
            require(
                receipt["header24"]
                == "d4c3b2a10200040000000000000000000000040001000000"
                and receipt["deadline_utc"] == "2026-11-14T02:23:00+00:00",
                f"capture header/deadline {name}",
            )
            starts.add(receipt["start_ticks"])
            inodes.add((receipt["dev"], receipt["inode"]))
        require(len(starts) == len(inodes) == 1, f"capture identity drift {label}")
        journal = (
            base / f"{'host' if label == 'host' else 'ns'}-recorder-journal.txt"
        ).read_text()
        require("0 packets dropped by kernel" in journal, f"capture drops {label}")
        require(
            f"tcpdump[{pid}]" in journal and "packets captured" in journal,
            f"capture journal {label}",
        )
    units = (base / "units-terminal.txt").read_text()
    for unit in (
        "mothra-b52-host-capture",
        "mothra-b52-ns-capture",
        "mothra-classic-proxy-b52-omit",
        "mothra-classic-proxy-b52-one",
        "mothra-classic-proxy-b52-four",
    ):
        require(
            f"Id={unit}.service\nActiveState=inactive\nMainPID=0" in units,
            f"unit cleanup {unit}",
        )
    require(
        (base / "former-pids-terminal.txt").read_text().strip() == "PID COMMAND",
        "former capture/proxy PID cleanup",
    )
    require(
        "15652" not in (base / "listeners-terminal.txt").read_text(),
        "owned listener cleanup",
    )
    return {
        "readiness_checks": 10,
        "recorder_pids": [3394965, 3394975],
        "journals_zero_drops": True,
    }


def check_selection(base: Path, manifest: dict, packets: dict) -> None:
    inventory_report = json.loads((base / "pcap-inventory.json").read_text())["files"]
    for name, selection in manifest["selection"].items():
        chosen = base / "pcaps" / name
        require(
            chosen.stat().st_size == selection["selected_bytes"]
            and digest(chosen.read_bytes()) == selection["selected_sha256"],
            f"selected PCAP identity {name}",
        )
        require(
            len(packets["pcaps/" + name]) == len(selection["selected_record_indexes"]),
            f"selected PCAP record count {name}",
        )
        original = inventory_report[name]
        require(
            selection["original_bytes"] == original["bytes"]
            and selection["original_sha256"] == original["sha256"],
            f"original PCAP provenance {name}",
        )
        for route in selection["routes"]:
            src_ip, src_port, dst_ip, dst_port = route["route"]
            selected = [
                p
                for p in packets["pcaps/" + name]
                if (
                    (p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"])
                    == (src_ip, src_port, dst_ip, dst_port)
                    or (p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"])
                    == (dst_ip, dst_port, src_ip, src_port)
                )
            ]
            require(
                len(selected) == route["packet_count"]
                and sum(
                    bool(
                        p["flags"] & 2
                        and not p["flags"] & 16
                        and (p["src_ip"], p["src_port"]) == (src_ip, src_port)
                    )
                    for p in selected
                )
                == 1,
                "selected SYN lifetime",
            )
            require(
                [p["flags"] for p in selected if p["flags"] & 5]
                == route["terminal_flags"]
                and route["terminal_flags"],
                "selected TCP tails",
            )


def check_case(base: Path, name: str, spec: dict, packets: dict) -> dict:
    streams = {}
    wire = {}
    for kind in ("control", "data"):
        routes = spec["routes"][kind]
        require(len(routes) == 5, f"{name} five views")
        pairs = [flow(packets[route[0]], route) for route in routes]
        wire[kind] = pairs
        require(len({c for c, _ in pairs}) == 1, f"{name} {kind} client parity")
        if kind == "control":
            require(pairs[0][1] == pairs[1][1], f"{name} downstream parity")
            require(
                pairs[2][1] == pairs[3][1] == pairs[4][1], f"{name} raw server parity"
            )
            raw = pairs[2][1]
            require(raw[:8] == bytes.fromhex("5452545000000000"), "server hello")
            size = int.from_bytes(raw[24:28], "big")
            ack = raw[8 : 28 + size]
            rewritten = transform_ack(ack, 1, name)
            require(
                ack.hex() == SOURCE_ACK_HEX
                and digest(ack) == SOURCE_ACK_SHA
                and rewritten.hex() == spec["expected_ack_hex"]
                and digest(rewritten) == spec["expected_ack_sha256"],
                f"{name} source/forwarded ACK",
            )
            require(
                pairs[0][1] == raw[:8] + rewritten + raw[8 + len(ack) :],
                f"{name} sole ACK rewrite",
            )
            client = pairs[0][0]
            require(
                client[:12] == bytes.fromhex("54525450484f544c00010002"), "client hello"
            )
            requests = parse_frames(client[12:])
            replies = parse_frames(pairs[0][1][8:])
            require(
                [f["type"] for f in requests] == [107, 121, 300, 212]
                and [f["type"] for f in replies] == [0, 109, 0, 354, 122, 0, 0]
                and [f["id"] for f in requests] == [1, 2, 3, 4]
                and [f["id"] for f in replies] == [1, 1, 2, 2, 3, 3, 4]
                and all(
                    f["flags"] == f["error"] == f["is_reply"] == 0 for f in requests
                )
                and all(f["flags"] == f["error"] == 0 for f in replies)
                and [f["is_reply"] for f in replies] == [1, 0, 1, 0, 0, 1, 1],
                f"{name} control sequence",
            )
            require(field_map(replies[0]) == EXPECTED_FIELDS[name], f"{name} 161 shape")
            require(
                digest(field_map(replies[1])[101]) == AGREEMENT_SHA,
                f"{name} 109 agreement",
            )
            roster = field_map(replies[5])
            expected_user_id = {
                "omit-161": 0x45,
                "one-byte-161": 0x46,
                "four-byte-161": 0x47,
            }[name]
            require(
                field_map(requests[1])[102] == b"unnamed"
                and roster
                == {
                    300: expected_user_id.to_bytes(2, "big")
                    + bytes.fromhex("019e00120007756e6e616d6564")
                },
                f"{name} roster",
            )
            reference = field_map(replies[6])[107]
        else:
            require(len({s for _, s in pairs}) == 1, f"{name} data parity")
            require(
                len(pairs[0][0]) == 16
                and pairs[0][0][:4] == b"HTXF"
                and pairs[0][0][4:8] == reference,
                f"{name} data header/ref",
            )
            require(
                len(pairs[0][1]) == 58 and pairs[0][1][:6] == b"GIF89a",
                f"{name} data payload",
            )
        streams[kind] = {
            "client_bytes": len(pairs[0][0]),
            "raw_server_bytes": len(pairs[2][1]),
            "forwarded_server_bytes": len(pairs[0][1]),
        }
    report = json.loads((base / name / "proxy/report.json").read_text())
    entries = report["entries"]
    events = [entry["event"] for entry in entries]
    require(
        events[:5]
        == ["client-handshake", "server-handshake", "login-request", "server", "server"]
        and len(events) == 15
        and events.count("server") == 7
        and events.count("client") == 3
        and events.count("data-client") == events.count("data-server") == 1,
        f"{name} audit events",
    )

    def logged(events: set[str], key: str) -> bytes:
        return b"".join(
            bytes.fromhex(entry[key]) for entry in entries if entry["event"] in events
        )

    control = wire["control"]
    data = wire["data"]
    require(
        logged({"client-handshake", "login-request", "client"}, "raw_hex")
        == control[0][0]
        and logged({"server-handshake", "server"}, "raw_hex") == control[2][1]
        and logged({"server-handshake", "server"}, "forwarded_hex") == control[0][1],
        f"{name} audit/control wire",
    )
    require(
        logged({"data-client"}, "raw_hex") == data[0][0]
        and logged({"data-server"}, "raw_hex") == data[0][1]
        and all(
            entry["raw_hex"] == entry["forwarded_hex"]
            for index, entry in enumerate(entries)
            if index != 3
        ),
        f"{name} audit/data and sole rewrite",
    )
    observation = report["observation"]
    require(
        report["variant"] == name
        and report["status"] == "intentional-observation-cutoff"
        and not report["errors"],
        f"{name} proxy status",
    )
    require(
        observation["state"] == "fired"
        and observation["valid_30_seconds"]
        and observation["raw_ack_sha256"] == SOURCE_ACK_SHA
        and observation["forwarded_ack_sha256"] == spec["expected_ack_sha256"],
        f"{name} watchdog receipt",
    )
    start = observation["ack_sent_monotonic_ns"]
    end = observation["relay_teardown_ns"]
    require(
        observation["cutoff_due_ns"] - start == 28_000_000_000
        and end - start < 30_000_000_000,
        f"{name} cutoff timing",
    )
    return {
        "streams": streams,
        "ack_fields": {str(k): v.hex() for k, v in EXPECTED_FIELDS[name].items()},
        "teardown_seconds": round((end - start) / 1e9, 6),
    }


def verify(base: Path) -> dict:
    base = base.resolve()
    inventory(base)
    manifest = json.loads((base / "manifest.json").read_text())
    require(
        manifest["schema_version"] == 1 and set(manifest["cases"]) == set(VARIANTS),
        "manifest cases",
    )
    require(
        manifest["original_ack_hex"] == SOURCE_ACK_HEX
        and manifest["original_ack_sha256"] == SOURCE_ACK_SHA,
        "original two-zero ACK guard",
    )
    root = mothra_root()
    source = manifest["source"]
    for key in ("proxy", "parser"):
        check_source_snapshot(base, source, key)
    require(
        digest((root / "scripts/capture_readiness.py").read_bytes())
        == manifest["capture_gate_sha256"],
        "capture gate source identity",
    )
    require(
        source["client_data_sha256"].startswith("7f286e3f")
        and source["client_resource_sha256"].startswith("f762cfde")
        and source["client_vers_short"] == "1.9.1.0",
        "client identity record",
    )
    packets = {
        "pcaps/" + p.name: read_packets(p) for p in (base / "pcaps").glob("*.pcap")
    }
    require(len(packets) == 4, "four selected capture views")
    check_selection(base, manifest, packets)
    return {
        "a7": verify_a7(base),
        "capture": check_readiness(base, manifest),
        "cases": {
            name: check_case(base, name, manifest["cases"][name], packets)
            for name in VARIANTS
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.corpus), indent=2))


if __name__ == "__main__":
    main()
