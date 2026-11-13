#!/usr/bin/env python3
"""Verify one isolated Classic client session from retained packet bytes."""

import argparse
import hashlib
import json
import struct
from datetime import datetime
from pathlib import Path

from pcap_tcp import lifetime, read_packets, stream
from verify_mac_peer_first_session import AGREEMENT, field_map, parse_frames, require

CAPTURES = (
    "host-final.pcap",
    "client-guest-final.pcap",
    "server-guest-final.pcap",
    "nonlocal-known-ip.pcap",
)
DNS_QUESTION = b"\x03www\x11developingnetwork\x03com\x00\x00\x01\x00\x01"
DNS_SUFFIX = b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + DNS_QUESTION


def utc_us(path: Path) -> int:
    value = path.read_text().strip().replace(" UTC", "+00:00")
    stamp = datetime.fromisoformat(value)
    offset = stamp.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError("Action time is not UTC")
    return int(stamp.timestamp()) * 1_000_000 + stamp.microsecond


def syn(
    packets: list[dict],
    src: str,
    dst: str,
    port: int,
    near: int | None = None,
    source_port: int | None = None,
) -> dict:
    candidates = [
        p
        for p in packets
        if p["src_ip"] == src
        and p["dst_ip"] == dst
        and p["dst_port"] == port
        and p["flags"] & 2
        and not p["flags"] & 16
        and (near is None or abs(p["timestamp_us"] - near) < 2_000_000)
        and (source_port is None or p["src_port"] == source_port)
    ]
    require(len(candidates) == 1, "Missing or ambiguous session SYN")
    return candidates[0]


def flow(packets: list[dict], item: dict) -> tuple[list[dict], bytes, bytes]:
    source = (item["src_ip"], item["src_port"])
    target = (item["dst_ip"], item["dst_port"])
    view = lifetime(packets, source, target, item["timestamp_us"])
    return view, stream(view, source, target), stream(view, target, source)


def check_control(client: bytes, server: bytes) -> dict:
    require(
        client[:12] == bytes.fromhex("54525450484f544c00010002")
        and server[:8] == bytes.fromhex("5452545000000000"),
        "Control handshake differs",
    )
    requests = parse_frames(client[12:])
    replies = parse_frames(server[8:])
    require(
        [(f["flags"], f["is_reply"], f["type"], f["id"], f["error"]) for f in requests]
        == [(0, 0, 107, 1, 0), (0, 0, 121, 2, 0), (0, 0, 300, 3, 0), (0, 0, 212, 4, 0)],
        "Control request type/id/status differs or extra numbered request",
    )
    require(
        [(f["flags"], f["is_reply"], f["type"], f["id"], f["error"]) for f in replies]
        == [
            (0, 1, 0, 1, 0),
            (0, 0, 109, 1, 0),
            (0, 1, 0, 2, 0),
            (0, 0, 354, 2, 0),
            (0, 0, 122, 3, 0),
            (0, 1, 0, 3, 0),
            (0, 1, 0, 4, 0),
        ],
        "Control reply type/id/status differs",
    )
    require(
        [field_map(f) for f in requests]
        == [
            {
                105: bytes.fromhex("9e9b929691"),
                106: bytes.fromhex("92908b978d9ecec6"),
                160: b"\x00\xbe",
            },
            {102: b"unnamed", 104: b"\x01\x9e", 113: b"\x00\x00"},
            {},
            {},
        ],
        "Control request fields differ",
    )
    fields = [field_map(f) for f in replies]
    require(
        fields[0] == {160: b"\x00\xbe", 161: b"\x00\x00"},
        "Login 161 or success fields differ",
    )
    require(
        fields[1] == {101: AGREEMENT} and fields[2] == {},
        "Known agreement/reply differs",
    )
    require(
        fields[3] == {110: bytes.fromhex("fff3cfefff800000")}, "Opaque bitmap differs"
    )
    require(
        fields[4] == {152: b"GIFf", 153: b"https://example.invalid/mothra-banner"},
        "Banner reference differs",
    )
    roster = fields[5].get(300, b"")
    require(
        set(fields[5]) == {300}
        and len(roster) == 15
        and int.from_bytes(roster[:2], "big") > 0
        and roster[2:] == bytes.fromhex("019e00120007") + b"unnamed",
        "Roster layout/name differs",
    )
    reference = fields[6].get(107, b"")
    require(
        set(fields[6]) == {108, 107}
        and fields[6][108] == b"\x00\x3a"
        and len(reference) == 4
        and reference != b"\x00" * 4,
        "212 length/reference differs",
    )
    return {
        "uid": int.from_bytes(roster[:2], "big"),
        "data_reference_hex": reference.hex(),
        "client_types": [f["type"] for f in requests],
        "server_types": [f["type"] for f in replies],
    }


def ipv4_records(path: Path) -> list[dict]:
    raw = path.read_bytes()
    require(len(raw) >= 24, "Truncated guest PCAP")
    order = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(raw[:4])
    if order is None:
        raise ValueError("Guest PCAP magic differs")
    require(
        struct.unpack_from(order + "I", raw, 20)[0] == 1, "Guest PCAP linktype differs"
    )
    result = []
    at = 24
    while at < len(raw):
        require(at + 16 <= len(raw), "Truncated guest PCAP record")
        sec, usec, length, original = struct.unpack_from(order + "IIII", raw, at)
        at += 16
        require(
            length == original and at + length <= len(raw) and usec < 1_000_000,
            "Truncated guest packet",
        )
        frame = raw[at : at + length]
        at += length
        if len(frame) < 34 or frame[12:14] != b"\x08\x00":
            continue
        ip = frame[14:]
        header = (ip[0] & 15) * 4
        total = int.from_bytes(ip[2:4], "big")
        require(
            ip[0] >> 4 == 4 and 20 <= header <= total <= len(ip), "Invalid guest IPv4"
        )
        require(not int.from_bytes(ip[6:8], "big") & 0x3FFF, "Fragmented guest IPv4")
        result.append(
            {
                "when": sec * 1_000_000 + usec,
                "proto": ip[9],
                "src": ".".join(map(str, ip[12:16])),
                "dst": ".".join(map(str, ip[16:20])),
                "ip": ip[:total],
                "body": ip[header:total],
            }
        )
    return result


def check_dns_and_egress(path: Path, disconnect_us: int) -> dict:
    records = ipv4_records(path)
    queries = []
    errors = []
    for record in records:
        if (
            record["proto"] == 17
            and record["src"] == "10.0.2.15"
            and record["dst"] == "10.0.2.3"
        ):
            udp = record["body"]
            require(
                len(udp) >= 20 and udp[:2] == b"\xc0\x00" and udp[2:4] == b"\x00\x35",
                "Unexpected guest UDP DNS socket",
            )
            require(
                int.from_bytes(udp[4:6], "big") == len(udp) and udp[10:] == DNS_SUFFIX,
                "DNS request bytes differ",
            )
            queries.append(record)
        if (
            record["proto"] == 1
            and record["src"] == "10.0.2.2"
            and record["dst"] == "10.0.2.15"
        ):
            icmp = record["body"]
            require(
                len(icmp) >= 8 and icmp[:2] == b"\x03\x00",
                "DNS error type/code differs",
            )
            errors.append(record)
    require(len(queries) == len(errors) == 15, "DNS query/error count differs")
    remaining = errors.copy()
    for query in queries:
        matches = [
            error
            for error in remaining
            if error["body"][8:].startswith(query["ip"])
            and 0 <= error["when"] - query["when"] <= 1_000_000
        ]
        require(len(matches) == 1, "Missing matching DNS network-unreachable error")
        remaining.remove(matches[0])
    require(not remaining, "Unpaired DNS error")
    before_disconnect = [
        error["when"] for error in errors if error["when"] < disconnect_us
    ]
    require(len(before_disconnect) == 10, "Pre-disconnect DNS error count differs")
    return {
        "queries": len(queries),
        "matched_unreachable": len(errors),
        "last_predisconnect_error_us": max(before_disconnect),
        "query_ids": [int.from_bytes(q["body"][8:10], "big") for q in queries],
    }


def check_observer(path: Path) -> None:
    raw = path.read_bytes()
    require(len(raw) == 24, "Unexpected public-IP host observer packet")
    require(
        raw[:4] == b"\xd4\xc3\xb2\xa1" and struct.unpack_from("<I", raw, 20)[0] == 276,
        "Known-IP observer header differs",
    )


def check_data(reference: bytes, outbound: bytes, inbound: bytes) -> None:
    require(
        outbound == b"HTXF" + reference + b"\x00\x00\x00\x00\x00\x02\x00\x00",
        "Dynamic 212/data HTXF reference differs",
    )
    require(
        len(inbound) == 58 and inbound.startswith(b"GIF89a"),
        "58-byte banner response differs",
    )


def check_isolation(directory: Path) -> None:
    host = (directory / "host-netns.txt").read_text().strip()
    guest = (directory / "emulator-netns.txt").read_text().strip()
    require(
        host.startswith("net:[") and guest.startswith("net:[") and host != guest,
        "Actual guest/host namespace witness differs",
    )
    require(
        (directory / "namespace-v4-routes.txt").read_text() == ""
        and (directory / "namespace-v6-routes.txt").read_text() == "",
        "Guest namespace has nonlocal route",
    )
    require(
        (directory / "namespace-addresses.txt").read_text().strip()
        == "lo               UNKNOWN        127.0.0.1/8 ::1/128",
        "Guest namespace interface witness differs",
    )
    for name, target in (
        ("bridge-ready.json", ["127.0.0.1", 15500]),
        ("data-bridge-ready.json", ["127.0.0.1", 15501]),
    ):
        item = json.loads((directory / name).read_text())
        require(
            item["fixed_target"]
            == {"kind": "tcp", "address": target, "synthetic": False}
            and item["netns"] == host,
            "Fixed host bridge witness differs",
        )
    x = json.loads((directory / "x-bridge-ready.json").read_text())
    require(
        x["fixed_target"] == {"kind": "x-abstract", "display": ":107"}
        and x["netns"] == host,
        "Fixed X bridge witness differs",
    )
    fds = (directory / "emulator-fds.txt").read_text()
    require(
        "hotline-client-isolated-01/working.dsk" in fds
        and "mac-peer-isolated-01/client-guest.pcap" in fds,
        "Emulator FD witness missing",
    )
    require(
        "7f286e3f8941c2261fc9c32b2d1d03acef32bdea567362a1c64abd5d64fe5315"
        in (directory / "return-hashes.txt").read_text()
        and "f762cfdedcc39758f841f720a4586dbbb88a7b74ec9e83db1793791b7c3f318b"
        in (directory / "return-hashes.txt").read_text(),
        "Finder fork witness differs",
    )
    assets = json.loads((directory / "assets.json").read_text())
    require(
        assets["rom_sha256"]
        == "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
        and assets["base_disk_sha256"]
        == "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910",
        "Stopped base/ROM identity witness differs",
    )
    require(
        (directory / "emulator-hash.txt")
        .read_text()
        .startswith("9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"),
        "Actual emulator hash witness differs",
    )
    require(
        "CapAmb:\t0000000000020000" in (directory / "emulator-status.txt").read_text()
        and "name of display:    :107"
        in (directory / "namespace-xdpyinfo.txt").read_text(),
        "Actual capability/X witness differs",
    )
    require(
        "length 32 type APPL creator HTLC"
        in (directory / "return-finder.txt").read_text(),
        "Finder type/creator witness differs",
    )


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    require(set(manifest["capture"]) == set(CAPTURES), "Capture inventory differs")
    for name in CAPTURES:
        raw = (directory / name).read_bytes()
        item = manifest["capture"][name]
        require(
            len(raw) == item["size"]
            and hashlib.sha256(raw).hexdigest() == item["sha256"],
            f"Capture SHA/size differs: {name}",
        )
    require(
        hashlib.sha256(
            (
                Path(__file__).resolve().parents[2]
                / "mothra/scripts/mac_network_isolation.py"
            ).read_bytes()
        ).hexdigest()
        == manifest["helper_sha256"],
        "Isolated helper source differs",
    )
    check_isolation(directory)
    check_observer(directory / "nonlocal-known-ip.pcap")
    host = read_packets(directory / "host-final.pcap")
    client = read_packets(directory / "client-guest-final.pcap")
    server = read_packets(directory / "server-guest-final.pcap")
    require(
        len(
            [
                p
                for p in client
                if p["src_ip"] == "10.0.2.15" and p["dst_ip"] != "10.0.2.2"
            ]
        )
        == 0,
        "Public or unexpected guest TCP destination",
    )
    require(
        len([p for p in client if p["flags"] & 2 and not p["flags"] & 16]) == 2,
        "Guest TCP connection count differs",
    )
    hc = syn(host, "127.0.0.1", "127.0.0.1", 15500)
    cc = syn(client, "10.0.2.15", "10.0.2.2", 15500, hc["timestamp_us"])
    sc = syn(server, "10.0.2.2", "10.0.2.15", 5500, hc["timestamp_us"], hc["src_port"])
    hv, ho, hi = flow(host, hc)
    _, co, ci = flow(client, cc)
    _, so, si = flow(server, sc)
    require(ho == co == so and hi == ci == si, "Control bytes differ across NAT views")
    control = check_control(ho, hi)
    hd = syn(host, "127.0.0.1", "127.0.0.1", 15501)
    cd = syn(client, "10.0.2.15", "10.0.2.2", 15501, hd["timestamp_us"])
    sd = syn(server, "10.0.2.2", "10.0.2.15", 5501, hd["timestamp_us"], hd["src_port"])
    hdata, hdo, hdi = flow(host, hd)
    _, cdo, cdi = flow(client, cd)
    _, sdo, sdi = flow(server, sd)
    require(
        hdo == cdo == sdo and hdi == cdi == sdi, "Data bytes differ across NAT views"
    )
    check_data(bytes.fromhex(control["data_reference_hex"]), hdo, hdi)
    quiet_end = utc_us(directory / "quiet-end-time.txt")
    disconnect = utc_us(directory / "disconnect-time.txt")
    quit_time = utc_us(directory / "quit-time.txt")
    dns = check_dns_and_egress(directory / "client-guest-final.pcap", disconnect)
    last_data = max(p["timestamp_us"] for p in hdata)
    require(
        quiet_end - last_data >= 130_000_000
        and quiet_end - dns["last_predisconnect_error_us"] >= 130_000_000,
        "Finite quiet window shorter than 130 seconds",
    )
    require(
        quiet_end < disconnect < quit_time
        and any(
            p["flags"] & 1
            and p["src_port"] == hc["src_port"]
            and p["timestamp_us"] > quiet_end
            for p in hv
        ),
        "Disconnect/quit timing or FIN differs",
    )
    require(
        max(p["timestamp_us"] for p in hv if p["payload_hex"]) < quiet_end,
        "Unexpected control payload in quiet window",
    )
    return {
        "status": "verified-isolated-finite-session",
        "control_bytes": {"client": len(ho), "server": len(hi)},
        "data_bytes": {"client": len(hdo), "server": len(hdi)},
        "control": control,
        "dns": dns,
        "data_last_to_quiet_end_us": quiet_end - last_data,
        "dns_last_to_quiet_end_us": quiet_end - dns["last_predisconnect_error_us"],
        "host_ports": {"control": hc["src_port"], "data": hd["src_port"]},
        "guest_ports": {"control": cc["src_port"], "data": cd["src_port"]},
        "server_nat_ports": {"control": sc["src_port"], "data": sd["src_port"]},
        "banner_ui_complete": False,
        "universal_500_schedule": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == "__main__":
    main()
