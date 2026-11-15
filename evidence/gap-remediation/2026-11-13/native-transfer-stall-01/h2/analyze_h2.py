#!/usr/bin/env python3
"""Inspect TCP receive-window and ACK state for frozen C35 data lifetime only."""

import datetime as dt
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT.parent / "hotline-protocol-docs/scripts"))
from pcap_tcp import lifetime, read_packets, stream  # noqa: E402


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def headers(path: Path) -> dict[int, dict]:
    result = {}
    with path.open("rb") as source:
        header = source.read(24)
        order = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(header[:4])
        if order is None:
            raise ValueError("PCAP magic differs")
        index = 0
        while record := source.read(16):
            if len(record) != 16:
                raise ValueError("Truncated PCAP record")
            seconds, micros, size, original = struct.unpack(order + "IIII", record)
            if size != original or micros >= 1_000_000:
                raise ValueError("Invalid PCAP record")
            frame = source.read(size)
            if len(frame) != size:
                raise ValueError("Truncated PCAP bytes")
            index += 1
            if frame[12:14] != b"\x08\x00":
                continue
            ip = frame[14:]
            if ip[9] != 6:
                continue
            tcp = ip[(ip[0] & 15) * 4 : int.from_bytes(ip[2:4], "big")]
            offset = (tcp[12] >> 4) * 4
            if len(tcp) < offset or offset < 20:
                raise ValueError("Invalid TCP offset")
            options = []
            raw = tcp[20:offset]
            i = 0
            while i < len(raw):
                kind = raw[i]
                if kind == 0:
                    break
                if kind == 1:
                    i += 1
                    continue
                if i + 2 > len(raw) or raw[i + 1] < 2 or i + raw[i + 1] > len(raw):
                    raise ValueError("Malformed TCP option")
                options.append((kind, raw[i + 2 : i + raw[i + 1]].hex()))
                i += raw[i + 1]
            result[index] = {
                "timestamp_us": seconds * 1_000_000 + micros,
                "window_raw": int.from_bytes(tcp[14:16], "big"),
                "options": options,
            }
    return result


def scale(packet: dict) -> int | None:
    values = [bytes.fromhex(value) for kind, value in packet["options"] if kind == 3]
    if not values:
        return None
    if len(values) != 1 or len(values[0]) != 1 or values[0][0] > 14:
        raise ValueError("Ambiguous TCP window scale")
    return values[0][0]


def main() -> None:
    out = Path(__file__).resolve().parent
    boot = ROOT / "state/native-sessions/native-banlab-boot-c34"
    report_path = ROOT / "state/native-sessions/native-banlab-c35/a7-capture/report.json"
    report = json.loads(report_path.read_text())
    assert report["status"] == "failed" and report["completed_actions"] == 21
    event = next(e for e in report["events"] if e["event"] == "connect" and e["connection"] == "download")
    assert event["peer_address"] == ["127.0.0.1", 15731]
    local = event["local_address"][1]
    when = int(dt.datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1_000_000) + event["elapsed_ns"] // 1000
    result = {"hypothesis": "H2: zero receiver window or unacknowledged server tail blocked transmission", "input_sha256": {"report": sha(report_path)}, "views": {}}
    for label, path, client, server, port in (
        ("namespace", boot / "lab-namespace.pcap", "127.0.0.1", "127.0.0.1", 15731),
        ("guest", boot / "lab-guest.pcap", "10.0.2.2", "10.0.2.15", 5501),
    ):
        result["input_sha256"][label + "_pcap"] = sha(path)
        parsed = read_packets(path)
        selected = lifetime(parsed, (client, local), (server, port), when)
        raw = headers(path)
        client_packets = [p for p in selected if p["src_ip"] == client and p["src_port"] == local]
        server_packets = [p for p in selected if p["src_ip"] == server and p["src_port"] == port]
        syn = [p for p in client_packets if p["flags"] & 2 and not p["flags"] & 16]
        synack = [p for p in server_packets if p["flags"] & 2 and p["flags"] & 16]
        if len(syn) != 1 or len(synack) != 1:
            raise ValueError(label + " SYN options ambiguous")
        client_scale = scale(raw[syn[0]["index"]])
        server_scale = scale(raw[synack[0]["index"]])
        negotiated = client_scale is not None and server_scale is not None
        client_factor = 1 << client_scale if negotiated else 1
        received = stream(selected, (server, port), (client, local))
        assert len(received) == 98304
        server_base = (synack[0]["sequence"] + 1) & 0xFFFFFFFF
        payload = [p for p in server_packets if p["payload_hex"] and not p["flags"] & 4]
        last_payload = max(payload, key=lambda p: p["timestamp_us"])
        last_end = ((last_payload["sequence"] - server_base) & 0xFFFFFFFF) + len(bytes.fromhex(last_payload["payload_hex"]))
        acks = [p for p in client_packets if p["flags"] & 16 and not p["flags"] & 4]
        ack_rows = [{"index": p["index"], "timestamp_us": p["timestamp_us"], "relative_ack": (p["acknowledgement"] - server_base) & 0xFFFFFFFF, "window_raw": raw[p["index"]]["window_raw"], "window_effective": raw[p["index"]]["window_raw"] * client_factor} for p in acks]
        covering = [row for row in ack_rows if row["relative_ack"] >= last_end]
        client_flags = {packet["index"]: packet["flags"] for packet in client_packets}
        pre_fin_acks = [row for row in ack_rows if not client_flags[row["index"]] & 1]
        idle_acks = [row for row in pre_fin_acks if row["timestamp_us"] > last_payload["timestamp_us"]]
        late_window_updates = [row for row in pre_fin_acks if row["timestamp_us"] >= last_payload["timestamp_us"] + 1_000_000 and not client_flags[row["index"]] & 4]
        result["views"][label] = {
            "flow": {"client": [client, local], "server": [server, port]},
            "client_syn": {"index": syn[0]["index"], "options": raw[syn[0]["index"]]["options"], "window_raw": raw[syn[0]["index"]]["window_raw"], "scale": client_scale},
            "server_synack": {"index": synack[0]["index"], "options": raw[synack[0]["index"]]["options"], "window_raw": raw[synack[0]["index"]]["window_raw"], "scale": server_scale},
            "scale_negotiated": negotiated,
            "server_base_sequence": server_base,
            "server_application_bytes": len(received),
            "last_server_payload": {"index": last_payload["index"], "timestamp_us": last_payload["timestamp_us"], "relative_end": last_end},
            "max_client_ack_relative": max(row["relative_ack"] for row in ack_rows),
            "last_payload_fully_acked": bool(covering),
            "first_full_ack": covering[0] if covering else None,
            "last_non_fin_ack": pre_fin_acks[-1],
            "last_advertised_window": ack_rows[-1],
            "idle_ack_rows": idle_acks,
            "late_window_updates": late_window_updates,
            "zero_window_ack_count": sum(row["window_raw"] == 0 for row in ack_rows),
            "server_payload_packets": len(payload),
            "server_payload_raw_bytes": sum(len(bytes.fromhex(p["payload_hex"])) for p in payload),
            "server_payload_overlap_bytes": sum(len(bytes.fromhex(p["payload_hex"])) for p in payload) - len(received),
            "terminal_packets": [{"index": p["index"], "timestamp_us": p["timestamp_us"], "flags": p["flags"], "from_server": p in server_packets, "rst_diagnostic_hex": p["payload_hex"] if p["flags"] & 4 else ""} for p in selected if p["flags"] & 5],
        }
    if all(v["last_payload_fully_acked"] and v["zero_window_ack_count"] == 0 and v["last_non_fin_ack"]["window_effective"] > 0 for v in result["views"].values()):
        result["verdict"] = "H2 falsified: final server payload fully acknowledged with positive receiver window in both views"
    else:
        result["verdict"] = "H2 inconclusive: missing full ACK or positive receive-window witness"
    (out / "analysis.json").write_text(json.dumps(result, indent=2) + "\n")
    print(result["verdict"])


if __name__ == "__main__":
    main()
