#!/usr/bin/env python3
"""Replay the failed C35 transfer and bounded H1/H2 packet findings offline."""

import argparse
import datetime as dt
import hashlib
import json
import struct
from pathlib import Path

from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import verify_capture

SOURCE_PLAN_SHA = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"
PREFIX_SHA = "b4c6dc15be0d82de42d3aa7102c1feca67397b978591ac8be2d2c846d6a62e7c"


def require(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict:
    return json.loads(path.read_text())


# fmt: off
def raw_headers(path: Path) -> dict[int, dict]:
    """Return TCP windows/options indexed by the original PCAP record number."""
    parsed = {}
    with path.open("rb") as source:
        header = source.read(24)
        order = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(header[:4])
        if order is None:
            raise ValueError("PCAP magic differs")
        number = 0
        while record := source.read(16):
            require(len(record) == 16, "Truncated PCAP record")
            seconds, micros, size, original = struct.unpack(order + "IIII", record)
            require(size == original and micros < 1_000_000, "Invalid PCAP record")
            frame = source.read(size)
            require(len(frame) == size, "Truncated PCAP bytes")
            number += 1
            if frame[12:14] != b"\x08\x00":
                continue
            ip = frame[14:]
            if ip[9] != 6:
                continue
            tcp = ip[(ip[0] & 15) * 4 : int.from_bytes(ip[2:4], "big")]
            offset = (tcp[12] >> 4) * 4
            require(20 <= offset <= len(tcp), "Invalid TCP offset")
            options = tcp[20:offset]
            scales = []
            pos = 0
            while pos < len(options):
                kind = options[pos]
                if kind == 0:
                    break
                if kind == 1:
                    pos += 1
                    continue
                require(pos + 2 <= len(options), "Truncated TCP option")
                length = options[pos + 1]
                require(2 <= length <= len(options) - pos, "Invalid TCP option")
                if kind == 3:
                    require(length == 3 and options[pos + 2] <= 14, "Invalid window scale")
                    scales.append(options[pos + 2])
                pos += length
            require(len(scales) <= 1, "Ambiguous window scale")
            parsed[number] = {
                "window": int.from_bytes(tcp[14:16], "big"),
                "scale": scales[0] if scales else None,
                "time_us": seconds * 1_000_000 + micros,
            }
    return parsed


def inventory(corpus: Path) -> None:
    manifest = load(corpus / "manifest.json")
    require(manifest["schema"] == "native-transfer-stall-01", "Manifest schema differs")
    expected = manifest["files"]
    actual = {str(p.relative_to(corpus)) for p in corpus.rglob("*") if p.is_file() and p.name not in {"manifest.json", "SHA256SUMS"}}
    require(actual == set(expected), "Corpus inventory differs")
    for name, digest in expected.items():
        require(sha(corpus / name) == digest, f"SHA differs: {name}")
    require(
        (corpus / "SHA256SUMS").read_text().splitlines() == [f"{digest}  {name}" for name, digest in sorted(expected.items())],
        "SHA list differs",
    )
    provenance = load(corpus / "source-provenance.json")["sources"]
    for name, record in provenance.items():
        require(
            sha(corpus / name) == record["sha256"] and (corpus / name).stat().st_size == record["bytes"],
            f"Source provenance differs: {name}",
        )


def verify(corpus: Path) -> dict:
    corpus = corpus.resolve()
    inventory(corpus)
    source = load(corpus / "failure/a7-original-plan.json")
    plan = load(corpus / "failure/a7-as-run-plan.json")
    require(sha(corpus / "failure/a7-original-plan.json") == SOURCE_PLAN_SHA, "A7 source plan differs")
    require(len(source["steps"]) == 29 and source["steps"] == plan["steps"], "A7 steps differ")
    for key in source.keys() - {"environment", "endpoints"}:
        require(source[key] == plan[key], f"A7 {key} changed")
    require(plan["endpoints"] == {"control": {"host": "127.0.0.1", "port": 15730}, "data": {"host": "127.0.0.1", "port": 15731}}, "A7 lab endpoints differ")
    report = verify_capture(corpus / "failure")
    require(
        report["status"] == "failed" and report["completed_actions"] == 21 and report["error"] == "TimeoutError: timed out",
        "Mandatory A7 failure was recast",
    )
    received = bytes.fromhex(report["streams"]["download"]["received_hex"])
    require(
        len(received) == 98304 and hashlib.sha256(received).hexdigest() == PREFIX_SHA,
        "Failed read prefix differs",
    )
    terminal = load(corpus / "failure/terminal.json")
    require(
        not terminal["processes"]["lab"]["exists"] and terminal["guard_seed_ban_probe_executed"] is False,
        "Lab retirement or option-two scope differs",
    )
    require(
        terminal["a7_failure"]["download_received_bytes"] == len(received),
        "Terminal failure length differs",
    )
    require(
        terminal["processes"]["primary"]["fd6"].endswith("hotline22-recovery/working.dsk"),
        "Primary FD changed",
    )
    require(
        read_packets(corpus / "capture/host-primary.pcap") == [],
        "Primary capture has packets",
    )
    require(
        "0 packets dropped by kernel" in (corpus / "capture/namespace-recorder.log").read_text(),
        "Namespace packet drops unknown",
    )
    require(
        "0 packets dropped by kernel" in (corpus / "capture/host-recorder.log").read_text(),
        "Host packet drops unknown",
    )
    h1 = load(corpus / "h1/analysis.json")
    h2 = load(corpus / "h2/analysis.json")
    require(
        "H1 falsified" in h1["verdict"] and "H2 falsified" in h2["verdict"],
        "Frozen hypothesis classifications differ",
    )
    event = next(e for e in report["events"] if e["event"] == "connect" and e["connection"] == "download")
    require(event["peer_address"] == ["127.0.0.1", 15731], "Data flow endpoint differs")
    local = event["local_address"][1]
    when = int(dt.datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1_000_000) + event["elapsed_ns"] // 1000
    result = {"status": "verified_failed_baseline", "received_bytes": len(received), "option_two_executed": False, "views": {}}
    for label, client, server, port, expected_window, expected_scale in (
        ("namespace", "127.0.0.1", "127.0.0.1", 15731, 79872, 7),
        ("guest", "10.0.2.2", "10.0.2.15", 5501, 8760, None),
    ):
        path = corpus / f"capture/{label}.pcap"
        packets = read_packets(path)
        if label == "namespace":
            require(
                not any(p["src_port"] in {15500, 15501} or p["dst_port"] in {15500, 15501} for p in packets),
                "Primary bridge was used",
            )
        flow = lifetime(packets, (client, local), (server, port), when)
        heads = raw_headers(path)
        from_client = [p for p in flow if p["src_ip"] == client and p["src_port"] == local]
        from_server = [p for p in flow if p["src_ip"] == server and p["src_port"] == port]
        syn = [p for p in from_client if p["flags"] & 2 and not p["flags"] & 16]
        synack = [p for p in from_server if p["flags"] & 2 and p["flags"] & 16]
        require(len(syn) == len(synack) == 1, "SYN association differs")
        client_scale = heads[syn[0]["index"]]["scale"]
        server_scale = heads[synack[0]["index"]]["scale"]
        require(
            client_scale == server_scale == expected_scale,
            f"{label} window-scale negotiation differs",
        )
        factor = 1 << client_scale if client_scale is not None else 1
        application = stream(flow, (server, port), (client, local))
        require(application == received, f"{label} data differs or has suffix")
        require(
            stream(flow, (client, local), (server, port)) == bytes.fromhex(report["streams"]["download"]["sent_hex"]),
            f"{label} HTXF differs",
        )
        server_payload = [p for p in from_server if p["payload_hex"] and not p["flags"] & 4]
        require(
            sum(len(bytes.fromhex(p["payload_hex"])) for p in server_payload) == len(application),
            f"{label} retransmission tail differs",
        )
        base = (synack[0]["sequence"] + 1) & 0xFFFFFFFF
        last = max(server_payload, key=lambda p: p["timestamp_us"])
        end = ((last["sequence"] - base) & 0xFFFFFFFF) + len(bytes.fromhex(last["payload_hex"]))
        require(end == len(application), f"{label} final sequence differs")
        acks = [p for p in from_client if p["flags"] & 16 and not p["flags"] & 4]
        windows = [heads[p["index"]]["window"] * factor for p in acks]
        covered = [p for p in acks if (p["acknowledgement"] - base) & 0xFFFFFFFF >= end]
        require(bool(covered) and all(window > 0 for window in windows), f"{label} zero window or unacknowledged tail")
        require(windows[-1] == expected_window, f"{label} last window differs")
        require(h1["views"][label]["server_application_bytes"] == len(application) and h1["views"][label]["suffix_bytes_beyond_recorder"] == 0, "H1 frozen view differs")
        require(h2["views"][label]["last_payload_fully_acked"] and h2["views"][label]["zero_window_ack_count"] == 0, "H2 frozen view differs")
        require(h2["views"][label]["last_server_payload"]["relative_end"] == end, "H2 frozen sequence differs")
        result["views"][label] = {"packets": len(flow), "server_bytes": len(application), "first_full_ack_index": covered[0]["index"], "last_effective_window": windows[-1], "scale": client_scale}
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    print(json.dumps(verify(parser.parse_args().corpus), indent=2))


if __name__ == "__main__":
    main()
