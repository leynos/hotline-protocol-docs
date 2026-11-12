#!/usr/bin/env python3
"""Verify bounded native handshake outcomes against TCP and Ethernet records."""

import argparse
import json
from datetime import datetime
from pathlib import Path

from pcap_tcp import direction, read_packets, stream
from protocol_capture import verify_capture
from verify_native_core import require

HANDSHAKE = bytes.fromhex("54525450484f544c00010002")
SUCCESS = bytes.fromhex("5452545000000000")
FAILURE = bytes.fromhex("5452545000000001")


def verify_timing(directory: Path, guest: list[dict]) -> dict:
    """Check the two bounded close observations without claiming a hard deadline."""
    baseline = verify_capture(
        directory / "initial-transcripts/failed-login-guest-drain"
    )
    require(baseline["status"] == "failed", "65-second observation status changed")
    started = (
        datetime.fromisoformat(baseline["recorded_at_utc"]).timestamp()
        - baseline["events"][-1]["elapsed_ns"] / 1e9
    )
    candidates = {
        p["src_port"]
        for p in guest
        if p["src_ip"] == "10.0.2.2"
        and p["dst_port"] == 5500
        and p["flags"] & 2
        and abs(p["timestamp_us"] / 1e6 - started) < 0.25
    }
    require(len(candidates) == 1, "Old socket port cannot be identified unambiguously")
    port = candidates.pop()
    incoming = direction(guest, ("10.0.2.2", port), ("10.0.2.15", 5500))
    outgoing = direction(guest, ("10.0.2.15", 5500), ("10.0.2.2", port))
    client_end = next(p for p in incoming if p["flags"] & 5)
    require(
        not any(
            p["flags"] & 5 and p["timestamp_us"] < client_end["timestamp_us"]
            for p in outgoing
        ),
        "Guest closed during baseline waiting period",
    )
    last_data = max(
        p["timestamp_us"] for p in outgoing if p["payload_hex"] and not p["flags"] & 4
    )
    silence = (client_end["timestamp_us"] - last_data) / 1e6
    require(silence >= 65, "Baseline guest silence was shorter than65 seconds")
    isolated = verify_capture(directory / "isolated-failure-quiet-and-tick")
    require(isolated["status"] == "completed", "Isolated35-second observation changed")
    host = read_packets(directory / "isolated-host.pcap")
    ports = {}
    for event in isolated["events"]:
        if event["event"] != "connect":
            continue
        client, server = tuple(event["local_address"]), tuple(event["peer_address"])
        ports[event["connection"]] = client[1]
        recorded = isolated["streams"][event["connection"]]
        require(
            stream(host, client, server).hex() == recorded["sent_hex"]
            and stream(host, server, client).hex() == recorded["received_hex"],
            "Isolated socket and packet streams differ",
        )
        require(
            stream(guest, ("10.0.2.2", client[1]), ("10.0.2.15", 5500)).hex()
            == recorded["sent_hex"]
            and stream(guest, ("10.0.2.15", 5500), ("10.0.2.2", client[1])).hex()
            == recorded["received_hex"],
            "Isolated guest stream differs",
        )
    quiet = next(e for e in isolated["events"] if e["event"] == "quiet")
    previous_receive = max(
        e["elapsed_ns"]
        for e in isolated["events"]
        if e["event"] == "receive" and e["connection"] == "main"
    )
    require(
        quiet["elapsed_ns"] - previous_receive >= 35 * 1e9,
        "No35-second quiet observation",
    )
    syn = next(
        p
        for p in guest
        if p["src_port"] == ports["tick"] and p["dst_port"] == 5500 and p["flags"] & 2
    )
    reset = next(
        p
        for p in guest
        if p["src_port"] == 5500 and p["dst_port"] == ports["main"] and p["flags"] & 4
    )
    require(
        reset["timestamp_us"] >= syn["timestamp_us"],
        "Isolated reset preceded new connection",
    )
    main_syn = next(
        p
        for p in guest
        if p["src_port"] == ports["main"] and p["dst_port"] == 5500 and p["flags"] & 2
    )
    require(
        not any(
            p["flags"] & 2
            and p["src_ip"] == "10.0.2.2"
            and 5500 <= p["dst_port"] <= 5503
            and p["src_port"] not in ports.values()
            and main_syn["timestamp_us"] <= p["timestamp_us"] <= syn["timestamp_us"]
            for p in guest
        ),
        "Other control/data connection overlaps isolated window",
    )
    return {
        "baseline_guest_silence_seconds": silence,
        "baseline_port_identification": "Unique SYN within250ms of UTC end minus monotonic duration; old recorder had no socket address metadata",
        "isolated_reset_after_new_syn_ms": (reset["timestamp_us"] - syn["timestamp_us"])
        / 1000,
        "scope": "Bounded observations; dispatcher scheduling and unique causal mechanism remain open",
    }


def verify(directory: Path) -> dict:
    """Match each addressed socket to exact guest TCP bytes and close ordering."""
    guest = read_packets(directory / "guest.pcap")
    host = read_packets(directory / "host.pcap")
    observations = []
    expected_names = {
        "normal-control",
        "normal-alternate-control",
        "wrong-magic",
        "wrong-version",
        "wrong-subprotocol",
        "wrong-subversion",
        "short-eof",
        "pipelined-login",
        "thirteenth-byte-is-frame-prefix",
    } | {f"segmented-{n}" for n in [1, 4, 8, 10, 11]}
    for path in sorted((directory / "transcripts").glob("*/report.json")):
        name = path.parent.name
        report = verify_capture(path.parent)
        expected_status = (
            "failed" if name == "normal-alternate-control" else "completed"
        )
        require(report["status"] == expected_status, name + ": capture status changed")
        connect = report["events"][0]
        source = tuple(connect["local_address"])
        endpoint = tuple(connect["peer_address"])
        request = bytes.fromhex(report["streams"]["main"]["sent_hex"])
        response = bytes.fromhex(report["streams"]["main"]["received_hex"])
        require(
            stream(host, source, endpoint) == request, name + ": host sent bytes differ"
        )
        require(
            stream(host, endpoint, source) == response,
            name + ": host received bytes differ",
        )
        guest_client = ("10.0.2.2", source[1])
        guest_server = ("10.0.2.15", 5500 + endpoint[1] - 15500)
        require(
            stream(guest, guest_client, guest_server) == request,
            name + ": guest input differs",
        )
        require(
            stream(guest, guest_server, guest_client) == response,
            name + ": guest output differs",
        )
        incoming = direction(guest, guest_client, guest_server)
        outgoing = direction(guest, guest_server, guest_client)
        server_end = [p for p in outgoing if p["flags"] & 5]
        client_end = [p for p in incoming if p["flags"] & 5]
        require(bool(server_end), name + ": incomplete guest close observation")
        server_first = (
            not client_end
            or server_end[0]["timestamp_us"] < client_end[0]["timestamp_us"]
        )
        if name in {"wrong-version", "wrong-subprotocol", "wrong-subversion"}:
            require(response == FAILURE, name + ": failure handshake changed")
            require(server_first, name + ": server did not initiate close")
            last_data = max(
                p["timestamp_us"]
                for p in outgoing
                if p["payload_hex"] and not p["flags"] & 4
            )
            require(
                last_data <= server_end[0]["timestamp_us"],
                name + ": close preceded failure bytes",
            )
        elif name == "wrong-magic":
            require(
                not response and server_first and server_end[0]["flags"] & 4,
                "Wrong magic did not reset without application bytes",
            )
        elif name == "short-eof":
            require(
                request == HANDSHAKE[:11] and not response,
                "Truncated handshake changed",
            )
            require(
                bool(client_end) and not server_first and client_end[0]["flags"] & 1,
                "Truncated input did not half-close first",
            )
        elif name == "normal-alternate-control":
            require(
                request == HANDSHAKE and not response,
                "Alternate-port observation changed",
            )
            require(
                bool(client_end) and not server_first,
                "Alternate-port close was not client initiated",
            )
        else:
            require(response.startswith(SUCCESS), name + ": success handshake changed")
            if name == "normal-control":
                require(
                    request == HANDSHAKE and response == SUCCESS,
                    "Normal handshake bytes changed",
                )
            if name.startswith("segmented-"):
                n = int(name.split("-")[1])
                require(request == HANDSHAKE, name + ": segmented input changed")
                sends = [e for e in report["events"] if e["event"] == "send"]
                require(
                    bytes.fromhex(sends[0]["hex"]) == HANDSHAKE[:n],
                    name + ": split point changed",
                )
                require(
                    any(e["event"] == "quiet" for e in report["events"]),
                    name + ": no bounded quiet observation",
                )
                plan = json.loads((path.parent / "plan.json").read_text())
                window = next(
                    s["timeout"] for s in plan["steps"] if s["op"] == "expect_quiet"
                )
                require(window >= 3, name + ": quiet observation too short")
                quiet = next(e for e in report["events"] if e["event"] == "quiet")
                require(
                    quiet["action"] < sends[1]["action"]
                    and quiet["elapsed_ns"] - sends[0]["elapsed_ns"] >= window * 1e9,
                    name + ": quiet timing/order evidence changed",
                )
            if name in {"pipelined-login", "thirteenth-byte-is-frame-prefix"}:
                require(request[:12] == HANDSHAKE, name + ": handshake prefix changed")
                require(
                    [(f["is_reply"], f["type"], f["error"]) for f in report["frames"]]
                    == [(1, 0, 0), (0, 354, 0), (0, 109, 0)],
                    name + ": pipelined login failed",
                )
        observations.append(
            {
                "case": name,
                "host_client_port": source[1],
                "guest_server_port": guest_server[1],
                "sent_bytes": len(request),
                "received_bytes": len(response),
                "guest_first_close": "server" if server_first else "client",
                "guest_server_close_kind": "RST"
                if server_end[0]["flags"] & 4
                else "FIN",
                "reset_diagnostics_hex": [
                    p["payload_hex"]
                    for p in outgoing
                    if p["flags"] & 4 and p["payload_hex"]
                ],
                "capture_status": report["status"],
            }
        )
    require(
        {o["case"] for o in observations} == expected_names,
        "Incomplete handshake case catalogue",
    )
    return {
        "cases": observations,
        "timing": verify_timing(directory, guest),
        "scope": "Recorded boundary exchanges and guest FIN/RST ordering only; no timer or alternate-wrapper negotiation completion",
    }


def main() -> None:
    """Verify one immutable handshake evidence batch."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == "__main__":
    main()
