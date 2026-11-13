#!/usr/bin/env python3
"""Verify the finite, interrupted Classic client capture across three views."""

import argparse
import hashlib
import json
from pathlib import Path

from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import decode_frame

AGREEMENT = (
    b"This is the server agreement.  \r"
    b"The server owner puts any kind of conditions or conditions they want you "
    b"to agree to before entering.  \r"
    b"They can change this agreement by modifying the agreement.txt file "
    b"in the server directory.\rSay you agree!"
)
HTTP_REQUEST = b"GET /zipads/zip-hot.asp?c=82&h=69 HTTP/1.1\r\n"
CONTROL_CONNECT_US = 1794592084729501
DATA_CONNECT_US = 1794592189150000
CLIENT_CONTROL = ("10.0.2.15", 49152)
CLIENT_TARGET = ("10.0.2.2", 15500)
HOST_CLIENT = ("127.0.0.1", 59232)
HOST_SERVER = ("127.0.0.1", 15500)
SERVER_NAT = ("10.0.2.2", 59232)
SERVER_CONTROL = ("10.0.2.15", 5500)
CLIENT_DATA = ("10.0.2.15", 49155)
CLIENT_DATA_TARGET = ("10.0.2.2", 15501)
SERVER_DATA_NAT = ("10.0.2.2", 36936)
SERVER_DATA = ("10.0.2.15", 5501)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def parse_frames(data: bytes) -> list[dict]:
    """Require complete, unfragmented frames and fully consumed scalar TLVs."""
    result = []
    while data:
        require(len(data) >= 20, "Incomplete control frame header")
        size = int.from_bytes(data[16:20], "big")
        require(size <= 524288 and len(data) >= 20 + size, "Incomplete control frame")
        frame = decode_frame(data[: 20 + size])
        require(
            frame["total_size"] == size
            and frame.get("declared_field_count") == len(frame.get("fields", []))
            and frame.get("unconsumed_hex") == "",
            "Fragmented or malformed control frame",
        )
        result.append(frame)
        data = data[20 + size :]
    return result


def field_map(frame: dict) -> dict[int, bytes]:
    result = {item["id"]: bytes.fromhex(item["hex"]) for item in frame["fields"]}
    require(len(result) == len(frame["fields"]), "Duplicate control field")
    return result


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
        "Control request type/id/status differs",
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
                160: bytes.fromhex("00be"),
            },
            {102: b"unnamed", 104: bytes.fromhex("019e"), 113: b"\x00\x00"},
            {},
            {},
        ],
        "Control request fields differ",
    )
    require(
        [field_map(f) for f in replies]
        == [
            {160: bytes.fromhex("00be"), 161: b"\x00\x00"},
            {101: AGREEMENT},
            {},
            {110: bytes.fromhex("fff3cfefff800000")},
            {152: b"GIFf", 153: b"https://example.invalid/mothra-banner"},
            {300: bytes.fromhex("0007019e00120007756e6e616d6564")},
            {108: bytes.fromhex("003a"), 107: bytes.fromhex("00038325")},
        ],
        "Control reply fields differ",
    )
    return {
        "request_types": [f["type"] for f in requests],
        "reply_types": [f["type"] for f in replies],
    }


def selected_streams(
    packets: list[dict], source: tuple[str, int], dest: tuple[str, int], near_us: int
) -> tuple[list[dict], bytes, bytes]:
    view = lifetime(packets, source, dest, near_us)
    return view, stream(view, source, dest), stream(view, dest, source)


def check_http(packets: list[dict]) -> list[dict]:
    """Count complete SYN-scoped TCP exchanges, never duplicated packets."""
    sources = {
        p["src_port"]
        for p in packets
        if p["src_ip"] == "10.0.2.15"
        and p["dst_ip"] == "207.148.248.143"
        and p["dst_port"] == 80
        and p["flags"] & 2
        and not p["flags"] & 16
    }
    require(len(sources) == 5, "External HTTP connection count differs")
    result = []
    for port in sorted(sources):
        source = ("10.0.2.15", port)
        dest = ("207.148.248.143", 80)
        syn = next(
            p
            for p in packets
            if (p["src_ip"], p["src_port"]) == source
            and (p["dst_ip"], p["dst_port"]) == dest
            and p["flags"] & 2
            and not p["flags"] & 16
        )
        view, request, reply = selected_streams(
            packets, source, dest, syn["timestamp_us"]
        )
        require(
            request.startswith(HTTP_REQUEST)
            and b"\r\nHost: www.developingnetwork.com\r\n" in request
            and request.endswith(b"\r\n\r\n")
            and reply.startswith(b"HTTP/1.1 404 Not Found\r\n"),
            "Missing or changed external HTTP exchange",
        )
        get_when = min(
            p["timestamp_us"]
            for p in view
            if p["src_port"] == port and p["payload_hex"]
        )
        reply_when = min(
            p["timestamp_us"] for p in view if p["src_port"] == 80 and p["payload_hex"]
        )
        result.append(
            {"guest_source_port": port, "get_us": get_when, "reply_us": reply_when}
        )
    require(
        result[0]["get_us"] < 1794592188965025,
        "First external GET no longer precedes agreement",
    )
    return result


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    names = ("host-final.pcap", "client-guest-final.pcap", "server-guest-final.pcap")
    require(set(manifest["capture"]) == set(names), "Capture inventory differs")
    for name in names:
        path = directory / name
        require(
            path.stat().st_size == manifest["capture"][name]["size"]
            and hashlib.sha256(path.read_bytes()).hexdigest()
            == manifest["capture"][name]["sha256"],
            f"Capture SHA/size differs: {name}",
        )
    host = read_packets(directory / names[0])
    client = read_packets(directory / names[1])
    server = read_packets(directory / names[2])
    require(
        len([p for p in client if p["flags"] & 2 and not p["flags"] & 16]) == 7,
        "Client guest TCP connection inventory differs",
    )
    host_view, host_out, host_in = selected_streams(
        host, HOST_CLIENT, HOST_SERVER, CONTROL_CONNECT_US
    )
    client_view, client_out, client_in = selected_streams(
        client, CLIENT_CONTROL, CLIENT_TARGET, CONTROL_CONNECT_US
    )
    server_view, server_out, server_in = selected_streams(
        server, SERVER_NAT, SERVER_CONTROL, CONTROL_CONNECT_US
    )
    require(
        host_out == client_out == server_out and host_in == client_in == server_in,
        "Missing or changed guest control bytes across NAT views",
    )
    controls = check_control(host_out, host_in)
    require(
        len(host_view) == 23
        and len(client_view) == 24
        and len(server_view) == 25
        and len([p for p in host if p["flags"] & 2 and not p["flags"] & 16]) == 1,
        "Control lifetime or one-connect count differs",
    )
    guest_data, data_out, data_in = selected_streams(
        client, CLIENT_DATA, CLIENT_DATA_TARGET, DATA_CONNECT_US
    )
    server_data, server_data_out, server_data_in = selected_streams(
        server, SERVER_DATA_NAT, SERVER_DATA, DATA_CONNECT_US
    )
    require(
        data_out == server_data_out == bytes.fromhex("48545846000383250000000000020000")
        and data_in == server_data_in
        and len(data_in) == 58
        and data_in.startswith(b"GIF89a")
        and len(guest_data) == 7
        and len(server_data) == 12,
        "Missing or changed 15501 guest transfer bytes",
    )
    # The host recorder was filtered to 15500; no host-data parity is inferred.
    http = check_http(client)
    last_request = max(
        p["timestamp_us"]
        for p in host_view
        if p["src_port"] == 59232
        and bytes.fromhex(p["payload_hex"]).startswith(
            bytes.fromhex("000000d400000004")
        )
    )
    client_fin = min(
        p["timestamp_us"]
        for p in host_view
        if p["src_port"] == 59232 and p["flags"] & 1
    )
    require(client_fin > last_request, "Missing control FIN after final request")
    return {
        "status": "verified-partial-session",
        "control_bytes": {"client": len(host_out), "server": len(host_in)},
        "control": controls,
        "data_15501_bytes": {"client": len(data_out), "server": len(data_in)},
        "http_exchanges": http,
        "last_request_to_fin_us": client_fin - last_request,
        "control_syn_to_fin_us": client_fin - host_view[0]["timestamp_us"],
        "idle_test_valid": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == "__main__":
    main()
