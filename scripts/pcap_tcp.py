"""Read bounded Ethernet/IPv4 TCP observations without inventing missing bytes."""

import struct
from pathlib import Path


def read_packets(path: Path) -> list[dict]:
    """Read classic microsecond PCAP; reject incomplete or fragmented TCP input."""
    packets = []
    with path.open("rb") as source:
        header = source.read(24)
        if len(header) != 24:
            raise ValueError("Truncated PCAP header")
        order = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(header[:4])
        if order is None:
            raise ValueError("Expected classic microsecond PCAP")
        _, major, minor, _, _, snaplen, linktype = struct.unpack(
            order + "IHHIIII", header
        )
        if (major, minor, linktype) != (2, 4, 1):
            raise ValueError("Expected PCAP2.4 Ethernet")
        index = 0
        while raw_header := source.read(16):
            if len(raw_header) != 16:
                raise ValueError("Truncated packet record")
            seconds, micros, size, original = struct.unpack(order + "IIII", raw_header)
            if micros >= 1000000 or size != original or size > snaplen or size > 65535:
                raise ValueError("Truncated or invalid packet length/timestamp")
            frame = source.read(size)
            if len(frame) != size:
                raise ValueError("Truncated packet bytes")
            index += 1
            if len(frame) < 14 or frame[12:14] != b"\x08\x00":
                continue
            ip = frame[14:]
            if len(ip) < 20 or ip[0] >> 4 != 4:
                raise ValueError("Invalid IPv4 header")
            length = (ip[0] & 15) * 4
            total = int.from_bytes(ip[2:4], "big")
            if not 20 <= length <= total <= len(ip):
                raise ValueError("Invalid IPv4 size")
            if ip[9] != 6:
                continue
            if int.from_bytes(ip[6:8], "big") & 0x3FFF:
                raise ValueError("Fragmented TCP requires separate IP reassembly")
            tcp = ip[length:total]
            if len(tcp) < 20:
                raise ValueError("Truncated TCP header")
            offset = (tcp[12] >> 4) * 4
            if not 20 <= offset <= len(tcp):
                raise ValueError("Invalid TCP size")
            packets.append(
                {
                    "index": index,
                    "timestamp_us": seconds * 1000000 + micros,
                    "src_ip": ".".join(str(b) for b in ip[12:16]),
                    "dst_ip": ".".join(str(b) for b in ip[16:20]),
                    "src_port": int.from_bytes(tcp[:2], "big"),
                    "dst_port": int.from_bytes(tcp[2:4], "big"),
                    "sequence": int.from_bytes(tcp[4:8], "big"),
                    "acknowledgement": int.from_bytes(tcp[8:12], "big"),
                    "flags": tcp[13] | ((tcp[12] & 1) << 8),
                    "payload_hex": tcp[offset:].hex(),
                }
            )
    return packets


def direction(
    packets: list[dict], source: tuple[str, int], destination: tuple[str, int]
) -> list[dict]:
    """Select one TCP direction; port lifetimes must be scoped by the caller."""
    return [
        p
        for p in packets
        if (p["src_ip"], p["src_port"]) == source
        and (p["dst_ip"], p["dst_port"]) == destination
    ]


def stream(
    packets: list[dict], source: tuple[str, int], destination: tuple[str, int]
) -> bytes:
    """Reassemble a SYN-identified direction with matching overlaps and no gaps."""
    selected = direction(packets, source, destination)
    syns = [p for p in selected if p["flags"] & 2]
    if not syns or len({p["sequence"] for p in syns}) != 1:
        raise ValueError("Missing SYN or reused TCP port lifetime")
    base = (syns[0]["sequence"] + 1) & 0xFFFFFFFF
    segments = []
    for packet in selected:
        # A reset may carry diagnostic bytes. Keep them in the packet view,
        # but do not merge them into the application stream (RFC9293 3.5.3).
        if packet["flags"] & 4:
            continue
        data = bytes.fromhex(packet["payload_hex"])
        if data:
            offset = (
                packet["sequence"] + bool(packet["flags"] & 2) - base
            ) & 0xFFFFFFFF
            if offset + len(data) > 8 * 1024 * 1024:
                raise ValueError("TCP stream exceeds analysis bound")
            segments.append((offset, data))
    result = bytearray()
    for offset, data in sorted(segments):
        if offset > len(result):
            raise ValueError("TCP sequence gap")
        overlap = min(len(result) - offset, len(data))
        if result[offset : offset + overlap] != data[:overlap]:
            raise ValueError("Conflicting TCP retransmission")
        result.extend(data[overlap:])
    return bytes(result)


def lifetime(
    packets: list[dict],
    source: tuple[str, int],
    destination: tuple[str, int],
    connect_us: int,
) -> list[dict]:
    """Select a unique SYN lifetime near a socket event; reject ambiguous reuse."""
    incoming = direction(packets, source, destination)
    first_syns: dict[int, int] = {}
    for packet in incoming:
        if packet["flags"] & 2 and not packet["flags"] & 16:
            first_syns.setdefault(packet["sequence"], packet["timestamp_us"])
    candidates = [
        (sequence, when)
        for sequence, when in first_syns.items()
        if abs(when - connect_us) <= 2_000_000
    ]
    if len(candidates) != 1:
        raise ValueError("Missing or ambiguous SYN lifetime near socket event")
    sequence, start = candidates[0]
    end = min(
        (
            when
            for other, when in first_syns.items()
            if other != sequence and when > start
        ),
        default=float("inf"),
    )
    return [
        p
        for p in packets
        if start <= p["timestamp_us"] < end
        and (
            (
                (p["src_ip"], p["src_port"]) == source
                and (p["dst_ip"], p["dst_port"]) == destination
            )
            or (
                (p["src_ip"], p["src_port"]) == destination
                and (p["dst_ip"], p["dst_port"]) == source
            )
        )
    ]
