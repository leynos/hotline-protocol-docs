"""Read the guest and observer captures and check the DNS queries and errors."""

import struct
import typing as typ

from verify_mac_peer_first_session import require

if typ.TYPE_CHECKING:
    from pathlib import Path

type Packet = dict[str, typ.Any]

DNS_QUESTION = b"\x03www\x11developingnetwork\x03com\x00\x00\x01\x00\x01"
DNS_SUFFIX = b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + DNS_QUESTION
PCAP_HEADER_BYTES = 24
PCAP_RECORD_BYTES = 16
USEC_PER_SEC = 1_000_000
ETHERNET_IPV4_MIN_BYTES = 34  # an Ethernet header and the start of an IPv4 header
ETHERNET_HEADER_BYTES = 14
IPV4_VERSION = 4
IPV4_MIN_HEADER_BYTES = 20
DNS_QUERY_MIN_BYTES = 20  # a UDP header and the DNS header
ICMP_MIN_BYTES = 8
DNS_QUERIES = 15
MATCH_WINDOW_US = USEC_PER_SEC  # one second
PRE_DISCONNECT_ERRORS = 10
OBSERVER_LINKTYPE = 276
UDP_PROTOCOL = 17
ICMP_PROTOCOL = 1
MAGIC_MESSAGE = "Guest PCAP magic differs"


def ipv4_record(frame: bytes, when: int) -> Packet:
    """Return the fields of one guest IPv4 packet, requiring a valid header.

    Returns
    -------
    dict[str, typing.Any]
        The capture time, protocol, addresses, packet bytes and payload.
    """
    ip = frame[ETHERNET_HEADER_BYTES:]
    header = (ip[0] & 15) * 4
    total = int.from_bytes(ip[2:4], "big")
    require(
        ip[0] >> 4 == IPV4_VERSION
        and IPV4_MIN_HEADER_BYTES <= header <= total <= len(ip),
        "Invalid guest IPv4",
    )
    require(not int.from_bytes(ip[6:8], "big") & 0x3FFF, "Fragmented guest IPv4")
    return {
        "when": when,
        "proto": ip[9],
        "src": ".".join(map(str, ip[12:16])),
        "dst": ".".join(map(str, ip[16:20])),
        "ip": ip[:total],
        "body": ip[header:total],
    }


def ipv4_records(path: Path) -> list[Packet]:
    """Return the IPv4 packets of a guest PCAP, requiring every record to be whole.

    Returns
    -------
    list[dict[str, typing.Any]]
        The IPv4 packets, in capture order.

    Raises
    ------
    ValueError
        When the PCAP magic is not a classic PCAP magic.
    """
    raw = path.read_bytes()
    require(len(raw) >= PCAP_HEADER_BYTES, "Truncated guest PCAP")
    order = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(raw[:4])
    if order is None:
        raise ValueError(MAGIC_MESSAGE)
    require(
        struct.unpack_from(order + "I", raw, 20)[0] == 1,
        "Guest PCAP linktype differs",
    )
    result: list[Packet] = []
    at = PCAP_HEADER_BYTES
    while at < len(raw):
        require(at + PCAP_RECORD_BYTES <= len(raw), "Truncated guest PCAP record")
        sec, usec, length, original = struct.unpack_from(order + "IIII", raw, at)
        at += PCAP_RECORD_BYTES
        require(
            length == original and at + length <= len(raw) and usec < USEC_PER_SEC,
            "Truncated guest packet",
        )
        frame = raw[at : at + length]
        at += length
        if len(frame) < ETHERNET_IPV4_MIN_BYTES or frame[12:14] != b"\x08\x00":
            continue
        result.append(ipv4_record(frame, sec * USEC_PER_SEC + usec))
    return result


def check_query(record: Packet) -> None:
    """Require one guest DNS query to use the expected socket and request bytes."""
    udp = record["body"]
    require(
        len(udp) >= DNS_QUERY_MIN_BYTES
        and udp[:2] == b"\xc0\x00"
        and udp[2:4] == b"\x00\x35",
        "Unexpected guest UDP DNS socket",
    )
    require(
        int.from_bytes(udp[4:6], "big") == len(udp) and udp[10:] == DNS_SUFFIX,
        "DNS request bytes differ",
    )


def check_unreachable(record: Packet) -> None:
    """Require one host ICMP reply to be a destination-unreachable error."""
    icmp = record["body"]
    require(
        len(icmp) >= ICMP_MIN_BYTES and icmp[:2] == b"\x03\x00",
        "DNS error type/code differs",
    )


def addressed(record: Packet, proto: int, src: str, dst: str) -> bool:
    """Return whether a packet has the protocol and the source and destination.

    Returns
    -------
    bool
        True when all three fields match.
    """
    return record["proto"] == proto and record["src"] == src and record["dst"] == dst


def dns_records(records: list[Packet]) -> tuple[list[Packet], list[Packet]]:
    """Collect the guest's DNS queries and the unreachable errors, checking each.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], list[dict[str, typing.Any]]]
        The queries and the errors, each in capture order.
    """
    queries: list[Packet] = []
    errors: list[Packet] = []
    for record in records:
        if addressed(record, UDP_PROTOCOL, "10.0.2.15", "10.0.2.3"):
            check_query(record)
            queries.append(record)
        if addressed(record, ICMP_PROTOCOL, "10.0.2.2", "10.0.2.15"):
            check_unreachable(record)
            errors.append(record)
    return queries, errors


def pair_unreachable(queries: list[Packet], errors: list[Packet]) -> None:
    """Require each query to have exactly one matching error and no spare error."""
    remaining = errors.copy()
    for query in queries:
        matches = [
            error
            for error in remaining
            if error["body"][8:].startswith(query["ip"])
            and 0 <= error["when"] - query["when"] <= MATCH_WINDOW_US
        ]
        require(len(matches) == 1, "Missing matching DNS network-unreachable error")
        remaining.remove(matches[0])
    require(not remaining, "Unpaired DNS error")


def check_dns_and_egress(path: Path, disconnect_us: int) -> dict[str, typ.Any]:
    """Check the guest's DNS queries against their unreachable replies.

    Returns
    -------
    dict[str, typing.Any]
        The query count, the matched error count, the last pre-disconnect error
        time and the query identifiers.
    """
    records = ipv4_records(path)
    queries, errors = dns_records(records)
    require(len(queries) == len(errors) == DNS_QUERIES, "DNS query/error count differs")
    pair_unreachable(queries, errors)
    before_disconnect = [
        error["when"] for error in errors if error["when"] < disconnect_us
    ]
    require(
        len(before_disconnect) == PRE_DISCONNECT_ERRORS,
        "Pre-disconnect DNS error count differs",
    )
    return {
        "queries": len(queries),
        "matched_unreachable": len(errors),
        "last_predisconnect_error_us": max(before_disconnect),
        "query_ids": [int.from_bytes(q["body"][8:10], "big") for q in queries],
    }


def check_observer(path: Path) -> None:
    """Require the public-IP observer capture to hold only its header."""
    raw = path.read_bytes()
    require(len(raw) == PCAP_HEADER_BYTES, "Unexpected public-IP host observer packet")
    require(
        raw[:4] == b"\xd4\xc3\xb2\xa1"
        and struct.unpack_from("<I", raw, 20)[0] == OBSERVER_LINKTYPE,
        "Known-IP observer header differs",
    )
