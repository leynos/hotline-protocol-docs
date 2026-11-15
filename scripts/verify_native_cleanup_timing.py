"""Place a cleanup request and a stream's bytes on the guest packet timeline.

``flow`` locates the guest's packets for one capture connection, ``request_time``
finds when the whole 214 request had reached the guest, and ``bytes_after``
counts the stream bytes that the guest first saw after a cutoff.
"""

import datetime as dt

from native_wire_names import TYPE_REFERENCE_CLEANUP
from pcap_tcp import direction, lifetime, stream
from verify_native_core import require

# The capture's two ends: the host-side client address, and the guest server
# whose data port is the peer port less a fixed offset.
HOST_ADDRESS = "10.0.2.2"
GUEST_ADDRESS = "10.0.2.15"
GUEST_PORT_BASE = 5500
PEER_PORT_BASE = 15500
MICROSECONDS = 1e6
NANOSECONDS_PER_MICROSECOND = 1000
CLEANUP_REQUEST_BYTES = 30  # a 20-byte header, a count word and one 4-byte field
TYPE_START = 2  # the transaction type follows the flag and reply bytes
TYPE_END = 4
SEQUENCE_MASK = 0xFFFFFFFF
TCP_FIN = 1
TCP_SYN = 2
TCP_RST = 4


def flow(
    report: dict, connection: str, guest: list[dict]
) -> tuple[list[dict], tuple, tuple]:
    """Find the guest packets of one capture connection.

    Returns
    -------
    tuple[list[dict], tuple, tuple]
        The packets of the connection's lifetime, the host endpoint and the
        guest endpoint.
    """
    event = next(
        e
        for e in report["events"]
        if e["event"] == "connect" and e["connection"] == connection
    )
    source = (HOST_ADDRESS, event["local_address"][1])
    endpoint = (
        GUEST_ADDRESS,
        GUEST_PORT_BASE + event["peer_address"][1] - PEER_PORT_BASE,
    )
    when = int(
        dt.datetime.fromisoformat(report["started_at_utc"]).timestamp() * MICROSECONDS
        + event["elapsed_ns"] / NANOSECONDS_PER_MICROSECOND
    )
    return lifetime(guest, source, endpoint, when), source, endpoint


def first_sequence(selected: list[dict]) -> int:
    """Find where the stream's data begins.

    Returns
    -------
    int
        The sequence number of the first data byte after the SYN.
    """
    syn = next(p["sequence"] for p in selected if p["flags"] & TCP_SYN)
    return (syn + 1) & SEQUENCE_MASK


def request_bytes(report: dict, response: dict) -> bytes:
    """Return the bytes that the cleanup request sent, which must be a 214.

    Returns
    -------
    bytes
        The concatenated ``send`` events of the request's action.
    """
    action = response["action"] - 1
    wire = bytes.fromhex(
        "".join(
            e["hex"]
            for e in report["events"]
            if e["action"] == action and e["event"] == "send"
        )
    )
    require(
        len(wire) == CLEANUP_REQUEST_BYTES
        and int.from_bytes(wire[TYPE_START:TYPE_END], "big") == TYPE_REFERENCE_CLEANUP,
        "Unexpected cleanup request bytes",
    )
    return wire


def first_seen(
    selected: list[dict], base: int, start: int, size: int
) -> dict[int, int]:
    """Map each stream offset of a request to the first time it was seen.

    Returns
    -------
    dict[int, int]
        The earliest packet timestamp per offset in ``start`` to ``start + size``.
    """
    seen: dict[int, int] = {}
    for packet in selected:
        if packet["flags"] & TCP_RST:
            continue
        offset = (
            packet["sequence"] + bool(packet["flags"] & TCP_SYN) - base
        ) & SEQUENCE_MASK
        count = len(bytes.fromhex(packet["payload_hex"]))
        for index in range(max(start, offset), min(start + size, offset + count)):
            seen[index] = min(
                seen.get(index, packet["timestamp_us"]), packet["timestamp_us"]
            )
    return seen


def request_time(report: dict, response: dict, guest: list[dict]) -> int:
    """Observe complete incoming214 bytes, not the internal handler instant.

    Returns
    -------
    int
        The microsecond timestamp at which the last request byte first arrived.
    """
    wire = request_bytes(report, response)
    packets, source, endpoint = flow(report, response["connection"], guest)
    raw = stream(packets, source, endpoint)
    require(raw.count(wire) == 1, "Cleanup request not unique")
    start = raw.index(wire)
    selected = direction(packets, source, endpoint)
    base = first_sequence(selected)
    seen = first_seen(selected, base, start, len(wire))
    require(len(seen) == len(wire), "Missing timed cleanup request bytes")
    return max(seen.values())


def delivered_spans(
    selected: list[dict], base: int, total: int, cutoff: int
) -> list[tuple[int, int]]:
    """List the stream spans that arrived by the cutoff, clipped to ``total``.

    Returns
    -------
    list[tuple[int, int]]
        The start and end offset of each non-empty span.
    """
    spans = []
    for packet in selected:
        if packet["flags"] & TCP_RST or packet["timestamp_us"] > cutoff:
            continue
        start = (
            packet["sequence"] + bool(packet["flags"] & TCP_SYN) - base
        ) & SEQUENCE_MASK
        end = min(total, start + len(bytes.fromhex(packet["payload_hex"])))
        if start < end:
            spans.append((start, end))
    return spans


def covered_bytes(spans: list[tuple[int, int]]) -> int:
    """Count the distinct offsets in the spans, without counting overlaps.

    Returns
    -------
    int
        The size of the union of the spans.
    """
    covered, end = 0, 0
    for start, stop in sorted(spans):
        covered += max(0, stop - max(start, end))
        end = max(end, stop)
    return covered


def bytes_after(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # the callers' shape
    packets: list[dict], source: tuple, endpoint: tuple, total: int, cutoff: int
) -> int:
    """Count bytes first observed after cutoff without double-counting retries.

    Returns
    -------
    int
        The bytes of ``total`` that no packet at or before ``cutoff`` carried.
    """
    selected = direction(packets, source, endpoint)
    base = first_sequence(selected)
    return total - covered_bytes(delivered_spans(selected, base, total, cutoff))
