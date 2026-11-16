"""Check the packet captures of the board flows against the reports and the plan.

Each flow is one socket of the board case. Its namespace and guest lifetimes must
carry, in each direction, the bytes that the report records, and the independent
paired-stream review must agree with every flow.
"""

import dataclasses as dc
import typing as typ

from verify_native_board_checks import Report, need, read, utc
from verify_native_board_pins import ENDPOINT_PORT, PORTS

if typ.TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType

type Endpoint = tuple[str, int]
type Ends = tuple[Endpoint, Endpoint, Endpoint, Endpoint]

GUEST_PORT = 5500  # the guest's server port, as the guest capture records it
SYN_FLAG = 2  # the TCP SYN bit of a segment's flags
ACK_FLAG = 16  # the TCP ACK bit of a segment's flags
SYN_COUNT = 6  # one SYN lifetime for each flow, in each capture
NAMESPACE_PACKETS = 830  # the packets of the namespace capture
GUEST_PACKETS = 915  # the packets of the guest capture
BRIDGE_PORTS = {15500, 15501}  # the primary bridge's ports, which no flow may touch
FLOW_COUNT = 6  # the flows of the board case
MICROS_PER_SECOND = 1_000_000
NANOS_PER_MICRO = 1000
REVIEW_KEYS = ("report", "connection", "port", "sent", "received")


@dc.dataclass(frozen=True, slots=True)
class Captures:
    """The tcp reader and the namespace and guest captures that the flows read."""

    tcp: ModuleType
    namespace: list[Report]
    guest: list[Report]


@dc.dataclass(frozen=True, slots=True)
class Socket:
    """One board socket: its report, its two lifetimes and its endpoints."""

    phase: str
    name: str
    port: int
    report: Report
    tcp: ModuleType
    namespace_life: list[Report]
    guest_life: list[Report]
    sent_ends: Ends
    received_ends: Ends


def check_bridge_capture(
    host: list[Report], namespace: list[Report], guest: list[Report]
) -> None:
    """Check that the primary capture is empty and the namespace capture is complete.

    Parameters
    ----------
    host : list[dict[str, typing.Any]]
        The packets of the primary-port capture.
    namespace : list[dict[str, typing.Any]]
        The packets of the namespace capture.
    guest : list[dict[str, typing.Any]]
        The packets of the guest capture.
    """
    need(not host, "Primary-port SYN capture is not empty")
    need(
        len(namespace) == NAMESPACE_PACKETS
        and len(guest) == GUEST_PACKETS
        and all(
            item["src_port"] not in BRIDGE_PORTS
            and item["dst_port"] not in BRIDGE_PORTS
            for item in namespace
        ),
        "Namespace packet count or primary bridge contact differs",
    )


def check_syn_lifetimes(namespace: list[Report], guest: list[Report]) -> None:
    """Check that each capture has one SYN lifetime for each planned flow.

    Parameters
    ----------
    namespace : list[dict[str, typing.Any]]
        The packets of the namespace capture.
    guest : list[dict[str, typing.Any]]
        The packets of the guest capture.
    """
    expected = [port for _, _, port in PORTS]
    for view, name in ((namespace, "namespace"), (guest, "guest")):
        syn = [
            item
            for item in view
            if item["flags"] & SYN_FLAG and not item["flags"] & ACK_FLAG
        ]
        need(
            len(syn) == SYN_COUNT and [item["src_port"] for item in syn] == expected,
            f"{name} six SYN lifetimes differ",
        )


def connect_microseconds(source: Report, spec: tuple[str, str, int]) -> int:
    """Check a socket's connect event and return its time in microseconds.

    Parameters
    ----------
    source : dict[str, typing.Any]
        The report that holds the socket's events.
    spec : tuple[str, str, int]
        The report's phase, the connection's name and its port.

    Returns
    -------
    int
        The connect time, in microseconds since the epoch.
    """
    phase, name, port = spec
    connect = [
        event
        for event in source["events"]
        if event["connection"] == name and event["event"] == "connect"
    ]
    need(
        len(connect) == 1
        and connect[0]["local_address"] == ["127.0.0.1", port]
        and connect[0]["peer_address"] == ["127.0.0.1", ENDPOINT_PORT],
        f"{phase}/{name} socket identity differs",
    )
    started = source.get("started_at_utc", source.get("started_utc"))
    return int(
        utc(started).timestamp() * MICROS_PER_SECOND
        + connect[0]["elapsed_ns"] / NANOS_PER_MICRO
    )


def open_socket(
    captures: Captures, spec: tuple[str, str, int], source: Report
) -> Socket:
    """Find a socket's lifetimes in both captures and record its endpoints.

    Parameters
    ----------
    captures : Captures
        The tcp reader and the two captures.
    spec : tuple[str, str, int]
        The report's phase, the connection's name and its port.
    source : dict[str, typing.Any]
        The report of the socket's phase.

    Returns
    -------
    Socket
        The socket, with its lifetimes and the endpoints of each direction.
    """
    phase, name, port = spec
    connect_us = connect_microseconds(source, spec)
    n_client, n_server = ("127.0.0.1", port), ("127.0.0.1", ENDPOINT_PORT)
    g_client, g_server = ("10.0.2.2", port), ("10.0.2.15", GUEST_PORT)
    namespace_life = captures.tcp.lifetime(
        captures.namespace, n_client, n_server, connect_us
    )
    guest_life = captures.tcp.lifetime(captures.guest, g_client, g_server, connect_us)
    return Socket(
        phase,
        name,
        port,
        source,
        captures.tcp,
        namespace_life,
        guest_life,
        (n_client, n_server, g_client, g_server),
        (n_server, n_client, g_server, g_client),
    )


def leg_length(connection: Socket, label: str, ends: Ends, key: str) -> int:
    """Check one direction of a socket's bytes in both captures, and return its length.

    Parameters
    ----------
    connection : Socket
        The socket whose direction is checked.
    label : str
        The direction's name, which appears in the failure message.
    ends : Ends
        The endpoints of the namespace direction and of the guest direction.
    key : str
        The report's key for the direction's bytes.

    Returns
    -------
    int
        The number of bytes that the report records for the direction.
    """
    ns_data = connection.tcp.stream(connection.namespace_life, ends[0], ends[1])
    guest_data = connection.tcp.stream(connection.guest_life, ends[2], ends[3])
    recorded = bytes.fromhex(connection.report["streams"][connection.name][key])
    need(
        ns_data == guest_data == recorded,
        f"{connection.phase}/{connection.name} {label} "
        "PCAP/report bytes or tail differ",
    )
    return len(recorded)


def flow(captures: Captures, spec: tuple[str, str, int], source: Report) -> Report:
    """Check one board socket in both captures and summarise it.

    Parameters
    ----------
    captures : Captures
        The tcp reader and the two captures.
    spec : tuple[str, str, int]
        The report's phase, the connection's name and its port.
    source : dict[str, typing.Any]
        The report of the socket's phase.

    Returns
    -------
    dict[str, typing.Any]
        The socket's report, connection, port, byte counts and packet counts.
    """
    connection = open_socket(captures, spec, source)
    item = {
        "report": connection.phase,
        "connection": connection.name,
        "port": connection.port,
    }
    item["sent"] = leg_length(connection, "sent", connection.sent_ends, "sent_hex")
    item["received"] = leg_length(
        connection, "received", connection.received_ends, "received_hex"
    )
    item["namespace_packets"] = len(connection.namespace_life)
    item["guest_packets"] = len(connection.guest_life)
    return item


def flows(captures: Captures, raw: Path, report: Report) -> list[Report]:
    """Check every planned board socket, in plan order.

    Parameters
    ----------
    captures : Captures
        The tcp reader and the two captures.
    raw : pathlib.Path
        The raw directory of the corpus, which holds the phase reports.
    report : dict[str, typing.Any]
        The coordinator's report.

    Returns
    -------
    list[dict[str, typing.Any]]
        One summary for each planned socket.
    """
    summary: list[Report] = []
    for phase, name, port in PORTS:
        source = report if phase == "coordinator" else read(raw / phase / "report.json")
        summary.append(flow(captures, (phase, name, port), source))
    return summary


def check_review(review: Report, summary: list[Report]) -> None:
    """Check that the independent paired-stream review agrees with every flow.

    Parameters
    ----------
    review : dict[str, typing.Any]
        The independent review.
    summary : list[dict[str, typing.Any]]
        The summary of each flow, in plan order.
    """
    need(
        review["status"] == "PASS"
        and len(review["flows"]) == FLOW_COUNT
        and all(
            all(item[key] == other[key] for key in REVIEW_KEYS)
            and item["namespace_packets"] == other["namespace_packets"]
            and item["guest_packets"] == other["guest_packets"]
            for item, other in zip(summary, review["flows"], strict=True)
        ),
        "Independent paired-stream review differs",
    )


def packets(
    corpus: Path, modules: tuple[ModuleType, ...], report: Report
) -> list[Report]:
    """Check the captures of every board flow and return their summaries.

    Returns
    -------
    list[dict[str, typing.Any]]
        One summary for each planned flow.
    """
    raw = corpus / "raw"
    tcp = modules[4]
    host = tcp.read_packets(raw / "primary-syn.pcap")
    namespace = tcp.read_packets(raw / "lab-namespace.pcap")
    guest = tcp.read_packets(raw / "lab-guest.pcap")
    check_bridge_capture(host, namespace, guest)
    check_syn_lifetimes(namespace, guest)
    summary = flows(Captures(tcp, namespace, guest), raw, report)
    check_review(read(raw / "parent-paired-stream-review.json"), summary)
    return summary
