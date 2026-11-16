"""Flow checks of the liveness replay: each flow across both captures and the report.

Each flow's bytes must agree across the namespace capture, the guest capture and
the coordinator's report. The summaries built here are what the paired-stream
review must reproduce.
"""

import dataclasses as dc
import typing as typ

from verify_native_liveness_checks import Report, need, read, utc

if typ.TYPE_CHECKING:
    from pathlib import Path

type Packet = dict[str, typ.Any]
type Address = tuple[str, int]

RELAY_PORT = 15840  # the port of the replayed server
GUEST_SERVER = ("10.0.2.15", 5500)  # the address and port of the guest's server
GUEST_CLIENT_HOST = "10.0.2.2"  # the address by which the guest sees the host
LOOPBACK = "127.0.0.1"  # the address of the host's loopback interface
TCP_FIN = 1  # the FIN flag bit of a TCP frame
TCP_RST = 4  # the RST flag bit of a TCP frame
FIN_PAIR = 2  # the FIN frames of a closed guest flow
US_PER_SECOND = 1_000_000  # microseconds in a second
NS_PER_US = 1000  # nanoseconds in a microsecond
RESET_FLOWS = frozenset({"a", "b", "f"})  # the flows that end in a reset
FIN_FLOWS = frozenset({"o", "s35", "s75", "s120"})  # the flows that end in a FIN pair
SENT_ORDER = (
    0,
    1,
    2,
    3,
)  # namespace client, namespace server, guest client, guest server
RECEIVED_ORDER = (1, 0, 3, 2)  # the same four endpoints, seen from the server


@dc.dataclass(frozen=True, slots=True)
class Captures:
    """The packet reader and the two captures that the flow checks read.

    Attributes
    ----------
    tcp : typing.Any
        The TCP reader module.
    namespace : list[dict[str, typing.Any]]
        The packets of the namespace capture.
    guest : list[dict[str, typing.Any]]
        The packets of the guest capture.
    """

    tcp: typ.Any
    namespace: list[Packet]
    guest: list[Packet]


@dc.dataclass(frozen=True, slots=True)
class Flow:
    """One flow of the report, with its lifetimes in the namespace and the guest.

    Attributes
    ----------
    folder : str
        The report folder that holds the flow.
    name : str
        The connection name.
    source : dict[str, typing.Any]
        The report that records the flow's events and streams.
    tcp : typing.Any
        The TCP reader module.
    namespace_life : list[dict[str, typing.Any]]
        The namespace packets of the flow's lifetime.
    guest_life : list[dict[str, typing.Any]]
        The guest packets of the flow's lifetime.
    ends : tuple[tuple[str, int], tuple[str, int], tuple[str, int], tuple[str, int]]
        The endpoints: namespace client, namespace server, guest client, guest server.
    """

    folder: str
    name: str
    port: int
    source: Report
    tcp: typ.Any
    namespace_life: list[Packet]
    guest_life: list[Packet]
    ends: tuple[Address, Address, Address, Address]


def source_report(raw: Path, report: Report, folder: str) -> Report:
    """Return the report that records the flow's events and streams.

    Parameters
    ----------
    raw : pathlib.Path
        The raw evidence directory.
    report : dict[str, typing.Any]
        The coordinator report.
    folder : str
        The report folder.

    Returns
    -------
    dict[str, typing.Any]
        The coordinator report, or the folder's own report.
    """
    return report if folder == "coordinator" else read(raw / folder / "report.json")


def _connect(source: Report, folder: str, name: str, port: int) -> Report:
    """Check the single connect event of a flow and return it.

    Parameters
    ----------
    source : dict[str, typing.Any]
        The report that records the flow's events.
    folder : str
        The report folder, for the message.
    name : str
        The connection name.
    port : int
        The local port of the connection.

    Returns
    -------
    dict[str, typing.Any]
        The connect event.
    """
    connect = [
        e
        for e in source["events"]
        if e["connection"] == name and e["event"] == "connect"
    ]
    need(
        len(connect) == 1
        and connect[0]["local_address"] == [LOOPBACK, port]
        and connect[0]["peer_address"] == [LOOPBACK, RELAY_PORT],
        f"{folder}/{name} connection identity differs",
    )
    return connect[0]


def _connect_us(source: Report, connect: Report) -> int:
    """Return the connect time of a flow in microseconds since the epoch.

    Parameters
    ----------
    source : dict[str, typing.Any]
        The report that records the start time.
    connect : dict[str, typing.Any]
        The connect event.

    Returns
    -------
    int
        The connect time, in microseconds.
    """
    return int(
        utc(source["started_at_utc"]).timestamp() * US_PER_SECOND
        + connect["elapsed_ns"] / NS_PER_US
    )


def _endpoints(port: int) -> tuple[Address, Address, Address, Address]:
    """Return the namespace and guest endpoints of a flow.

    Parameters
    ----------
    port : int
        The local port of the connection.

    Returns
    -------
    tuple[tuple[str, int], tuple[str, int], tuple[str, int], tuple[str, int]]
        The namespace client, namespace server, guest client and guest server.
    """
    return (
        (LOOPBACK, port),
        (LOOPBACK, RELAY_PORT),
        (GUEST_CLIENT_HOST, port),
        GUEST_SERVER,
    )


def _lifetimes(
    spec: tuple[str, str, int],
    source: Report,
    captures: Captures,
) -> Flow:
    """Open the lifetimes of one flow in both captures.

    Parameters
    ----------
    spec : tuple[str, str, int]
        The report folder, the connection name and the local port of the flow.
    source : dict[str, typing.Any]
        The report that records the flow's events and streams.
    captures : Captures
        The packet reader and the two captures.

    Returns
    -------
    Flow
        The flow, with its lifetimes and endpoints.
    """
    folder, name, port = spec
    connect_us = _connect_us(source, _connect(source, folder, name, port))
    ends = _endpoints(port)
    tcp = captures.tcp
    return Flow(
        folder,
        name,
        port,
        source,
        tcp,
        tcp.lifetime(captures.namespace, ends[0], ends[1], connect_us),
        tcp.lifetime(captures.guest, ends[2], ends[3], connect_us),
        ends,
    )


def _direction(
    flow: Flow,
    direction: str,
    key: str,
    order: tuple[int, int, int, int],
) -> int:
    """Check the bytes of one direction of a flow and return their length.

    Parameters
    ----------
    flow : Flow
        The flow.
    direction : str
        ``sent`` or ``received``, for the message.
    key : str
        The stream key of the report, ``sent_hex`` or ``received_hex``.
    order : tuple[int, int, int, int]
        The indices into the flow's endpoints, as (from, to) for the namespace
        pair and then the guest pair.

    Returns
    -------
    int
        The number of recorded bytes in this direction.
    """
    a, b, c, d = (flow.ends[index] for index in order)
    ns_bytes = flow.tcp.stream(flow.namespace_life, a, b)
    guest_bytes = flow.tcp.stream(flow.guest_life, c, d)
    recorded = bytes.fromhex(flow.source["streams"][flow.name][key])
    need(
        ns_bytes == guest_bytes == recorded,
        f"{flow.folder}/{flow.name} {direction} packet/report bytes or tail differ",
    )
    return len(recorded)


def _counts(flow: Flow) -> Report:
    """Return the packet and FIN and RST counts of a flow's two lifetimes.

    Parameters
    ----------
    flow : Flow
        The flow.

    Returns
    -------
    dict[str, int]
        The six counts, in the order of the paired-stream review.
    """
    n, g = flow.namespace_life, flow.guest_life
    return {
        "namespace_packets": len(n),
        "guest_packets": len(g),
        "namespace_fin": sum(bool(p["flags"] & TCP_FIN) for p in n),
        "namespace_rst": sum(bool(p["flags"] & TCP_RST) for p in n),
        "guest_fin": sum(bool(p["flags"] & TCP_FIN) for p in g),
        "guest_rst": sum(bool(p["flags"] & TCP_RST) for p in g),
    }


def _check_ends(name: str, item: Report) -> None:
    """Check how a flow ended in the guest: by reset or by a FIN pair.

    Parameters
    ----------
    name : str
        The connection name.
    item : dict[str, typing.Any]
        The flow's summary, with its guest counts.
    """
    if name in RESET_FLOWS:
        need(
            item["guest_rst"] >= 1 and item["guest_fin"] == 0,
            f"{name} guest reset/relay EOF distinction differs",
        )
    if name in FIN_FLOWS:
        need(item["guest_fin"] == FIN_PAIR, f"{name} guest FIN pair differs")


def flow_summary(
    spec: tuple[str, str, int],
    source: Report,
    captures: Captures,
) -> Report:
    """Check one flow across both captures and the report, and summarise it.

    Parameters
    ----------
    spec : tuple[str, str, int]
        The report folder, the connection name and the local port of the flow.
    source : dict[str, typing.Any]
        The report that records the flow's events and streams.
    captures : Captures
        The packet reader and the two captures.

    Returns
    -------
    dict[str, typing.Any]
        The flow's summary, as compared by the paired-stream review.
    """
    flow = _lifetimes(spec, source, captures)
    item: Report = {"folder": flow.folder, "connection": flow.name, "port": flow.port}
    item["sent"] = _direction(flow, "sent", "sent_hex", SENT_ORDER)
    item["received"] = _direction(flow, "received", "received_hex", RECEIVED_ORDER)
    item.update(_counts(flow))
    _check_ends(flow.name, item)
    return item
