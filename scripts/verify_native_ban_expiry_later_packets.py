"""Check the packets and paired TCP streams of the later temporary-ban epoch."""

import typing as typ

from verify_native_ban_expiry_first_common import need, when
from verify_native_ban_expiry_later_wire import (
    CONTROL_PORT,
    FIRST_CONNECTIONS,
    GUEST_PORT,
    GUEST_SYNS,
    HOST_PCAP_HEADER,
    LATER_CONNECTIONS,
    NAMESPACE_SYNS,
)

if typ.TYPE_CHECKING:
    import types
    from pathlib import Path

# The lanes that one control connection is checked on: the label, the client
# and server addresses, and the server port on that lane.
LANES = (
    ("namespace", "127.0.0.1", "127.0.0.1", CONTROL_PORT),
    ("guest", "10.0.2.2", "10.0.2.15", GUEST_PORT),
)


def continuity_gate(corpus: Path, first: Path) -> None:
    """Check that the later guest capture extends the first and stayed silent.

    Parameters
    ----------
    corpus : Path
        The later corpus directory.
    first : Path
        The first-epoch corpus directory.
    """
    post = corpus / "raw/post"
    pre = corpus / "raw/pre"
    guest_bytes = (post / "lab-guest-final.pcap").read_bytes()
    first_prefix = (first / "raw/lab-guest.pcap").read_bytes()
    need(
        guest_bytes.startswith(first_prefix)
        and (pre / "primary-syn.pcap").read_bytes() == HOST_PCAP_HEADER
        and (pre / "lab-namespace.pcap").read_bytes() == HOST_PCAP_HEADER
        and (post / "primary-syn.pcap").read_bytes() == HOST_PCAP_HEADER,
        "First-to-later guest continuity or primary silence differs",
    )


def initial_syns(packets: list, port: int) -> list:
    """Select the packets that open a connection to ``port``.

    Parameters
    ----------
    packets : list
        The packets of one capture.
    port : int
        The destination port of the connections.

    Returns
    -------
    list
        The SYN packets, which carry no ACK, sent to ``port``.
    """
    return [
        p
        for p in packets
        if p["dst_port"] == port and p["flags"] & 2 and not p["flags"] & 16
    ]


def idle_gate(
    first: Path, guest: list, namespace: list, tcp: types.ModuleType
) -> tuple[list, list]:
    """Check the SYNs of the unobserved idle gap and return the later ones.

    Parameters
    ----------
    first : Path
        The first-epoch corpus directory.
    guest : list
        The packets of the later guest capture.
    namespace : list
        The packets of the later namespace capture.
    tcp : types.ModuleType
        The module that reads packet captures.

    Returns
    -------
    tuple[list, list]
        The guest SYNs and the namespace SYNs of the later epoch.
    """
    first_guest = tcp.read_packets(first / "raw/lab-guest.pcap")
    first_syns = initial_syns(first_guest, GUEST_PORT)
    guest_syns = initial_syns(guest, GUEST_PORT)
    ns_syns = initial_syns(namespace, CONTROL_PORT)
    need(
        len(first_syns) == FIRST_CONNECTIONS
        and len(guest_syns) == GUEST_SYNS
        and len(ns_syns) == NAMESPACE_SYNS
        and [p["src_port"] for p in guest_syns[:FIRST_CONNECTIONS]]
        == [p["src_port"] for p in first_syns]
        and not any(
            p["src_port"] in {15500, 15501} or p["dst_port"] in {15500, 15501}
            for p in namespace
        ),
        "Unexpected SYN or primary bridge use during unobserved idle gap",
    )
    return guest_syns, ns_syns


def check_lanes(
    name: str, report: dict, captures: dict, tcp: types.ModuleType
) -> tuple[int, dict]:
    """Check the paired bytes of one case's connection on each lane.

    Parameters
    ----------
    name : str
        The case name, which prefixes the failure messages.
    report : dict
        The verified report of the case, with its connection event and streams.
    captures : dict
        The packets of each capture, keyed by lane label.
    tcp : types.ModuleType
        The module that reads the TCP lifetimes and streams.

    Returns
    -------
    tuple[int, dict]
        The client source port of the case's connection, and the packet counts
        and byte totals of its paired streams.
    """
    connects = [event for event in report["events"] if event["event"] == "connect"]
    need(len(connects) == 1, f"{name} connection count differs")
    event = connects[0]
    port = event["local_address"][1]
    now_us = (
        int(when(report["started_at_utc"]).timestamp() * 1_000_000)
        + event["elapsed_ns"] // 1000
    )
    values = []
    for label, client, server, target in LANES:
        flow = tcp.lifetime(captures[label], (client, port), (server, target), now_us)
        sent = tcp.stream(flow, (client, port), (server, target))
        received = tcp.stream(flow, (server, target), (client, port))
        expected = report["streams"][event["connection"]]
        need(
            len(flow) > 0
            and flow[0]["flags"] & 2
            and sent.hex() == expected["sent_hex"]
            and received.hex() == expected["received_hex"],
            f"{name}/{label} paired TCP bytes or tail differs",
        )
        values.append((len(flow), len(sent), len(received)))
    need(values[0][1:] == values[1][1:], f"{name} paired view differs")
    counts = {
        "namespace_packets": values[0][0],
        "guest_packets": values[1][0],
        "sent_bytes": values[0][1],
        "received_bytes": values[0][2],
    }
    return port, counts


def packet_gate(
    corpus: Path, first: Path, reports: dict, tcp: types.ModuleType
) -> dict:
    """Check the later captures against each case and the four later lifetimes.

    Parameters
    ----------
    corpus : Path
        The later corpus directory.
    first : Path
        The first-epoch corpus directory.
    reports : dict
        The verified report of each case, by name.
    tcp : types.ModuleType
        The module that reads packet captures and TCP streams.

    Returns
    -------
    dict
        The packet counts and byte totals of each case.
    """
    continuity_gate(corpus, first)
    guest = tcp.read_packets(corpus / "raw/post/lab-guest-final.pcap")
    namespace = tcp.read_packets(corpus / "raw/post/lab-namespace.pcap")
    guest_syns, ns_syns = idle_gate(first, guest, namespace, tcp)
    captures = {"namespace": namespace, "guest": guest}
    ports = []
    counts = {}
    for name, report in reports.items():
        port, counts[name] = check_lanes(name, report, captures, tcp)
        ports.append(port)
    need(
        len(set(ports)) == LATER_CONNECTIONS
        and [p["src_port"] for p in guest_syns[-LATER_CONNECTIONS:]] == ports
        and [p["src_port"] for p in ns_syns] == ports,
        "Four later lifetimes or ordering differ",
    )
    return counts
