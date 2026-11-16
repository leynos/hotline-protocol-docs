"""Check the C56 phases against the lab's host, namespace and guest packet captures."""

import dataclasses as dc
import datetime as dt
import hashlib
import typing as typ

from pcap_tcp import lifetime, read_packets, stream
from verify_native_ban_control_core import (
    CONTROL_PORT,
    GUEST_PORT,
    PHASES,
    Json,
    loaded,
    need,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

type Packets = list[dict[str, typ.Any]]

PRIMARY_PORTS = {15500, 15501}  # the bridge ports of the primary lab
MICROSECONDS = 1_000_000
CONNECTIONS = 6  # one for each of the two logins, the target and the three controls
SYN_ONLY = 2  # the TCP flags of a connection's first packet
FIN_FLAG = 1
RST_FLAG = 4
TAIL_BYTES = 96  # the saved tail of a received stream
NO_DROPS = "0 packets dropped by kernel"
NO_PACKETS = "0 packets captured"


@dc.dataclass(frozen=True, slots=True)
class Witness:
    """The packet captures and the saved views of the lab.

    Attributes
    ----------
    namespace : list[dict[str, typing.Any]]
        The packets seen in the lab's network namespace.
    guest : list[dict[str, typing.Any]]
        The packets seen by the guest.
    views : dict[str, typing.Any]
        The saved view of each phase's connections.
    """

    namespace: Packets
    guest: Packets
    views: Json

    def vantages(self) -> list[tuple[str, Packets, str, str, int]]:
        """List where a connection is seen.

        Returns
        -------
        list[tuple[str, list[dict[str, typing.Any]], str, str, int]]
            The label, the packets, the client and server addresses and the
            server port of each.
        """
        return [
            ("namespace", self.namespace, "127.0.0.1", "127.0.0.1", CONTROL_PORT),
            ("guest", self.guest, "10.0.2.2", "10.0.2.15", GUEST_PORT),
        ]


@dc.dataclass(frozen=True, slots=True)
class Flow:
    """One recorded connection of a phase.

    Attributes
    ----------
    phase : str
        The phase's name.
    name : str
        The connection's name.
    port : int
        The client's TCP source port.
    start : int
        The connect time in microseconds since the epoch.
    report : dict[str, typing.Any]
        The phase's capture report.
    """

    phase: str
    name: str
    port: int
    start: int
    report: Json


def boot_captures(boot: Path) -> tuple[Packets, Packets]:
    """Check the lab's isolation in its captures and read the packets.

    Parameters
    ----------
    boot : pathlib.Path
        The ``boot-c55`` directory.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], list[dict[str, typing.Any]]]
        The namespace and guest packets.
    """
    need(not read_packets(boot / "primary-syn.pcap"), "Primary SYN capture is nonempty")
    namespace = read_packets(boot / "lab-namespace.pcap")
    guest = read_packets(boot / "lab-guest.pcap")
    need(
        not [
            packet
            for packet in namespace
            if packet["src_port"] in PRIMARY_PORTS
            or packet["dst_port"] in PRIMARY_PORTS
        ],
        "Lab touched fixed primary bridge",
    )
    for label in ("host", "namespace"):
        log = (boot / f"{label}-recorder.log").read_text()
        need(NO_DROPS in log, f"{label} packet drops differ")
    need(
        NO_PACKETS in (boot / "host-recorder.log").read_text(),
        "Primary SYN count differs",
    )
    return namespace, guest


def view_matches(
    saved: Json, observed: tuple[Packets, bytes, bytes], flow: Flow
) -> bool:
    """Compare a saved view with the packets and streams that were observed.

    Parameters
    ----------
    saved : dict[str, typing.Any]
        The saved view of one connection from one vantage.
    observed : tuple[list[dict[str, typing.Any]], bytes, bytes]
        The connection's packets, and the bytes sent and received.
    flow : Flow
        The connection, whose report holds the recorder's own streams.

    Returns
    -------
    bool
        Whether the view agrees with every observation.
    """
    selected, sent, received = observed
    return bool(
        saved["packet_indices"] == [p["index"] for p in selected]
        and saved["packet_count"] == len(selected)
        and saved["first_us"] == selected[0]["timestamp_us"]
        and saved["last_us"] == selected[-1]["timestamp_us"]
        and saved["fin_packets"]
        == [p["index"] for p in selected if p["flags"] & FIN_FLAG]
        and saved["rst_packets"]
        == [p["index"] for p in selected if p["flags"] & RST_FLAG]
        and saved["sent_len"] == len(sent)
        and saved["received_len"] == len(received)
        and saved["sent_sha256"] == hashlib.sha256(sent).hexdigest()
        and saved["received_sha256"] == hashlib.sha256(received).hexdigest()
        and saved["sent_hex"] == sent.hex()
        and saved["received_hex"] == received.hex()
        and saved["received_tail_hex"] == received[-TAIL_BYTES:].hex()
        and sent.hex() == flow.report["streams"][flow.name]["sent_hex"]
        and received.hex() == flow.report["streams"][flow.name]["received_hex"]
    )


def is_target_namespace(flow: Flow, label: str) -> bool:
    """Say whether a view is the target's, as the namespace saw it.

    Returns
    -------
    bool
        Whether the target's server FIN is expected in this view.
    """
    return (flow.phase, flow.name, label) == ("ban", "target", "namespace")


def check_flow(witness: Witness, flow: Flow) -> None:
    """Check one connection's saved views against both packet captures.

    Parameters
    ----------
    witness : Witness
        The captures and the saved views.
    flow : Flow
        The connection.
    """
    for label, source, client, server, target in witness.vantages():
        where = f"{flow.phase}/{flow.name}/{label}"
        selected = lifetime(source, (client, flow.port), (server, target), flow.start)
        need(bool(selected), f"{where} TCP lifetime missing")
        sent = stream(selected, (client, flow.port), (server, target))
        received = stream(selected, (server, target), (client, flow.port))
        saved = witness.views[flow.phase][flow.name][label]
        need(
            view_matches(saved, (selected, sent, received), flow),
            f"{where} scoped stream differs",
        )
        if is_target_namespace(flow, label):
            need(
                any(
                    p["src_port"] == target and p["flags"] & FIN_FLAG for p in selected
                ),
                "Target server FIN missing",
            )


def check_phase(witness: Witness, phase: str, report: Json, observed: set[int]) -> None:
    """Check every connection of one phase.

    Parameters
    ----------
    witness : Witness
        The captures and the saved views.
    phase : str
        The phase's name.
    report : dict[str, typing.Any]
        The phase's capture report.
    observed : set[int]
        The client ports seen so far; each connection adds its own.
    """
    started = int(
        dt.datetime.fromisoformat(report["started_at_utc"]).timestamp() * MICROSECONDS
    )
    connections = [event for event in report["events"] if event["event"] == "connect"]
    need(
        set(witness.views[phase]) == {e["connection"] for e in connections},
        "Packet socket inventory differs",
    )
    for event in connections:
        name = event["connection"]
        port = event["local_address"][1]
        need(port not in observed, "Repeated client TCP source port")
        observed.add(port)
        start = started + event["elapsed_ns"] // 1000
        check_flow(witness, Flow(phase, name, port, start, report))


def packets(corpus: Path, reports: dict[str, Json]) -> Json:
    """Check every phase's connections against the lab's captures.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    reports : dict[str, dict[str, typing.Any]]
        Each phase's replayed report.

    Returns
    -------
    dict[str, typing.Any]
        The connection and packet counts.
    """
    namespace, guest = boot_captures(corpus / "boot-c55")
    views = loaded(corpus / "packet-views.json")
    need(set(views) == set(PHASES), "Packet phase inventory differs")
    witness = Witness(namespace, guest, views)
    observed: set[int] = set()
    for phase, report in reports.items():
        check_phase(witness, phase, report, observed)
    need(
        len(observed) == CONNECTIONS
        and sum(
            p["dst_port"] == CONTROL_PORT and p["flags"] == SYN_ONLY for p in namespace
        )
        == CONNECTIONS,
        "Unexpected namespace TCP connection count",
    )
    return {
        "connections": len(observed),
        "namespace_packets": len(namespace),
        "guest_packets": len(guest),
    }
