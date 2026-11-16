"""Compare the recorded persistence streams with the paired packet captures."""

import dataclasses as dc
import typing as typ

from pcap_tcp import read_packets, stream
from protocol_capture import digest
from verify_native_settings_persistence_core import (
    ACK_FLAG,
    GUEST_PORT,
    LAB_PORT,
    PCAP_HEADER_BYTES,
    SYN_FLAG,
    Json,
    read_json,
    require,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

type Packets = list[dict[str, typ.Any]]
type Address = tuple[str, int]

LIFETIMES = 3  # the readiness capture and the two sockets of the phase
FLOW_CASES = ("readiness", "main", "subject")
PCAP_NAMES = ("primary-syn.pcap", "namespace.pcap", "guest.pcap")
HOST = "127.0.0.1"
GUEST_CLIENT = "10.0.2.2"
GUEST_SERVER = "10.0.2.15"


@dc.dataclass(frozen=True, slots=True)
class Captures:
    """The host and guest packets of a phase.

    Attributes
    ----------
    host : list[dict[str, typing.Any]]
        The packets seen in the lab's network namespace.
    guest : list[dict[str, typing.Any]]
        The packets seen by the guest.
    """

    host: Packets
    guest: Packets

    def vantages(self, port: int) -> list[tuple[str, Packets, Address, Address]]:
        """List where a connection from a client port is seen.

        Returns
        -------
        list[tuple[str, list[dict[str, typing.Any]], tuple[str, int], tuple[str, int]]]
            The label, the packets, the server address and the client address.
        """
        return [
            ("namespace", self.host, (HOST, LAB_PORT), (HOST, port)),
            ("guest", self.guest, (GUEST_SERVER, GUEST_PORT), (GUEST_CLIENT, port)),
        ]


@dc.dataclass(frozen=True, slots=True)
class Flow:
    """One recorded connection of a phase.

    Attributes
    ----------
    port : int
        The client's TCP source port.
    case : str
        ``readiness``, ``main`` or ``subject``.
    report : dict[str, typing.Any]
        The capture report that recorded the connection.
    row : dict[str, typing.Any]
        The corpus's recorded row for the connection.
    """

    port: int
    case: str
    report: Json
    row: Json


def syn_ports(packets: Packets) -> list[int]:
    """List the source ports of the connections that a capture shows opening.

    Returns
    -------
    list[int]
        The ports of the packets with SYN set and ACK clear, in order.
    """
    return [
        p["src_port"]
        for p in packets
        if p["flags"] & SYN_FLAG and not p["flags"] & ACK_FLAG
    ]


def read_captures(directory: Path, recorded: Json) -> tuple[Captures, list[int]]:
    """Check the claim, the empty primary capture and the SYN lifetimes.

    Parameters
    ----------
    directory : pathlib.Path
        The phase directory.
    recorded : dict[str, typing.Any]
        The corpus's recorded paired streams.

    Returns
    -------
    tuple[Captures, list[int]]
        The packets, and the client ports of the three connections.
    """
    require(
        recorded["paired_complete"] and recorded["lifetime_count"] == LIFETIMES,
        "Paired packet claim differs",
    )
    primary = directory / "primary-syn.pcap"
    require(
        primary.stat().st_size == PCAP_HEADER_BYTES and not read_packets(primary),
        "Primary SYN capture is nonempty",
    )
    host = read_packets(directory / "namespace.pcap")
    guest = read_packets(directory / "guest.pcap")
    host_ports = syn_ports(host)
    guest_ports = syn_ports(guest)
    require(
        len(host_ports) == LIFETIMES
        and len(set(host_ports)) == LIFETIMES
        and host_ports == guest_ports,
        "SYN lifetimes differ",
    )
    return Captures(host, guest), host_ports


def check_stream(flow: Flow, label: str, direction: str, data: bytes) -> None:
    """Check one direction of one connection against the corpus's record.

    Parameters
    ----------
    flow : Flow
        The connection.
    label : str
        The vantage, ``namespace`` or ``guest``.
    direction : str
        ``sent`` or ``received``.
    data : bytes
        The application bytes that the capture shows.
    """
    row = flow.row
    require(
        len(data) == row[f"{label}_{direction}_bytes"]
        and digest(data) == row[f"{label}_{direction}_sha256"],
        "Paired packet stream differs",
    )
    recorder = bytes.fromhex(
        flow.report["streams"]["main" if flow.case == "readiness" else flow.case][
            direction + "_hex"
        ]
    )
    require(data == recorder, "Recorder/packet application bytes differ")


def check_flow(captures: Captures, flow: Flow) -> None:
    """Check both directions of one connection from both vantages.

    Parameters
    ----------
    captures : Captures
        The host and guest packets.
    flow : Flow
        The connection.
    """
    require(
        flow.row["port"] == flow.port and flow.row["case"] == flow.case,
        "Paired flow identity differs",
    )
    for label, packets, server, client in captures.vantages(flow.port):
        for direction, src, dst in (
            ("sent", client, server),
            ("received", server, client),
        ):
            check_stream(flow, label, direction, stream(packets, src, dst))


def check_provenance(directory: Path, recorded: Json) -> None:
    """Check the size and digest of each capture file against the record.

    Parameters
    ----------
    directory : pathlib.Path
        The phase directory.
    recorded : dict[str, typing.Any]
        The corpus's recorded paired streams.
    """
    for name in PCAP_NAMES:
        path = directory / name
        require(
            recorded["pcaps"][name]
            == {"bytes": path.stat().st_size, "sha256": digest(path.read_bytes())},
            "PCAP provenance differs",
        )


def paired_packets(corpus: Path, phase: int) -> list[Json]:
    """Pair every recorded connection of a phase with both packet captures.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    phase : int
        The phase number, 1 or 2.

    Returns
    -------
    list[dict[str, typing.Any]]
        The corpus's recorded rows, one for each connection.
    """
    directory = corpus / f"phase{phase}"
    recorded = read_json(directory / "paired-streams.json")
    captures, host_ports = read_captures(directory, recorded)
    ready = read_json(directory / "readiness/report.json")
    observed = read_json(
        directory / ("phase1" if phase == 1 else "phase2") / "report.json"
    )
    for port, case, report, row in zip(
        host_ports,
        FLOW_CASES,
        (ready, observed, observed),
        recorded["flows"],
        strict=True,
    ):
        check_flow(captures, Flow(port, case, report, row))
    check_provenance(directory, recorded)
    return recorded["flows"]
