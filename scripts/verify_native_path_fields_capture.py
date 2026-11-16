"""Gates that pair the retained captures with the report and the derived flows."""

import dataclasses as dc
import hashlib
import typing as typ

from verify_native_path_fields_constants import (
    ACK_FLAG,
    CASE_PORT,
    CONNECTIONS,
    GUEST_PORT,
    PCAP_HEADER,
    PORTS,
    READINESS_ACTIONS,
    SYN_FLAG,
    TERMINAL_FLAGS,
)
from verify_native_path_fields_core import need, read

if typ.TYPE_CHECKING:
    import types
    from pathlib import Path


@dc.dataclass(frozen=True, slots=True)
class _Flow:
    """One TCP connection of one view, named by its view and its report label."""

    view: str
    label: str
    client: tuple[str, int]
    server: tuple[str, int]


@dc.dataclass(frozen=True, slots=True)
class _Evidence:
    """The corpus facts and the TCP reader that the flow checks share."""

    corpus: Path
    epoch: Path
    derived: dict
    reports: dict
    tcp: types.ModuleType


def _pre_checks(epoch: Path, modules: tuple[types.ModuleType, ...]) -> dict:
    """Check the readiness capture and the primary SYN capture.

    Returns
    -------
    dict
        The verified readiness report.
    """
    _, _, readiness, capture, tcp = modules
    pre = capture.verify_capture(epoch / "readiness")
    readiness.readiness(pre)
    need(
        pre["status"] == "completed" and pre["completed_actions"] == READINESS_ACTIONS,
        "Readiness differs",
    )
    host = tcp.read_packets(epoch / "primary-syn.pcap")
    need(
        host == [] and (epoch / "primary-syn.pcap").stat().st_size == PCAP_HEADER,
        "Primary SYN capture differs",
    )
    return pre


def _check_view(view: str, packets: list[dict], endpoint: tuple[str, str, int]) -> None:
    """Check the two SYNs of a view and the TCP lifetime of its packets."""
    client_ip, server_ip, server_port = endpoint
    syns = [p for p in packets if p["flags"] & SYN_FLAG and not p["flags"] & ACK_FLAG]
    need(
        len(syns) == CONNECTIONS
        and {p["src_port"] for p in syns} == set(PORTS.values())
        and all(
            (p["src_ip"], p["dst_ip"], p["dst_port"])
            == (client_ip, server_ip, server_port)
            for p in syns
        ),
        f"{view} SYN/endpoint differs",
    )
    need(
        all(
            (p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"])
            in {(client_ip, port, server_ip, server_port) for port in PORTS.values()}
            | {(server_ip, server_port, client_ip, port) for port in PORTS.values()}
            for p in packets
        ),
        f"{view} unexpected TCP lifetime",
    )


def _streams(
    evidence: _Evidence, packets: list[dict], flow: _Flow
) -> tuple[bytes, bytes]:
    """Reassemble the bytes sent by the client and received from the server.

    Returns
    -------
    tuple[bytes, bytes]
        The sent and the received streams of the connection.
    """
    sent = evidence.tcp.stream(packets, flow.client, flow.server)
    received = evidence.tcp.stream(packets, flow.server, flow.client)
    return sent, received


def _check_report(
    evidence: _Evidence, flow: _Flow, streams: tuple[bytes, bytes]
) -> None:
    """Check the reassembled streams against the report's recorded bytes."""
    sent, received = streams
    expected = evidence.reports[flow.label]["streams"]["main"]
    need(
        sent.hex() == expected["sent_hex"]
        and received.hex() == expected["received_hex"],
        f"{flow.view}/{flow.label} PCAP/report byte mismatch",
    )


def _check_derived(
    evidence: _Evidence, flow: _Flow, streams: tuple[bytes, bytes]
) -> dict:
    """Check the derived flow record and the stream files it names.

    Returns
    -------
    dict
        The derived record of the view.
    """
    sent, received = streams
    item = next(f for f in evidence.derived["flows"] if f["label"] == flow.label)
    details = item["views"][flow.view]
    need(
        details["client"] == [*flow.client]
        and details["server"] == [*flow.server]
        and details["sent"]["bytes"] == len(sent)
        and details["received"]["bytes"] == len(received)
        and details["sent"]["sha256"] == hashlib.sha256(sent).hexdigest()
        and details["received"]["sha256"] == hashlib.sha256(received).hexdigest()
        and (evidence.corpus / details["sent"]["file"]).read_bytes() == sent
        and (evidence.corpus / details["received"]["file"]).read_bytes() == received,
        f"{flow.view}/{flow.label} derived stream differs",
    )
    return details


def _check_lifetime(packets: list[dict], flow: _Flow, details: dict) -> None:
    """Check that the connection's packets and terminal flags match the record."""
    ports = {flow.client[1], flow.server[1]}
    selected = [p for p in packets if p["src_port"] in ports and p["dst_port"] in ports]
    terminals = [
        {
            "index": p["index"],
            "flags": p["flags"],
            "timestamp_us": p["timestamp_us"],
            "payload_hex": p["payload_hex"],
        }
        for p in selected
        if p["flags"] & TERMINAL_FLAGS
    ]
    need(
        details["terminal_flags"] == terminals
        and details["packet_count"] == len(selected),
        f"{flow.view}/{flow.label} complete TCP lifetime differs",
    )


def _check_flow(
    evidence: _Evidence, packets: list[dict], flow: _Flow
) -> tuple[int, int]:
    """Check one connection against the report and the derived record.

    Returns
    -------
    tuple[int, int]
        The lengths of the sent and the received streams.
    """
    streams = _streams(evidence, packets, flow)
    _check_report(evidence, flow, streams)
    details = _check_derived(evidence, flow, streams)
    _check_lifetime(packets, flow, details)
    return len(streams[0]), len(streams[1])


def _check_views(evidence: _Evidence) -> dict:
    """Check every view's connections, in the order the corpus names them.

    Returns
    -------
    dict
        The stream lengths of each view and label.
    """
    measured: dict[str, tuple[int, int]] = {}
    for view, client_ip, server_ip, server_port in (
        ("namespace", "127.0.0.1", "127.0.0.1", CASE_PORT),
        ("guest", "10.0.2.2", "10.0.2.15", GUEST_PORT),
    ):
        packets = evidence.tcp.read_packets(evidence.epoch / f"lab-{view}.pcap")
        _check_view(view, packets, (client_ip, server_ip, server_port))
        for label, port in PORTS.items():
            flow = _Flow(view, label, (client_ip, port), (server_ip, server_port))
            measured[f"{view}/{label}"] = _check_flow(evidence, packets, flow)
    return measured


def paired(corpus: Path, report: dict, modules: tuple[types.ModuleType, ...]) -> dict:
    """Gate the captures of both views against the report and the derived flows.

    Returns
    -------
    dict
        The stream lengths of each view and label.
    """
    epoch = corpus / "raw/epoch"
    pre = _pre_checks(epoch, modules)
    derived = read(corpus / "derived/flows.json")
    need(len(derived["flows"]) == CONNECTIONS, "Derived flow count differs")
    evidence = _Evidence(
        corpus, epoch, derived, {"readiness": pre, "case": report}, modules[4]
    )
    measured = _check_views(evidence)
    need(
        set(measured.values()) == {(231, 2759), (11529, 8295)},
        "Readiness/case stream lengths differ",
    )
    return measured
