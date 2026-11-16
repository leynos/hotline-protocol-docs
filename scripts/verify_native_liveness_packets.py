"""Check the captured packets, the connection identities and the paired-stream review.

The flow checks live in verify_native_liveness_flows. This module checks the SYN
lifetimes of both captures, the primary bridge, and the independent review.
"""

import typing as typ

from verify_native_liveness_checks import Report, need, read
from verify_native_liveness_flows import Captures, Packet, flow_summary, source_report
from verify_native_liveness_pins import PORTS

if typ.TYPE_CHECKING:
    from pathlib import Path

PRIMARY_PORTS = (15500, 15501)  # the primary bridge ports that the namespace must avoid
RETRANSMITTED_PORT = 45508  # the flow whose first SYN is retransmitted
TCP_SYN = 2  # the SYN flag bit of a TCP frame
TCP_ACK = 16  # the ACK flag bit of a TCP frame
NAMESPACE_SYN_COUNT = 9  # the SYN lifetimes in the namespace capture
GUEST_SYN_COUNT = 10  # the SYN lifetimes in the guest capture
RETRANSMITTED_SYNS = 2  # the SYN frames of the retransmitted flow
REVIEW_FLOWS = 9  # the flows in the independent paired-stream review


def _check_syn(namespace: list[Packet], guest: list[Packet]) -> None:
    """Check the SYN lifetimes of both captures and the retransmitted SYN.

    Parameters
    ----------
    namespace : list[dict[str, typing.Any]]
        The packets of the namespace capture.
    guest : list[dict[str, typing.Any]]
        The packets of the guest capture.
    """
    ns_syn = [p for p in namespace if p["flags"] & TCP_SYN and not p["flags"] & TCP_ACK]
    guest_syn = [p for p in guest if p["flags"] & TCP_SYN and not p["flags"] & TCP_ACK]
    expected = [port for _, _, port in PORTS]
    need(
        len(ns_syn) == NAMESPACE_SYN_COUNT
        and [p["src_port"] for p in ns_syn] == expected
        and len(guest_syn) == GUEST_SYN_COUNT
        and {p["src_port"] for p in guest_syn} == set(expected)
        and len([p for p in guest_syn if p["src_port"] == RETRANSMITTED_PORT])
        == RETRANSMITTED_SYNS
        and len({
            p["sequence"] for p in guest_syn if p["src_port"] == RETRANSMITTED_PORT
        })
        == 1,
        "Nine SYN lifetimes or S120 retransmission differs",
    )


def _review_matches(review: Report, summary: list[Report]) -> bool:
    """Return whether the independent review reproduces the flow summaries.

    Parameters
    ----------
    review : dict[str, typing.Any]
        The paired-stream review.
    summary : list[dict[str, typing.Any]]
        The flow summaries, in the order of ``PORTS``.

    Returns
    -------
    bool
        Whether the status, the flow count and every flow agree.
    """
    return (
        review["status"] == "PASS"
        and len(review["flows"]) == REVIEW_FLOWS
        and all(
            (
                item["report"],
                item["connection"],
                item["port"],
                item["sent"],
                item["received"],
            )
            == (
                other["folder"],
                other["connection"],
                other["port"],
                other["sent"],
                other["received"],
            )
            for item, other in zip(review["flows"], summary, strict=True)
        )
    )


def packet_gate(
    corpus: Path,
    modules: tuple[typ.Any, ...],
    report: Report,
) -> list[Report]:
    """Check the captures, the connection identities and the review.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    modules : tuple[typing.Any, ...]
        The frozen modules, as yielded by ``frozen``.
    report : dict[str, typing.Any]
        The coordinator report.

    Returns
    -------
    list[dict[str, typing.Any]]
        The flow summaries, in the order of ``PORTS``.
    """
    raw = corpus / "raw"
    tcp = modules[4]
    host = tcp.read_packets(raw / "primary-syn.pcap")
    namespace = tcp.read_packets(raw / "lab-namespace.pcap")
    guest = tcp.read_packets(raw / "lab-guest.pcap")
    need(not host, "Primary-port SYN capture is not empty")
    need(
        all(
            p["src_port"] not in PRIMARY_PORTS and p["dst_port"] not in PRIMARY_PORTS
            for p in namespace
        ),
        "Namespace capture contacted primary bridge",
    )
    _check_syn(namespace, guest)
    captures = Captures(tcp, namespace, guest)
    summary = [
        flow_summary((folder, name, port), source_report(raw, report, folder), captures)
        for folder, name, port in PORTS
    ]
    review = read(raw / "parent-paired-stream-review.json")
    need(
        _review_matches(review, summary),
        "Independent paired-stream review differs",
    )
    return summary
