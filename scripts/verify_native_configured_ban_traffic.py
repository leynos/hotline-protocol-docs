"""Check the paired TCP bytes of the five client connections in both captures."""

import dataclasses as dc
import datetime as dt
import hashlib
import typing as typ

from pcap_tcp import lifetime, read_packets, stream
from verify_native_configured_ban_constants import (
    CONTROL_PORT,
    GUEST_PORT,
    PHASES,
    PRIMARY_PORTS,
    SCOPED_CONNECTIONS,
    TCP_FIN,
    TCP_RST,
    TCP_SYN,
)
from verify_native_configured_ban_support import Path, need, read

# The captures that each connection is checked in: the label, the client address,
# the server address and the server port of that capture.
SIDES = (
    ("namespace", "127.0.0.1", "127.0.0.1", CONTROL_PORT),
    ("guest", "10.0.2.2", "10.0.2.15", GUEST_PORT),
)


@dc.dataclass(frozen=True, slots=True)
class _Phase:
    """One source-plan phase, with the saved views and captures its connections use."""

    name: str
    report: dict[str, typ.Any]
    started: int
    views: dict[str, typ.Any]
    sources: dict[str, list[dict[str, typ.Any]]]


@dc.dataclass(frozen=True, slots=True)
class _Link:
    """One client connection of one phase, with its local port and its start."""

    phase: _Phase
    name: str
    port: int
    when: int


def packets(corpus: Path, reports: dict[str, dict]) -> dict:
    """Check the packet views, the paired bytes and the five SYN lifetimes.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    reports : dict[str, dict[str, typing.Any]]
        The verified report of each source-plan phase.

    Returns
    -------
    dict[str, int]
        The number of connections and the packet count of each capture.
    """
    sources = _read_captures(corpus)
    views = read(corpus / "packet-views.json")
    need(set(views) == set(PHASES), "Packet phase inventory differs")
    observed: set[int] = set()
    for name, report in reports.items():
        _check_phase(_phase(name, report, views, sources), observed)
    need(
        len(observed) == SCOPED_CONNECTIONS
        and sum(
            p["dst_port"] == CONTROL_PORT and p["flags"] == TCP_SYN
            for p in sources["namespace"]
        )
        == SCOPED_CONNECTIONS,
        "Five complete SYN lifetimes differ",
    )
    return {
        "connections": len(observed),
        "namespace_packets": len(sources["namespace"]),
        "guest_packets": len(sources["guest"]),
    }


def _read_captures(corpus: Path) -> dict[str, list[dict[str, typ.Any]]]:
    """Read the two captures, and check that the primary server saw no contact.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, list[dict[str, typing.Any]]]
        The packets of the namespace and the guest captures.
    """
    first = corpus / "native-configured-apply-c65"
    root = corpus / "native-configured-apply-c66"
    need(not read_packets(first / "primary-syn.pcap"), "C65 primary SYN exists")
    need(not read_packets(root / "primary-syn.pcap"), "Primary SYN capture is nonempty")
    namespace = read_packets(root / "lab-namespace.pcap")
    guest = read_packets(root / "lab-guest.pcap")
    need(
        not any(
            p["src_port"] in PRIMARY_PORTS or p["dst_port"] in PRIMARY_PORTS
            for p in namespace
        )
        and {p["src_port"] for p in namespace if p["dst_port"] == CONTROL_PORT}
        == {53240, 53250, 53262, 44898, 44902},
        "Primary bridge contact or five-client scope differs",
    )
    for label in ("host", "namespace"):
        log = (root / f"{label}-recorder.log").read_text()
        need("0 packets dropped by kernel" in log, f"{label} capture drops differ")
    need(
        "0 packets captured" in (root / "host-recorder.log").read_text(),
        "Primary SYN counter differs",
    )
    return {"namespace": namespace, "guest": guest}


def _phase(
    name: str,
    report: dict[str, typ.Any],
    views: dict[str, typ.Any],
    sources: dict[str, list[dict[str, typ.Any]]],
) -> _Phase:
    """Return the phase record, with the start of its capture in microseconds.

    Parameters
    ----------
    name : str
        The source-plan phase.
    report : dict[str, typing.Any]
        The verified report of the phase.
    views : dict[str, typing.Any]
        The saved packet views of every phase.
    sources : dict[str, list[dict[str, typing.Any]]]
        The packets of each capture.

    Returns
    -------
    _Phase
        The phase record.
    """
    started = int(
        dt.datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1_000_000
    )
    return _Phase(name, report, started, views, sources)


def _check_phase(phase: _Phase, observed: set[int]) -> None:
    """Check the socket inventory of one phase and each of its connections.

    Parameters
    ----------
    phase : _Phase
        The phase to check.
    observed : set[int]
        The client source ports already seen in the packet views.
    """
    connects = [e for e in phase.report["events"] if e["event"] == "connect"]
    need(
        set(phase.views[phase.name]) == {e["connection"] for e in connects},
        "Packet socket inventory differs",
    )
    for event in connects:
        name, port = event["connection"], event["local_address"][1]
        need(port not in observed, "Repeated client TCP source port")
        observed.add(port)
        when = phase.started + event["elapsed_ns"] // 1000
        _check_link(_Link(phase, name, port, when))


def _check_link(link: _Link) -> None:
    """Check one connection in each capture.

    Parameters
    ----------
    link : _Link
        The connection to check.
    """
    for label, client_ip, server_ip, server_port in SIDES:
        _check_side(link, label, ((client_ip, link.port), (server_ip, server_port)))


def _check_side(
    link: _Link, label: str, ends: tuple[tuple[str, int], tuple[str, int]]
) -> None:
    """Check the paired bytes of one connection in one capture.

    Parameters
    ----------
    link : _Link
        The connection to check.
    label : str
        The capture: ``namespace`` or ``guest``.
    ends : tuple[tuple[str, int], tuple[str, int]]
        The client and the server endpoint, each an address and a port.
    """
    client_end, server_end = ends
    scoped = lifetime(link.phase.sources[label], client_end, server_end, link.when)
    sent = stream(scoped, client_end, server_end)
    received = stream(scoped, server_end, client_end)
    saved = link.phase.views[link.phase.name][link.name][label]
    need(
        bool(scoped)
        and saved["client_port"] == link.port
        and saved["packet_indices"] == [p["index"] for p in scoped]
        and saved["packet_count"] == len(scoped)
        and saved["first_us"] == scoped[0]["timestamp_us"]
        and saved["last_us"] == scoped[-1]["timestamp_us"]
        and saved["fin_packets"] == [p["index"] for p in scoped if p["flags"] & TCP_FIN]
        and saved["rst_packets"] == [p["index"] for p in scoped if p["flags"] & TCP_RST]
        and saved["sent_len"] == len(sent)
        and saved["received_len"] == len(received)
        and saved["sent_sha256"] == hashlib.sha256(sent).hexdigest()
        and saved["received_sha256"] == hashlib.sha256(received).hexdigest()
        and saved["sent_hex"]
        == sent.hex()
        == link.phase.report["streams"][link.name]["sent_hex"]
        and saved["received_hex"]
        == received.hex()
        == link.phase.report["streams"][link.name]["received_hex"]
        and saved["received_tail_hex"] == received[-96:].hex(),
        f"{link.phase.name}/{link.name}/{label} paired TCP bytes differ",
    )
    if link.phase.name == "held-apply":
        need(
            any(
                p["src_port"] == server_end[1] and p["flags"] & TCP_FIN for p in scoped
            ),
            f"{link.name}/{label} server FIN missing",
        )
