"""Check the packets, paired TCP streams and visible clock of the first epoch."""

import dataclasses as dc
import typing as typ

from verify_native_ban_expiry_first_common import need, read, sha, when
from verify_native_ban_expiry_first_wire import (
    CONTROL_PORT,
    FIRST_CONNECTIONS,
    GUEST_PORT,
    MAX_BRACKET_SECONDS,
    PROTECTED_UNREAD,
    SYN,
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


@dc.dataclass(frozen=True, slots=True)
class Probe:
    """One recorded control connection, located on the packet timeline."""

    name: str
    event: dict
    report: dict
    port: int
    when_us: int


def settle_gate(raw: Path, namespace: list) -> None:
    """Check that no namespace traffic was captured during the settle interval.

    Parameters
    ----------
    raw : Path
        The raw receipts directory.
    namespace : list
        The packets of the namespace capture.
    """
    settle = read(raw / "results-first-c77/summary.json")["post_readiness_settle"]
    start, end = (
        int(when(settle[k]).timestamp() * 1_000_000)
        for k in ("started_utc", "completed_utc")
    )
    need(
        not [p for p in namespace if start <= p["timestamp_us"] <= end],
        "Namespace traffic occurred during 35s settle",
    )


def check_event(probe: Probe, captures: dict, tcp: types.ModuleType) -> None:
    """Check the paired TCP bytes of one control connection on each lane.

    Parameters
    ----------
    probe : Probe
        The connection to check, with its place on the timeline.
    captures : dict
        The packets of each capture, keyed by lane label.
    tcp : types.ModuleType
        The module that reads the TCP lifetimes and streams.
    """
    for label, client, server, target in LANES:
        flow = tcp.lifetime(
            captures[label], (client, probe.port), (server, target), probe.when_us
        )
        sent = tcp.stream(flow, (client, probe.port), (server, target))
        received = tcp.stream(flow, (server, target), (client, probe.port))
        expected_received = bytes.fromhex(
            probe.report["streams"][probe.event["connection"]]["received_hex"]
        )
        if probe.name == "protected" and probe.event["connection"] == "main":
            expected_received += PROTECTED_UNREAD
        need(
            bool(flow)
            and sent.hex()
            == probe.report["streams"][probe.event["connection"]]["sent_hex"]
            and received == expected_received
            and flow[0]["flags"] & 2
            and flow[-1]["timestamp_us"] >= flow[0]["timestamp_us"],
            f"{probe.name}/{probe.event['connection']}/{label} paired TCP bytes differ",
        )


def connection_gate(
    reports: dict, namespace: list, guest: list, tcp: types.ModuleType
) -> set:
    """Check every recorded control connection of every case, once each.

    Parameters
    ----------
    reports : dict
        The verified report of each case, by name.
    namespace : list
        The packets of the namespace capture.
    guest : list
        The packets of the guest capture.
    tcp : types.ModuleType
        The module that reads the TCP lifetimes and streams.

    Returns
    -------
    set
        The client source port of each connection.
    """
    captures = {"namespace": namespace, "guest": guest}
    ports = set()
    for name, report in reports.items():
        origin = when(report["started_at_utc"])
        for event in (e for e in report["events"] if e["event"] == "connect"):
            port = event["local_address"][1]
            need(port not in ports, "Repeated client TCP source port")
            ports.add(port)
            when_us = int(origin.timestamp() * 1_000_000) + event["elapsed_ns"] // 1000
            check_event(Probe(name, event, report, port, when_us), captures, tcp)
    return ports


def packet_gate(corpus: Path, raw: Path, reports: dict, tcp: types.ModuleType) -> dict:
    """Check the captured packets of the first epoch against its control streams.

    Parameters
    ----------
    corpus : Path
        The corpus directory, which the checks do not read.
    raw : Path
        The raw receipts directory.
    reports : dict
        The verified report of each case, by name.
    tcp : types.ModuleType
        The module that reads the packet captures and TCP streams.

    Returns
    -------
    dict
        The number of connections and of packets in each capture.
    """
    namespace = tcp.read_packets(raw / "lab-namespace.pcap")
    guest = tcp.read_packets(raw / "lab-guest.pcap")
    need(not tcp.read_packets(raw / "primary-syn.pcap"), "Primary-port SYN observed")
    need(
        not any(
            p["src_port"] in {15500, 15501} or p["dst_port"] in {15500, 15501}
            for p in namespace
        ),
        "Fixed primary bridge was used",
    )
    settle_gate(raw, namespace)
    ports = connection_gate(reports, namespace, guest, tcp)
    need(
        len(ports) == FIRST_CONNECTIONS
        and sum(p["dst_port"] == CONTROL_PORT and p["flags"] == SYN for p in namespace)
        == FIRST_CONNECTIONS
        and sum(p["dst_port"] == GUEST_PORT and p["flags"] == SYN for p in guest)
        == FIRST_CONNECTIONS,
        "Thirteen SYN-scoped control lifetimes differ",
    )
    return {
        "connections": len(ports),
        "namespace_packets": len(namespace),
        "guest_packets": len(guest),
    }


def clock_gate(corpus: Path, raw: Path) -> None:
    """Check the visible guest clock transcriptions against their host brackets.

    Parameters
    ----------
    corpus : Path
        The corpus directory, which holds the clock observations.
    raw : Path
        The raw receipts directory, which holds the screenshots and brackets.
    """
    value = read(corpus / "clock-observations.json")
    need(
        value["method"].startswith("manual transcription")
        and [v["visible_menubar_clock_transcription"] for v in value["observations"]]
        == ["Sat 5:49:09 AM", "Sat 5:51:09 AM", "Sat 5:55:26 AM"],
        "Visual guest clock transcription differs",
    )
    previous = None
    for row in value["observations"]:
        path = raw / row["screenshot"]
        need(
            sha(path) == row["screenshot_sha256"]
            and (raw / row["screenshot"].replace(".png", "-before.utc"))
            .read_text()
            .strip()
            == row["before_utc"]
            and (raw / row["screenshot"].replace(".png", "-after.utc"))
            .read_text()
            .strip()
            == row["after_utc"],
            "Clock screenshot or host brackets differ",
        )
        before, after = when(row["before_utc"]), when(row["after_utc"])
        need(
            before <= after and (after - before).total_seconds() < MAX_BRACKET_SECONDS,
            "Clock host bracket differs",
        )
        if previous:
            need(previous < before, "Clock observation order differs")
        previous = after
