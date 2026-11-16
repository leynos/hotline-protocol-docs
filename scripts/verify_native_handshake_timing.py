"""Check the two bounded close observations of the handshake corpus.

The 65-second guest silence of the old recorder and the 35-second isolated
quiet are bounded observations; neither is a claim about a hard deadline.
"""

import datetime as dt
import typing as typ

from native_packet_evidence import (
    GUEST_CLIENT_HOST,
    GUEST_SERVER_BASE,
    GUEST_SERVER_HOST,
    MICROSECONDS_PER_SECOND,
    TCP_CLOSE_FLAGS,
    TCP_RST,
)
from pcap_tcp import direction, read_packets, stream
from protocol_capture import verify_capture
from verify_native_core import require

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]
type Packets = list[dict[str, typ.Any]]

TCP_SYN = 2
BASELINE_SILENCE_SECONDS = 65
ISOLATED_QUIET_NS = 35 * 1e9
PORT_TOLERANCE_SECONDS = 0.25  # how far a SYN may be from the recorder's own start
NANOSECONDS_PER_SECOND = 1e9
MICROSECONDS_PER_MILLISECOND = 1000
CONTROL_PORTS = 4  # the control port and the three data ports after it
SCOPE = (
    "Bounded observations; dispatcher scheduling and unique causal mechanism "
    "remain open"
)
IDENTIFICATION = (
    "Unique SYN within250ms of UTC end minus monotonic duration; old recorder "
    "had no socket address metadata"
)


def identify_port(baseline: Report, guest: Packets) -> int:
    """Find the guest-side source port of the old recorder's socket.

    Returns
    -------
    int
        The one port whose SYN falls at the start that the report implies.
    """
    started = (
        dt.datetime.fromisoformat(baseline["recorded_at_utc"]).timestamp()
        - baseline["events"][-1]["elapsed_ns"] / NANOSECONDS_PER_SECOND
    )
    candidates = {
        p["src_port"]
        for p in guest
        if p["src_ip"] == GUEST_CLIENT_HOST
        and p["dst_port"] == GUEST_SERVER_BASE
        and p["flags"] & TCP_SYN
        and abs(p["timestamp_us"] / MICROSECONDS_PER_SECOND - started)
        < PORT_TOLERANCE_SECONDS
    }
    require(len(candidates) == 1, "Old socket port cannot be identified unambiguously")
    return candidates.pop()


def baseline_silence(directory: Path, guest: Packets) -> float:
    """Measure the guest's silence before the client closed the old socket.

    Returns
    -------
    float
        The seconds between the guest's last data and the client's close.
    """
    baseline = verify_capture(
        directory / "initial-transcripts/failed-login-guest-drain"
    )
    require(baseline["status"] == "failed", "65-second observation status changed")
    port = identify_port(baseline, guest)
    client = (GUEST_CLIENT_HOST, port)
    server = (GUEST_SERVER_HOST, GUEST_SERVER_BASE)
    incoming = direction(guest, client, server)
    outgoing = direction(guest, server, client)
    client_end = next(p for p in incoming if p["flags"] & TCP_CLOSE_FLAGS)
    require(
        not any(
            p["flags"] & TCP_CLOSE_FLAGS
            and p["timestamp_us"] < client_end["timestamp_us"]
            for p in outgoing
        ),
        "Guest closed during baseline waiting period",
    )
    last_data = max(
        p["timestamp_us"]
        for p in outgoing
        if p["payload_hex"] and not p["flags"] & TCP_RST
    )
    silence = (client_end["timestamp_us"] - last_data) / MICROSECONDS_PER_SECOND
    require(
        silence >= BASELINE_SILENCE_SECONDS,
        "Baseline guest silence was shorter than65 seconds",
    )
    return silence


def isolated_ports(isolated: Report, host: Packets, guest: Packets) -> dict[str, int]:
    """Check each isolated socket against the host and guest packet streams.

    Returns
    -------
    dict[str, int]
        The client port of each connection.
    """
    ports = {}
    for event in isolated["events"]:
        if event["event"] != "connect":
            continue
        client, server = tuple(event["local_address"]), tuple(event["peer_address"])
        ports[event["connection"]] = client[1]
        recorded = isolated["streams"][event["connection"]]
        require(
            stream(host, client, server).hex() == recorded["sent_hex"]
            and stream(host, server, client).hex() == recorded["received_hex"],
            "Isolated socket and packet streams differ",
        )
        guest_client = (GUEST_CLIENT_HOST, client[1])
        guest_server = (GUEST_SERVER_HOST, GUEST_SERVER_BASE)
        require(
            stream(guest, guest_client, guest_server).hex() == recorded["sent_hex"]
            and stream(guest, guest_server, guest_client).hex()
            == recorded["received_hex"],
            "Isolated guest stream differs",
        )
    return ports


def first_packet(guest: Packets, source: int, destination: int, flag: int) -> Report:
    """Find the first guest packet from ``source`` to ``destination`` with ``flag``.

    Returns
    -------
    dict[str, typing.Any]
        The packet.
    """
    return next(
        p
        for p in guest
        if p["src_port"] == source
        and p["dst_port"] == destination
        and p["flags"] & flag
    )


def check_isolated_window(
    isolated: Report, guest: Packets, ports: dict[str, int]
) -> float:
    """Check the isolated quiet, the reset's timing and the absence of other traffic.

    Returns
    -------
    float
        The milliseconds from the new connection's SYN to the old one's reset.
    """
    quiet = next(e for e in isolated["events"] if e["event"] == "quiet")
    previous_receive = max(
        e["elapsed_ns"]
        for e in isolated["events"]
        if e["event"] == "receive" and e["connection"] == "main"
    )
    require(
        quiet["elapsed_ns"] - previous_receive >= ISOLATED_QUIET_NS,
        "No35-second quiet observation",
    )
    syn = first_packet(guest, ports["tick"], GUEST_SERVER_BASE, TCP_SYN)
    reset = first_packet(guest, GUEST_SERVER_BASE, ports["main"], TCP_RST)
    require(
        reset["timestamp_us"] >= syn["timestamp_us"],
        "Isolated reset preceded new connection",
    )
    main_syn = first_packet(guest, ports["main"], GUEST_SERVER_BASE, TCP_SYN)
    require(
        not any(
            p["flags"] & TCP_SYN
            and p["src_ip"] == GUEST_CLIENT_HOST
            and GUEST_SERVER_BASE <= p["dst_port"] < GUEST_SERVER_BASE + CONTROL_PORTS
            and p["src_port"] not in ports.values()
            and main_syn["timestamp_us"] <= p["timestamp_us"] <= syn["timestamp_us"]
            for p in guest
        ),
        "Other control/data connection overlaps isolated window",
    )
    return (reset["timestamp_us"] - syn["timestamp_us"]) / MICROSECONDS_PER_MILLISECOND


def verify_timing(directory: Path, guest: Packets) -> Report:
    """Check the two bounded close observations without claiming a hard deadline.

    Returns
    -------
    dict[str, typing.Any]
        The baseline silence, how the port was found, the reset delay and the scope.
    """
    silence = baseline_silence(directory, guest)
    isolated = verify_capture(directory / "isolated-failure-quiet-and-tick")
    require(isolated["status"] == "completed", "Isolated35-second observation changed")
    host = read_packets(directory / "isolated-host.pcap")
    ports = isolated_ports(isolated, host, guest)
    reset_ms = check_isolated_window(isolated, guest, ports)
    return {
        "baseline_guest_silence_seconds": silence,
        "baseline_port_identification": IDENTIFICATION,
        "isolated_reset_after_new_syn_ms": reset_ms,
        "scope": SCOPE,
    }
