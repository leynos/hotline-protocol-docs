"""Check the failed lifetime trial, whose host and guest streams differ.

The trial keeps host-only late input and guest-only cleanup outside the equal
streams: the waiting session's late acceptance reached the host after the guest
had closed, and the observer's removal notice reached the guest only.
"""

import dataclasses as dc
import datetime as dt
import typing as typ

from native_packet_evidence import (
    GUEST_CLIENT_HOST,
    GUEST_SERVER_BASE,
    GUEST_SERVER_HOST,
    MICROSECONDS_PER_SECOND,
    NANOSECONDS_PER_MICROSECOND,
    TCP_CLOSE_FLAGS,
)
from native_wire_names import TYPE_ACCEPT_AGREEMENT, TYPE_USER_LEFT
from pcap_tcp import direction, stream
from pcap_tcp import lifetime as tcp_lifetime
from protocol_capture import decode_frame
from verify_native_core import require

type Report = dict[str, typ.Any]
type Packets = list[dict[str, typ.Any]]
type Address = tuple[str, int]

ACCEPT_ID = 2
CLEANUP_TAIL_BYTES = 28  # the length of the guest-only removal notice


@dc.dataclass(frozen=True, slots=True)
class Trial:
    """The host and guest streams of one connection of the failed trial."""

    name: str
    host_input: bytes
    guest_input: bytes
    host_output: bytes
    guest_output: bytes
    guest_packets: Packets
    guest_pair: tuple[Address, Address]


def open_trial(host: Packets, guest: Packets, start: float, event: Report) -> Trial:
    """Gather one connection's streams from the host and the guest packets.

    Returns
    -------
    Trial
        The connection's inputs and outputs as each side saw them.
    """
    client, server = tuple(event["local_address"]), tuple(event["peer_address"])
    guest_client = (GUEST_CLIENT_HOST, client[1])
    guest_server = (GUEST_SERVER_HOST, GUEST_SERVER_BASE)
    when = int(start + event["elapsed_ns"] / NANOSECONDS_PER_MICROSECOND)
    hp = tcp_lifetime(host, client, server, when)
    gp = tcp_lifetime(guest, guest_client, guest_server, when)
    return Trial(
        event["connection"],
        stream(hp, client, server),
        stream(gp, guest_client, guest_server),
        stream(hp, server, client),
        stream(gp, guest_server, guest_client),
        gp,
        (guest_client, guest_server),
    )


def check_waiting(report: Report, trial: Trial, start: float) -> None:
    """Check the host-only late acceptance and that it followed the native close."""
    require(
        trial.host_input.startswith(trial.guest_input),
        "Failed waiting input boundary is not a prefix",
    )
    late = trial.host_input[len(trial.guest_input) :]
    frame = decode_frame(late)
    require(
        frame["type"] == TYPE_ACCEPT_AGREEMENT and frame["id"] == ACCEPT_ID,
        "Expected host-only late acceptance",
    )
    sent = next(
        e
        for e in report["events"]
        if e["event"] == "send"
        and e["connection"] == trial.name
        and e["hex"] == late.hex()
    )
    client, server = trial.guest_pair
    closes = [
        p
        for p in direction(trial.guest_packets, server, client)
        if p["flags"] & TCP_CLOSE_FLAGS
    ]
    require(
        bool(closes)
        and closes[0]["timestamp_us"]
        < start + sent["elapsed_ns"] / NANOSECONDS_PER_MICROSECOND,
        "Late acceptance preceded native close",
    )


def check_observer(trial: Trial) -> None:
    """Check the guest-only removal notice that followed the observer's output."""
    require(
        trial.guest_output.startswith(trial.host_output),
        "Failed observer output boundary is not a prefix",
    )
    late = trial.guest_output[len(trial.host_output) :]
    frame = decode_frame(late)
    require(
        len(late) == CLEANUP_TAIL_BYTES
        and frame["type"] == TYPE_USER_LEFT
        and not frame["is_reply"],
        "Expected guest-only cleanup tail",
    )


def check_trial(
    report: Report, packets: tuple[Packets, Packets], start: float, event: Report
) -> None:
    """Check one connection of the failed trial against both packet views."""
    trial = open_trial(*packets, start, event)
    name = trial.name
    require(
        trial.host_input.hex() == report["streams"][name]["sent_hex"],
        "Failed trial host input differs",
    )
    received = bytes.fromhex(report["streams"][name]["received_hex"])
    require(
        trial.host_output.startswith(received),
        "Failed trial recorded output is not a prefix",
    )
    if name == "waiting":
        check_waiting(report, trial, start)
    else:
        require(
            trial.host_input == trial.guest_input,
            "Failed trial input differs outside waiting session",
        )
    if name == "observer":
        check_observer(trial)
    else:
        require(
            trial.host_output == trial.guest_output,
            "Failed trial output differs outside observer cleanup",
        )


def check_failed_lifetime(report: Report, host: Packets, guest: Packets) -> None:
    """Keep host-only late input and guest-only cleanup outside equal streams."""
    start = (
        dt.datetime.fromisoformat(report["started_at_utc"]).timestamp()
        * MICROSECONDS_PER_SECOND
    )
    require(report["status"] == "failed", "Long waiting hypothesis was rewritten")
    for event in report["events"]:
        if event["event"] == "connect":
            check_trial(report, (host, guest), start, event)
