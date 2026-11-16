"""Check the packet captures against the recorder streams of the first pair."""

import runpy
import typing as typ

from native_wire_names import (
    TYPE_ENUMERATE_ACCOUNTS,
    TYPE_GET_FILE_INFO,
    TYPE_GET_USER_ROSTER,
    TYPE_LIST_FILES,
    TYPE_LOGIN,
)
from verify_native_rate304_partial_core import CONTROL_PORT, PORTS, need, read

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

TYPE_OBSERVER_TARGET = 303  # the observer control whose target is field 103
TCP_RST = 4  # the reset bit of a TCP flags byte
TCP_SYN = 2  # the SYN bit of a TCP flags byte
TCP_ACK = 16  # the acknowledgement bit of a TCP flags byte
NAMESPACE_PACKETS = 75  # packets in the namespace capture of the first pair
GUEST_PACKETS = 82  # packets in the guest capture of the first pair
SYN_LIFETIMES = 3  # one SYN lifetime for each of the three connections
READINESS_ACTIONS = 18  # the separate readiness control's action count
READINESS_SENT = 7  # the requests sent by the separate readiness control
NO_ERROR_TEXT = ""  # the error text that the readiness report holds when it has none
KERNEL_DROP_LINES = 2  # the recorder reports zero kernel drops twice
GUEST_PORT = 5500  # the guest control port that the guest recorder names
HELLO = "54525450484f544c00010002"  # the greeting that opens each connection
READINESS_REQUESTS = [
    (TYPE_LOGIN, 1),
    (TYPE_ENUMERATE_ACCOUNTS, 10),
    (TYPE_LIST_FILES, 11),
    (TYPE_GET_FILE_INFO, 12),
    (TYPE_GET_USER_ROSTER, 13),
    (TYPE_OBSERVER_TARGET, 14),
]
STREAM_LENGTHS = [(231, 2759), (108, 448), (159, 521)]


def check_syn_lifetimes(view: list[dict]) -> None:
    """Check the three SYN lifetimes and the absence of any reset in one capture."""
    syns = [p for p in view if p["flags"] & TCP_SYN and not p["flags"] & TCP_ACK]
    need(
        {p["src_port"] for p in syns} == set(PORTS.values())
        and len(syns) == SYN_LIFETIMES,
        "Three SYN lifetimes differ",
    )
    need(not any(p["flags"] & TCP_RST for p in view), "Unexpected TCP reset")


def check_readiness(readiness: dict) -> None:
    """Check the separate readiness control's status and its request sequence."""
    need(
        readiness["status"] == "completed"
        and readiness["completed_actions"] == READINESS_ACTIONS
        and readiness["error"] == NO_ERROR_TEXT,
        "Separate 18-action readiness differs",
    )
    sent = [
        bytes.fromhex(event["hex"])
        for event in readiness["events"]
        if event["event"] == "send"
    ]
    need(
        len(sent) == READINESS_SENT
        and sent[0] == bytes.fromhex(HELLO)
        and [
            (int.from_bytes(value[:4], "big"), int.from_bytes(value[4:8], "big"))
            for value in sent[1:]
        ]
        == READINESS_REQUESTS,
        "Separate readiness request sequence differs",
    )


def endpoints(server: str, port: int) -> tuple[tuple[str, int], tuple[str, int]]:
    """Return the client and target endpoints that one recorded stream uses.

    Returns
    -------
    tuple[tuple[str, int], tuple[str, int]]
        The client endpoint, then the target endpoint.
    """
    client = ("127.0.0.1" if server.startswith("127") else "10.0.2.2", port)
    target = (server, CONTROL_PORT if server.startswith("127") else GUEST_PORT)
    return client, target


def check_streams(
    stream: cabc.Callable[..., bytes],
    views: tuple[list[dict], list[dict]],
    readiness: dict,
    report: dict,
) -> None:
    """Check each recorded stream against the packets in both captures."""
    for name, port in PORTS.items():
        expected = (
            readiness["streams"]["main"] if name == "main" else report["streams"][name]
        )
        for view, server in ((views[0], "127.0.0.1"), (views[1], "10.0.2.15")):
            client, target = endpoints(server, port)
            need(
                stream(view, client, target).hex() == expected["sent_hex"]
                and stream(view, target, client).hex() == expected["received_hex"],
                f"{name} packet stream differs from recorder",
            )


def stream_lengths(row: dict) -> tuple[int, int]:
    """Return the sent and received byte lengths of one recorded stream.

    Returns
    -------
    tuple[int, int]
        The sent length, then the received length.
    """
    return len(bytes.fromhex(row["sent_hex"])), len(bytes.fromhex(row["received_hex"]))


def check_lengths(readiness: dict, report: dict) -> None:
    """Check the full stream lengths of the three connections."""
    need(
        [
            stream_lengths(readiness["streams"]["main"]),
            stream_lengths(report["streams"]["observer"]),
            stream_lengths(report["streams"]["paced"]),
        ]
        == STREAM_LENGTHS,
        "Full stream lengths differ",
    )


def check_journal(raw: Path) -> None:
    """Check the capture journal for the packet counts and the zero drops."""
    journal = (raw / "capture-journal-terminal.txt").read_text()
    need(
        "0 packets captured" in journal
        and "75 packets captured" in journal
        and journal.count("0 packets dropped by kernel") == KERNEL_DROP_LINES,
        "Recorder drop or primary-contact proof differs",
    )


def packet_evidence(raw: Path, report: dict) -> None:
    """Check the captures, the readiness control and the recorded streams."""
    parser = runpy.run_path(str(raw / "sources/pcap_tcp.py"))
    packets, stream = parser["read_packets"], parser["stream"]
    host = packets(raw / "primary-syn.pcap")
    ns = packets(raw / "lab-namespace.pcap")
    guest = packets(raw / "lab-guest.pcap")
    need(
        len(host) == 0 and len(ns) == NAMESPACE_PACKETS and len(guest) == GUEST_PACKETS,
        "Capture packet count differs",
    )
    for view in (ns, guest):
        check_syn_lifetimes(view)
    readiness = read(raw / "readiness/report.json")
    check_readiness(readiness)
    check_streams(stream, (ns, guest), readiness, report)
    check_lengths(readiness, report)
    check_journal(raw)
