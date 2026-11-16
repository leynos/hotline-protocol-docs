"""Reconcile the saved host and guest packet views with each recorded stream."""

import dataclasses as dc
import datetime as dt
import json
import typing as typ

from native_wire_names import FIELD_USER_ID, TYPE_USER_LEFT
from pcap_tcp import direction, lifetime, read_packets, stream
from protocol_capture import decode_frame, digest
from verify_native_core import require
from verify_native_shx import fields

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]
type Endpoint = tuple[str, int]

HOST_ADDRESS = "127.0.0.1"
GUEST_CLIENT_ADDRESS = "10.0.2.2"
GUEST_SERVER_ADDRESS = "10.0.2.15"
HOST_PORT_BASE = 15500  # the first host port of the plans' endpoints
GUEST_PORT_BASE = 5500  # the guest port that the first host port maps to
TEARDOWN_TAIL_BYTES = 28  # one 302 frame with one user-id field
END_FLAGS = 5  # a FIN or an RST ends a direction
MICROSECONDS = 1_000_000
NANOSECONDS_PER_MICROSECOND = 1000


@dc.dataclass(frozen=True, slots=True)
class View:
    """One side's packets and the client and server endpoints on that side."""

    name: str
    packets: list[Report]
    client: Endpoint
    server: Endpoint


@dc.dataclass(frozen=True, slots=True)
class Observation:
    """What is known about one capture while its packet views are checked."""

    label: str
    report: Report
    host: list[Report]
    guest: list[Report]
    peer_uid: bytes

    def views(self, local: int, target: int) -> list[View]:
        """Name the host and guest views of one connection.

        Parameters
        ----------
        local : int
            The client's local port.
        target : int
            The server's port on the host.

        Returns
        -------
        list[View]
            The host view, then the guest view.
        """
        guest_port = GUEST_PORT_BASE + target - HOST_PORT_BASE
        return [
            View(
                "host",
                self.host,
                (HOST_ADDRESS, local),
                (HOST_ADDRESS, target),
            ),
            View(
                "guest",
                self.guest,
                (GUEST_CLIENT_ADDRESS, local),
                (GUEST_SERVER_ADDRESS, guest_port),
            ),
        ]


def teardown_tail_is_a_departure(tail: bytes, peer_uid: bytes) -> bool:
    """Say whether the tail is one 302 frame that names the peer.

    Returns
    -------
    bool
        ``True`` for exactly 28 bytes that decode as a 302 with the peer's id.
    """
    if len(tail) != TEARDOWN_TAIL_BYTES:
        return False
    frame = decode_frame(tail)
    return frame["type"] == TYPE_USER_LEFT and fields(frame) == {
        FIELD_USER_ID: peer_uid
    }


def check_view(observation: Observation, name: str, view: View, when: int) -> Report:
    """Check one connection as one side of the network saw it.

    Parameters
    ----------
    observation : Observation
        The capture being checked.
    name : str
        The connection's name.
    view : View
        The side to check.
    when : int
        The connection's time in microseconds since the epoch.

    Returns
    -------
    dict[str, typing.Any]
        The summary that the saved reconciliation must equal.
    """
    label = observation.label
    recorded = observation.report["streams"][name]
    selected = lifetime(view.packets, view.client, view.server, when)
    sent = stream(selected, view.client, view.server)
    received = stream(selected, view.server, view.client)
    prefix = bytes.fromhex(recorded["received_hex"])
    where = f"{label}/{name}/{view.name}"
    require(sent == bytes.fromhex(recorded["sent_hex"]), f"{where}: TCP input differs")
    require(received.startswith(prefix), f"{where}: TCP output prefix differs")
    tail = received[len(prefix) :]
    if label == "observe" and name == "main":
        require(
            teardown_tail_is_a_departure(tail, observation.peer_uid),
            "PM teardown tail differs",
        )
    else:
        require(not tail, f"{where}: unexpected unread tail")
    ends = [
        p["flags"]
        for p in direction(selected, view.server, view.client)
        if p["flags"] & END_FLAGS
    ]
    return {
        "packets": len(selected),
        "sent_bytes": len(sent),
        "received_bytes": len(received),
        "recorded_received_bytes": len(prefix),
        "unread_tail_bytes": len(tail),
        "unread_tail_sha256": digest(tail),
        "terminal_flags": ends,
    }


def check_connection(observation: Observation, event: Report, started: int) -> Report:
    """Check one ``connect`` event on both sides.

    Parameters
    ----------
    observation : Observation
        The capture being checked.
    event : dict[str, typing.Any]
        The ``connect`` event.
    started : int
        The capture's start in microseconds since the epoch.

    Returns
    -------
    dict[str, typing.Any]
        The ports and the summary of each view.
    """
    name = event["connection"]
    local, target = event["local_address"][1], event["peer_address"][1]
    when = started + event["elapsed_ns"] // NANOSECONDS_PER_MICROSECOND
    views = {
        view.name: check_view(observation, name, view, when)
        for view in observation.views(local, target)
    }
    return {"local_port": local, "target_port": target, "views": views}


def label_views(root: Path, label: str, report: Report, peer_uid: bytes) -> Report:
    """Check every connection of one capture against its saved packets.

    Parameters
    ----------
    root : pathlib.Path
        The corpus root.
    label : str
        ``preflight``, ``observe`` or ``postflight``.
    report : dict[str, typing.Any]
        The capture's report.
    peer_uid : bytes
        The peer's user id.

    Returns
    -------
    dict[str, typing.Any]
        The capture's status and the summary of each connection.
    """
    observation = Observation(
        label,
        report,
        read_packets(root / f"host-after-{label}.pcap"),
        read_packets(root / f"guest-after-{label}.pcap"),
        peer_uid,
    )
    started = int(
        dt.datetime.fromisoformat(report["started_at_utc"]).timestamp() * MICROSECONDS
    )
    sockets = {}
    for event in report["events"]:
        if event["event"] == "connect":
            sockets[event["connection"]] = check_connection(observation, event, started)
    return {"status": report["status"], "connections": sockets}


def check_snapshots(root: Path) -> None:
    """Check that each later packet snapshot extends the one before it.

    Parameters
    ----------
    root : pathlib.Path
        The corpus root.
    """
    for prefix in ("host", "guest"):
        previous = (root / f"{prefix}-after-preflight.pcap").read_bytes()
        for label in ("observe", "postflight"):
            current = (root / f"{prefix}-after-{label}.pcap").read_bytes()
            require(
                current.startswith(previous) and len(current) > len(previous),
                f"{prefix} cumulative snapshot boundary differs",
            )
            previous = current


def packet_views(root: Path, reports: dict[str, Report], peer_uid: bytes) -> Report:
    """Reconcile the packet views of every capture and the saved receipt.

    The checks run in a fixed order: each capture's connections, in the order
    of ``reports``, then the saved reconciliation, the snapshot boundaries and
    the final host capture.

    Parameters
    ----------
    root : pathlib.Path
        The corpus root.
    reports : dict[str, dict[str, typing.Any]]
        The verified report of each capture by label.
    peer_uid : bytes
        The peer's user id.

    Returns
    -------
    dict[str, typing.Any]
        The observed reconciliation, equal to the saved one.
    """
    saved = json.loads((root / "packet-reconciliation.json").read_text())
    observed = {
        label: label_views(root, label, report, peer_uid)
        for label, report in reports.items()
    }
    require(observed == saved, "Saved PM packet reconciliation differs")
    check_snapshots(root)
    require(
        (root / "host.pcap").read_bytes()
        == (root / "host-after-postflight.pcap").read_bytes(),
        "Final host capture differs",
    )
    return observed
