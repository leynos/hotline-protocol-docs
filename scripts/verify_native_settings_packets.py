"""Compare the recorded settings streams with the host and guest packet captures."""

import dataclasses as dc
import datetime as dt
import json
import typing as typ

from native_packet_evidence import reconcile
from native_wire_names import FIELD_USER_ID, TYPE_USER_LEFT
from pcap_tcp import lifetime, stream
from protocol_capture import decode_frame
from verify_native_core import require
from verify_native_settings_core import Report, values

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

type Packets = list[dict[str, typ.Any]]
type Address = tuple[str, int]

MICROSECONDS = 1e6
GUEST_CLIENT = "10.0.2.2"
GUEST_SERVER = "10.0.2.15"
GUEST_PORT_BASE = 5500  # the guest forwards the lab port 15500 to 5500
HOST_PORT_BASE = 15500
A7_SOCKETS = 2
UNREAD_302_BYTES = 28  # a 302 frame with one two-byte user id field
SOCKET_NAMES = {"main", "subject"}
CHECKED_VANTAGES = ("host", "guest")


@dc.dataclass(frozen=True, slots=True)
class Connection:
    """One recorded socket, as the capture's ``connect`` event describes it.

    Attributes
    ----------
    name : str
        The connection's name in the plan.
    source : tuple[str, int]
        The client address on the host.
    endpoint : tuple[str, int]
        The server address on the host.
    when : int
        The connect time in microseconds since the epoch.
    """

    name: str
    source: Address
    endpoint: Address
    when: int

    def vantages(
        self, host: Packets, guest: Packets
    ) -> list[tuple[str, Packets, Address, Address]]:
        """List where the connection is seen: on the host and in the guest.

        Parameters
        ----------
        host : list[dict[str, typing.Any]]
            The host's packets.
        guest : list[dict[str, typing.Any]]
            The guest's packets.

        Returns
        -------
        list[tuple[str, list[dict[str, typing.Any]], tuple[str, int], tuple[str, int]]]
            The label, the packets, and the client and server addresses of each.
        """
        return [
            ("host", host, self.source, self.endpoint),
            (
                "guest",
                guest,
                (GUEST_CLIENT, self.source[1]),
                (GUEST_SERVER, GUEST_PORT_BASE + self.endpoint[1] - HOST_PORT_BASE),
            ),
        ]


def started_at(report: Report) -> float:
    """Read the capture's start time.

    Returns
    -------
    float
        Microseconds since the epoch.
    """
    return (
        dt.datetime.fromisoformat(report["started_at_utc"]).timestamp() * MICROSECONDS
    )


def connections(report: Report, started: float) -> cabc.Iterator[Connection]:
    """Walk the ``connect`` events of a report.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The capture report.
    started : float
        The capture's start time in microseconds.

    Yields
    ------
    Connection
        Each recorded socket, in event order.
    """
    for event in report["events"]:
        if event["event"] != "connect":
            continue
        name = event["connection"]
        source = tuple(event["local_address"])
        endpoint = tuple(event["peer_address"])
        when = int(started + event["elapsed_ns"] / 1000)
        yield Connection(name, source, endpoint, when)


def a7_packets(report: Report, host: Packets, guest: Packets) -> int:
    """Require the recorded A7 streams in both packet captures.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The A7 capture report.
    host : list[dict[str, typing.Any]]
        The host's packets.
    guest : list[dict[str, typing.Any]]
        The guest's packets.

    Returns
    -------
    int
        The number of sockets paired.
    """
    paired = 0
    for connection in connections(report, started_at(report)):
        name = connection.name
        for label, packets, client, server in connection.vantages(host, guest):
            selected = lifetime(packets, client, server, connection.when)
            require(
                stream(selected, client, server).hex()
                == report["streams"][name]["sent_hex"],
                f"A7 {name} {label} input differs",
            )
            require(
                stream(selected, server, client).hex()
                == report["streams"][name]["received_hex"],
                f"A7 {name} {label} output differs",
            )
        paired += 1
    require(paired == A7_SOCKETS, "A7 paired socket count differs")
    return paired


def unread_tails(
    name: str, report: Report, host: Packets, guest: Packets
) -> dict[str, dict[str, bytes]]:
    """Read what each capture holds beyond the recorded output of each socket.

    Parameters
    ----------
    name : str
        The case name.
    report : dict[str, typing.Any]
        The case's report.
    host : list[dict[str, typing.Any]]
        The host's packets.
    guest : list[dict[str, typing.Any]]
        The guest's packets.

    Returns
    -------
    dict[str, dict[str, bytes]]
        The unread bytes by vantage and connection name.
    """
    tails: dict[str, dict[str, bytes]] = {"host": {}, "guest": {}}
    for connection in connections(report, started_at(report)):
        prefix = bytes.fromhex(report["streams"][connection.name]["received_hex"])
        for label, packets, client, server in connection.vantages(host, guest):
            actual = stream(
                lifetime(packets, client, server, connection.when), server, client
            )
            require(actual.startswith(prefix), f"{name}: {label} output prefix differs")
            tails[label][connection.name] = actual[len(prefix) :]
    return tails


def check_unread(name: str, result: Report, tails: dict[str, dict[str, bytes]]) -> None:
    """Check that the two captures agree and that only a 302 is left unread.

    Parameters
    ----------
    name : str
        The case name.
    result : dict[str, typing.Any]
        The case's semantic result, which names the subject's user id.
    tails : dict[str, dict[str, bytes]]
        The unread bytes by vantage and connection name.
    """
    require(tails["host"] == tails["guest"], f"{name}: host/guest unread tails differ")
    require(set(tails["host"]) == SOCKET_NAMES, f"{name}: socket inventory differs")
    require(tails["host"]["subject"] == b"", f"{name}: subject unread tail differs")
    tail = tails["host"]["main"]
    if tail:
        require(len(tail) == UNREAD_302_BYTES, f"{name}: unread tail length differs")
        frame = decode_frame(tail)
        require(
            frame["type"] == TYPE_USER_LEFT
            and values(frame)
            == {FIELD_USER_ID: bytes.fromhex(result["subject_uid_hex"])},
            f"{name}: unread 302 differs",
        )


def check_recorded(
    name: str, recorded: Report, tails: dict[str, dict[str, bytes]]
) -> None:
    """Compare the unread bytes with the tails that the corpus recorded.

    Parameters
    ----------
    name : str
        The case name.
    recorded : dict[str, typing.Any]
        The corpus's recorded tails of the case.
    tails : dict[str, dict[str, bytes]]
        The unread bytes by vantage and connection name.
    """
    require(
        all(
            recorded[c][label + "_hex"] == tails[label][c].hex()
            for c in tails["host"]
            for label in CHECKED_VANTAGES
        ),
        f"{name}: recorded tails differ",
    )


def case_packets(
    raw: Path, results: list[Report], host: Packets, guest: Packets
) -> int:
    """Reconcile every case's recorded streams with both packet captures.

    Parameters
    ----------
    raw : pathlib.Path
        The corpus's ``raw`` directory.
    results : list[dict[str, typing.Any]]
        The semantic result of each case.
    host : list[dict[str, typing.Any]]
        The host's packets.
    guest : list[dict[str, typing.Any]]
        The guest's packets.

    Returns
    -------
    int
        The number of paired sockets: two vantages for each socket.
    """
    retained = json.loads((raw / "packet-reconciliation.json").read_text())
    require(
        set(retained) == {r["case"] for r in results}, "Packet case inventory differs"
    )
    paired = 0
    for result in results:
        name = result["case"]
        report = json.loads((raw / "cases" / name / "report.json").read_text())
        tails = unread_tails(name, report, host, guest)
        check_unread(name, result, tails)
        check_recorded(name, retained[name]["tails"], tails)
        reconcile(
            report, host, guest, tails["host"], guest_unread_output=tails["guest"]
        )
        paired += 2
    return paired
