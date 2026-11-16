"""Pin the order of the failed login-extras trial's checks.

The goldens observe only the retained corpus, so the order in which an unsound
trial is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. The trials are small synthetic packet records, because the
retained packet captures are not read by new tests. Every expectation was
observed on the version of the scripts before the verifier was split into
``verify_native_login_extras_*`` modules (commit 0b34126).

A trial that breaks check ``n`` also breaks every check after it, so the
message that comes back names the first check that the verifier makes.
"""

import dataclasses as dc
import datetime as dt
import struct
import typing as typ

import pytest
from verify_native_login_extras import check_failed_lifetime

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]
type Packets = list[dict[str, typ.Any]]

STARTED = "2026-11-13T02:25:49+00:00"
START_US = int(dt.datetime.fromisoformat(STARTED).timestamp()) * 1_000_000
SYN, SYN_ACK, PSH_ACK, FIN_ACK = 2, 18, 24, 17
HOST = "127.0.0.1"
GUEST_CLIENT = "10.0.2.2"
GUEST_SERVER = "10.0.2.15"
HOST_SERVER_PORT = 15500
GUEST_SERVER_PORT = 5500
CONNECT_NS = 1_000_000
SEND_NS = 5_000_000
ACCEPT = 121
REMOVAL = 302
ACCEPT_ID = 2
CLEANUP_BYTES = 28
PORTS = {"observer": 50001, "waiting": 50002, "fresh": 50003}


def frame(kind: int, identifier: int, size: int = 0) -> bytes:
    """Build one physical frame whose data is ``size`` zero bytes.

    Returns
    -------
    bytes
        The twenty-byte header and the data.
    """
    return struct.pack(">BBHIIII", 0, 0, kind, identifier, 0, size, size) + bytes(size)


ACCEPTANCE = frame(ACCEPT, ACCEPT_ID)
REMOVED = frame(REMOVAL, 0, CLEANUP_BYTES - 20)
INPUT = b"hello"
OUTPUT = b"world"


def segment(
    path: tuple[tuple[str, int], tuple[str, int]],
    header: tuple[int, int],
    payload: bytes = b"",
    when: int = START_US,
) -> dict[str, typ.Any]:
    """Build one packet record.

    Returns
    -------
    dict[str, typing.Any]
        The record, as the packet reader would have made it.
    """
    (source, destination), (flags, sequence) = path, header
    return {
        "src_ip": source[0],
        "src_port": source[1],
        "dst_ip": destination[0],
        "dst_port": destination[1],
        "flags": flags,
        "sequence": sequence,
        "payload_hex": payload.hex(),
        "timestamp_us": when,
    }


def one_way(
    source: tuple[str, int], destination: tuple[str, int], payload: bytes, flags: int
) -> Packets:
    """Build the opening packet of one direction, and its data if any.

    Returns
    -------
    list[dict[str, typing.Any]]
        The packets of the direction.
    """
    packets = [segment((source, destination), (flags, 1000))]
    if payload:
        packets.append(segment((source, destination), (PSH_ACK, 1001), payload))
    return packets


@dc.dataclass(slots=True)
class Trial:
    """One connection of the failed trial, as the host and the guest saw it."""

    name: str
    host_input: bytes = INPUT
    guest_input: bytes = INPUT
    host_output: bytes = OUTPUT
    guest_output: bytes = OUTPUT
    sent_hex: str | None = None
    received_hex: str | None = None
    closed_after_send: bool = False
    late_event_hex: str | None = None

    def packets(self) -> tuple[Packets, Packets]:
        """Build the host and the guest packet records.

        Returns
        -------
        tuple[list, list]
            The host packets and the guest packets of the connection.
        """
        port = PORTS[self.name]
        client, server = (HOST, port), (HOST, HOST_SERVER_PORT)
        guest_client, guest_server = (
            (GUEST_CLIENT, port),
            (GUEST_SERVER, GUEST_SERVER_PORT),
        )
        host = one_way(client, server, self.host_input, SYN)
        host += one_way(server, client, self.host_output, SYN_ACK)
        guest = one_way(guest_client, guest_server, self.guest_input, SYN)
        guest += one_way(guest_server, guest_client, self.guest_output, SYN_ACK)
        closed = START_US + (SEND_NS // 1000 + 1 if self.closed_after_send else 1)
        guest.append(
            segment((guest_server, guest_client), (FIN_ACK, 9000), when=closed)
        )
        return host, guest

    def events(self) -> list[Report]:
        """Build the connect event and, for the waiting session, the late send.

        Returns
        -------
        list[dict[str, typing.Any]]
            The events of the connection.
        """
        port = PORTS[self.name]
        events = [
            {
                "event": "connect",
                "connection": self.name,
                "local_address": [HOST, port],
                "peer_address": [HOST, HOST_SERVER_PORT],
                "elapsed_ns": CONNECT_NS,
            }
        ]
        if self.name == "waiting":
            late = self.host_input[len(self.guest_input) :]
            events.append({
                "event": "send",
                "connection": self.name,
                "hex": self.late_event_hex or late.hex(),
                "elapsed_ns": SEND_NS,
            })
        return events

    def stream(self) -> Report:
        """Build the recorded streams of the connection.

        Returns
        -------
        dict[str, str]
            The hexadecimal bytes the driver sent and received.
        """
        return {
            "sent_hex": self.sent_hex
            if self.sent_hex is not None
            else self.host_input.hex(),
            "received_hex": self.received_hex
            if self.received_hex is not None
            else self.host_output.hex(),
        }


def run(trials: list[Trial], status: str = "failed") -> None:
    """Check a failed trial made of ``trials``, in order."""
    host: Packets = []
    guest: Packets = []
    report: Report = {
        "started_at_utc": STARTED,
        "status": status,
        "events": [],
        "streams": {},
    }
    for trial in trials:
        trial_host, trial_guest = trial.packets()
        host += trial_host
        guest += trial_guest
        report["events"] += trial.events()
        report["streams"][trial.name] = trial.stream()
    check_failed_lifetime(report, host, guest)


def waiting() -> Trial:
    """Build a sound waiting session whose acceptance came after the close.

    Returns
    -------
    Trial
        The connection.
    """
    return Trial(
        "waiting",
        host_input=INPUT + ACCEPTANCE,
        closed_after_send=False,
    )


type Break = cabc.Callable[[Trial], None]
type Chain = list[tuple[str, str, Break]]


def sent_differs(trial: Trial) -> None:
    """Record other sent bytes than the host saw."""
    trial.sent_hex = "ff"


def received_differs(trial: Trial) -> None:
    """Record received bytes that the host output does not begin with."""
    trial.received_hex = "ff"


def guest_input_differs(trial: Trial) -> None:
    """Give the guest input that the host input does not begin with."""
    trial.guest_input = b"jello"


def other_late_frame(trial: Trial) -> None:
    """Make the late input another frame than the acceptance."""
    trial.host_input = INPUT + frame(ACCEPT, ACCEPT_ID + 1)
    trial.sent_hex = None


def closed_late(trial: Trial) -> None:
    """Close the guest connection only after the late input was sent."""
    trial.closed_after_send = True


def output_differs(trial: Trial) -> None:
    """Give the guest another output than the host."""
    trial.guest_output = OUTPUT + b"!"


def not_prefixed_output(trial: Trial) -> None:
    """Give the guest an output that does not begin with the host output."""
    trial.guest_output = b"WORLD" + REMOVED


def other_tail(trial: Trial) -> None:
    """Give the guest an output tail that is not the removal notice."""
    trial.guest_output = OUTPUT + frame(REMOVAL + 1, 0, CLEANUP_BYTES - 20)


WAITING: Chain = [
    ("sent", "Failed trial host input differs", sent_differs),
    ("received", "Failed trial recorded output is not a prefix", received_differs),
    ("boundary", "Failed waiting input boundary is not a prefix", guest_input_differs),
    ("frame", "Expected host-only late acceptance", other_late_frame),
    ("close", "Late acceptance preceded native close", closed_late),
    (
        "output",
        "Failed trial output differs outside observer cleanup",
        output_differs,
    ),
]


class WaitingOrderTests:
    """Keep the waiting session's checks in the order in which they have run."""

    def test_the_sound_trial_is_accepted(self) -> None:
        """A trial with the late acceptance after the close passes every check."""
        trial = waiting()
        trial.closed_after_send = False
        trial.guest_output = trial.host_output
        run([trial])

    @pytest.mark.parametrize("first", range(len(WAITING)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        trial = waiting()
        for _label, _message, apply in reversed(WAITING[first:]):
            apply(trial)
        _label, message, _apply = WAITING[first]
        with pytest.raises(ValueError, match=message):
            run([trial])


def observer() -> Trial:
    """Build a sound observer whose guest output has the removal notice.

    Returns
    -------
    Trial
        The connection.
    """
    return Trial("observer", guest_output=OUTPUT + REMOVED)


def observer_input_differs(trial: Trial) -> None:
    """Give the guest another input than the host."""
    trial.guest_input = INPUT + b"!"


OBSERVER: Chain = [
    ("sent", "Failed trial host input differs", sent_differs),
    ("received", "Failed trial recorded output is not a prefix", received_differs),
    (
        "input",
        "Failed trial input differs outside waiting session",
        observer_input_differs,
    ),
    (
        "boundary",
        "Failed observer output boundary is not a prefix",
        not_prefixed_output,
    ),
    ("tail", "Expected guest-only cleanup tail", other_tail),
]


class ObserverOrderTests:
    """Keep the observer's checks in the order in which they have run."""

    def test_the_sound_trial_is_accepted(self) -> None:
        """A trial whose guest output ends in the removal notice passes."""
        run([observer()])

    @pytest.mark.parametrize("first", range(len(OBSERVER)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        trial = observer()
        for _label, _message, apply in reversed(OBSERVER[first:]):
            apply(trial)
        _label, message, _apply = OBSERVER[first]
        with pytest.raises(ValueError, match=message):
            run([trial])


class TrialOrderTests:
    """Keep the status, the connection order and the other sessions in order."""

    def test_the_status_is_checked_before_any_connection(self) -> None:
        """A completed trial is refused before its packets are read."""
        with pytest.raises(ValueError, match="Long waiting hypothesis was rewritten"):
            run([], status="completed")

    def test_a_trial_without_connections_is_accepted(self) -> None:
        """A failed trial with no connect event has nothing to refuse."""
        run([])

    def test_connections_are_checked_in_the_order_of_their_events(self) -> None:
        """The first connection's fault is reported before the second's."""
        first, second = observer(), waiting()
        sent_differs(first)
        received_differs(second)
        with pytest.raises(ValueError, match="Failed trial host input differs"):
            run([first, second])
        first, second = observer(), waiting()
        received_differs(first)
        sent_differs(second)
        with pytest.raises(ValueError, match="recorded output is not a prefix"):
            run([first, second])

    def test_another_session_must_match_on_both_sides(self) -> None:
        """A session other than the two named ones has equal host and guest views."""
        sound = Trial("fresh")
        run([sound])
        with pytest.raises(ValueError, match="input differs outside waiting session"):
            run([Trial("fresh", guest_input=INPUT + b"!")])
        with pytest.raises(ValueError, match="output differs outside observer cleanup"):
            run([Trial("fresh", guest_output=OUTPUT + b"!")])
