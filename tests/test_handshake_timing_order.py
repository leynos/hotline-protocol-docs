"""Pin the order of the handshake verifier's timing checks.

The goldens observe only the retained corpus, so the order in which an unsound
observation is refused is held here, outside ``scripts/tests``, whose tests are
the golden keys. Every expectation was observed on the version of the scripts
before ``verify_timing`` was split into smaller functions (commit 8b4c3df).

The capture and packet readers are replaced with synthetic ones. A case that
breaks check ``n`` also breaks every check after it, so the message that comes
back names the first check that the verifier makes.
"""

import dataclasses as dc
import datetime as dt
import typing as typ
from pathlib import Path

import pytest
import verify_native_handshakes as handshakes
from handshake_helpers import patch_all

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

FIN = 1
SYN = 2
RST = 4
GUEST = "10.0.2.15"
HOST = "10.0.2.2"
SERVER_PORT = 5500
BASELINE_RECORDED = "2026-01-01T00:02:00+00:00"
BASELINE_NS = 70_000_000_000  # how long the old recorder ran
BASELINE_PORT = 40001
MAIN_PORT = 40010
TICK_PORT = 40011
STRAY_PORT = 49999
SECOND_US = 1_000_000


@dc.dataclass(slots=True)
class Timing:
    """The synthetic observations behind the two bounded timing checks."""

    baseline_status: str = "failed"
    baseline_syn: bool = True
    guest_closes_early: bool = False
    client_close_after_us: int = 70 * SECOND_US
    isolated_status: str = "completed"
    host_differs: bool = False
    guest_differs: bool = False
    quiet_ns: int = 40_000_000_000
    reset_before_syn: bool = False
    overlap: bool = False

    @staticmethod
    def started_us() -> int:
        """Return when the old recorder began, as the report implies.

        Returns
        -------
        int
            Microseconds since the epoch.
        """
        recorded = dt.datetime.fromisoformat(BASELINE_RECORDED).timestamp()
        return round((recorded - BASELINE_NS / 1e9) * SECOND_US)

    @staticmethod
    def packet(source: int, destination: int, flags: int, when: int) -> Report:
        """Build one TCP packet record.

        Returns
        -------
        dict[str, typing.Any]
            The record.
        """
        return {
            "src_ip": GUEST if source == SERVER_PORT else HOST,
            "src_port": source,
            "dst_port": destination,
            "flags": flags,
            "timestamp_us": when,
            "payload_hex": "",
        }

    def guest(self) -> list[Report]:
        """Build the guest packets that the SYN and reset lookups read.

        Returns
        -------
        list[dict[str, typing.Any]]
            The packets of the baseline and the isolated observation.
        """
        start = self.started_us()
        main_syn = start + 100 * SECOND_US
        tick_syn = main_syn + 40 * SECOND_US
        reset = tick_syn - 1 if self.reset_before_syn else tick_syn + 5000
        packets = [
            self.packet(MAIN_PORT, SERVER_PORT, SYN, main_syn),
            self.packet(TICK_PORT, SERVER_PORT, SYN, tick_syn),
            self.packet(SERVER_PORT, MAIN_PORT, RST, reset),
        ]
        if self.baseline_syn:
            packets.insert(0, self.packet(BASELINE_PORT, SERVER_PORT, SYN, start))
        if self.overlap:
            packets.append(self.packet(STRAY_PORT, 5501, SYN, main_syn + SECOND_US))
        return packets

    def reports(self) -> dict[str, Report]:
        """Build the two capture reports by directory name.

        Returns
        -------
        dict[str, dict[str, typing.Any]]
            The baseline report and the isolated report.
        """
        connects = [
            {
                "event": "connect",
                "connection": name,
                "local_address": ["127.0.0.1", port],
                "peer_address": ["127.0.0.1", 15500],
            }
            for name, port in [("main", MAIN_PORT), ("tick", TICK_PORT)]
        ]
        events = [
            *connects,
            {"event": "receive", "connection": "main", "elapsed_ns": SECOND_US},
            {"event": "quiet", "connection": "main", "elapsed_ns": self.quiet_ns},
        ]
        empty = {"sent_hex": "", "received_hex": ""}
        return {
            "failed-login-guest-drain": {
                "status": self.baseline_status,
                "recorded_at_utc": BASELINE_RECORDED,
                "events": [{"elapsed_ns": BASELINE_NS}],
            },
            "isolated-failure-quiet-and-tick": {
                "status": self.isolated_status,
                "events": events,
                "streams": {"main": dict(empty), "tick": dict(empty)},
            },
        }

    def stream(self, packets: list[typ.Any]) -> bytes:
        """Return the bytes of a stream, which differ when the view is broken.

        Returns
        -------
        bytes
            Empty, unless this view is the broken one.
        """
        view = packets[0] if isinstance(packets[0], str) else "guest"
        host_broken = view == "host" and self.host_differs
        guest_broken = view == "guest" and self.guest_differs
        return b"x" if host_broken or guest_broken else b""

    def direction(self, source: tuple[str, int]) -> list[Report]:
        """Return the packets that travelled from ``source`` on the old socket.

        Returns
        -------
        list[dict[str, typing.Any]]
            The client's close, or the server's data and any early close.
        """
        start = self.started_us()
        if source[1] == BASELINE_PORT:
            close = start + self.client_close_after_us
            return [self.packet(BASELINE_PORT, SERVER_PORT, FIN, close)]
        data = self.packet(SERVER_PORT, BASELINE_PORT, 0, start + SECOND_US)
        data["payload_hex"] = "aa"
        packets = [data]
        if self.guest_closes_early:
            early = start + 2 * SECOND_US
            packets.append(self.packet(SERVER_PORT, BASELINE_PORT, FIN, early))
        return packets


type Break = cabc.Callable[[Timing], None]
type Chain = list[tuple[str, str, Break]]


def baseline_completed(timing: Timing) -> None:
    """Report the baseline capture as completed."""
    timing.baseline_status = "completed"


def no_baseline_syn(timing: Timing) -> None:
    """Remove the SYN that identifies the old socket."""
    timing.baseline_syn = False


def early_guest_close(timing: Timing) -> None:
    """Make the guest close during the waiting period."""
    timing.guest_closes_early = True


def short_silence(timing: Timing) -> None:
    """Make the client close after thirty seconds."""
    timing.client_close_after_us = 30 * SECOND_US


def isolated_failed(timing: Timing) -> None:
    """Report the isolated capture as failed."""
    timing.isolated_status = "failed"


def host_differs(timing: Timing) -> None:
    """Make the host packet stream differ from the socket's."""
    timing.host_differs = True


def guest_differs(timing: Timing) -> None:
    """Make the guest packet stream differ from the socket's."""
    timing.guest_differs = True


def short_quiet(timing: Timing) -> None:
    """Shorten the quiet observation to twenty seconds."""
    timing.quiet_ns = 20_000_000_000


def early_reset(timing: Timing) -> None:
    """Make the reset precede the new connection."""
    timing.reset_before_syn = True


def stray_connection(timing: Timing) -> None:
    """Add another connection inside the isolated window."""
    timing.overlap = True


TIMING: Chain = [
    ("baseline status", "65-second observation status changed", baseline_completed),
    ("port", "Old socket port cannot be identified unambiguously", no_baseline_syn),
    ("early close", "Guest closed during baseline waiting period", early_guest_close),
    ("silence", "Baseline guest silence was shorter than65 seconds", short_silence),
    ("isolated status", "Isolated35-second observation changed", isolated_failed),
    ("host streams", "Isolated socket and packet streams differ", host_differs),
    ("guest streams", "Isolated guest stream differs", guest_differs),
    ("quiet", "No35-second quiet observation", short_quiet),
    ("reset", "Isolated reset preceded new connection", early_reset),
    (
        "overlap",
        "Other control/data connection overlaps isolated window",
        stray_connection,
    ),
]


def run_timing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, timing: Timing
) -> Report:
    """Run the timing checks against a synthetic observation.

    Returns
    -------
    dict[str, typing.Any]
        The result of ``verify_timing``.
    """
    reports = timing.reports()
    patch_all(
        monkeypatch,
        read_packets=lambda _path: ["host"],
        verify_capture=lambda path: reports[Path(path).name],
        stream=lambda packets, _source, _endpoint: timing.stream(packets),
        direction=lambda _packets, source, _endpoint: timing.direction(source),
    )
    return handshakes.verify_timing(tmp_path, timing.guest())


class TimingOrderTests:
    """Keep the timing checks in the order in which they have always run."""

    def test_the_unbroken_observation_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The synthetic observation passes, so each break is the cause."""
        result = run_timing(monkeypatch, tmp_path, Timing())
        assert result["baseline_guest_silence_seconds"] == pytest.approx(69.0), (
            "the baseline silence runs from the last data to the client's close"
        )

    @pytest.mark.parametrize("first", range(len(TIMING)))
    def test_the_first_broken_check_is_the_one_reported(
        self, first: int, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        timing = Timing()
        for _label, _message, apply in reversed(TIMING[first:]):
            apply(timing)
        _label, message, _apply = TIMING[first]
        with pytest.raises(ValueError, match=message):
            run_timing(monkeypatch, tmp_path, timing)
