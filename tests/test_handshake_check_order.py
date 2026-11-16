"""Pin the order of the handshake verifier's checks.

The goldens observe only the retained corpus, so the order in which an unsound
case is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. Every expectation was observed on the version of the scripts
before ``verify`` and ``verify_timing`` were split into smaller functions
(commit 8b4c3df).

The capture and packet readers are replaced with synthetic ones, in every module
that holds the name, so that a case can be broken one check at a time. A case
that breaks check ``n`` also breaks every check after it, so the message that
comes back names the first check that the verifier makes.
"""

import dataclasses as dc
import typing as typ
from pathlib import Path

import pytest
import verify_native_handshakes as handshakes
from handshake_helpers import patch_all
from verify_native_handshakes import FAILURE, HANDSHAKE, SUCCESS

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

FIN = 1
RST = 4
SYN = 2
CLIENT_PORT = 40000
CLIENT = ("10.0.2.2", CLIENT_PORT)
SERVER = ("10.0.2.15", 5500)
HOST_FORWARD = ("127.0.0.1", 15500)
HOST_CLIENT = ("127.0.0.1", CLIENT_PORT)


@dc.dataclass(slots=True)
class Scenario:
    """The synthetic observations behind one handshake case."""

    status: str = "completed"
    request: bytes = HANDSHAKE
    response: bytes = FAILURE
    host_sent: bytes | None = None
    host_received: bytes | None = None
    guest_input: bytes | None = None
    guest_output: bytes | None = None
    server_end: list[Report] = dc.field(
        default_factory=lambda: [{"flags": FIN, "timestamp_us": 100}]
    )
    client_end: list[Report] = dc.field(default_factory=list)
    last_data_us: int = 50

    def report(self) -> Report:
        """Build the capture report.

        Returns
        -------
        dict[str, typing.Any]
            The report that ``verify_capture`` returns.
        """
        return {
            "status": self.status,
            "events": [
                {
                    "event": "connect",
                    "local_address": list(HOST_CLIENT),
                    "peer_address": list(HOST_FORWARD),
                }
            ],
            "streams": {
                "main": {
                    "sent_hex": self.request.hex(),
                    "received_hex": self.response.hex(),
                }
            },
            "frames": [],
        }

    def stream(self, packets: list[str], source: tuple[str, int]) -> bytes:
        """Return the bytes that travelled from ``source``, as one view saw them.

        Returns
        -------
        bytes
            The request when ``source`` is the client, else the response.
        """
        client = source[1] == CLIENT_PORT
        view = packets[0]
        override = {
            ("host", True): self.host_sent,
            ("host", False): self.host_received,
            ("guest", True): self.guest_input,
            ("guest", False): self.guest_output,
        }[view, client]
        if override is not None:
            return override
        return self.request if client else self.response

    def direction(self, source: tuple[str, int]) -> list[Report]:
        """Return the close and data packets that travelled from ``source``.

        Returns
        -------
        list[dict[str, typing.Any]]
            The client's packets, or the server's.
        """
        if source[1] == CLIENT_PORT:
            return list(self.client_end)
        data = {"flags": 0, "payload_hex": "aa", "timestamp_us": self.last_data_us}
        return [data, *({**p, "payload_hex": ""} for p in self.server_end)]


type Break = cabc.Callable[[Scenario], None]
type Chain = list[tuple[str, str, Break]]


def install(
    monkeypatch: pytest.MonkeyPatch, directory: Path, name: str, scenario: Scenario
) -> None:
    """Lay out a one-case corpus and route the readers to the scenario."""
    case = directory / "transcripts" / name
    case.mkdir(parents=True)
    (case / "report.json").write_text("{}")
    patch_all(
        monkeypatch,
        read_packets=lambda path: ["host" if "host" in Path(path).name else "guest"],
        verify_capture=lambda _path: scenario.report(),
        stream=lambda packets, source, _endpoint: scenario.stream(packets, source),
        direction=lambda _packets, source, _endpoint: scenario.direction(source),
        verify_timing=lambda _directory, _guest: {},
    )


def run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str, scenario: Scenario
) -> Report:
    """Verify a one-case corpus.

    Returns
    -------
    dict[str, typing.Any]
        The result of ``verify``, when the case is accepted.
    """
    install(monkeypatch, tmp_path, name, scenario)
    return handshakes.verify(tmp_path)


def scenario_from(chain: Chain, first: int, base: Scenario) -> Scenario:
    """Break the scenario from check ``first`` on, last break first.

    Returns
    -------
    Scenario
        The broken scenario.
    """
    for _label, _message, apply in reversed(chain[first:]):
        apply(base)
    return base


def status(scenario: Scenario) -> None:
    """Report the capture as failed."""
    scenario.status = "failed"


def host_sent(scenario: Scenario) -> None:
    """Make the host's view of the request differ."""
    scenario.host_sent = b"x"


def host_received(scenario: Scenario) -> None:
    """Make the host's view of the response differ."""
    scenario.host_received = b"x"


def guest_input(scenario: Scenario) -> None:
    """Make the guest's view of the request differ."""
    scenario.guest_input = b"x"


def guest_output(scenario: Scenario) -> None:
    """Make the guest's view of the response differ."""
    scenario.guest_output = b"x"


def no_server_close(scenario: Scenario) -> None:
    """Remove the guest's close."""
    scenario.server_end = []


def success_response(scenario: Scenario) -> None:
    """Make the server accept a handshake that it should refuse."""
    scenario.response = SUCCESS


def client_first(scenario: Scenario) -> None:
    """Make the client close before the server."""
    scenario.client_end = [{"flags": FIN, "timestamp_us": 10}]


def late_data(scenario: Scenario) -> None:
    """Make the last failure bytes come after the server's close."""
    scenario.last_data_us = 200


FAILING: Chain = [
    ("status", "wrong-version: capture status changed", status),
    ("host sent", "wrong-version: host sent bytes differ", host_sent),
    ("host received", "wrong-version: host received bytes differ", host_received),
    ("guest input", "wrong-version: guest input differs", guest_input),
    ("guest output", "wrong-version: guest output differs", guest_output),
    ("close", "wrong-version: incomplete guest close observation", no_server_close),
    ("failure bytes", "wrong-version: failure handshake changed", success_response),
    ("close order", "wrong-version: server did not initiate close", client_first),
    ("data order", "wrong-version: close preceded failure bytes", late_data),
]


class RefusedHandshakeOrderTests:
    """Keep the checks of a refused handshake in the order they have always run."""

    def test_the_unbroken_case_is_accepted_up_to_the_catalogue(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The synthetic case passes every check but the catalogue's."""
        with pytest.raises(ValueError, match="Incomplete handshake case catalogue"):
            run(monkeypatch, tmp_path, "wrong-version", Scenario())

    @pytest.mark.parametrize("first", range(len(FAILING)))
    def test_the_first_broken_check_is_the_one_reported(
        self, first: int, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        scenario = scenario_from(FAILING, first, Scenario())
        _label, message, _apply = FAILING[first]
        with pytest.raises(ValueError, match=message):
            run(monkeypatch, tmp_path, "wrong-version", scenario)


def short_with_response(scenario: Scenario) -> None:
    """Give a truncated handshake a response."""
    scenario.response = FAILURE


def server_closes_first(scenario: Scenario) -> None:
    """Make the server close a truncated handshake."""
    scenario.client_end = []


SHORT: Chain = [
    ("truncated bytes", "Truncated handshake changed", short_with_response),
    ("half close", "Truncated input did not half-close first", server_closes_first),
]


class ShortHandshakeOrderTests:
    """Keep the checks of a truncated handshake in the order they have always run."""

    @pytest.mark.parametrize("first", range(len(SHORT)))
    def test_the_first_broken_check_is_the_one_reported(
        self, first: int, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        scenario = Scenario(
            request=HANDSHAKE[:11],
            response=b"",
            client_end=[{"flags": FIN, "timestamp_us": 10}],
        )
        scenario_from(SHORT, first, scenario)
        _label, message, _apply = SHORT[first]
        with pytest.raises(ValueError, match=message):
            run(monkeypatch, tmp_path, "short-eof", scenario)


def not_a_success(scenario: Scenario) -> None:
    """Give a normal handshake a response that is not the success word."""
    scenario.response = b"x"


def padded_success(scenario: Scenario) -> None:
    """Give a normal handshake the success word and more."""
    scenario.response = SUCCESS + b"x"


NORMAL: Chain = [
    ("success word", "normal-control: success handshake changed", not_a_success),
    ("exact bytes", "Normal handshake bytes changed", padded_success),
]


class NormalHandshakeOrderTests:
    """Keep the checks of a normal handshake in the order they have always run."""

    @pytest.mark.parametrize("first", range(len(NORMAL)))
    def test_the_first_broken_check_is_the_one_reported(
        self, first: int, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        scenario = scenario_from(NORMAL, first, Scenario(response=SUCCESS))
        _label, message, _apply = NORMAL[first]
        with pytest.raises(ValueError, match=message):
            run(monkeypatch, tmp_path, "normal-control", scenario)
