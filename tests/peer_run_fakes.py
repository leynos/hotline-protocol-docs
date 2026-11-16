"""Fakes for the process, socket and clock boundaries of ``peer_tolerance_run.py``.

The runner starts a root packet recorder, a fixture server and the capture
driver, binds probe sockets and sleeps. None of that may happen in a test, so
the runner's own references to ``subprocess``, ``socket`` and ``time`` are
replaced by the namespaces that :class:`Boundary` builds. The fakes record every
call and answer from a script that a test sets before the run.
"""

import dataclasses as dc
import json
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # only its exception types and constants are used
import types
import typing as typ
from pathlib import Path

if typ.TYPE_CHECKING:
    import collections.abc as cabc

FIRST_PORT = 15600


@dc.dataclass(slots=True)
class FakeProcess:
    """A child process that answers from a script.

    Attributes
    ----------
    exit_code : int | None
        What ``poll`` returns: ``None`` while the process is alive.
    wait_code : int
        What ``wait`` returns.
    stalls : bool
        Whether the first ``wait`` raises ``TimeoutExpired``.
    signals : list[int]
        The signals sent to the process, in order.
    waits : list[float | None]
        The timeouts that ``wait`` was called with, in order.
    """

    exit_code: int | None = None
    wait_code: int = 0
    stalls: bool = False
    signals: list[int] = dc.field(default_factory=list)
    waits: list[float | None] = dc.field(default_factory=list)
    polls: int = 0

    def poll(self) -> int | None:
        """Report whether the process has ended.

        Returns
        -------
        int | None
            The scripted exit code, or ``None`` while alive.
        """
        self.polls += 1
        return self.exit_code

    def wait(self, timeout: float | None = None) -> int:
        """Wait for the process, stalling once if scripted.

        Returns
        -------
        int
            The scripted wait code.

        Raises
        ------
        subprocess.TimeoutExpired
            On the first call, when the process is scripted to stall.
        """
        first = not self.waits
        self.waits.append(timeout)
        if self.stalls and first:
            raise subprocess.TimeoutExpired("fake", timeout or 0)
        return self.wait_code

    def send_signal(self, sig: int) -> None:
        """Record a signal, and that the process has been told to end."""
        self.signals.append(sig)
        self.exit_code = self.wait_code


@dc.dataclass(slots=True)
class Probe:
    """A socket that records its bind and fails for a busy port."""

    boundary: Boundary

    def __enter__(self) -> Probe:
        """Enter the context.

        Returns
        -------
        Probe
            This probe.
        """
        return self

    def __exit__(self, *_: object) -> None:
        """Leave the context."""

    def bind(self, address: tuple[str, int]) -> None:
        """Record a bind, failing for a busy port.

        Raises
        ------
        OSError
            If the port is scripted as busy.
        """
        self.boundary.binds.append(address)
        if address[1] in self.boundary.busy_ports:
            message = "Address already in use"
            raise OSError(message)


@dc.dataclass(slots=True)
class Boundary:
    """The recorded calls and scripted answers of the runner's outside world.

    Attributes
    ----------
    recorder_exit : int | None
        The exit code that the packet recorder reports; ``None`` keeps it alive.
    fixture_exit : int | None
        The exit code that a fixture server reports at start; ``None`` keeps it
        alive.
    fixture_ready : bool
        Whether the fixture server writes its ``ready.json``.
    fixture_stalls : bool
        Whether the fixture server fails to end when waited for.
    fixture_code : int
        The code with which the fixture server ends.
    session_code : int
        The return code of the capture driver.
    busy_ports : set[int]
        The ports whose probe bind fails.
    during_session : collections.abc.Callable[[], None]
        Called while the capture driver runs, to let a test disturb the host.
    """

    recorder_exit: int | None = None
    fixture_exit: int | None = None
    fixture_ready: bool = True
    fixture_stalls: bool = False
    fixture_code: int = 0
    session_code: int = 0
    busy_ports: set[int] = dc.field(default_factory=set)
    during_session: cabc.Callable[[], None] = lambda: None
    popens: list[tuple[list[str], FakeProcess]] = dc.field(default_factory=list)
    runs: list[tuple[list[str], dict[str, object]]] = dc.field(default_factory=list)
    binds: list[tuple[str, int]] = dc.field(default_factory=list)
    sleeps: list[float] = dc.field(default_factory=list)
    clock: float = 0.0

    def popen(self, argv: list[str], **_: object) -> FakeProcess:
        """Start a fake child: the packet recorder or a fixture server.

        Returns
        -------
        FakeProcess
            The process, which has been recorded.
        """
        if argv[0] == "sudo":
            process = FakeProcess(exit_code=self.recorder_exit)
        else:
            process = FakeProcess(
                exit_code=self.fixture_exit,
                wait_code=self.fixture_code,
                stalls=self.fixture_stalls,
            )
            if self.fixture_ready:
                fixture = Path(argv[argv.index("--output") + 1])
                fixture.mkdir(parents=True, exist_ok=True)
                (fixture / "ready.json").write_text(json.dumps({"ready": True}))
        self.popens.append((argv, process))
        return process

    def run(self, argv: list[str], **options: object) -> types.SimpleNamespace:
        """Run the fake capture driver.

        Returns
        -------
        types.SimpleNamespace
            A result with the scripted return code and some output.
        """
        self.runs.append((argv, options))
        self.during_session()
        return types.SimpleNamespace(
            returncode=self.session_code, stdout="driver out\n", stderr="driver err\n"
        )

    def socket(self) -> Probe:
        """Build a probe socket that fails to bind a busy port.

        Returns
        -------
        Probe
            A context manager with a ``bind`` method.
        """
        return Probe(self)

    def monotonic(self) -> float:
        """Advance and read the fake clock.

        Returns
        -------
        float
            The time, which grows by a second at each reading.
        """
        self.clock += 1.0
        return self.clock

    def namespaces(self) -> dict[str, types.SimpleNamespace]:
        """Build the replacements for the runner's three module references.

        Returns
        -------
        dict[str, types.SimpleNamespace]
            Fakes for ``subprocess``, ``socket`` and ``time``, by name.
        """
        return {
            "subprocess": types.SimpleNamespace(
                Popen=self.popen,
                run=self.run,
                TimeoutExpired=subprocess.TimeoutExpired,
                STDOUT=subprocess.STDOUT,
            ),
            "socket": types.SimpleNamespace(socket=self.socket),
            "time": types.SimpleNamespace(
                sleep=self.sleeps.append, monotonic=self.monotonic
            ),
        }
