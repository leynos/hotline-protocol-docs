"""Drive the peer's pseudo-terminal for ``capture_shx_session``.

Part of the capture driver's module set (``capture_shx_session.CAPTURE_MODULES``).
:class:`Session` types each plan step to the peer and records what comes back;
:func:`start` forks the peer onto the terminal. This is the module that reads the
clock, the terminal and the child's status, so it holds those boundaries.
"""

import contextlib
import errno
import os
import pty
import re
import select
import signal
import time
import typing as typ

OUTPUT_BOUND = 8 * 1024 * 1024
READ_SIZE = 65536
POLL_SECONDS = 0.1
WARM_UP_SECONDS = 1
STEP_TIMEOUT = 15
SETTLE_SECONDS = 2
FAILED_TO_EXEC = 127
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

type Report = dict[str, typ.Any]


class Session:
    """The terminal of the peer: its descriptor, its output and its events."""

    def __init__(self, pid: int, descriptor: int, began: int) -> None:
        """Start timing a session.

        Parameters
        ----------
        pid : int
            The child's process id.
        descriptor : int
            The pseudo-terminal descriptor.
        began : int
            The ``time.monotonic_ns`` reading from before the fork.
        """
        self.pid = pid
        self.fd = descriptor
        self.began = began
        self.events: list[dict[str, str | int]] = []
        self.raw = bytearray()
        self.ended = False
        self.code: int | None = None
        self.completed = 0

    def event(self, kind: str, data: bytes = b"", step: int = -1) -> None:
        """Record one event.

        Parameters
        ----------
        kind : str
            ``"input"``, ``"output"`` or ``"process-exit"``.
        data : bytes
            The bytes, or the exit code as text.
        step : int
            The step index, or ``-1`` before the first.
        """
        self.events.append({
            "event": kind,
            "step": step,
            "elapsed_ns": time.monotonic_ns() - self.began,
            "hex": data.hex(),
        })

    def _read(self, step: int) -> bytes:
        """Read what the terminal has, if anything.

        Returns
        -------
        bytes
            The output, which is also kept and recorded.

        Raises
        ------
        ValueError
            If the output exceeds the capture bound.
        OSError
            If the read fails for a reason other than the terminal hanging up.
        """
        data = b""
        try:
            data = os.read(self.fd, READ_SIZE)
        except OSError as exc:
            if exc.errno != errno.EIO:
                raise
        if data:
            self.raw.extend(data)
            self.event("output", data, step)
            if len(self.raw) > OUTPUT_BOUND:
                message = "Terminal output exceeds capture bound"
                raise ValueError(message)
        return data

    def poll(self, timeout: float, step: int) -> bytes:
        """Wait for output, then note whether the child has exited.

        Returns
        -------
        bytes
            The output read, possibly empty.
        """
        data = b""
        if select.select([self.fd], [], [], timeout)[0]:
            data = self._read(step)
        child, status = (0, 0) if self.ended else os.waitpid(self.pid, os.WNOHANG)
        if child:
            self.ended, self.code = True, os.waitstatus_to_exitcode(status)
            self.event("process-exit", str(self.code).encode(), step)
        return data

    def warm_up(self) -> None:
        """Let the peer print its banner."""
        until = time.monotonic() + WARM_UP_SECONDS
        while time.monotonic() < until and not self.ended:
            self.poll(POLL_SECONDS, -1)

    def _wait_for(self, index: int, step: dict[str, typ.Any]) -> bool:
        """Collect output until the step's pattern matches or its time runs out.

        Returns
        -------
        bool
            Whether the step's ``expect`` pattern matched (always, if it has none).
        """
        segment = bytearray()
        deadline = time.monotonic() + step.get("timeout", STEP_TIMEOUT)
        matched = "expect" not in step
        while time.monotonic() < deadline:
            segment.extend(self.poll(POLL_SECONDS, index))
            clean = ANSI_ESCAPE.sub("", segment.decode("latin1"))
            if not matched and re.search(step["expect"], clean, re.DOTALL):
                matched = True
                deadline = self._settle(deadline, step)
            if self.ended:
                break
            if matched and "expect_exit" in step:
                continue
            if matched and "expect" not in step:
                deadline = self._settle(deadline, step)
        return matched

    @staticmethod
    def _settle(deadline: float, step: dict[str, typ.Any]) -> float:
        """Shorten a deadline to the step's settling time from now.

        Returns
        -------
        float
            The earlier of the deadline and now plus the settling time.
        """
        return min(
            deadline, time.monotonic() + step.get("settle_seconds", SETTLE_SECONDS)
        )

    def _exit_differs(self, step: dict[str, typ.Any]) -> bool:
        """Say whether the child has not exited with the status the step expects.

        Returns
        -------
        bool
            ``True`` if it is still running or exited with another status.
        """
        return not self.ended or self.code != step["expect_exit"]

    def run_step(self, index: int, step: dict[str, typ.Any]) -> None:
        """Type one command and check what comes back.

        Raises
        ------
        RuntimeError
            If the peer exited before the step, or exited with another status.
        TimeoutError
            If the output did not match the expected pattern in time.
        """
        if self.ended:
            message = f"Peer exited before step {index}: {self.code}"
            raise RuntimeError(message)
        value = step["command"].encode() + b"\n"
        os.write(self.fd, value)
        self.event("input", value, index)
        if not self._wait_for(index, step):
            message = f"Step {index} output did not match {step['expect']!r}"
            raise TimeoutError(message)
        if "expect_exit" in step and self._exit_differs(step):
            message = f"Step {index} exit differs: {self.code}"
            raise RuntimeError(message)
        self.completed += 1

    def run(self, plan: Report) -> None:
        """Run the warm-up and every step of the plan."""
        self.warm_up()
        for index, step in enumerate(plan["steps"]):
            self.run_step(index, step)

    def stop(self) -> None:
        """Terminate the child if it is still running, then close the terminal."""
        if not self.ended:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.pid, signal.SIGTERM)
            _, status = os.waitpid(self.pid, 0)
            self.code = os.waitstatus_to_exitcode(status)
        os.close(self.fd)


def start(command: list[str]) -> Session:
    """Fork the peer onto a pseudo-terminal.

    Returns
    -------
    Session
        The parent's side of the session.
    """
    began = time.monotonic_ns()
    pid, descriptor = pty.fork()
    if pid == 0:
        try:
            os.execvpe(  # ruff: ignore[start-process-with-no-shell]  # the child becomes the sandbox command
                command[0], command, dict(os.environ, TERM="dumb")
            )
        finally:
            os._exit(FAILED_TO_EXEC)
    return Session(pid, descriptor, began)
