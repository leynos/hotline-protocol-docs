"""Fakes for the terminal, process and clock boundaries of ``capture_shx_session.py``.

The capture driver forks a pseudo-terminal child that runs the peer under
``bwrap`` and ``strace``, reads and writes the terminal, and waits for the child.
None of that may happen in a test. ``Terminal`` stands in for ``pty``, ``select``,
``time`` and the process calls of ``os``: it answers each command that the driver
types from a script, can end the child, and keeps a fake clock that advances only
when the driver waits. Nothing is forked, executed or read from a real descriptor.
"""

import dataclasses as dc
import errno
import os
import types
import typing as typ

if typ.TYPE_CHECKING:
    import collections.abc as cabc

PID = 4242
FD = 77
TERMINATED = 15  # the wait status of a child that SIGTERM ended


def require(*, ok: bool, name: str) -> None:
    """Fail when the driver addresses something other than the fake child.

    Raises
    ------
    AssertionError
        If ``ok`` is false.
    """
    if not ok:
        message = f"unexpected {name}"
        raise AssertionError(message)


@dc.dataclass(slots=True)
class Terminal:
    """A scripted pseudo-terminal child.

    Attributes
    ----------
    replies : dict[str, bytes]
        What the child prints when a command is typed.
    exits : dict[str, int]
        The exit code with which the child ends once the command is typed.
    initial : bytes
        What the child prints at start.
    ended : int | None
        The exit code of a child that has already ended, if any.
    failing_read : OSError | None
        An error that every read raises.
    on_write : collections.abc.Callable[[bytes], None]
        Called with each typed line, so that a test can disturb the host.
    lookup_error : bool
        Whether ``killpg`` finds no process.
    """

    replies: dict[str, bytes] = dc.field(default_factory=dict)
    exits: dict[str, int] = dc.field(default_factory=dict)
    initial: bytes = b""
    ended: int | None = None
    failing_read: OSError | None = None
    on_write: cabc.Callable[[bytes], None] = lambda _: None
    lookup_error: bool = False
    queue: list[bytes] = dc.field(default_factory=list)
    written: list[bytes] = dc.field(default_factory=list)
    closed: list[int] = dc.field(default_factory=list)
    killed: list[tuple[int, int]] = dc.field(default_factory=list)
    execs: list[list[str]] = dc.field(default_factory=list)
    clock: float = 0.0
    reaped: bool = False
    readings: int = 0

    def fork(self) -> tuple[int, int]:
        """Pretend to fork a child; the parent's answer is the only one given.

        Returns
        -------
        tuple[int, int]
            The child's process id and the terminal descriptor.
        """
        if self.initial:
            self.queue.append(self.initial)
        return PID, FD

    def select(
        self, readable: list[int], _w: list[int], _x: list[int], timeout: float
    ) -> tuple[list[int], list[int], list[int]]:
        """Wait on the descriptor, advancing the clock by the timeout.

        Returns
        -------
        tuple[list[int], list[int], list[int]]
            The descriptor as readable when output is queued or reads fail.
        """
        self.clock += timeout
        ready = bool(self.queue) or self.failing_read is not None
        return (list(readable) if ready else []), [], []

    def read(self, descriptor: int, _size: int) -> bytes:
        """Read the next queued chunk.

        Returns
        -------
        bytes
            The chunk, or nothing when none is queued.
        """
        require(ok=descriptor == FD, name="descriptor")
        if self.failing_read is not None:
            raise self.failing_read
        return self.queue.pop(0) if self.queue else b""

    def write(self, descriptor: int, data: bytes) -> int:
        """Take a typed line and queue the scripted reply.

        Returns
        -------
        int
            The number of bytes written.
        """
        require(ok=descriptor == FD, name="descriptor")
        self.written.append(data)
        self.on_write(data)
        command = data.decode().rstrip("\n")
        if command in self.replies:
            self.queue.append(self.replies[command])
        if command in self.exits:
            self.ended = self.exits[command]
        return len(data)

    def waitpid(self, pid: int, flags: int) -> tuple[int, int]:
        """Reap the child if it has ended, or on a blocking wait.

        Returns
        -------
        tuple[int, int]
            The process id and wait status, or zeros while the child lives.
        """
        require(ok=pid == PID, name="pid")
        if flags:
            if self.ended is None:
                return 0, 0
            return PID, self.ended << 8
        self.reaped = True
        status = self.ended << 8 if self.ended is not None else TERMINATED
        return PID, status

    def killpg(self, pid: int, sig: int) -> None:
        """Record a signal to the child's group.

        Raises
        ------
        ProcessLookupError
            If scripted so.
        """
        self.killed.append((pid, sig))
        if self.lookup_error:
            raise ProcessLookupError

    def close(self, descriptor: int) -> None:
        """Record a closed descriptor, once."""
        if descriptor not in self.closed:
            self.closed.append(descriptor)

    def execvpe(self, program: str, argv: list[str], _env: dict[str, str]) -> None:
        """Refuse to execute anything.

        Raises
        ------
        AssertionError
            Always: the fake parent never runs the child branch.
        """
        self.execs.append([program, *argv])
        message = "the child branch must not run in a test"
        raise AssertionError(message)

    def monotonic(self) -> float:
        """Read the fake clock.

        Returns
        -------
        float
            The seconds waited so far.
        """
        self.readings += 1
        return self.clock

    def monotonic_ns(self) -> int:
        """Read the fake clock in nanoseconds.

        Returns
        -------
        int
            The nanoseconds waited so far.
        """
        return round(self.clock * 1e9)

    def namespaces(self, environ: dict[str, str]) -> dict[str, types.SimpleNamespace]:
        """Build the replacements for the driver's module references.

        Parameters
        ----------
        environ : dict[str, str]
            The environment that the fake ``os`` shows.

        Returns
        -------
        dict[str, types.SimpleNamespace]
            Fakes for ``os``, ``pty``, ``select``, ``shutil`` and ``time``.
        """
        fake_os = types.SimpleNamespace(
            environ=environ,
            WNOHANG=1,
            execvpe=self.execvpe,
            _exit=self.close,
            write=self.write,
            read=self.read,
            waitpid=self.waitpid,
            waitstatus_to_exitcode=os.waitstatus_to_exitcode,
            killpg=self.killpg,
            close=self.close,
        )
        return {
            "os": fake_os,
            "pty": types.SimpleNamespace(fork=self.fork),
            "select": types.SimpleNamespace(select=self.select),
            "shutil": types.SimpleNamespace(which=lambda name: f"/usr/bin/{name}"),
            "time": types.SimpleNamespace(
                monotonic=self.monotonic, monotonic_ns=self.monotonic_ns
            ),
        }


EIO = OSError(errno.EIO, "Input/output error")
