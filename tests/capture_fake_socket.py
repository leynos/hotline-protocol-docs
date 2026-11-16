"""A fake socket and step runner for characterizing ``protocol_capture``.

The socket serves queued chunks and records what is sent, so a ``Recorder`` can
execute steps without opening anything.
"""

import socket
import struct
import typing as typ

import protocol_capture as pc

LIMIT = 8 * 1024 * 1024

type Step = dict[str, typ.Any]


class FakeSocket:
    """A socket that serves queued chunks and records what is sent."""

    def __init__(self, chunks: list[bytes] | None = None, step: int = 0) -> None:
        """Queue the chunks to receive.

        Parameters
        ----------
        chunks : list[bytes] | None
            Each ``recv`` returns the next chunk, then ``b""``.
        step : int
            How many bytes each ``send`` accepts; zero accepts all and -1 none.
        """
        self.chunks = list(chunks or [])
        self.step = step
        self.sent = b""
        self.timeouts: list[float] = []
        self.shutdowns: list[int] = []
        self.closed = False
        self.closed_for_writing = False
        self.last_timeout = 0.0
        self.silent = False

    def settimeout(self, value: float) -> None:
        """Record a timeout."""
        self.last_timeout = value
        self.timeouts.append(value)

    def recv(self, size: int) -> bytes:
        """Serve the next chunk, cut to ``size``.

        Returns
        -------
        bytes
            The bytes, or ``b""`` at the end.

        Raises
        ------
        TimeoutError
            If the socket is silent.
        """
        if self.silent:
            raise TimeoutError
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
            chunk = chunk[:size]
        return chunk

    def send(self, data: bytes) -> int:
        """Accept some bytes.

        Returns
        -------
        int
            The number accepted.
        """
        if self.step == -1:
            return 0
        count = self.step or len(data)
        self.sent += data[:count]
        return count

    def shutdown(self, how: int) -> None:
        """Record a shutdown."""
        self.closed_for_writing = how == socket.SHUT_WR
        self.shutdowns.append(how)

    def close(self) -> None:
        """Record the close."""
        self.closed = True


def recorder(fake: FakeSocket | None = None) -> pc.Recorder:
    """Make a recorder with a fake on ``main``.

    Returns
    -------
    protocol_capture.Recorder
        The recorder.
    """
    plan = {"endpoints": {}}
    rec = pc.Recorder(plan)
    rec.sockets["main"] = typ.cast("socket.socket", fake or FakeSocket())
    return rec


def frame(payload: bytes = b"", *, is_reply: int = 1, kind: int = 0) -> bytes:
    """Build a complete physical frame.

    Returns
    -------
    bytes
        The header and the payload.
    """
    head = struct.pack(">BBHIIII", 0, is_reply, kind, 7, 0, len(payload), len(payload))
    return head + payload


def ending(rec: pc.Recorder, step: Step) -> str:
    """Execute a step and describe how it ended.

    Returns
    -------
    str
        The type and message of the error, or ``"done"``.
    """
    try:
        rec.execute(0, step)
    except Exception as error:  # ruff: ignore[blind-except]  # the type is the observation
        return f"{type(error).__name__}: {error}"
    return "done"


def kinds(rec: pc.Recorder) -> list[str]:
    """List the events' kinds.

    Returns
    -------
    list[str]
        The ``event`` of each recorded event.
    """
    return [event["event"] for event in rec.events]
