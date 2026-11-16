"""Collect the bytes of the four board sockets and cut them into strict frames.

Part of the board runner (``native_board_control``), whose ``CAPTURE_MODULES``
lists this module and which re-exports every public name below.
"""

import hashlib
import select
import socket
import time
import typing as typ

import native_board_cases as cases
from protocol_capture import Recorder, decode_frame
from verify_native_shx import fields

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

HEADER_BYTES = 20
SIZE_START = 16
SHORT_FRAME_BYTES = 22
MAX_FRAME_DATA = 65541
RECEIVE_CHUNK = 65536
MAX_SOCKETS = 4
CONNECT_SECONDS = 5
SEND_STALL_SECONDS = 3
HELLO_REPLY_BYTES = 8
CLOSE_WAIT_SECONDS = 2
DEFAULT_WAIT_SECONDS = 5


def need(ok: bool, message: str) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]  # called as need(ok, message) throughout
    """Fail closed unless a condition holds.

    Parameters
    ----------
    ok : bool
        The condition.
    message : str
        The message of the failure.

    Raises
    ------
    ValueError
        If the condition is false.
    """
    if not ok:
        raise ValueError(message)


def sha(raw: bytes) -> str:
    """Hash bytes.

    Returns
    -------
    str
        The SHA-256 in lower-case hexadecimal.
    """
    return hashlib.sha256(raw).hexdigest()


def strict(raw: bytes) -> Report:
    """Decode one physical frame and refuse any malformed or fragmented one.

    Returns
    -------
    dict[str, typing.Any]
        The decoded frame.
    """
    need(len(raw) >= SHORT_FRAME_BYTES, "Short physical frame")
    size = int.from_bytes(raw[SIZE_START:HEADER_BYTES], "big")
    need(
        len(raw) == HEADER_BYTES + size and size <= MAX_FRAME_DATA,
        "Frame size/fragment differs",
    )
    value = decode_frame(raw)
    need(
        value["flags"] == 0
        and value["total_size"] == size
        and value.get("declared_field_count") == len(value.get("fields", []))
        and not value.get("unconsumed_hex"),
        "Malformed or fragmented board frame",
    )
    fields(value)
    return value


def frame_fields(frame: Report) -> dict[int, bytes]:
    """Read a frame's fields as a map, refusing a repeated field.

    Returns
    -------
    dict[int, bytes]
        The field values by identifier.
    """
    result = fields(frame)
    need(len(result) == len(frame["fields"]), "Duplicate board TLV")
    return result


def one(  # pylint: disable=too-many-arguments,too-many-positional-arguments  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # the five selectors name one frame, in the order every caller gives them
    frames: list[Report], name: str, kind: int, identifier: int, reply: int
) -> Report:
    """Find the single frame of a flow with a given type, id and reply marker.

    Returns
    -------
    dict[str, typing.Any]
        The frame.
    """
    matches = [
        frame
        for frame in frames
        if frame["connection"] == name
        and frame["type"] == kind
        and frame["id"] == identifier
        and frame["is_reply"] == reply
    ]
    need(len(matches) == 1, f"Missing/duplicate {name}/{kind}/{identifier}")
    return matches[0]


class Wire:
    """Collect all bytes from four sockets; never assume a cross-socket order."""

    def __init__(self, recorder: Recorder, deadline: float) -> None:
        """Start with no sockets, for a case that must finish by ``deadline``."""
        self.recorder = recorder
        self.deadline = deadline
        self.buffers: dict[str, bytearray] = {}
        self.eof: set[str] = set()
        self.bytes_seen = 0
        self.frames_seen = 0
        self.action = 0

    def connect(self, name: str, endpoint: tuple[str, int]) -> None:
        """Open a flow and complete the TRTP hello exchange."""
        need(len(self.recorder.sockets) < MAX_SOCKETS, "Too many board sockets")
        sock = socket.create_connection(
            endpoint, min(CONNECT_SECONDS, self.deadline - time.monotonic())
        )
        sock.settimeout(0.0)
        self.recorder.sockets[name] = sock
        self.buffers[name] = bytearray()
        self.recorder.event(self.action, name, "connect")
        self.recorder.events[-1].update(
            local_address=list(sock.getsockname()),
            peer_address=list(sock.getpeername()),
        )
        self.action += 1
        self.send(name, bytes.fromhex(cases.HELLO))
        hello = bytearray()
        while len(hello) < HELLO_REPLY_BYTES:
            self.poll(
                min(self.deadline, time.monotonic() + CONNECT_SECONDS),
                handshake=(name, hello),
            )
        need(hello.hex() == cases.HELLO_REPLY, "Board TRTP handshake differs")

    def send(self, name: str, data: bytes) -> None:
        """Send every byte of ``data``, recording each partial write."""
        sock = self.recorder.sockets[name]
        offset = 0
        while offset < len(data):
            remaining = self.deadline - time.monotonic()
            need(remaining > 0, "Board send deadline")
            _, ready, _ = select.select(
                [], [sock], [], min(remaining, SEND_STALL_SECONDS)
            )
            need(bool(ready), "Board send stalled")
            count = sock.send(data[offset:])
            need(count > 0, "Board send EOF")
            self.recorder.event(
                self.action, name, "send", data[offset : offset + count]
            )
            offset += count
        self.action += 1

    def mark(self, name: str, label: str) -> None:
        """Record the start of a labelled operation."""
        self.recorder.event(-1, name, "operation")
        self.recorder.events[-1]["label"] = label

    def _frames_of(self, name: str) -> None:
        """Cut every complete frame from a flow's buffer and record it."""
        buffer = self.buffers[name]
        while len(buffer) >= HEADER_BYTES:
            size = int.from_bytes(buffer[SIZE_START:HEADER_BYTES], "big")
            need(size <= MAX_FRAME_DATA, "Board frame size bound")
            if len(buffer) < HEADER_BYTES + size:
                break
            frame_raw = bytes(buffer[: HEADER_BYTES + size])
            del buffer[: HEADER_BYTES + size]
            decoded = strict(frame_raw)
            self.frames_seen += 1
            need(self.frames_seen <= cases.MAX_FRAMES, "Board frame-count bound")
            self.recorder.frames.append({
                "action": -1,
                "connection": name,
                "arrival_ns": time.monotonic_ns() - self.recorder.started,
                "raw_hex": frame_raw.hex(),
                **decoded,
            })

    def _receive(
        self,
        name: str,
        sock: socket.socket,
        handshake: tuple[str, bytearray] | None,
    ) -> None:
        """Read what a ready socket holds; take the hello reply first if awaited."""
        need(self.bytes_seen < cases.MAX_CAPTURE_BYTES, "Board capture byte bound")
        raw = sock.recv(min(RECEIVE_CHUNK, cases.MAX_CAPTURE_BYTES - self.bytes_seen))
        if not raw:
            self.recorder.event(-1, name, "eof")
            self.eof.add(name)
            return
        self.bytes_seen += len(raw)
        need(self.bytes_seen <= cases.MAX_CAPTURE_BYTES, "Board capture byte bound")
        self.recorder.event(-1, name, "receive", raw)
        if handshake and handshake[0] == name:
            missing = HELLO_REPLY_BYTES - len(handshake[1])
            handshake[1].extend(raw[:missing])
            raw = raw[missing:]
            if not raw:
                return
        self.buffers[name].extend(raw)
        self._frames_of(name)

    def poll(
        self, until: float, handshake: tuple[str, bytearray] | None = None
    ) -> None:
        """Wait for the sockets until ``until`` and read each that is ready."""
        active = {
            name: sock
            for name, sock in self.recorder.sockets.items()
            if name not in self.eof
        }
        remaining = min(until, self.deadline) - time.monotonic()
        need(remaining > 0, "Board observation deadline")
        ready, _, _ = select.select(list(active.values()), [], [], remaining)
        if not ready:
            return
        for name, sock in active.items():
            if sock in ready:
                self._receive(name, sock, handshake)

    def until(
        self, predicate: cabc.Callable[[], bool], seconds: float = DEFAULT_WAIT_SECONDS
    ) -> None:
        """Poll until a condition holds, or fail naming the missing frame."""
        stop = min(self.deadline, time.monotonic() + seconds)
        while not predicate():
            need(time.monotonic() < stop, "Required board frame missing")
            self.poll(stop)

    def observe(self, seconds: float) -> None:
        """Poll for a fixed time, whatever arrives."""
        stop = min(self.deadline, time.monotonic() + seconds)
        while time.monotonic() < stop:
            self.poll(stop)

    def _half_close(self, name: str, sock: socket.socket) -> None:
        """Shut the write side, record the outcome, then wait for the peer's EOF."""
        try:
            sock.shutdown(socket.SHUT_WR)
            self.recorder.event(-1, name, "shutdown_write")
        except OSError as exc:
            self.recorder.event(-1, name, "shutdown_error")
            self.recorder.events[-1]["error"] = str(exc)
        stop = min(self.deadline, time.monotonic() + CLOSE_WAIT_SECONDS)
        while name not in self.eof and time.monotonic() < stop:
            self.poll(stop)
        if name not in self.eof:
            self.recorder.event(-1, name, "no_eof_within_2s")
        need(not self.buffers[name], "Truncated board frame in tail")

    def close(self, name: str) -> None:
        """Half-close a flow, read its tail, and close it."""
        sock = self.recorder.sockets.get(name)
        if sock is None:
            return
        try:
            self._half_close(name, sock)
        finally:
            try:
                sock.close()
            except OSError as exc:
                self.recorder.event(-1, name, "close_error")
                self.recorder.events[-1]["error"] = str(exc)
            else:
                self.recorder.event(-1, name, "close")
            del self.recorder.sockets[name]
