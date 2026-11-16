"""Collect the frames of both sockets of one overlap, in whatever order they land.

The collector reads each socket in bounded chunks and parses every complete
frame that the chunks form. It makes no assumption about the order in which
the two sockets deliver their frames.
"""

import select
import time
import typing as typ

from native_roster_overlap_control_checks import frame_key, need
from native_wire_names import FRAME_HEADER_BYTES, FRAME_SIZE_START
from protocol_capture import Recorder, decode_frame

if typ.TYPE_CHECKING:
    import socket

MAX_BYTES = 65536  # the inbound bytes that one overlap may read in total
MAX_FRAMES = 32  # the frames that one overlap may parse in total
MAX_DRAIN_DATA = 65516  # the largest data size of a drained frame: 64 KiB less a header
READ_CHUNK_BYTES = 4096  # the most bytes that one read from a socket asks for


class DualDrain:
    """Bounded two-socket byte collector; no expected arrival order."""

    def __init__(self, recorder: Recorder, epoch_deadline: float) -> None:
        """Start an empty collector for the two sockets of a recorder.

        Parameters
        ----------
        recorder : Recorder
            The recorder whose sockets are read and whose frames grow.
        epoch_deadline : float
            The monotonic time after which no drain may run.
        """
        self.recorder = recorder
        self.deadline = epoch_deadline
        self.buffers = {"a": bytearray(), "b": bytearray()}
        self.eof: set[str] = set()
        self.bytes_read = 0
        self.frames_seen = 0

    def pump(self, until: float) -> None:
        """Wait until a socket is readable, then read it and parse its frames.

        Parameters
        ----------
        until : float
            The monotonic time after which the wait gives up.

        Raises
        ------
        TimeoutError
            When the drain expired, both sockets closed, or nothing arrived.
        """
        active = {
            label: sock
            for label, sock in self.recorder.sockets.items()
            if label not in self.eof
        }
        remaining = min(until, self.deadline) - time.monotonic()
        if remaining <= 0 or not active:
            message = "Dual-socket drain expired or both sockets closed"
            raise TimeoutError(message)
        ready, _, _ = select.select(list(active.values()), [], [], remaining)
        if not ready:
            message = "Dual-socket drain timed out"
            raise TimeoutError(message)
        for label, sock in active.items():
            if sock in ready:
                self._read(label, sock)

    def _read(self, label: str, sock: socket.socket) -> None:
        """Read one chunk from a readable socket and parse the frames it completes.

        Parameters
        ----------
        label : str
            The connection label of the socket, ``"a"`` or ``"b"``.
        sock : socket.socket
            The readable socket.
        """
        need(self.bytes_read < MAX_BYTES, "Dual-socket byte limit")
        raw = sock.recv(min(READ_CHUNK_BYTES, MAX_BYTES - self.bytes_read))
        if not raw:
            self.recorder.event(-1, label, "eof")
            self.eof.add(label)
            need(not self.buffers[label], "Truncated frame at socket EOF")
            return
        self.recorder.event(-1, label, "receive", raw)
        self.bytes_read += len(raw)
        need(self.bytes_read <= MAX_BYTES, "Dual-socket byte limit")
        self.buffers[label].extend(raw)
        while len(self.buffers[label]) >= FRAME_HEADER_BYTES:
            if not self._take_frame(label):
                break

    def _take_frame(self, label: str) -> bool:
        """Parse the next frame of a socket's buffer, if the buffer holds all of it.

        Parameters
        ----------
        label : str
            The connection label of the socket, ``"a"`` or ``"b"``.

        Returns
        -------
        bool
            ``True`` when a frame was taken; ``False`` when the buffer holds
            only part of one.
        """
        size = int.from_bytes(
            self.buffers[label][FRAME_SIZE_START:FRAME_HEADER_BYTES], "big"
        )
        need(size <= MAX_DRAIN_DATA, "Oversize frame in dual drain")
        if len(self.buffers[label]) < FRAME_HEADER_BYTES + size:
            return False
        frame_raw = bytes(self.buffers[label][: FRAME_HEADER_BYTES + size])
        del self.buffers[label][: FRAME_HEADER_BYTES + size]
        decoded = decode_frame(frame_raw)
        need(
            decoded["total_size"] == decoded["data_size"]
            and decoded.get("declared_field_count") == len(decoded.get("fields", []))
            and not decoded.get("unconsumed_hex"),
            "Malformed or fragmented dual-drain frame",
        )
        self.frames_seen += 1
        need(self.frames_seen <= MAX_FRAMES, "Dual-socket frame limit")
        self.recorder.frames.append({
            "action": -1,
            "connection": label,
            "arrival_ns": time.monotonic_ns() - self.recorder.started,
            "raw_hex": frame_raw.hex(),
            **decoded,
        })
        return True

    def until(
        self, required: set[tuple[str, int, int, int]], seconds: float
    ) -> list[dict]:
        """Drain both sockets until every required frame key has arrived.

        Parameters
        ----------
        required : set[tuple[str, int, int, int]]
            The frame keys that must all arrive.
        seconds : float
            The longest that this drain may wait, before the epoch deadline.

        Returns
        -------
        list[dict]
            The frames that this drain collected, in arrival order.
        """
        start = len(self.recorder.frames)
        stop = min(time.monotonic() + seconds, self.deadline)
        while not required.issubset({
            frame_key(f) for f in self.recorder.frames[start:]
        }) or any(self.buffers.values()):
            self.pump(stop)
        return self.recorder.frames[start:]
