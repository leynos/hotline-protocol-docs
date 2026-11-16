"""Hold the sockets, bytes and frames of one liveness run in a timeline.

Part of the liveness runner (``native_liveness_control``), whose
``CAPTURE_MODULES`` lists this module and which re-exports every public name
below.
"""

import hashlib
import select
import socket
import time
import typing as typ

import native_liveness_cases as cases
from protocol_capture import Recorder, decode_frame

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

# The size of a frame header, and the offset of the data size within it.
HEADER_BYTES = 20
SIZE_START = 16
RECEIVE_CHUNK = 65536
POLL_SLICE_SECONDS = 0.05
IDLE_SLICE_SECONDS = 0.02
DRAIN_SECONDS = 3
HELLO_REPLY_BYTES = 8
DEFAULT_STEP_TIMEOUT = 2


def need(condition: bool, message: str) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]  # called as need(condition, message) throughout
    """Fail closed unless a condition holds.

    Parameters
    ----------
    condition : bool
        The condition.
    message : str
        The message of the failure.

    Raises
    ------
    ValueError
        If the condition is false.
    """
    if not condition:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    """Hash bytes.

    Returns
    -------
    str
        The SHA-256 in lower-case hexadecimal.
    """
    return hashlib.sha256(raw).hexdigest()


class Timeline:
    """Retain complete receive chunks, parsed frames and all socket terminals."""

    def __init__(self, plan: Report, deadline: float) -> None:
        """Start an empty timeline for a plan that must finish by ``deadline``."""
        self.plan = plan
        self.deadline = deadline
        self.recorder = Recorder({"endpoints": {"control": plan["endpoint"]}})
        self.buffers: dict[str, bytearray] = {}
        self.terminals: dict[str, str] = {}
        self.window_status: dict[str, str] = {}
        self.window_frame_count: int | None = None
        self.frames: list[Report] = []
        self.operations: list[Report] = []
        self.next_action = 0
        self.max_bytes = plan["schedule"]["max_bytes"]
        self.tail_mode = False
        self.tail_bytes: dict[str, int] = {}

    def action(self) -> int:
        """Take the next action number.

        Returns
        -------
        int
            The action number.
        """
        result = self.next_action
        self.next_action += 1
        return result

    def execute(self, step: Report) -> None:
        """Run one recorder step, bounded by the deadline and the byte cap."""
        need(time.monotonic() < self.deadline, "Global liveness deadline reached")
        self.recorder.execute(
            self.action(),
            {
                **step,
                "timeout": min(
                    step.get("timeout", DEFAULT_STEP_TIMEOUT),
                    self.deadline - time.monotonic(),
                ),
            },
        )
        need(self.recorder.byte_count <= self.max_bytes, "128KiB capture cap reached")

    def connect(self, name: str) -> None:
        """Open a flow and complete the hello exchange."""
        need(name not in self.recorder.sockets, "Duplicate flow")
        need(
            len(self.recorder.sockets) < self.plan["schedule"]["max_simultaneous"],
            "Simultaneous flow bound reached",
        )
        self.execute({"op": "connect", "connection": name, "endpoint": "control"})
        self.execute({"op": "send", "connection": name, "hex": cases.HELLO})
        self.execute({
            "op": "read",
            "connection": name,
            "size": HELLO_REPLY_BYTES,
            "expect_hex": cases.HELLO_REPLY,
        })
        self.buffers[name] = bytearray()

    def send(self, name: str, raw_hex: str) -> None:
        """Send bytes on an open flow that has not ended."""
        need(name in self.recorder.sockets, f"Unknown flow {name}")
        need(name not in self.terminals, f"Flow {name} already ended")
        self.execute({"op": "send", "connection": name, "hex": raw_hex})

    def _allowance(self, name: str) -> int:
        """Say how many bytes one read may take, within the total and tail caps.

        Returns
        -------
        int
            The size to ask ``recv`` for.
        """
        allowance = min(RECEIVE_CHUNK, self.max_bytes - self.recorder.byte_count)
        if self.tail_mode:
            allowance = min(
                allowance,
                self.plan["schedule"]["max_tail_bytes_per_flow"]
                - self.tail_bytes.get(name, 0),
            )
        need(allowance > 0, "Total or per-flow tail capture cap reached")
        return allowance

    def _receive(self, sock: socket.socket, name: str) -> None:
        """Read what a ready socket holds, or record its reset or EOF."""
        try:
            data = sock.recv(self._allowance(name))
        except ConnectionResetError:
            self.recorder.event(-1, name, "rst")
            self.terminals[name] = "rst"
            return
        if not data:
            self.recorder.event(-1, name, "eof")
            self.terminals[name] = "eof"
            return
        self.recorder.event(-1, name, "receive", data)
        if self.tail_mode:
            self.tail_bytes[name] = self.tail_bytes.get(name, 0) + len(data)
        self.buffers[name].extend(data)
        self._parse(name)

    def poll(self, seconds: float) -> None:
        """Read from every live flow for up to ``seconds``."""
        until = min(time.monotonic() + seconds, self.deadline)
        while time.monotonic() < until and self.recorder.sockets:
            active = {
                sock: name
                for name, sock in self.recorder.sockets.items()
                if name not in self.terminals
            }
            if not active:
                time.sleep(min(IDLE_SLICE_SECONDS, max(0, until - time.monotonic())))
                continue
            ready, _, _ = select.select(
                list(active),
                [],
                [],
                min(POLL_SLICE_SECONDS, max(0, until - time.monotonic())),
            )
            for sock in ready:
                self._receive(sock, active[sock])

    def _parse(self, name: str) -> None:
        """Cut complete frames from a flow's buffer and decode them."""
        buffer = self.buffers[name]
        while len(buffer) >= HEADER_BYTES:
            size = HEADER_BYTES + int.from_bytes(buffer[SIZE_START:HEADER_BYTES], "big")
            need(
                HEADER_BYTES <= size <= self.max_bytes,
                "Unbounded or malformed frame size",
            )
            if len(buffer) < size:
                break
            raw = bytes(buffer[:size])
            del buffer[:size]
            frame = {
                "connection": name,
                "raw_hex": raw.hex(),
                "arrival_elapsed_ns": time.monotonic_ns() - self.recorder.started,
                **decode_frame(raw),
            }
            self.frames.append(frame)
            need(len(self.frames) <= cases.MAX_FRAMES, "128-frame cap reached")

    def wait_for(
        self, predicate: cabc.Callable[[], bool], seconds: float, label: str
    ) -> None:
        """Poll until a condition holds, or fail naming what is missing."""
        end = min(time.monotonic() + seconds, self.deadline)
        while not predicate():
            need(time.monotonic() < end, f"Missing {label}")
            self.poll(min(POLL_SLICE_SECONDS, end - time.monotonic()))

    def close(self, name: str) -> None:
        """Close a flow and record it, if it is open."""
        if name in self.recorder.sockets:
            self.recorder.sockets.pop(name).close()
            self.recorder.event(self.action(), name, "close")

    def final_drain(self) -> None:
        """Half-close every live flow, read the tail and close them all."""
        self.tail_mode = True
        for name, sock in list(self.recorder.sockets.items()):
            if name not in self.terminals:
                try:
                    sock.shutdown(socket.SHUT_WR)
                    self.recorder.event(self.action(), name, "shutdown_write")
                except OSError:
                    self.recorder.event(self.action(), name, "shutdown_write_failed")
        self.poll(min(DRAIN_SECONDS, max(0, self.deadline - time.monotonic())))
        for name in list(self.recorder.sockets):
            if name not in self.terminals:
                self.terminals[name] = "bounded_no_eof"
            self.close(name)
