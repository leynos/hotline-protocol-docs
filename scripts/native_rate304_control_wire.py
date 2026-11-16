"""Collect the sockets, bytes and frames of one 304 run in a bounded collector.

Part of the 304 runner (``native_rate304_control``), whose ``CAPTURE_MODULES``
lists this module and which re-exports every public name below. The path-fields
and missing-alias runners build on :class:`Wire`.
"""

import select
import socket
import time
import typing as typ

import native_rate304_cases as cases
from native_rate304_control_frames import (
    Report,
    login_identity,
    need,
)
from native_wire_names import (
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from protocol_capture import Recorder, decode_frame
from verify_native_auth import ADMIN

if typ.TYPE_CHECKING:
    import collections.abc as cabc

HEADER_BYTES = 20
SIZE_START = 16
MAX_FRAME_BYTES = 65536
MAX_TAIL_SECONDS = 2
DEFAULT_STEP_TIMEOUT = 3
HELLO_REPLY_BYTES = 8
LOGIN_WAIT_SECONDS = 5
POLL_SLICE_SECONDS = 0.05
RECEIVE_CHUNK = 65536


class Wire:
    """One bounded multi-socket collector retaining every observed byte."""

    def __init__(
        self,
        plan: Report,
        deadline: float,
        guard: cabc.Callable[[], None] | None = None,
    ) -> None:
        """Start empty for a plan that must finish by ``deadline``."""
        self.plan, self.deadline = plan, deadline
        self.guard = guard
        self.recorder = Recorder({"endpoints": {"control": plan["endpoint"]}})
        self.buffers: dict[str, bytearray] = {}
        self.frames: list[Report] = []
        self.terminals: dict[str, str] = {}
        self.actions: list[Report] = []
        self.next_action = 0
        self.tail_bytes: dict[str, int] = {}
        self.tail_mode = False
        self.identities: dict[str, int] = {}

    def execute(self, step: Report) -> None:
        """Run one recorder step, bounded by the deadline and the byte cap."""
        remaining = self.deadline - time.monotonic()
        need(remaining > 0, "Case deadline reached")
        self.recorder.execute(
            self.next_action,
            {
                **step,
                "timeout": min(step.get("timeout", DEFAULT_STEP_TIMEOUT), remaining),
            },
        )
        self.next_action += 1
        need(
            self.recorder.byte_count <= self.plan["schedule"]["max_bytes"],
            "Case byte cap reached",
        )

    def connect_login_probe(self, name: str) -> None:
        """Connect a flow, complete the hello exchange and send its login.

        The reply is neither awaited nor checked.
        """
        if self.guard is not None:
            self.guard()
        need(
            len(self.recorder.sockets) < self.plan["schedule"]["max_simultaneous"],
            "Simultaneous socket cap reached",
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
        self.send(name, self.plan["logins"][name], f"{name}-login")

    def connect_login(self, name: str) -> None:
        """Log a flow in and require its 107 reply, 354 and 109."""
        self.connect_login_probe(name)
        self.wait_for(
            lambda: all([
                bool(self.match(name, 0, 1, 1)),
                bool(self.match(name, TYPE_PRIVILEGES_NOTIFICATION, None, 0)),
                bool(self.match(name, TYPE_LOGIN_AGREEMENT, None, 0)),
            ]),
            LOGIN_WAIT_SECONDS,
            f"{name} early107/354/109",
        )
        login_identity(self.frames, name, ADMIN if name == "observer" else bytes(8))

    def send(self, name: str, raw: str, label: str) -> None:
        """Send bytes on an open flow and record the action."""
        need(name in self.recorder.sockets, "Send on closed socket")
        start = len(self.recorder.events)
        self.execute({"op": "send", "connection": name, "hex": raw})
        self.actions.append({
            "label": label,
            "connection": name,
            "hex": raw,
            "elapsed_ns": time.monotonic_ns() - self.recorder.started,
            "event_range": [start, len(self.recorder.events)],
        })

    def match(
        self, name: str, kind: int, identifier: int | None, reply: int
    ) -> list[Report]:
        """List a flow's frames of one type and reply marker, by optional id.

        Returns
        -------
        list[dict[str, typing.Any]]
            The matching frames, in order.
        """
        return [
            f
            for f in self.frames
            if f["connection"] == name
            and f["type"] == kind
            and f["is_reply"] == reply
            and (identifier is None or f["id"] == identifier)
        ]

    def _receive(self, sock: socket.socket, name: str) -> None:
        """Read what a ready socket holds, or record its reset or EOF."""
        allowance = self.plan["schedule"]["max_bytes"] - self.recorder.byte_count
        if self.tail_mode:
            allowance = min(
                allowance,
                self.plan["schedule"]["max_tail_bytes_per_flow"]
                - self.tail_bytes.get(name, 0),
            )
        need(allowance > 0, "Case/tail byte cap reached")
        try:
            raw = sock.recv(min(RECEIVE_CHUNK, allowance))
        except ConnectionResetError:
            self.recorder.event(-1, name, "rst")
            self.terminals[name] = "rst"
            return
        if not raw:
            self.recorder.event(-1, name, "eof")
            self.terminals[name] = "eof"
            return
        self.recorder.event(-1, name, "receive", raw)
        if self.tail_mode:
            self.tail_bytes[name] = self.tail_bytes.get(name, 0) + len(raw)
        self.buffers[name].extend(raw)
        self.parse(name)

    def poll(self, seconds: float) -> None:
        """Read from every live flow for up to ``seconds``."""
        until = min(time.monotonic() + seconds, self.deadline)
        while time.monotonic() < until:
            active = {
                sock: name
                for name, sock in self.recorder.sockets.items()
                if name not in self.terminals
            }
            if not active:
                return
            ready, _, _ = select.select(
                list(active),
                [],
                [],
                min(POLL_SLICE_SECONDS, max(0, until - time.monotonic())),
            )
            for sock in ready:
                self._receive(sock, active[sock])

    def parse(self, name: str) -> None:
        """Cut complete frames from a flow's buffer and decode them."""
        buffer = self.buffers[name]
        while len(buffer) >= HEADER_BYTES:
            size = HEADER_BYTES + int.from_bytes(buffer[SIZE_START:HEADER_BYTES], "big")
            need(HEADER_BYTES <= size <= MAX_FRAME_BYTES, "Frame exceeds hard bound")
            if len(buffer) < size:
                return
            raw = bytes(buffer[:size])
            del buffer[:size]
            value = decode_frame(raw)
            need(value["total_size"] == value["data_size"], "Fragmented logical frame")
            self.frames.append({
                "connection": name,
                "raw_hex": raw.hex(),
                "arrival_elapsed_ns": time.monotonic_ns() - self.recorder.started,
                **value,
            })
            need(
                len(self.frames) <= self.plan["schedule"]["max_frames"],
                "Case frame cap reached",
            )

    def wait_for(
        self, predicate: cabc.Callable[[], bool], seconds: float, label: str
    ) -> None:
        """Poll until a condition holds, or fail naming what is missing."""
        until = min(time.monotonic() + seconds, self.deadline)
        while not predicate():
            need(time.monotonic() < until, f"Missing {label}")
            self.poll(min(POLL_SLICE_SECONDS, until - time.monotonic()))

    def shutdown_and_close(self, name: str) -> None:
        """Half-close a flow, read its tail and close it."""
        sock = self.recorder.sockets.get(name)
        if sock is None:
            return
        if name not in self.terminals:
            try:
                sock.shutdown(socket.SHUT_WR)
                self.recorder.event(self.next_action, name, "shutdown_write")
            except OSError:
                self.recorder.event(self.next_action, name, "shutdown_write_failed")
        self.tail_mode = True
        self.poll(min(MAX_TAIL_SECONDS, max(0, self.deadline - time.monotonic())))
        self.recorder.sockets.pop(name).close()
        self.recorder.event(self.next_action, name, "close")
        self.next_action += 1
        self.terminals.setdefault(name, "bounded_no_eof")

    def close_all(self) -> None:
        """Close every flow; on a failure, release the flow and re-raise.

        Raises
        ------
        OSError
            If a flow fails to close, after the flow is released.
        ValueError
            If a flow fails to close, after the flow is released.
        TimeoutError
            If a flow fails to close, after the flow is released.
        """
        self.tail_mode = True
        for name in list(self.recorder.sockets):
            try:
                self.shutdown_and_close(name)
            except OSError, ValueError, TimeoutError:
                # Caller records failure; preserve and release every owned descriptor.
                sock = self.recorder.sockets.pop(name, None)
                if sock is not None:
                    sock.close()
                    self.recorder.event(self.next_action, name, "close_after_failure")
                raise
