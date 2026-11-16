"""Run a capture plan's steps for ``protocol_capture`` and keep what happened.

Part of the capture driver's module set (``protocol_capture.CAPTURE_MODULES``).
:class:`RecorderBase` holds the run; ``protocol_capture.Recorder`` completes it
with the session limit, which it reads from its own module so that a test that
patches ``protocol_capture.MAX_CAPTURE_BYTES`` is still obeyed.
"""

import datetime as dt
import socket
import time
import typing as typ

from protocol_capture_decode import HEADER_SIZE, decode_frame
from protocol_capture_plan import VARIABLE, field_saves

CHUNK_SIZE = 65536
FRAME_OBSERVATION_BOUND = 256
FRAME_SIZE_START = 16
SIZE_WIDTH_MIN = 1
SIZE_WIDTH_MAX = 4
DEFAULT_TIMEOUT = 2

type Step = dict[str, typ.Any]


def streams_of(events: list[dict[str, typ.Any]]) -> dict[str, dict[str, str]]:
    """Rebuild each connection's byte streams from its events.

    Parameters
    ----------
    events : list[dict[str, typing.Any]]
        The recorded events.

    Returns
    -------
    dict[str, dict[str, str]]
        For each named connection, the hexadecimal of what was sent and what
        was received, in event order.
    """
    streams: dict[str, dict[str, str]] = {}
    for event in events:
        name = event["connection"]
        if not name:
            continue
        stream = streams.setdefault(name, {"sent_hex": "", "received_hex": ""})
        match event["event"]:
            case "send":
                stream["sent_hex"] += event["hex"]
            case "receive":
                stream["received_hex"] += event["hex"]
    return streams


def _incomplete(decoded: dict[str, typ.Any], fields: list[typ.Any]) -> bool:
    """Say whether a decoded frame is not a whole, fully consumed one.

    Returns
    -------
    bool
        ``True`` with bytes left over, a count that differs from the fields
        read, or a fragment.
    """
    if decoded.get("unconsumed_hex") or decoded.get("declared_field_count") != len(
        fields
    ):
        return True
    return decoded["total_size"] != decoded["data_size"]


class RecorderBase:
    """Retain every successful send/receive chunk and action-relative timing."""

    def __init__(self, plan: dict[str, typ.Any]) -> None:
        """Start a run of ``plan`` at the current time.

        Parameters
        ----------
        plan : dict[str, typing.Any]
            The validated plan, or a stand-in that has its ``endpoints``.
        """
        self.plan = plan
        self.started = time.monotonic_ns()
        self.started_at_utc = dt.datetime.now(dt.UTC).isoformat()
        self.sockets: dict[str, socket.socket] = {}
        self.variables: dict[str, bytes] = {}
        self.events: list[dict[str, typ.Any]] = []
        self.frames: list[dict[str, typ.Any]] = []
        self.byte_count = 0

    @property
    def limit(self) -> int:
        """The most bytes a session may carry.

        Raises
        ------
        NotImplementedError
            Always; ``protocol_capture.Recorder`` supplies it.
        """
        raise NotImplementedError

    def event(self, action: int, name: str, direction: str, data: bytes = b"") -> None:
        """Record one event and its bytes.

        Parameters
        ----------
        action : int
            The index of the step.
        name : str
            The connection, or ``""``.
        direction : str
            The kind of event, for example ``"send"``.
        data : bytes
            The bytes sent or received.

        Raises
        ------
        ValueError
            If the session now exceeds the limit; the event is kept.
        """
        self.byte_count += len(data)
        self.events.append({
            "action": action,
            "connection": name,
            "event": direction,
            "elapsed_ns": time.monotonic_ns() - self.started,
            "hex": data.hex(),
        })

        if data and self.byte_count > self.limit:
            message = "Session exceeds capture limit"
            raise ValueError(message)

    def read(self, action: int, name: str, size: int | None, deadline: float) -> bytes:
        """Receive ``size`` bytes, or everything until end of stream.

        Parameters
        ----------
        action : int
            The index of the step.
        name : str
            The connection.
        size : int | None
            The number of bytes, or ``None`` to read to the end.
        deadline : float
            A ``time.monotonic`` instant.

        Returns
        -------
        bytes
            What was received.

        Raises
        ------
        TimeoutError
            If the deadline passes.
        EOFError
            If the stream ends before ``size`` bytes.
        """
        chunks = bytearray()
        connection = self.sockets[name]
        while size is None or len(chunks) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                message = "Action timed out"
                raise TimeoutError(message)
            connection.settimeout(remaining)
            count = (
                min(CHUNK_SIZE, size - len(chunks)) if size is not None else CHUNK_SIZE
            )
            data = connection.recv(count)
            if not data:
                self.event(action, name, "eof")
                if size is not None:
                    message = f"EOF before {size} requested bytes"
                    raise EOFError(message)
                break
            self.event(action, name, "receive", data)
            chunks.extend(data)
        return bytes(chunks)

    def _capture_connect(self, action: int, name: str, step: Step) -> None:
        """Open a connection to the step's endpoint and record both addresses."""
        endpoint = self.plan["endpoints"][step["endpoint"]]
        self.sockets[name] = socket.create_connection(
            (endpoint["host"], endpoint["port"]), step.get("timeout", DEFAULT_TIMEOUT)
        )
        self.event(action, name, "connect")
        self.events[-1].update(
            local_address=list(self.sockets[name].getsockname()),
            peer_address=list(self.sockets[name].getpeername()),
        )

    def _capture_quiet(self, action: int, name: str, step: Step) -> None:
        """Require that nothing arrives within the step's timeout.

        Raises
        ------
        ValueError
            If a byte or the end of the stream arrives; it is recorded first.
        """
        self.sockets[name].settimeout(step.get("timeout", DEFAULT_TIMEOUT))
        try:
            data = self.sockets[name].recv(1)
        except TimeoutError:
            self.event(action, name, "quiet")
        else:
            self.event(action, name, "receive" if data else "eof", data)
            message = "Expected bounded silence, received bytes or EOF"
            raise ValueError(message)

    def _capture_send(
        self, action: int, name: str, step: Step, deadline: float
    ) -> None:
        """Send the step's bytes, with saved values substituted, in chunks.

        Raises
        ------
        ValueError
            If the bytes exceed what the session may still carry.
        TimeoutError
            If the deadline passes before everything is sent.
        EOFError
            If the socket accepts no bytes.
        """
        encoded = VARIABLE.sub(lambda m: self.variables[m[1]].hex(), step["hex"])
        data = bytes.fromhex(encoded)
        if len(data) > self.limit - self.byte_count:
            message = "Send exceeds remaining capture limit"
            raise ValueError(message)
        while data:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                message = "Action timed out"
                raise TimeoutError(message)
            self.sockets[name].settimeout(remaining)
            count = self.sockets[name].send(data)
            if not count:
                message = "Socket closed during send"
                raise EOFError(message)
            self.event(action, name, "send", data[:count])
            data = data[count:]

    def _capture_frames(
        self, action: int, name: str, step: Step, deadline: float
    ) -> bytes:
        """Read frames until one matches the step's ``match_frame``.

        Returns
        -------
        bytes
            The bytes of the last frame read.

        Raises
        ------
        ValueError
            If a frame is over the limit, or none of 256 frames matches.
        """
        for _ in range(FRAME_OBSERVATION_BOUND):
            header = self.read(action, name, HEADER_SIZE, deadline)
            size = int.from_bytes(header[FRAME_SIZE_START:HEADER_SIZE], "big")
            if size > self.limit - HEADER_SIZE:
                message = "Frame exceeds capture limit"
                raise ValueError(message)
            data = header + self.read(action, name, size, deadline)
            decoded = decode_frame(data)
            self.frames.append({"action": action, "connection": name, **decoded})
            if all(decoded[k] == v for k, v in step.get("match_frame", {}).items()):
                return data
        message = "Frame match exceeds256-frame observation bound"
        raise ValueError(message)

    def _capture_sized(
        self, action: int, name: str, step: Step, deadline: float
    ) -> bytes:
        """Read a fixed or saved-size block, or everything to the end.

        Returns
        -------
        bytes
            What was received.

        Raises
        ------
        ValueError
            If a saved size is not one to four bytes or is out of range.
        """
        size = step.get("size") if step["op"] == "read" else None
        if "size_from" in step:
            raw = self.variables[step["size_from"]]
            if not SIZE_WIDTH_MIN <= len(raw) <= SIZE_WIDTH_MAX:
                message = "Saved size must contain one to four bytes"
                raise ValueError(message)
            size = int.from_bytes(raw, "big")
            if not 0 < size <= self.limit:
                message = "Read size exceeds capture limit"
                raise ValueError(message)
        return self.read(action, name, size, deadline)

    def _capture_fields(self, step: Step) -> None:
        """Keep the frame fields the step selects by identifier.

        Raises
        ------
        ValueError
            If a field is missing, repeated or the frame is incomplete.
        """
        for variable, field_id in field_saves(step).items():
            decoded = self.frames[-1]
            fields = decoded.get("fields", [])
            matches = [f for f in fields if f["id"] == field_id]
            if len(matches) != 1 or _incomplete(decoded, fields):
                message = "Saved field is missing, ambiguous or incomplete"
                raise ValueError(message)
            self.variables[variable] = bytes.fromhex(matches[0]["hex"])

    def _capture_receive(
        self, action: int, name: str, step: Step, deadline: float
    ) -> None:
        """Read what the step asks for, check it and keep what it saves.

        Raises
        ------
        ValueError
            If the bytes are not the expected ones, or a save does not fit.
        """
        if step["op"] == "read_frame":
            data = self._capture_frames(action, name, step, deadline)
        else:
            data = self._capture_sized(action, name, step, deadline)
        if "expect_hex" in step and data != bytes.fromhex(step["expect_hex"]):
            message = f"Expected {step['expect_hex']}, received {data.hex()}"
            raise ValueError(message)
        if "save" in step:
            saved = step["save"]
            end = saved["offset"] + saved["size"]
            if end > len(data):
                message = "Saved bytes exceed received value"
                raise ValueError(message)
            self.variables[saved["name"]] = data[saved["offset"] : end]
        self._capture_fields(step)

    def execute(self, action: int, step: Step) -> None:
        """Run one step of the plan.

        Parameters
        ----------
        action : int
            The index of the step.
        step : dict[str, typing.Any]
            The step.
        """
        name = step.get("connection", "")
        op = step["op"]
        deadline = time.monotonic() + step.get("timeout", DEFAULT_TIMEOUT)
        match op:
            case "connect":
                self._capture_connect(action, name, step)
            case "close":
                self.sockets.pop(name).close()
                self.event(action, name, "close")
            case "pause":
                time.sleep(step["seconds"])
                self.event(action, name, "pause")
            case "shutdown_write":
                self.sockets[name].shutdown(socket.SHUT_WR)
                self.event(action, name, "shutdown_write")
            case "expect_quiet":
                self._capture_quiet(action, name, step)
            case "send":
                self._capture_send(action, name, step, deadline)
            case _:
                self._capture_receive(action, name, step, deadline)

    def streams(self) -> dict[str, dict[str, str]]:
        """Rebuild the byte streams from the events.

        Returns
        -------
        dict[str, dict[str, str]]
            See :func:`streams_of`.
        """
        return streams_of(self.events)
