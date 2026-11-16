"""Hold the roster correlation, audit log and observation watchdog of the proxy."""

import hashlib
import json
import threading
import time
import typing as typ

from classic_login_proxy_constants import (
    MAX_FRAME,
    MAX_OBSERVATION_NS,
    OBSERVATION_SECONDS,
)
from classic_login_proxy_errors import fail
from classic_login_proxy_frames import parse_frame
from native_plan import packet, payload
from native_wire_names import (
    FIELD_ROSTER_SUBJECT,
    FIELD_USER_RECORD,
    ROSTER_HEADER_BYTES,
    ROSTER_NAME_LENGTH_START,
    TYPE_GET_USER_ROSTER,
)

if typ.TYPE_CHECKING:
    import collections.abc as cabc


def capture_failure(action: cabc.Callable[[], None]) -> Exception | None:
    """Run one action and return the ordinary exception it raised, if any.

    Parameters
    ----------
    action : collections.abc.Callable[[], None]
        The action to run.

    Returns
    -------
    Exception | None
        The exception that ``action`` raised, or None when it completed.
    """
    try:
        action()
    except Exception as exc:  # ruff: ignore[blind-except]  # a failing thread must invalidate the run, whatever its type
        return exc
    return None


class RosterState:
    """Correlate the first actual 300 request with its direct success ACK."""

    def __init__(self) -> None:
        """Start with no request observed and no reply rewritten."""
        self.lock = threading.Lock()
        self.first_id: int | None = None
        self.rewritten = False

    def observe_client(self, raw: bytes) -> None:
        """Remember the ID of the first 300 request that the client sends.

        Parameters
        ----------
        raw : bytes
            One complete client frame.
        """
        frame = parse_frame(raw)
        if (frame["type"], frame["is_reply"], frame["error"], frame["flags"]) != (
            TYPE_GET_USER_ROSTER,
            0,
            0,
            0,
        ):
            return
        with self.lock:
            if self.first_id is None:
                self.first_id = frame["id"]

    def _awaits(self, frame: dict[str, typ.Any]) -> bool:
        """Tell whether a decoded server frame is the reply that is awaited.

        Parameters
        ----------
        frame : dict[str, typing.Any]
            The decoded server frame.

        Returns
        -------
        bool
            True when a first request is known, no reply was rewritten yet and
            the frame is the success reply to that request.
        """
        if self.first_id is None or self.rewritten:
            return False
        return (
            frame["type"],
            frame["is_reply"],
            frame["id"],
            frame["error"],
            frame["flags"],
        ) == (0, 1, self.first_id, 0, 0)

    def rewrite_reply(self, raw: bytes) -> bytes:
        """Add the subject field to the first matching roster reply.

        Parameters
        ----------
        raw : bytes
            One complete server frame.

        Returns
        -------
        bytes
            The rewritten reply for the first match, or ``raw`` unchanged.
        """
        frame = parse_frame(raw)
        with self.lock:
            if not self._awaits(frame):
                return raw
            records = [
                value for key, value in frame["fields"] if key == FIELD_USER_RECORD
            ]
            if not records or any(
                key == FIELD_ROSTER_SUBJECT for key, _ in frame["fields"]
            ):
                fail(
                    ValueError,
                    "Native roster has no valid 300 record or already has 115",
                )
            for record in records:
                _check_packed_record(record)
            body = payload([
                *frame["fields"],
                (FIELD_ROSTER_SUBJECT, b"fixture-subject"),
            ])
            if len(body) > MAX_FRAME:
                fail(ValueError, "Native roster rewrite exceeds frame bound")
            forwarded = bytes.fromhex(
                packet(
                    frame["type"],
                    frame["id"],
                    body,
                    flags=frame["flags"],
                    reply=frame["is_reply"],
                    error=frame["error"],
                )
            )
            self.rewritten = True
            return forwarded


def _check_packed_record(record: bytes) -> None:
    """Check that one packed 300 record has its header and its full name.

    Parameters
    ----------
    record : bytes
        The value of one 300 field.
    """
    if len(record) < ROSTER_HEADER_BYTES:
        fail(ValueError, "Native roster packed 300 record is short")
    name_size = int.from_bytes(
        record[ROSTER_NAME_LENGTH_START:ROSTER_HEADER_BYTES], "big"
    )
    if not name_size or len(record) != ROSTER_HEADER_BYTES + name_size:
        fail(ValueError, "Native roster packed 300 record length differs")


class Audit:
    """Bound the audit log and enforce the deadline and the abort flags."""

    def __init__(self, deadline: float, max_log: int = 800_000) -> None:
        """Start an empty log that must finish by ``deadline``.

        Parameters
        ----------
        deadline : float
            The monotonic time, in seconds, after which the run is stopped.
        max_log : int
            The bound, in bytes, on the encoded entries.
        """
        self.deadline = deadline
        self.max_log = max_log
        self.entries: list[dict[str, typ.Any]] = []
        self.used = 0
        self.lock = threading.Lock()
        self.abort = threading.Event()
        self.cutoff = threading.Event()

    def check(self) -> None:
        """Raise if the run was cut off, timed out or aborted."""
        if self.cutoff.is_set():
            fail(ObservationCutoff, "Intentional observation cutoff")
        if time.monotonic() >= self.deadline:
            fail(TimeoutError, "Proxy process deadline exceeded")
        if self.abort.is_set():
            fail(RuntimeError, "Proxy stopped after peer failure")

    def record(self, event: str, raw: bytes, forwarded: bytes) -> None:
        """Append one hex-encoded frame or byte chunk to the log.

        Parameters
        ----------
        event : str
            The name of the step that produced the bytes.
        raw : bytes
            The bytes as received.
        forwarded : bytes
            The bytes as sent on.
        """
        self.check()
        entry = {
            "event": event,
            "timestamp_us": time.time_ns() // 1000,
            "raw_hex": raw.hex(),
            "forwarded_hex": forwarded.hex(),
        }
        cost = len(json.dumps(entry).encode()) + 2
        with self.lock:
            if self.used + cost > self.max_log:
                fail(ValueError, "Aggregate proxy log exceeds bound")
            self.entries.append(entry)
            self.used += cost


class ObservationCutoff(RuntimeError):  # ruff: ignore[error-suffix-on-exception-name]  # the name is the proxy's public exception and must not change
    """Owned sockets were intentionally closed at the observation deadline."""


class ObservationWatchdog:
    """Close the owned sockets thirty seconds after the controlled ACK."""

    def __init__(
        self,
        audit: Audit,
        close_owned: cabc.Callable[[], None],
        clock_ns: cabc.Callable[[], int] = time.monotonic_ns,
    ) -> None:
        """Start a watchdog that is waiting for the first ACK.

        Parameters
        ----------
        audit : Audit
            The audit log whose cutoff and abort flags the watchdog sets.
        close_owned : collections.abc.Callable[[], None]
            The action that closes every socket the run owns.
        clock_ns : collections.abc.Callable[[], int]
            The monotonic clock, in nanoseconds.
        """
        self.audit = audit
        self.close_owned = close_owned
        self.clock_ns = clock_ns
        self.lock = threading.Lock()
        self.state = "waiting"
        self.ack_ns: int | None = None
        self.due_ns: int | None = None
        self.actual_ns: int | None = None
        self.closed_ns: int | None = None
        self.teardown_ns: int | None = None
        self.raw_sha256: str | None = None
        self.forwarded_sha256: str | None = None
        self.error: str | None = None

    def arm(self, raw: bytes, forwarded: bytes) -> None:
        """Start the observation window when the controlled ACK is sent.

        Parameters
        ----------
        raw : bytes
            The ACK as the server sent it.
        forwarded : bytes
            The ACK as the client receives it.
        """
        self.audit.check()
        with self.lock:
            if self.state != "waiting":
                fail(ValueError, "Observation watchdog armed twice")
            self.ack_ns = self.clock_ns()
            self.due_ns = self.ack_ns + OBSERVATION_SECONDS * 1_000_000_000
            self.raw_sha256 = hashlib.sha256(raw).hexdigest()
            self.forwarded_sha256 = hashlib.sha256(forwarded).hexdigest()
            self.state = "armed"

    def tick(self) -> bool:
        """Close the owned sockets if the armed window has expired.

        Returns
        -------
        bool
            True once the cutoff has fired, False while it has not.
        """
        with self.lock:
            if self.state != "armed" or self.due_ns is None:
                return False
            if self.clock_ns() < self.due_ns:
                return False
            self.state = "fired"
            self.actual_ns = self.clock_ns()
            self.audit.cutoff.set()
        try:
            failure = capture_failure(self.close_owned)
            if failure is not None:
                self.error = f"{type(failure).__name__}: {failure}"
                self.audit.abort.set()
        finally:
            self.closed_ns = self.clock_ns()
        return True

    def cancel(self) -> None:
        """Stop a watchdog that is still waiting or armed."""
        with self.lock:
            if self.state in {"waiting", "armed"}:
                self.state = "cancelled"

    def mark_teardown(self) -> None:
        """Record the time at which the relay was torn down."""
        self.teardown_ns = self.clock_ns()

    def run(self) -> None:
        """Poll the window until it fires, is cancelled or the run aborts."""
        while not self.audit.abort.is_set():
            if self.tick() or self.state == "cancelled":
                return
            time.sleep(0.05)

    def _within_window(self) -> bool:
        """Tell whether teardown finished inside the thirty-second window.

        Returns
        -------
        bool
            True when every timestamp exists, teardown is within the bound
            and no close error was recorded.
        """
        if self.ack_ns is None or self.closed_ns is None:
            return False
        if self.teardown_ns is None:
            return False
        return (
            self.teardown_ns - self.ack_ns <= MAX_OBSERVATION_NS and self.error is None
        )

    def receipt(self) -> dict[str, typ.Any]:
        """Return the observation timings and digests for the report.

        Returns
        -------
        dict[str, typing.Any]
            The watchdog state, its timestamps, the validity flag and the
            digests of the controlled ACK.
        """
        return {
            "state": self.state,
            "ack_sent_monotonic_ns": self.ack_ns,
            "cutoff_due_ns": self.due_ns,
            "cutoff_actual_ns": self.actual_ns,
            "last_owned_socket_close_ns": self.closed_ns,
            "relay_teardown_ns": self.teardown_ns,
            "valid_30_seconds": self._within_window(),
            "raw_ack_sha256": self.raw_sha256,
            "forwarded_ack_sha256": self.forwarded_sha256,
            "error": self.error,
        }
