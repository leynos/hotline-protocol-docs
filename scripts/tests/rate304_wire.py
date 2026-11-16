"""Run the scheduled actions against fake frames, and serve a delayed phase.

The schedule builder answers each action of the control's plan with the fake
frames that the real wire would return. The phase server plays the peer of
the subject and observer connections for one 52-request phase. Nothing here
asserts: the test module checks what these functions produce.
"""

import dataclasses as dc
import json
import time
import typing as typ

import capture_identity
import native_rate304_cases as cases
import native_rate304_control as control
from native_plan import packet, payload
from native_wire_names import FIELD_ICON, TYPE_PRESENCE_UPDATE, TYPE_USER_LEFT
from rate304_support import fake_report, frame, phase_receipt, stream_bytes, update

if typ.TYPE_CHECKING:
    import socket

PHASE_PAIRS = 26  # the ordered 304 and 500 pairs of one phase
PHASE_REQUESTS = 2 * PHASE_PAIRS  # the requests that one phase sends
LAST_PAIR = PHASE_PAIRS - 1  # the index of the last pair of a phase
DUPLICATED_PAIR = 5  # the pair whose observer notice a duplicate repeats
FRAME_HEADER_BYTES = 20  # the header of a frame, before its data


class UndeliveredFrameError(AssertionError):
    """Fake frames remained after every scheduled action had run."""


class RequestsDifferError(AssertionError):
    """The requests of a phase differ from the schedule."""


class PeerClosedError(EOFError):
    """A synthetic peer closed before a frame was complete."""


@dc.dataclass(frozen=True, slots=True)
class PeerScript:
    """Describe how a synthetic peer answers one phase."""

    delay: float
    missing: bool = False
    duplicate: bool = False
    foreign: bool = False
    observer_first: bool = False


def identifier_of(raw: str) -> int:
    """Return the request identifier that a raw frame carries.

    Returns
    -------
    int
        The big-endian identifier at bytes 4 to 8 of the frame.
    """
    return int.from_bytes(bytes.fromhex(raw)[4:8], "big")


class Trace:
    """Hold the events, actions and observed frames of one fake run."""

    def __init__(
        self, pool: list[dict[str, typ.Any]], *, observer_after_barrier: bool
    ) -> None:
        """Start an empty trace over the frames that remain to be delivered."""
        self.pool = pool
        self.observer_after_barrier = observer_after_barrier
        self.events: list[dict[str, typ.Any]] = []
        self.actions: list[dict[str, typ.Any]] = []
        self.observed: list[dict[str, typ.Any]] = []
        self.tick = 0

    def emit(self, name: str, kind: str, raw: str = "") -> None:
        """Record one event and advance the clock by one millisecond."""
        self.tick += 1_000_000
        self.events.append({
            "connection": name,
            "event": kind,
            "hex": raw,
            "elapsed_ns": self.tick,
        })

    def take(
        self,
        name: str,
        kind: int,
        identifier: int | None = None,
        icon: int | None = None,
    ) -> None:
        """Deliver the first pooled frame that matches, or fail.

        Raises
        ------
        AssertionError
            If no pooled frame matches.
        """
        for pos, candidate in enumerate(self.pool):
            if candidate["connection"] != name or candidate["type"] != kind:
                continue
            if identifier is not None and candidate["id"] != identifier:
                continue
            if icon is not None and control.exact_fields(candidate).get(
                FIELD_ICON
            ) != icon.to_bytes(2, "big"):
                continue
            result = self.pool.pop(pos)
            self.emit(name, "receive", result["raw_hex"])
            result["arrival_elapsed_ns"] = self.tick
            self.observed.append(result)
            return
        raise AssertionError((name, kind, identifier, icon))


def _answer_login(trace: Trace, name: str) -> None:
    """Deliver the replies that a login action receives."""
    for kind, identifier in ((0, 1), (354, 0), (109, 0)):
        trace.take(name, kind, identifier)
    if name in {"paced", "burst"}:
        trace.take("observer", TYPE_PRESENCE_UPDATE, icon=1)


def _answer_304(trace: Trace, label: str, name: str) -> None:
    """Deliver the presence notices that a 304 action receives."""
    icon = 28 if label == "paced-304-after-quiet" else int(label[-2:]) + 2
    if not trace.observer_after_barrier:
        trace.take("observer", TYPE_PRESENCE_UPDATE, icon=icon)
    trace.take(name, TYPE_PRESENCE_UPDATE, icon=icon)


def _answer_500(trace: Trace, label: str, name: str, raw: str) -> None:
    """Deliver the acknowledgements that a 500 action receives."""
    quiet = label == "paced-500-after-quiet"
    trace.take(name, 0, 2026 if quiet else identifier_of(raw))
    if trace.observer_after_barrier:
        icon = 28 if quiet else int(label[-2:]) + 2
        trace.take("observer", TYPE_PRESENCE_UPDATE, icon=icon)
    if quiet:
        trace.take("observer", TYPE_USER_LEFT, icon=None)


def _answer_observer(trace: Trace, label: str, raw: str) -> None:
    """Deliver the replies that the probe and observer actions receive."""
    if label == "probe-login":
        trace.take("probe", 0, 1)
    elif label.startswith("observer-"):
        trace.take("observer", 0, identifier_of(raw))


def _answer(trace: Trace, label: str, name: str, raw: str) -> None:
    """Deliver the frames that one action of the schedule receives."""
    if label.endswith("-login") and name != "probe":
        _answer_login(trace, name)
    elif label.endswith("-roster"):
        trace.take(name, 0, 10)
    elif label == "observer-roster-initial":
        trace.take("observer", 0, 10)
    elif label == "burst-304-terminal":
        trace.emit("burst", "eof")
        trace.take("observer", TYPE_USER_LEFT, icon=None)
    elif label.startswith(("paced-304-", "burst-304-")):
        _answer_304(trace, label, name)
    elif label.startswith(("paced-500-", "burst-500-")):
        _answer_500(trace, label, name, raw)
    else:
        _answer_observer(trace, label, raw)


def build_full_report(
    plan: dict[str, typ.Any],
    *,
    observer_after_barrier: bool = False,
    observer_uid: int = 1,
    target_uid: int | None = None,
) -> dict[str, typ.Any]:
    """Run every scheduled action against the fake frames and report the run.

    Returns
    -------
    dict[str, typ.Any]
        The completed report of the run.

    Raises
    ------
    UndeliveredFrameError
        If fake frames remain undelivered after the schedule.
    """
    source = fake_report(plan, observer_uid)
    pool = source["frames"] + [
        frame("observer", 0, 5000 + i, [], reply=1) for i in range(14)
    ]
    trace = Trace(pool, observer_after_barrier=observer_after_barrier)
    for label, name, raw in control.expected_actions(
        plan, 14, target_uid or observer_uid
    ):
        if label == "paced-304-after-quiet":
            trace.tick += 71_000_000_000
        if label.endswith("-login"):
            trace.emit(name, "send", cases.HELLO)
            trace.emit(name, "receive", cases.HELLO_REPLY)
        first = len(trace.events)
        trace.emit(name, "send", raw)
        trace.actions.append({
            "label": label,
            "connection": name,
            "hex": raw,
            "elapsed_ns": trace.tick,
            "event_range": [first, len(trace.events)],
        })
        _answer(trace, label, name, raw)
    if trace.pool:
        raise UndeliveredFrameError
    streams = stream_bytes(trace.events)
    source_record = capture_identity.identity(control.CAPTURE_MODULES)
    producer = capture_identity.identity(control.CASES_MODULES)
    return {
        **source,
        "status": "completed",
        "native_clock_calibrated": False,
        "phase_progress": {"paced": 26, "burst": 26},
        "phase_mode": plan["schedule"]["phase_mode"],
        "phase_receipts": {
            name: phase_receipt(plan, trace, name) for name in ("paced", "burst")
        },
        "plan_sha256": cases.digest((json.dumps(plan, indent=2) + "\n").encode()),
        "cases_sha256": producer["digest"],
        "cases_identity": producer,
        "source_sha256": source_record["digest"],
        "source_identity": source_record,
        "oracle_sha256": control.ORACLE_SHA256,
        "frames": trace.observed,
        "events": trace.events,
        "actions": trace.actions,
        "streams": streams,
        "unparsed_hex": dict.fromkeys(streams, ""),
    }


def exactly(sock: socket.socket, size: int) -> bytes:
    """Read exactly ``size`` bytes from a socket, or fail if it closes first.

    Returns
    -------
    bytes
        The bytes read.

    Raises
    ------
    PeerClosedError
        If the peer closes before ``size`` bytes arrive.
    """
    raw = bytearray()
    while len(raw) < size:
        part = sock.recv(size - len(raw))
        if not part:
            raise PeerClosedError
        raw.extend(part)
    return bytes(raw)


def read_requests(sock: socket.socket) -> list[dict[str, typ.Any]]:
    """Read the 52 requests that a subject sends in one phase.

    Returns
    -------
    list[dict[str, typ.Any]]
        The decoded requests, in the order they were sent.
    """
    received = []
    for _ in range(PHASE_REQUESTS):
        header = exactly(sock, FRAME_HEADER_BYTES)
        body = exactly(sock, int.from_bytes(header[16:20], "big"))
        received.append(control.decode_frame(header + body))
    return received


def check_requests(received: list[dict[str, typ.Any]]) -> None:
    """Check that the requests of a phase are the 52 that the schedule names.

    Raises
    ------
    RequestsDifferError
        If the requests differ from the schedule.
    """
    expected = [
        item for i in range(PHASE_PAIRS) for item in ((304, 1000 + i), (500, 2000 + i))
    ]
    if [(f["type"], f["id"]) for f in received] != expected:
        raise RequestsDifferError


def send_pair(
    subject_peer: socket.socket,
    observer_peer: socket.socket,
    index: int,
    script: PeerScript,
) -> None:
    """Send the presence notice and the acknowledgement of one pair."""
    notice = bytes.fromhex(
        packet(TYPE_PRESENCE_UPDATE, 0, payload(update(2, index + 2)))
    )
    skip = script.missing and index == LAST_PAIR
    if script.observer_first and not skip:
        observer_peer.sendall(notice)
    subject_peer.sendall(notice)
    if not script.observer_first and not skip:
        observer_peer.sendall(notice)
    if script.duplicate and index == DUPLICATED_PAIR:
        observer_peer.sendall(notice)
    subject_peer.sendall(bytes.fromhex(packet(0, 2000 + index, reply=1)))


def serve_phase(
    subject_peer: socket.socket,
    observer_peer: socket.socket,
    script: PeerScript,
    errors: list[Exception],
) -> None:
    """Answer the 52 requests of a phase as a peer that responds after a delay.

    Any failure of the peer is appended to ``errors`` rather than raised.
    """
    try:
        check_requests(read_requests(subject_peer))
        time.sleep(script.delay)
        if script.foreign:
            observer_peer.sendall(
                bytes.fromhex(packet(TYPE_PRESENCE_UPDATE, 0, payload(update(77, 2))))
            )
        for index in range(PHASE_PAIRS):
            send_pair(subject_peer, observer_peer, index, script)
    except (OSError, EOFError, AssertionError, ValueError) as error:
        errors.append(error)
