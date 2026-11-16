"""Support for the board tests: a fake wire, a refusal helper and a fake report."""

import json
import socket
import time
import typing as typ

import native_board_cases as cases
from native_board_control import (
    Wire,
    execute_case,
    sha,
    strict,
)
from native_plan import packet, payload
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_DATA,
    FIELD_ERROR_TEXT,
    FIELD_UNNAMED_WORD,
    FIELD_VERSION,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from protocol_capture import Recorder
from verify_mac_peer_first_session import AGREEMENT
from verify_native_auth import ADMIN
from verify_native_shx import fields

if typ.TYPE_CHECKING:
    import collections.abc as cabc

ACK = 0  # the type of a reply that carries no data of its own
BOARD_UPDATE = 102  # the notification that a board post sends to its recipients
BOARD_POST = 103  # the request type of a board post
REPORTED_VERSION = b"\0\xbe"  # the version that a login reply reports
UNNAMED_WORD = b"\0\0"  # the unnamed word that a login reply zeroes
ACCESS_BITMAP_BYTES = 8  # the access bitmap of a login without privileges
PERMISSION_TEXT = b"Permission denied"  # the refusal of a read by a low account
INVALID_SIZE_TEXT = b"Invalid size"  # the refusal of an oversized post
SENDER_HEADER = b"From BoardSender (Nov 14 08:20):\r\r"  # a post's segment header
POST_LIMIT = 8192  # the largest post that the board accepts
READ_LIMIT = 65535  # the most board bytes that one read returns
FILLER_REQUEST = 120  # the read whose board bytes a fault corrupts
FIRST_POST_ID = 1001  # the request identifier of the first fake post
SECOND_POST_ID = 1002  # the request identifier of the second fake post
REQUEST_ID = 77  # the request identifier of the hand-made frames
FAKE_DEADLINE_SECONDS = 30  # how long a fake wire may run
DEADLINE_SECONDS = 2  # how long a wire under test may run
POLL_SECONDS = 0.1  # one poll of a wire under test
NON_BLOCKING_TIMEOUT = 0.0  # setblocking(False) is the same as settimeout(0.0)
UNTIL_SECONDS = 5  # the default wait of a fake barrier
NANOS_PER_SECOND = 1e9
EXPECTED_POSTS = 13  # the posts of the generated case
EXPECTED_WAITING_UPDATES = 3  # the updates that the waiting connection receives
BOUNDARY_POSTS = (0, 1, 2, 3, 4, 9, 11, 12)  # the posts whose sizes are checked
BOUNDARY_SIZES = [0, 7, 7, 8191, 8192, 8192, 1, 8193]  # their expected sizes
SHORT_FRAME_BYTES = 9  # a frame cut short, before the end of its header
MALFORMED_HEADER_BYTES = 16  # the header bytes kept before a malformed size
MALFORMED_SIZE_BYTES = 4  # the size bytes that a malformed frame appends
PREFIX = b"Broken"  # the altered start of a segment
PREFIX_BYTES = len(PREFIX)
TIMING_SKEW_SECONDS = 2  # the skew added to an event's recorded time
UNEXPECTED_REQUEST = "Unexpected fake request {kind}"
NOT_RAISED = "the call did not raise an expected error"


class FakeWire(Wire):
    """Consume actual generated requests and emit deterministic native-shaped bytes."""

    def __init__(self, recorder: Recorder, fault: str | None = None) -> None:
        """Start a fake wire that records into ``recorder`` and injects ``fault``."""
        self.recorder = recorder
        self.board = b""
        self.fault = fault
        self.overhead = None
        self.closed: set[str] = set()
        self.deadline = time.monotonic() + FAKE_DEADLINE_SECONDS
        self.action = 0

    def emit(  # pylint: disable=too-many-arguments  # the fake's frame shape: name, type, identifier, fields and status
        self,
        name: str,
        kind: int,
        identifier: int,
        values: tuple[tuple[int, bytes], ...] = (),
        *,
        reply: int = 0,
        error: int = 0,
    ) -> dict[str, typ.Any]:
        """Record one frame that the fake peer sends to ``name``.

        Returns
        -------
        dict[str, typing.Any]
            The recorded frame.
        """
        raw = bytes.fromhex(
            packet(kind, identifier, payload(list(values)), reply=reply, error=error)
        )
        decoded = strict(raw)
        frame = {
            "action": -1,
            "connection": name,
            "arrival_ns": time.monotonic_ns() - self.recorder.started,
            "raw_hex": raw.hex(),
            **decoded,
        }
        self.recorder.frames.append(frame)
        self.recorder.event(-1, name, "receive", raw)
        return frame

    def connect(self, name: str, endpoint: tuple[str, int]) -> None:
        """Open the fake socket for ``name`` and record its handshake."""
        assert endpoint == ("127.0.0.1", cases.PORT), "the endpoint differs from plan"
        self.recorder.sockets[name] = socket.socket()
        self.recorder.event(self.action, name, "connect")
        self.recorder.event(-1, name, "send", bytes.fromhex(cases.HELLO))
        self.recorder.event(-1, name, "receive", bytes.fromhex(cases.HELLO_REPLY))
        self.action += 1

    def send(self, name: str, data: bytes) -> None:
        """Answer one generated request with the frames the native board sends.

        Raises
        ------
        AssertionError
            For a request type that the fake does not answer.
        """
        self.recorder.event(self.action, name, "send", data)
        self.action += 1
        frame = strict(data)
        values = fields(frame)
        kind, ident = frame["type"], frame["id"]
        match kind:
            case 107:  # TYPE_LOGIN
                self._login(name, ident)
            case 101:  # the board read
                self._read(name, ident)
            case 500:  # TYPE_EMPTY_ACK
                self.emit(name, ACK, ident, reply=1)
            case 103:  # BOARD_POST
                self._post(name, ident, values)
            case _:
                raise AssertionError(UNEXPECTED_REQUEST.format(kind=kind))

    def _login(self, name: str, ident: int) -> None:
        """Answer a login with its reply, its privileges and the agreement."""
        self.emit(
            name,
            ACK,
            ident,
            ((FIELD_VERSION, REPORTED_VERSION), (FIELD_UNNAMED_WORD, UNNAMED_WORD)),
            reply=1,
        )
        if name != "waiting":
            self.emit(
                name,
                TYPE_PRIVILEGES_NOTIFICATION,
                0,
                (
                    (
                        FIELD_ACCESS_BITMAP,
                        bytes(ACCESS_BITMAP_BYTES) if name == "denied" else ADMIN,
                    ),
                ),
            )
        elif self.fault == "waiting_online":
            self.emit(
                name, TYPE_PRIVILEGES_NOTIFICATION, 0, ((FIELD_ACCESS_BITMAP, ADMIN),)
            )
        self.emit(name, TYPE_LOGIN_AGREEMENT, 0, ((FIELD_DATA, AGREEMENT),))

    def _read(self, name: str, ident: int) -> None:
        """Answer a board read with the board, or refuse a low account's read."""
        if name == "denied":
            if self.fault == "permission":
                self.emit(name, ACK, ident, reply=1)
            else:
                self.emit(
                    name,
                    ACK,
                    ident,
                    ((FIELD_ERROR_TEXT, PERMISSION_TEXT),),
                    reply=1,
                    error=1,
                )
            return
        board = self.board[:READ_LIMIT]
        if self.fault == "filler" and ident == FILLER_REQUEST:
            board = board[:-1] + b"!"
        self.emit(name, ACK, ident, ((FIELD_DATA, board),) if board else (), reply=1)

    def _post(self, name: str, ident: int, values: dict[int, bytes]) -> None:
        """Answer a board post, store its segment and notify the recipients."""
        data = values[FIELD_DATA]
        if len(data) > POST_LIMIT:
            self.emit(
                name,
                ACK,
                ident,
                ((FIELD_ERROR_TEXT, INVALID_SIZE_TEXT),),
                reply=1,
                error=0 if self.fault == "error_status" else 1,
            )
            return
        self.emit(name, ACK, ident, reply=1)
        segment = SENDER_HEADER + data + cases.SEPARATOR
        if self.fault == "corrupt_segment" and ident == SECOND_POST_ID:
            segment = segment[:-1] + b"!"
        self.board = segment + self.board
        self._notify(ident, segment)

    def _drops(self, recipient: str, ident: int) -> bool:
        """Whether the fault withholds the first post's update from ``recipient``.

        Returns
        -------
        bool
            True when the update is withheld.
        """
        return (
            self.fault == "missing_eligible"
            and recipient == "eligible"
            and ident == FIRST_POST_ID
        )

    def _corrupts(self, recipient: str, ident: int) -> bool:
        """Whether the fault corrupts the first post's update for ``recipient``.

        Returns
        -------
        bool
            True when the update is corrupted.
        """
        return (
            self.fault == "wrong_waiting"
            and recipient == "waiting"
            and ident == FIRST_POST_ID
        )

    def _notify(self, ident: int, segment: bytes) -> None:
        """Send a board update of ``segment`` to each open recipient, as faulted."""
        for recipient in ("sender", "eligible", "waiting"):
            if recipient not in self.closed:
                if self._drops(recipient, ident):
                    continue
                observed = segment
                if self._corrupts(recipient, ident):
                    observed = segment + b"!"
                self.emit(recipient, BOARD_UPDATE, ident, ((FIELD_DATA, observed),))
        if self.fault == "denied_update" and ident == FIRST_POST_ID:
            self.emit("denied", BOARD_UPDATE, ident, ((FIELD_DATA, segment),))

    def until(
        self, predicate: cabc.Callable[[], bool], seconds: float = UNTIL_SECONDS
    ) -> None:
        """Require that ``predicate`` already holds, as the fake answers at once."""
        assert predicate(), "Fake response did not satisfy requested barrier"

    def observe(self, seconds: float) -> None:
        """Observe nothing, because the fake answers each request at once."""

    def close(self, name: str) -> None:
        """Close the fake socket for ``name`` and record its shutdown."""
        self.closed.add(name)
        self.recorder.sockets.pop(name).close()
        self.recorder.event(-1, name, "shutdown_write")
        self.recorder.event(-1, name, "eof")
        self.recorder.event(-1, name, "close")


def refuses(
    call: cabc.Callable[..., object],
    *args: object,
    errors: tuple[type[BaseException], ...] = (ValueError,),
    **kwargs: object,
) -> None:
    """Call ``call`` and require that it raises one of ``errors``.

    The original assertions named only the exception type, and so does this one.

    Raises
    ------
    AssertionError
        When the call returns normally, so that no expected error was raised.
    """
    try:
        call(*args, **kwargs)
    except errors:
        return
    raise AssertionError(NOT_RAISED)


def environment() -> dict[str, typ.Any]:
    """Return the verified runtime environment that the fixture is planned for.

    Returns
    -------
    dict[str, typing.Any]
        The environment, with the stopped board baseline of the fixture.
    """
    return {
        "fixture_profile": "control-only",
        "emulator_pid": 42,
        "emulator_starttime": 123,
        "emulator_sha256": "a" * 64,
        "emulator_netns_inode": 555,
        "owned_working_image": "/ignored/fresh.dsk",
        "owned_working_image_inode": 100,
        "stopped_board_baseline": {
            "path": cases.PATH,
            "catalog_id": 11191,
            "data_size": 0,
            "resource_size": 0,
            "finder_type": "TEXT",
            "finder_creator": "ttxt",
        },
    }


def fake_report(
    fault: str | None = None,
) -> tuple[dict[str, typ.Any], dict[str, typ.Any]]:
    """Execute the planned case against the fake wire and return its report.

    Returns
    -------
    tuple[dict[str, typing.Any], dict[str, typing.Any]]
        The plan and the report that the fake wire produced.
    """
    plan = cases.source_plan(environment())
    recorder = Recorder(plan)
    wire = FakeWire(recorder, fault)
    segments: list[bytes] = []
    payloads: list[bytes] = []
    reads: dict[str, str] = {}
    try:
        execute_case(wire, plan, recorder, segments, payloads, reads, pace_seconds=0)
    finally:
        for name in list(recorder.sockets):
            wire.close(name)
    whole = b"".join(reversed(segments))
    report = {
        "status": "completed",
        "plan_sha256": sha((json.dumps(plan, indent=2) + "\n").encode()),
        "elapsed_seconds": (time.monotonic_ns() - recorder.started) / NANOS_PER_SECOND,
        "byte_count": recorder.byte_count,
        "frames": recorder.frames,
        "events": recorder.events,
        "streams": recorder.streams(),
        "post_data_hex": [x.hex() for x in payloads],
        "segments_hex": [x.hex() for x in segments],
        "reads": reads,
        "whole_board_sha256": sha(whole),
        "storage": "requires_stopped_guest_fork",
        "full_a7": "not_exercised",
    }
    return plan, report
