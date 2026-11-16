"""Drive the board actors: log in, read the board, and post to it.

Part of the board runner (``native_board_control``), whose ``CAPTURE_MODULES``
lists this module and which re-exports every public name below. Each step fails
closed with a ``ValueError`` that names what differed.
"""

import native_board_cases as cases
from native_board_control_wire import Report, Wire, frame_fields, need, one, sha
from native_plan import packet
from native_wire_names import (
    FIELD_DATA,
    FIELD_ERROR_TEXT,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRIVILEGES_NOTIFICATION,
)

AGREEMENT_SHA = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
# The request types of the board: read the board, and the board update push.
TYPE_READ_BOARD = 101
TYPE_BOARD_UPDATE = 102
LOGIN_REPLY_FIELDS = {160: b"\0\xbe", 161: b"\0\0"}
OVERSIZE_OBSERVE_SECONDS = 0.4
UPDATE_OBSERVE_SECONDS = 0.2
BARRIER_WAIT_SECONDS = 5
SEGMENT_PREFIX = b"From "
MAX_READ_BYTES = 65535


def success(frame: Report, identifier: int) -> dict[int, bytes]:
    """Require a direct success acknowledgement and return its fields.

    Returns
    -------
    dict[int, bytes]
        The fields of the acknowledgement.
    """
    need(
        frame["id"] == identifier
        and frame["is_reply"] == 1
        and frame["type"] == 0
        and frame["error"] == 0,
        "Direct board success ACK differs",
    )
    return frame_fields(frame)


def _frames_of(wire: Wire, name: str, kind: int) -> list[Report]:
    """List the frames of one flow with one type.

    Returns
    -------
    list[dict[str, typing.Any]]
        The matching frames, in order.
    """
    return [
        f for f in wire.recorder.frames if f["connection"] == name and f["type"] == kind
    ]


def _has_reply(frames: list[Report], name: str, identifier: int) -> bool:
    """Say whether a flow received the reply to a request.

    Returns
    -------
    bool
        ``True`` when a reply with that identifier is among the frames.
    """
    return any(
        f["connection"] == name and f["is_reply"] == 1 and f["id"] == identifier
        for f in frames
    )


def _agreement(wire: Wire, name: str) -> None:
    """Require the actor to have received exactly the controlled agreement."""
    wire.until(lambda: bool(_frames_of(wire, name, TYPE_LOGIN_AGREEMENT)))
    notices = _frames_of(wire, name, TYPE_LOGIN_AGREEMENT)
    need(
        len(notices) == 1
        and sha(frame_fields(notices[0]).get(FIELD_DATA, b"")) == AGREEMENT_SHA,
        "Board actor agreement differs",
    )


def _access(wire: Wire, name: str, access: bytes | None) -> None:
    """Require the actor's privileges, or require that it is not online yet."""
    if access is None:
        need(
            not _frames_of(wire, name, TYPE_PRIVILEGES_NOTIFICATION),
            "Waiting actor became online",
        )
        return
    wire.until(lambda: bool(_frames_of(wire, name, TYPE_PRIVILEGES_NOTIFICATION)))
    first = _frames_of(wire, name, TYPE_PRIVILEGES_NOTIFICATION)[0]
    acl = one(wire.recorder.frames, name, TYPE_PRIVILEGES_NOTIFICATION, first["id"], 0)
    need(frame_fields(acl) == {110: access}, "Board actor ACL differs")


def login(wire: Wire, name: str, raw: bytes, access: bytes | None) -> None:
    """Connect an actor, log it in and check its replies.

    Parameters
    ----------
    wire : Wire
        The sockets of the case.
    name : str
        The actor.
    raw : bytes
        The login request.
    access : bytes | None
        The privileges the actor must be given, or ``None`` for an actor that
        must stay offline.
    """
    wire.connect(name, ("127.0.0.1", cases.PORT))
    wire.send(name, raw)
    wire.until(lambda: _has_reply(wire.recorder.frames, name, 1))
    reply = one(wire.recorder.frames, name, 0, 1, 1)
    need(
        frame_fields(reply) == LOGIN_REPLY_FIELDS and reply["error"] == 0,
        "Login ACK differs",
    )
    _agreement(wire, name)
    _access(wire, name, access)


def _ask_for_board(wire: Wire, name: str, identifier: int) -> Report:
    """Send a board read and wait for its reply.

    Returns
    -------
    dict[str, typing.Any]
        The reply frame.
    """
    before = len(wire.recorder.frames)
    wire.send(name, bytes.fromhex(packet(TYPE_READ_BOARD, identifier)))
    wire.until(lambda: _has_reply(wire.recorder.frames[before:], name, identifier))
    return one(wire.recorder.frames[before:], name, 0, identifier, 1)


def read_denied(wire: Wire, name: str, identifier: int) -> None:
    """Request the board as an actor that must be refused, and check the refusal."""
    frame = _ask_for_board(wire, name, identifier)
    result = frame_fields(frame)
    need(
        frame["error"] == 1 and set(result) == {FIELD_ERROR_TEXT},
        "Denied board read differs",
    )


def read_board(wire: Wire, name: str, identifier: int, expected: bytes | None) -> bytes:
    """Request the board and check what comes back.

    Parameters
    ----------
    wire : Wire
        The sockets of the case.
    name : str
        The actor that reads.
    identifier : int
        The request identifier.
    expected : bytes | None
        The aggregate that the reply must begin with, or ``None``.

    Returns
    -------
    bytes
        The board data of the reply.
    """
    frame = _ask_for_board(wire, name, identifier)
    result = frame_fields(frame)
    need(
        frame["error"] == 0 and set(result) <= {FIELD_DATA},
        "Board read status/fields differ",
    )
    actual = result.get(FIELD_DATA, b"")
    need((FIELD_DATA in result) == bool(actual), "Empty board field presence differs")
    if expected is not None:
        need(actual == expected[:MAX_READ_BYTES], "Board aggregate prefix differs")
    return actual


def check_segment(
    frame: Report, data: bytes, expected_overhead: int | None
) -> tuple[bytes, int]:
    """Check one board update segment and measure its rendered header.

    Returns
    -------
    tuple[bytes, int]
        The segment and the bytes it adds around ``data``.
    """
    need(
        frame["type"] == TYPE_BOARD_UPDATE
        and frame["is_reply"] == 0
        and frame["error"] == 0,
        "Board update header differs",
    )
    value = frame_fields(frame)
    need(set(value) == {FIELD_DATA}, "Board update fields differ")
    segment = value[FIELD_DATA]
    need(
        segment.startswith(SEGMENT_PREFIX) and segment.endswith(data + cases.SEPARATOR),
        "Board segment header/data/separator differs",
    )
    overhead = len(segment) - len(data)
    if expected_overhead is not None:
        need(overhead == expected_overhead, "Rendered header overhead changed")
    return segment, overhead


def _oversize_post(wire: Wire, before: int, identifier: int) -> None:
    """Require the oversize post to be refused without any update."""
    wire.until(lambda: _has_reply(wire.recorder.frames[before:], "sender", identifier))
    reply = one(wire.recorder.frames[before:], "sender", 0, identifier, 1)
    need(
        reply["error"] == 1 and set(frame_fields(reply)) == {FIELD_ERROR_TEXT},
        "Oversize post status differs",
    )
    wire.observe(OVERSIZE_OBSERVE_SECONDS)
    need(
        not any(f["type"] == TYPE_BOARD_UPDATE for f in wire.recorder.frames[before:]),
        "Oversize post emitted update",
    )


def _post_arrived(wire: Wire, before: int, identifier: int) -> bool:
    """Say whether the ACK and both updates of a post have arrived.

    Returns
    -------
    bool
        ``True`` when the sender has its ACK and its update, and the eligible
        reader has its update.
    """
    return all(
        any(
            f["connection"] == name
            and f["type"] == kind
            and (kind != 0 or f["id"] == identifier)
            for f in wire.recorder.frames[before:]
        )
        for name, kind in (
            ("sender", 0),
            ("sender", TYPE_BOARD_UPDATE),
            ("eligible", TYPE_BOARD_UPDATE),
        )
    )


def post(
    wire: Wire, index: int, data: bytes, overhead: int | None
) -> tuple[bytes, int | None]:
    """Post one message and check who is sent what.

    Parameters
    ----------
    wire : Wire
        The sockets of the case.
    index : int
        The post number.
    data : bytes
        The message.
    overhead : int | None
        The rendered header size measured by an earlier post, if any.

    Returns
    -------
    tuple[bytes, int | None]
        The segment the board holds for the post, and the header size.
    """
    before = len(wire.recorder.frames)
    wire.send("sender", bytes.fromhex(cases.post_packet(index, data)))
    identifier = cases.POST_ID + index
    if index == cases.REJECTED_POST:
        _oversize_post(wire, before, identifier)
        return b"", overhead
    wire.until(lambda: _post_arrived(wire, before, identifier), BARRIER_WAIT_SECONDS)
    recent = wire.recorder.frames[before:]
    reply = one(recent, "sender", 0, identifier, 1)
    need(success(reply, identifier) == {}, "Post ACK carries unexpected data")
    sender = [
        f
        for f in recent
        if f["connection"] == "sender" and f["type"] == TYPE_BOARD_UPDATE
    ]
    eligible = [
        f
        for f in recent
        if f["connection"] == "eligible" and f["type"] == TYPE_BOARD_UPDATE
    ]
    need(len(sender) == len(eligible) == 1, "Update recipient count differs")
    segment, overhead = check_segment(sender[0], data, overhead)
    need(
        frame_fields(eligible[0]) == {FIELD_DATA: segment},
        "Eligible update bytes differ",
    )
    wire.observe(UPDATE_OBSERVE_SECONDS)
    need(
        not any(
            f["connection"] == "denied" and f["type"] == TYPE_BOARD_UPDATE
            for f in wire.recorder.frames[before:]
        ),
        "Denied observer received update",
    )
    return segment, overhead
