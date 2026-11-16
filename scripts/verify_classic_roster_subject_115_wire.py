"""Check the Classic control exchange, its roster reply and the data streams."""

import dataclasses as dc
import typing as typ

from native_wire_names import (
    FIELD_ROSTER_SUBJECT,
    FIELD_USER_RECORD,
    FRAME_HEADER_BYTES,
    FRAME_SIZE_START,
    ROSTER_HEADER_BYTES,
    ROSTER_NAME_LENGTH_START,
)
from verify_classic_native_baseline import flow
from verify_classic_roster_subject_115_common import (
    AGREEMENT_SHA,
    FORWARDED_ROSTER_SHA,
    RAW_ACK_SHA,
    RAW_ROSTER_SHA,
    ROUTES,
    need,
    sha,
)
from verify_mac_peer_first_session import field_map, parse_frames

if typ.TYPE_CHECKING:
    from verify_classic_roster_subject_115_common import Packets

ROSTER_INDEX = 5  # position of the roster reply among the server replies
ROSTER_BYTES = 41  # length of the roster frame before the subject is appended
ROSTER_APPENDED_BYTES = 60  # length of the roster frame after the subject


@dc.dataclass(frozen=True, slots=True)
class Exchange:
    """The control exchange and the data streams of one capture set."""

    client: bytes
    downstream: bytes
    raw: bytes
    requests: list[dict[str, typ.Any]]
    replies: list[dict[str, typ.Any]]
    raw_replies: list[dict[str, typ.Any]]
    data: list[tuple[bytes, bytes]]


def split_frames(data: bytes) -> list[bytes]:
    """Split a byte stream into frames of a header and a body each.

    Returns
    -------
    list[bytes]
        The complete frames, in stream order.
    """
    result: list[bytes] = []
    while data:
        need(len(data) >= FRAME_HEADER_BYTES, "split frame header")
        size = int.from_bytes(data[FRAME_SIZE_START:FRAME_HEADER_BYTES], "big")
        need(len(data) >= FRAME_HEADER_BYTES + size, "split frame body")
        result.append(data[: FRAME_HEADER_BYTES + size])
        data = data[FRAME_HEADER_BYTES + size :]
    return result


def frame_header(frame: dict[str, typ.Any]) -> tuple[typ.Any, ...]:
    """Return the header fields of a frame that the wire check compares.

    Returns
    -------
    tuple[typing.Any, ...]
        The type, ID, flags, reply bit and error of the frame.
    """
    return (
        frame["type"],
        frame["id"],
        frame["flags"],
        frame["is_reply"],
        frame["error"],
    )


def wire_streams(
    manifest: dict[str, typ.Any],
    packets: Packets,
    kind: str,
) -> list[tuple[bytes, bytes]]:
    """Check one kind of route view and return the flow of each route.

    Returns
    -------
    list[tuple[bytes, bytes]]
        The client and downstream bytes of each route, in manifest order.
    """
    routes = manifest["routes"][kind]
    need(
        [r[0].removeprefix("pcaps/") for r in routes] == list(ROUTES),
        "five route views",
    )
    streams = [flow(packets[r[0]], r) for r in routes]
    need(len({client for client, _ in streams}) == 1, "client request parity")
    need(streams[0][1] == streams[1][1], "forwarded reply parity")
    need(streams[2][1] == streams[3][1] == streams[4][1], "raw reply parity")
    return streams


def build_exchange(manifest: dict[str, typ.Any], packets: Packets) -> Exchange:
    """Check the control and data routes and parse the control frames.

    Returns
    -------
    Exchange
        The parsed control exchange and the data streams.
    """
    pairs: dict[str, list[tuple[bytes, bytes]]] = {}
    for kind in ("control", "data"):
        pairs[kind] = wire_streams(manifest, packets, kind)
    control = pairs["control"]
    client, downstream = control[0]
    raw = control[2][1]
    need(
        client[:12] == bytes.fromhex("54525450484f544c00010002")
        and raw[:8] == downstream[:8] == b"TRTP\0\0\0\0",
        "handshake",
    )
    return Exchange(
        client=client,
        downstream=downstream,
        raw=raw,
        requests=parse_frames(client[12:]),
        replies=parse_frames(downstream[8:]),
        raw_replies=parse_frames(raw[8:]),
        data=pairs["data"],
    )


def check_frame_headers(exchange: Exchange) -> None:
    """Check the request sequence, the reply sequence and the raw reply identity."""
    need(
        [frame_header(f) for f in exchange.requests]
        == [(x, i, 0, 0, 0) for i, x in enumerate((107, 121, 300, 212), 1)],
        "client request sequence",
    )
    need(
        [frame_header(f) for f in exchange.replies]
        == [
            (0, 1, 0, 1, 0),
            (109, 1, 0, 0, 0),
            (0, 2, 0, 1, 0),
            (354, 2, 0, 0, 0),
            (122, 3, 0, 0, 0),
            (0, 3, 0, 1, 0),
            (0, 4, 0, 1, 0),
        ],
        "server reply sequence",
    )
    need(
        [frame_header(f) for f in exchange.raw_replies]
        == [frame_header(f) for f in exchange.replies],
        "reply header identity",
    )


def check_login_and_name(exchange: Exchange) -> None:
    """Check that the login ACK is unchanged and that the agreement and name match."""
    replies = exchange.replies
    need(
        exchange.raw_replies[0] == replies[0]
        and sha(exchange.raw[8:42]) == RAW_ACK_SHA
        and field_map(replies[0]) == {160: b"\0\xbe", 161: b"\0\0"},
        "unchanged login ACK",
    )
    need(
        sha(field_map(replies[1])[101]) == AGREEMENT_SHA
        and field_map(exchange.requests[1])[102] == b"unnamed",
        "agreement/name",
    )


def check_roster_append(original: bytes, rewritten: bytes) -> list[int]:
    """Check that the forwarded roster frame differs only by the appended subject.

    Returns
    -------
    list[int]
        The length of the raw roster frame and of the forwarded one.
    """
    expected = (
        original[:12]
        + (int.from_bytes(original[12:16], "big") + 19).to_bytes(4, "big") * 2
        + (int.from_bytes(original[20:22], "big") + 1).to_bytes(2, "big")
        + original[22:]
        + b"\0s\0\x0ffixture-subject"
    )
    need(
        rewritten == expected
        and len(original) == ROSTER_BYTES
        and len(rewritten) == ROSTER_APPENDED_BYTES,
        "sole roster TLV append",
    )
    return [len(original), len(rewritten)]


def check_roster_fields(
    raw_roster: dict[str, typ.Any], forwarded: dict[str, typ.Any]
) -> None:
    """Check the subject field and the packed user record of the roster reply."""
    need(
        FIELD_USER_RECORD in field_map(raw_roster)
        and FIELD_ROSTER_SUBJECT not in field_map(raw_roster)
        and field_map(forwarded)[FIELD_ROSTER_SUBJECT] == b"fixture-subject",
        "roster fields",
    )
    packed = field_map(raw_roster)[FIELD_USER_RECORD]
    need(
        len(packed) >= ROSTER_HEADER_BYTES
        and len(packed)
        == ROSTER_HEADER_BYTES
        + int.from_bytes(packed[ROSTER_NAME_LENGTH_START:ROSTER_HEADER_BYTES], "big")
        and len(packed) > ROSTER_HEADER_BYTES,
        "packed roster record",
    )


def check_reconstruction(
    exchange: Exchange,
    raw_frames: list[bytes],
    forwarded_frames: list[bytes],
) -> None:
    """Check that the frames rebuild both streams and that only the roster changed."""
    need(
        exchange.raw[:8] + b"".join(raw_frames) == exchange.raw,
        "raw frame reconstruction",
    )
    need(
        exchange.downstream[:8] + b"".join(forwarded_frames) == exchange.downstream,
        "forwarded frame reconstruction",
    )
    need(
        all(
            a == b
            for i, (a, b) in enumerate(
                # equal lengths are guaranteed: check_frame_headers compares the lists
                zip(exchange.raw_replies, exchange.replies, strict=True)
            )
            if i != ROSTER_INDEX
        ),
        "other replies unchanged",
    )


def check_roster(exchange: Exchange) -> dict[str, typ.Any]:
    """Check the roster reply as it was received and as it was forwarded.

    Returns
    -------
    dict[str, typing.Any]
        The roster ID and the lengths of the raw and the forwarded roster frame.
    """
    raw_roster = exchange.raw_replies[ROSTER_INDEX]
    forwarded_roster = exchange.replies[ROSTER_INDEX]
    raw_frames = split_frames(exchange.raw[8:])
    forwarded_frames = split_frames(exchange.downstream[8:])
    need(
        sha(raw_frames[ROSTER_INDEX]) == RAW_ROSTER_SHA
        and sha(forwarded_frames[ROSTER_INDEX]) == FORWARDED_ROSTER_SHA,
        "roster frame hashes",
    )
    roster_bytes = check_roster_append(
        raw_frames[ROSTER_INDEX], forwarded_frames[ROSTER_INDEX]
    )
    check_roster_fields(raw_roster, forwarded_roster)
    check_reconstruction(exchange, raw_frames, forwarded_frames)
    return {"roster_id": raw_roster["id"], "roster_bytes": roster_bytes}
