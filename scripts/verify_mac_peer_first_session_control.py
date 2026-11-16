"""Check the Classic client control and 15501 data connections across NAT views."""

import dataclasses as dc
import typing as typ

from protocol_capture import decode_frame
from verify_mac_peer_first_session_core import (
    AGREEMENT,
    BANNER_BYTES,
    CLIENT_CONTROL,
    CLIENT_DATA,
    CLIENT_DATA_PACKETS,
    CLIENT_DATA_TARGET,
    CLIENT_TARGET,
    CONTROL_CONNECT_US,
    CONTROL_LIFETIMES,
    DATA_CONNECT_US,
    DATA_MESSAGE,
    FRAME_HEADER_BYTES,
    HOST_CLIENT,
    HOST_SERVER,
    MAX_CONTROL_PAYLOAD,
    SERVER_CONTROL,
    SERVER_DATA,
    SERVER_DATA_NAT,
    SERVER_DATA_PACKETS,
    SERVER_NAT,
    is_syn,
    require,
    selected_streams,
)

type Record = dict[str, typ.Any]


def same_bytes(values: list[bytes]) -> bool:
    """Return whether every value equals the first.

    Returns
    -------
    bool
        True when all the values are equal.
    """
    return all(value == values[0] for value in values)


def parse_frames(data: bytes) -> list[Record]:
    """Require complete, unfragmented frames and fully consumed scalar TLVs.

    Returns
    -------
    list[dict[str, typing.Any]]
        The decoded frames, in order.
    """
    result: list[Record] = []
    while data:
        require(len(data) >= FRAME_HEADER_BYTES, "Incomplete control frame header")
        size = int.from_bytes(data[16:20], "big")
        require(
            size <= MAX_CONTROL_PAYLOAD and len(data) >= FRAME_HEADER_BYTES + size,
            "Incomplete control frame",
        )
        frame = decode_frame(data[: FRAME_HEADER_BYTES + size])
        require(
            frame["total_size"] == size
            and frame.get("declared_field_count") == len(frame.get("fields", []))
            and frame.get("unconsumed_hex") == "",  # pylint: disable=use-implicit-booleaness-not-comparison-to-string  # a missing value must stay unequal
            "Fragmented or malformed control frame",
        )
        result.append(frame)
        data = data[FRAME_HEADER_BYTES + size :]
    return result


def field_map(frame: Record) -> dict[int, bytes]:
    """Map each field identifier of a frame to its bytes.

    Returns
    -------
    dict[int, bytes]
        The field bytes keyed by field identifier.
    """
    result = {item["id"]: bytes.fromhex(item["hex"]) for item in frame["fields"]}
    require(len(result) == len(frame["fields"]), "Duplicate control field")
    return result


def check_control(client: bytes, server: bytes) -> dict[str, typ.Any]:
    """Require the exact control handshake, requests, replies and field values.

    Returns
    -------
    dict[str, typing.Any]
        The request and reply type sequences.
    """
    require(
        client[:12] == bytes.fromhex("54525450484f544c00010002")
        and server[:8] == bytes.fromhex("5452545000000000"),
        "Control handshake differs",
    )
    requests = parse_frames(client[12:])
    replies = parse_frames(server[8:])
    require(
        [(f["flags"], f["is_reply"], f["type"], f["id"], f["error"]) for f in requests]
        == [(0, 0, 107, 1, 0), (0, 0, 121, 2, 0), (0, 0, 300, 3, 0), (0, 0, 212, 4, 0)],
        "Control request type/id/status differs",
    )
    require(
        [(f["flags"], f["is_reply"], f["type"], f["id"], f["error"]) for f in replies]
        == [
            (0, 1, 0, 1, 0),
            (0, 0, 109, 1, 0),
            (0, 1, 0, 2, 0),
            (0, 0, 354, 2, 0),
            (0, 0, 122, 3, 0),
            (0, 1, 0, 3, 0),
            (0, 1, 0, 4, 0),
        ],
        "Control reply type/id/status differs",
    )
    require(
        [field_map(f) for f in requests]
        == [
            {
                105: bytes.fromhex("9e9b929691"),
                106: bytes.fromhex("92908b978d9ecec6"),
                160: bytes.fromhex("00be"),
            },
            {102: b"unnamed", 104: bytes.fromhex("019e"), 113: b"\x00\x00"},
            {},
            {},
        ],
        "Control request fields differ",
    )
    require(
        [field_map(f) for f in replies]
        == [
            {160: bytes.fromhex("00be"), 161: b"\x00\x00"},
            {101: AGREEMENT},
            {},
            {110: bytes.fromhex("fff3cfefff800000")},
            {152: b"GIFf", 153: b"https://example.invalid/mothra-banner"},
            {300: bytes.fromhex("0007019e00120007756e6e616d6564")},
            {108: bytes.fromhex("003a"), 107: bytes.fromhex("00038325")},
        ],
        "Control reply fields differ",
    )
    return {
        "request_types": [f["type"] for f in requests],
        "reply_types": [f["type"] for f in replies],
    }


@dc.dataclass(frozen=True, slots=True)
class ControlSession:
    """The guest control connection as the three NAT views record it."""

    view: list[Record]
    outbound: bytes
    inbound: bytes
    controls: dict[str, typ.Any]


def check_control_session(
    host: list[Record], client: list[Record], server: list[Record]
) -> ControlSession:
    """Require one control connection with the same bytes in all three views.

    Returns
    -------
    ControlSession
        The host view of the connection, its bytes and the checked control frames.
    """
    views = [
        selected_streams(host, HOST_CLIENT, HOST_SERVER, CONTROL_CONNECT_US),
        selected_streams(client, CLIENT_CONTROL, CLIENT_TARGET, CONTROL_CONNECT_US),
        selected_streams(server, SERVER_NAT, SERVER_CONTROL, CONTROL_CONNECT_US),
    ]
    require(
        same_bytes([out for _, out, _ in views])
        and same_bytes([inbound for _, _, inbound in views]),
        "Missing or changed guest control bytes across NAT views",
    )
    host_view, host_out, host_in = views[0]
    controls = check_control(host_out, host_in)
    require(
        tuple(len(view) for view, _, _ in views) == CONTROL_LIFETIMES,
        "Control lifetime or one-connect count differs",
    )
    require(
        len([p for p in host if is_syn(p)]) == 1,
        "Control lifetime or one-connect count differs",
    )
    return ControlSession(host_view, host_out, host_in, controls)


def check_data_session(
    client: list[Record], server: list[Record]
) -> tuple[bytes, bytes]:
    """Require the 15501 transfer to agree across the client and server views.

    Returns
    -------
    tuple[bytes, bytes]
        The bytes the client sent and the bytes the server sent on 15501.
    """
    guest_data, data_out, data_in = selected_streams(
        client, CLIENT_DATA, CLIENT_DATA_TARGET, DATA_CONNECT_US
    )
    server_data, server_data_out, server_data_in = selected_streams(
        server, SERVER_DATA_NAT, SERVER_DATA, DATA_CONNECT_US
    )
    require(
        data_out
        == server_data_out
        == bytes.fromhex("48545846000383250000000000020000"),
        DATA_MESSAGE,
    )
    require(
        data_in == server_data_in
        and len(data_in) == BANNER_BYTES
        and data_in.startswith(b"GIF89a"),
        DATA_MESSAGE,
    )
    require(
        len(guest_data) == CLIENT_DATA_PACKETS
        and len(server_data) == SERVER_DATA_PACKETS,
        DATA_MESSAGE,
    )
    return data_out, data_in
