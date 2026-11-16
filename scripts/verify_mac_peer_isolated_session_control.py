"""Check the isolated Classic client control reply fields and the 15501 data bytes."""

import typing as typ

from verify_mac_peer_first_session import AGREEMENT, field_map, parse_frames, require

ROSTER_BYTES = 15  # the length of field 300 in the roster reply
REFERENCE_BYTES = 4  # the length of the data reference in the 212 reply
BANNER_BYTES = 58  # the length of the banner response on the data connection


def check_control(client: bytes, server: bytes) -> dict[str, typ.Any]:
    """Require the isolated control handshake, requests, replies and field values.

    Returns
    -------
    dict[str, typing.Any]
        The UID, the data reference and the request and reply type sequences.
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
        "Control request type/id/status differs or extra numbered request",
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
                160: b"\x00\xbe",
            },
            {102: b"unnamed", 104: b"\x01\x9e", 113: b"\x00\x00"},
            {},
            {},
        ],
        "Control request fields differ",
    )
    fields = [field_map(f) for f in replies]
    require(
        fields[0] == {160: b"\x00\xbe", 161: b"\x00\x00"},
        "Login 161 or success fields differ",
    )
    require(
        fields[1] == {101: AGREEMENT} and fields[2] == {},
        "Known agreement/reply differs",
    )
    require(
        fields[3] == {110: bytes.fromhex("fff3cfefff800000")}, "Opaque bitmap differs"
    )
    require(
        fields[4] == {152: b"GIFf", 153: b"https://example.invalid/mothra-banner"},
        "Banner reference differs",
    )
    roster = fields[5].get(300, b"")
    require(
        set(fields[5]) == {300} and len(roster) == ROSTER_BYTES,
        "Roster layout/name differs",
    )
    require(
        int.from_bytes(roster[:2], "big") > 0
        and roster[2:] == bytes.fromhex("019e00120007") + b"unnamed",
        "Roster layout/name differs",
    )
    reference = fields[6].get(107, b"")
    require(
        set(fields[6]) == {108, 107} and fields[6][108] == b"\x00\x3a",
        "212 length/reference differs",
    )
    require(
        len(reference) == REFERENCE_BYTES and reference != b"\x00" * 4,
        "212 length/reference differs",
    )
    return {
        "uid": int.from_bytes(roster[:2], "big"),
        "data_reference_hex": reference.hex(),
        "client_types": [f["type"] for f in requests],
        "server_types": [f["type"] for f in replies],
    }


def check_data(reference: bytes, outbound: bytes, inbound: bytes) -> None:
    """Require the dynamic data reference and the banner response to match."""
    require(
        outbound == b"HTXF" + reference + b"\x00\x00\x00\x00\x00\x02\x00\x00",
        "Dynamic 212/data HTXF reference differs",
    )
    require(
        len(inbound) == BANNER_BYTES and inbound.startswith(b"GIF89a"),
        "58-byte banner response differs",
    )
