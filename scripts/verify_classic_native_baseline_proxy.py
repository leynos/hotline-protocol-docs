"""Check the Classic control stream, the watchdog and the proxy log of one case."""

import typing as typ

from verify_classic_native_baseline_common import (
    AGREEMENT_BYTES,
    AGREEMENT_SHA,
    CUTOFF_NS,
    MISSING_DATA_MESSAGE,
    WATCHDOG_LIMIT_NS,
    digest,
    require,
)
from verify_mac_peer_first_session import AGREEMENT, field_map, parse_frames


def ordered_frames(
    frames: list[dict[str, typ.Any]],
) -> list[tuple[int, int, int, int, int]]:
    """Reduce each decoded frame to the fields that fix the wire order.

    Returns
    -------
    list[tuple[int, int, int, int, int]]
        Flags, reply marker, type, ID and error of each frame, in order.
    """
    return [(f["flags"], f["is_reply"], f["type"], f["id"], f["error"]) for f in frames]


def verify_control(case: str, client: bytes, server: bytes) -> dict[str, typ.Any]:
    """Check the handshake, the request and reply sequence and the fixed fields.

    Returns
    -------
    dict[str, typing.Any]
        The request and reply types, in order.
    """
    require(client[:12] == bytes.fromhex("54525450484f544c00010002"), "Client hello")
    require(server[:8] == bytes.fromhex("5452545000000000"), "Server hello")
    requests = parse_frames(client[12:])
    replies = parse_frames(server[8:])
    expected_requests = [(0, 0, 107, 1, 0)]
    expected_replies = [(0, 1, 0, 1, 0), (0, 0, 109, 1, 0)]
    if case == "b47":
        expected_requests += [(0, 0, 121, 2, 0), (0, 0, 300, 3, 0), (0, 0, 212, 4, 0)]
        expected_replies += [
            (0, 1, 0, 2, 0),
            (0, 0, 354, 2, 0),
            (0, 0, 122, 3, 0),
            (0, 1, 0, 3, 0),
            (0, 1, 0, 4, 0),
        ]
    require(ordered_frames(requests) == expected_requests, "Request sequence")
    require(ordered_frames(replies) == expected_replies, "Reply sequence")
    require(
        field_map(replies[0]) == {160: b"\x00\xbe", 161: b"\0\0"}, "Login ACK fields"
    )
    agreement = field_map(replies[1])
    require(agreement == {101: AGREEMENT}, "Agreement text")
    require(
        len(AGREEMENT) == AGREEMENT_BYTES and digest(AGREEMENT) == AGREEMENT_SHA,
        "Agreement identity",
    )
    if case == "b47":
        require(field_map(requests[1])[102] == b"unnamed", "121 display name")
        require(
            field_map(requests[2]) == {} and field_map(requests[3]) == {},
            "Automatic requests",
        )
        require(
            field_map(replies[5])
            == {300: bytes.fromhex("003c019e00120007756e6e616d6564")},
            "Roster record",
        )
        require(
            field_map(replies[6])[107] == bytes.fromhex("003f7729"), "Banner reference"
        )
    return {
        "request_types": [f["type"] for f in requests],
        "reply_types": [f["type"] for f in replies],
    }


def verify_watchdog(report: dict[str, typ.Any]) -> dict[str, typ.Any]:
    """Check the intentional cutoff, its timing and the forwarded ACK.

    Returns
    -------
    dict[str, typing.Any]
        The teardown time in seconds and the proxy status.
    """
    observation = report["observation"]
    require(report["status"] == "intentional-observation-cutoff", "Proxy outcome")
    require(
        observation["state"] == "fired" and observation["valid_30_seconds"] is True,
        "Watchdog receipt",
    )
    start = observation["ack_sent_monotonic_ns"]
    finish = observation["relay_teardown_ns"]
    cutoff = observation["cutoff_actual_ns"]
    due = observation["cutoff_due_ns"]
    require(due - start == CUTOFF_NS, "Watchdog target")
    require(
        start <= due <= cutoff <= finish < start + WATCHDOG_LIMIT_NS,
        "Watchdog teardown",
    )
    require(not report["errors"] and observation["error"] is None, "Proxy errors")
    require(
        observation["raw_ack_sha256"] == observation["forwarded_ack_sha256"],
        "ACK rewrite",
    )
    return {"teardown_seconds": (finish - start) / 1e9, "status": report["status"]}


def verify_proxy_log(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # the callers' shape
    case: str,
    report: dict[str, typ.Any],
    client: bytes,
    server: bytes,
    data: tuple[bytes, bytes] | None,
) -> None:
    """Check that the proxy log matches the wire and records the expected events.

    Raises
    ------
    ValueError
        When a check fails, or when a B47 case has no banner data.
    """
    entries = report["entries"]

    def logged(event: str) -> bytes:
        """Join the raw bytes of every logged entry of one event kind.

        Returns
        -------
        bytes
            The concatenated raw bytes, in log order.
        """
        return b"".join(
            bytes.fromhex(e["raw_hex"]) for e in entries if e["event"] == event
        )

    require(
        all(e.get("raw_hex") == e.get("forwarded_hex") for e in entries),
        "Proxy altered baseline bytes",
    )
    control_client = (
        logged("client-handshake") + logged("login-request") + logged("client")
    )
    control_server = logged("server-handshake") + logged("server")
    require(
        control_client == client and control_server == server, "Proxy log/wire mismatch"
    )
    if case == "b46":
        expected = [
            "client-handshake",
            "server-handshake",
            "login-request",
            "server",
            "server",
        ]
        require([e["event"] for e in entries] == expected, "B46 must stop before 121")
    else:
        if data is None:
            raise ValueError(MISSING_DATA_MESSAGE)
        require(
            sum(e["event"] == "data-client" for e in entries) == 1
            and sum(e["event"] == "data-server" for e in entries) == 1,
            "Banner attachment",
        )
        require(logged("data-client") == data[0], "Data client log")
        require(logged("data-server") == data[1], "Data server log")
    raw = bytes.fromhex(entries[3]["raw_hex"])
    require(
        raw == server[8 : 8 + len(raw)]
        and digest(raw) == report["observation"]["raw_ack_sha256"],
        "ACK receipt mismatch",
    )
