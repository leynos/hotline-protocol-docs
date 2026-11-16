"""Check the B57 run: its routes, control stream, banner, proxy audit and cutoff."""

import typing as typ

from verify_classic_native_baseline import flow
from verify_classic_server_name_162_common import (
    AGREEMENT_SHA,
    CLIENT_HELLO,
    FIELDS,
    FORWARDED_ACK,
    GIF_BYTES,
    HTXF_BYTES,
    RAW_ACK,
    ROUTES,
    SERVER_HELLO,
    digest,
    load,
    require,
)
from verify_mac_peer_first_session import field_map, parse_frames

if typ.TYPE_CHECKING:
    from pathlib import Path

type Pairs = dict[str, list[tuple[bytes, bytes]]]
type Frames = list[dict[str, typ.Any]]

EVENT_COUNT = 15  # the proxy log entries of the B57 run
SERVER_EVENTS = 7  # the server entries of the B57 run
CLIENT_EVENTS = 3  # the client entries of the B57 run
ACK_ENTRY = 3  # the one log entry that carries the rewritten ACK
WATCHDOG_TARGET_NS = 28_000_000_000  # the intentional cutoff target
WATCHDOG_LIMIT_NS = 30_000_000_000  # the proxy must tear down within this bound
OBSERVED_TEARDOWN_NS = 28_195_908_139  # the teardown that the retained run recorded


def check_b57_views(
    manifest: dict[str, typ.Any], packets: dict[str, list[dict[str, typ.Any]]]
) -> Pairs:
    """Check that each route kind yields the same streams in all five views.

    Returns
    -------
    dict[str, list[tuple[bytes, bytes]]]
        The client and server streams of every route, by route kind.
    """
    routes = manifest["b57"]["routes"]
    require(set(routes) == {"control", "data"}, "B57 route kinds")
    pairs = {}
    for kind in ("control", "data"):
        require(
            [r[0].removeprefix("pcaps/") for r in routes[kind]] == list(ROUTES),
            f"B57 {kind} five views",
        )
        streams = [flow(packets[r[0]], r) for r in routes[kind]]
        require(
            len({client for client, _ in streams}) == 1, f"B57 {kind} upstream parity"
        )
        require(streams[0][1] == streams[1][1], f"B57 {kind} downstream parity")
        require(
            streams[2][1] == streams[3][1] == streams[4][1], f"B57 {kind} raw parity"
        )
        pairs[kind] = streams
    return pairs


def check_handshake(
    control: list[tuple[bytes, bytes]], manifest: dict[str, typ.Any]
) -> None:
    """Check the TRTP/HOTL handshake and the one ACK that the proxy rewrote."""
    raw = control[2][1]
    downstream = control[0][1]
    require(
        raw[:8] == SERVER_HELLO and control[0][0][:12] == CLIENT_HELLO,
        "TRTP/HOTL handshake",
    )
    require(
        raw[8 : 8 + len(RAW_ACK)] == RAW_ACK
        and digest(RAW_ACK) == manifest["original_ack_sha256"]
        and digest(FORWARDED_ACK) == manifest["forwarded_ack_sha256"]
        and downstream == SERVER_HELLO + FORWARDED_ACK + raw[8 + len(RAW_ACK) :],
        "B57 sole ACK rewrite",
    )


def check_frames(control: list[tuple[bytes, bytes]]) -> tuple[Frames, Frames]:
    """Check the request and reply sequence, the 162 fields and the roster request.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], list[dict[str, typing.Any]]]
        The decoded requests and the decoded downstream replies, in order.
    """
    raw = control[2][1]
    downstream = control[0][1]
    requests = parse_frames(control[0][0][12:])
    replies = parse_frames(downstream[8:])
    raw_replies = parse_frames(raw[8:])
    require(
        [f["type"] for f in requests] == [107, 121, 300, 212]
        and [f["id"] for f in requests] == [1, 2, 3, 4]
        and [f["type"] for f in replies] == [0, 109, 0, 354, 122, 0, 0]
        and [f["id"] for f in replies] == [1, 1, 2, 2, 3, 3, 4]
        and [(f["flags"], f["is_reply"], f["error"]) for f in requests]
        == [(0, 0, 0)] * 4
        and [(f["flags"], f["is_reply"], f["error"]) for f in replies]
        == [(0, x, 0) for x in (1, 0, 1, 0, 0, 1, 1)]
        and [
            (f["flags"], f["is_reply"], f["error"], f["id"], f["type"])
            for f in raw_replies
        ]
        == [
            (f["flags"], f["is_reply"], f["error"], f["id"], f["type"]) for f in replies
        ],
        "B57 control sequence/IDs/flags",
    )
    require(
        field_map(raw_replies[0]) == {160: b"\0\xbe", 161: b"\0\0"}
        and field_map(replies[0]) == FIELDS,
        "B57 162 fields",
    )
    require(digest(field_map(replies[1])[101]) == AGREEMENT_SHA, "B57 known agreement")
    require(field_map(requests[1])[102] == b"unnamed", "B57 unnamed roster request")
    return requests, replies


def check_banner(data: list[tuple[bytes, bytes]], reference: bytes) -> None:
    """Check the banner request and the delivered banner against the reference."""
    require(
        len(data[0][0]) == HTXF_BYTES
        and data[0][0][:4] == b"HTXF"
        and data[0][0][4:8] == reference
        and len(data[0][1]) == GIF_BYTES
        and data[0][1][:6] == b"GIF89a"
        and data[0][1] == data[2][1],
        "B57 banner reference/data parity",
    )


def check_audit(base: Path, pairs: Pairs) -> dict[str, typ.Any]:
    """Check the proxy audit log against the wire and its one sole mutation.

    Returns
    -------
    dict[str, typing.Any]
        The proxy report of the B57 run.
    """
    control = pairs["control"]
    raw = control[2][1]
    downstream = control[0][1]
    data = pairs["data"]
    report = load(base / "b57/proxy/report.json")
    entries = report["entries"]
    events = [e["event"] for e in entries]
    require(
        events[:5]
        == ["client-handshake", "server-handshake", "login-request", "server", "server"]
        and len(events) == EVENT_COUNT
        and events.count("server") == SERVER_EVENTS
        and events.count("client") == CLIENT_EVENTS
        and events.count("data-client") == events.count("data-server") == 1,
        "B57 proxy audit events",
    )

    def logged(names: set[str], key: str) -> bytes:
        """Join one key of the logged entries of the named events.

        Returns
        -------
        bytes
            The concatenated bytes, in log order.
        """
        return b"".join(bytes.fromhex(e[key]) for e in entries if e["event"] in names)

    require(
        logged({"client-handshake", "login-request", "client"}, "raw_hex")
        == control[0][0]
        and logged({"server-handshake", "server"}, "raw_hex") == raw
        and logged({"server-handshake", "server"}, "forwarded_hex") == downstream
        and logged({"data-client"}, "raw_hex") == data[0][0]
        and logged({"data-server"}, "raw_hex") == data[0][1]
        and all(
            e["raw_hex"] == e["forwarded_hex"]
            for i, e in enumerate(entries)
            if i != ACK_ENTRY
        ),
        "B57 proxy audit/wire and sole mutation",
    )
    return report


def check_observation(base: Path, report: dict[str, typ.Any]) -> int:
    """Check the cutoff receipt, its timing and the cleanup of the B57 proxy.

    Returns
    -------
    int
        The observed teardown time, in nanoseconds.
    """
    obs = report["observation"]
    require(
        report["variant"] == "server-name-162"
        and report["status"] == "intentional-observation-cutoff"
        and not report["errors"]
        and obs["state"] == "fired"
        and obs["valid_30_seconds"] is True
        and obs["raw_ack_sha256"] == digest(RAW_ACK)
        and obs["forwarded_ack_sha256"] == digest(FORWARDED_ACK),
        "B57 proxy cutoff status",
    )
    elapsed = obs["relay_teardown_ns"] - obs["ack_sent_monotonic_ns"]
    require(
        obs["cutoff_due_ns"] - obs["ack_sent_monotonic_ns"] == WATCHDOG_TARGET_NS
        and elapsed == OBSERVED_TEARDOWN_NS
        and elapsed < WATCHDOG_LIMIT_NS,
        "B57 cutoff timing",
    )
    require(
        "Id=mothra-classic-proxy-b57.service\nActiveState=inactive\nMainPID=0\nResult=success"
        in (base / "b57/units-terminal.txt").read_text()
        and "15652" not in (base / "b57/listeners-terminal.txt").read_text()
        and (base / "b57/active-native-terminal.txt")
        .read_text()
        .strip()
        .startswith("State"),
        "B57 proxy/socket cleanup",
    )
    return elapsed


def check_b57(
    base: Path,
    manifest: dict[str, typ.Any],
    packets: dict[str, list[dict[str, typ.Any]]],
) -> dict[str, typ.Any]:
    """Check the whole B57 run, from its routes to its cutoff and cleanup.

    Returns
    -------
    dict[str, typing.Any]
        The decoded fields, frame types, banner sizes and teardown time.
    """
    pairs = check_b57_views(manifest, packets)
    control = pairs["control"]
    check_handshake(control, manifest)
    requests, replies = check_frames(control)
    reference = field_map(replies[6])[107]
    check_banner(pairs["data"], reference)
    report = check_audit(base, pairs)
    elapsed = check_observation(base, report)
    return {
        "fields": {str(k): v.hex() for k, v in FIELDS.items()},
        "requests": [f["type"] for f in requests],
        "replies": [f["type"] for f in replies],
        "banner_bytes": [len(pairs["data"][0][0]), len(pairs["data"][0][1])],
        "teardown_seconds": elapsed / 1e9,
    }
