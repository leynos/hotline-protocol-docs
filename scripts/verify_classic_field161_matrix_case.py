"""Check one replayed field-161 case: its views, its ACK rewrite and its audit."""

import json
import typing as typ

from classic_login_proxy import transform_ack
from verify_classic_field161_matrix_common import (
    AGREEMENT_SHA,
    AUDIT_EVENTS,
    CLIENT_EVENTS,
    CUTOFF_NS,
    DATA_HEADER_BYTES,
    DATA_PAYLOAD_BYTES,
    EXPECTED_FIELDS,
    REWRITTEN_ENTRY,
    SERVER_EVENTS,
    SOURCE_ACK_HEX,
    SOURCE_ACK_SHA,
    TEARDOWN_LIMIT_NS,
    VIEWS_PER_STREAM,
    digest,
    require,
)
from verify_classic_native_baseline import flow
from verify_mac_peer_first_session import field_map, parse_frames

if typ.TYPE_CHECKING:
    from pathlib import Path


def view_pairs(
    name: str, spec: dict[str, typ.Any], packets: dict[str, typ.Any], kind: str
) -> list[tuple[bytes, bytes]]:
    """Read the client and server bytes of each view of one stream kind.

    Returns
    -------
    list[tuple[bytes, bytes]]
        The client and server bytes of each view, in the order of the spec.
    """
    routes = spec["routes"][kind]
    require(len(routes) == VIEWS_PER_STREAM, f"{name} five views")
    pairs = [flow(packets[route[0]], route) for route in routes]
    require(len({c for c, _ in pairs}) == 1, f"{name} {kind} client parity")
    return pairs


def check_acknowledgement(
    name: str, spec: dict[str, typ.Any], pairs: list[tuple[bytes, bytes]]
) -> None:
    """Check that the server ACK is the expected source and that only it was rewritten.

    Parameters
    ----------
    name : str
        The case name.
    spec : dict[str, typing.Any]
        The case's expectations.
    pairs : list[tuple[bytes, bytes]]
        The client and server bytes of each control view.
    """
    require(pairs[0][1] == pairs[1][1], f"{name} downstream parity")
    require(pairs[2][1] == pairs[3][1] == pairs[4][1], f"{name} raw server parity")
    raw = pairs[2][1]
    require(raw[:8] == bytes.fromhex("5452545000000000"), "server hello")
    size = int.from_bytes(raw[24:28], "big")
    ack = raw[8 : 28 + size]
    rewritten = transform_ack(ack, 1, name)
    require(
        ack.hex() == SOURCE_ACK_HEX and digest(ack) == SOURCE_ACK_SHA,
        f"{name} source/forwarded ACK",
    )
    require(
        rewritten.hex() == spec["expected_ack_hex"]
        and digest(rewritten) == spec["expected_ack_sha256"],
        f"{name} source/forwarded ACK",
    )
    require(
        pairs[0][1] == raw[:8] + rewritten + raw[8 + len(ack) :],
        f"{name} sole ACK rewrite",
    )


def check_sequence(
    name: str, pairs: list[tuple[bytes, bytes]]
) -> tuple[list[dict[str, typ.Any]], list[dict[str, typ.Any]]]:
    """Check the frames of the control exchange in their order and their flags.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], list[dict[str, typing.Any]]]
        The parsed client requests and the parsed server replies.
    """
    client = pairs[0][0]
    require(client[:12] == bytes.fromhex("54525450484f544c00010002"), "client hello")
    requests = parse_frames(client[12:])
    replies = parse_frames(pairs[0][1][8:])
    require(
        [f["type"] for f in requests] == [107, 121, 300, 212]
        and [f["type"] for f in replies] == [0, 109, 0, 354, 122, 0, 0],
        f"{name} control sequence",
    )
    require(
        [f["id"] for f in requests] == [1, 2, 3, 4]
        and [f["id"] for f in replies] == [1, 1, 2, 2, 3, 3, 4],
        f"{name} control sequence",
    )
    require(
        all(f["flags"] == f["error"] == f["is_reply"] == 0 for f in requests)
        and all(f["flags"] == f["error"] == 0 for f in replies),
        f"{name} control sequence",
    )
    require(
        [f["is_reply"] for f in replies] == [1, 0, 1, 0, 0, 1, 1],
        f"{name} control sequence",
    )
    return requests, replies


def check_login_fields(
    name: str,
    requests: list[dict[str, typ.Any]],
    replies: list[dict[str, typ.Any]],
) -> bytes:
    """Check the field-161 shape, the agreement and the roster of the login.

    Returns
    -------
    bytes
        The field-107 reference that the data connection must echo.
    """
    require(field_map(replies[0]) == EXPECTED_FIELDS[name], f"{name} 161 shape")
    require(
        digest(field_map(replies[1])[101]) == AGREEMENT_SHA,
        f"{name} 109 agreement",
    )
    roster = field_map(replies[5])
    expected_user_id = {
        "omit-161": 0x45,
        "one-byte-161": 0x46,
        "four-byte-161": 0x47,
    }[name]
    require(field_map(requests[1])[102] == b"unnamed", f"{name} roster")
    require(
        roster
        == {
            300: expected_user_id.to_bytes(2, "big")
            + bytes.fromhex("019e00120007756e6e616d6564")
        },
        f"{name} roster",
    )
    return field_map(replies[6])[107]


def check_control(
    name: str, spec: dict[str, typ.Any], pairs: list[tuple[bytes, bytes]]
) -> bytes:
    """Check the control stream of one case and return its data reference.

    Returns
    -------
    bytes
        The field-107 reference that the data connection must echo.
    """
    check_acknowledgement(name, spec, pairs)
    requests, replies = check_sequence(name, pairs)
    return check_login_fields(name, requests, replies)


def check_data(name: str, pairs: list[tuple[bytes, bytes]], reference: bytes) -> None:
    """Check the data stream of one case against its reference and payload.

    Parameters
    ----------
    name : str
        The case name.
    pairs : list[tuple[bytes, bytes]]
        The client and server bytes of each data view.
    reference : bytes
        The field-107 reference that the data header must echo.
    """
    require(len({s for _, s in pairs}) == 1, f"{name} data parity")
    require(
        len(pairs[0][0]) == DATA_HEADER_BYTES
        and pairs[0][0][:4] == b"HTXF"
        and pairs[0][0][4:8] == reference,
        f"{name} data header/ref",
    )
    require(
        len(pairs[0][1]) == DATA_PAYLOAD_BYTES and pairs[0][1][:6] == b"GIF89a",
        f"{name} data payload",
    )


def stream_sizes(pairs: list[tuple[bytes, bytes]]) -> dict[str, int]:
    """Measure the client, raw server and forwarded server bytes of one stream.

    Returns
    -------
    dict[str, int]
        The three byte counts.
    """
    return {
        "client_bytes": len(pairs[0][0]),
        "raw_server_bytes": len(pairs[2][1]),
        "forwarded_server_bytes": len(pairs[0][1]),
    }


def logged(entries: list[dict[str, typ.Any]], events: set[str], key: str) -> bytes:
    """Join the bytes of one key over the audited entries of some events.

    Returns
    -------
    bytes
        The concatenated bytes, in audit order.
    """
    return b"".join(
        bytes.fromhex(entry[key]) for entry in entries if entry["event"] in events
    )


def check_events(name: str, entries: list[dict[str, typ.Any]]) -> None:
    """Check the order and the counts of the audited proxy events.

    Parameters
    ----------
    name : str
        The case name.
    entries : list[dict[str, typing.Any]]
        The audited proxy entries.
    """
    events = [entry["event"] for entry in entries]
    require(
        events[:5]
        == [
            "client-handshake",
            "server-handshake",
            "login-request",
            "server",
            "server",
        ],
        f"{name} audit events",
    )
    require(
        len(events) == AUDIT_EVENTS
        and events.count("server") == SERVER_EVENTS
        and events.count("client") == CLIENT_EVENTS,
        f"{name} audit events",
    )
    require(
        events.count("data-client") == events.count("data-server") == 1,
        f"{name} audit events",
    )


def check_wire(
    name: str,
    entries: list[dict[str, typ.Any]],
    wire: dict[str, list[tuple[bytes, bytes]]],
) -> None:
    """Check that the audit log holds the same bytes as the captured wire.

    Parameters
    ----------
    name : str
        The case name.
    entries : list[dict[str, typing.Any]]
        The audited proxy entries.
    wire : dict[str, list[tuple[bytes, bytes]]]
        The client and server bytes of each view, by stream kind.
    """
    control = wire["control"]
    data = wire["data"]
    require(
        logged(entries, {"client-handshake", "login-request", "client"}, "raw_hex")
        == control[0][0],
        f"{name} audit/control wire",
    )
    require(
        logged(entries, {"server-handshake", "server"}, "raw_hex") == control[2][1],
        f"{name} audit/control wire",
    )
    require(
        logged(entries, {"server-handshake", "server"}, "forwarded_hex")
        == control[0][1],
        f"{name} audit/control wire",
    )
    require(
        logged(entries, {"data-client"}, "raw_hex") == data[0][0],
        f"{name} audit/data and sole rewrite",
    )
    require(
        logged(entries, {"data-server"}, "raw_hex") == data[0][1],
        f"{name} audit/data and sole rewrite",
    )
    require(
        all(
            entry["raw_hex"] == entry["forwarded_hex"]
            for index, entry in enumerate(entries)
            if index != REWRITTEN_ENTRY
        ),
        f"{name} audit/data and sole rewrite",
    )


def check_watchdog(
    name: str, report: dict[str, typ.Any], spec: dict[str, typ.Any]
) -> float:
    """Check the proxy's status and its watchdog receipt, and time the teardown.

    Parameters
    ----------
    name : str
        The case name.
    report : dict[str, typing.Any]
        The parsed proxy report.
    spec : dict[str, typing.Any]
        The case's expectations.

    Returns
    -------
    float
        The seconds from the ACK to the relay teardown, to six places.
    """
    require(
        report["variant"] == name
        and report["status"] == "intentional-observation-cutoff"
        and not report["errors"],
        f"{name} proxy status",
    )
    observation = report["observation"]
    require(
        observation["state"] == "fired" and observation["valid_30_seconds"],
        f"{name} watchdog receipt",
    )
    require(
        observation["raw_ack_sha256"] == SOURCE_ACK_SHA
        and observation["forwarded_ack_sha256"] == spec["expected_ack_sha256"],
        f"{name} watchdog receipt",
    )
    start = observation["ack_sent_monotonic_ns"]
    end = observation["relay_teardown_ns"]
    require(
        observation["cutoff_due_ns"] - start == CUTOFF_NS
        and end - start < TEARDOWN_LIMIT_NS,
        f"{name} cutoff timing",
    )
    return round((end - start) / 1e9, 6)


def check_audit(
    base: Path,
    name: str,
    spec: dict[str, typ.Any],
    wire: dict[str, list[tuple[bytes, bytes]]],
) -> float:
    """Check the proxy's audit log of one case against the captured wire.

    Returns
    -------
    float
        The seconds from the ACK to the relay teardown.
    """
    report = json.loads((base / name / "proxy/report.json").read_text())
    entries = report["entries"]
    check_events(name, entries)
    check_wire(name, entries, wire)
    return check_watchdog(name, report, spec)


def check_case(
    base: Path, name: str, spec: dict[str, typ.Any], packets: dict[str, typ.Any]
) -> dict[str, typ.Any]:
    """Check one replayed case from its captured views to its proxy audit.

    Returns
    -------
    dict[str, typing.Any]
        The stream sizes, the ACK fields and the teardown seconds of the case.
    """
    control = view_pairs(name, spec, packets, "control")
    reference = check_control(name, spec, control)
    data = view_pairs(name, spec, packets, "data")
    check_data(name, data, reference)
    wire = {"control": control, "data": data}
    teardown = check_audit(base, name, spec, wire)
    return {
        "streams": {kind: stream_sizes(pairs) for kind, pairs in wire.items()},
        "ack_fields": {str(k): v.hex() for k, v in EXPECTED_FIELDS[name].items()},
        "teardown_seconds": teardown,
    }
