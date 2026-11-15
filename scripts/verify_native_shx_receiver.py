"""Check the controlled receiver sessions of the shx extras corpus."""

import dataclasses as dc
import json
import typing as typ

from native_auth_steps import complement
from native_wire_names import (
    FIELD_DATA,
    FIELD_ICON,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    FIELD_ROSTER_SUBJECT,
    HANDSHAKE_REPLY_BYTES,
    HANDSHAKE_REQUEST_HEX,
    TYPE_BANNER_METADATA,
    TYPE_CHAT_NOTIFICATION,
    TYPE_GET_USER_ROSTER,
    TYPE_LOGIN,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRIVILEGES_NOTIFICATION,
    TYPE_SEND_CHAT,
)
from pcap_tcp import lifetime, stream
from serve_shx_fixture import SUBJECT, wire
from shx_syscalls import socket_io
from verify_native_core import require
from verify_native_shx_frames import HANDSHAKE_REQUEST_BYTES, LOGIN, fields, frames
from verify_native_shx_packets import HOST_ADDRESS, has_exec
from verify_native_shx_terminal import check_terminal

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

RECEIVER_PORT = 15510  # the controlled receiver fixture's listener
PROFILE = "controlled-receiver-fixture"
REPLY = 0  # the type of a reply frame
CHAT_LINE = "mothra-shx-basic-chat"
REQUEST_TYPES = [TYPE_LOGIN, TYPE_GET_USER_ROSTER, TYPE_GET_USER_ROSTER, TYPE_SEND_CHAT]
REQUEST_IDS = [1, 2, 3, 4]
ROSTER_IDS = {2, 3}
BOOTSTRAP = ["handshake", "login", "privileges", "agreement"]
SUBJECT_DISPLAYS = 2  # the subject line is shown after each roster reply
PEER_ICON = b"\x01\xf4"  # the `-i 500` of the login command
PEER_NAME = b"shx-peer-a"
PEER_PASSWORD = b"mothra19"
UNKNOWN_BANNER_NOTICE = b"unknown header type 0x0000007a"  # 0x7a is type 122


@dc.dataclass(frozen=True, slots=True)
class Exchange:
    """The bytes of one receiver session, as the peer and the fixture saw them.

    Attributes
    ----------
    port : int
        The peer's client port.
    sent : bytes
        What the peer wrote.
    received : bytes
        What the peer read.
    """

    port: int
    sent: bytes
    received: bytes


def receiver_commands() -> list[str]:
    """List the commands that a receiver plan types into the peer.

    Returns
    -------
    list[str]
        The commands, ending with the quit command.
    """
    return [
        "/version",
        LOGIN.replace(":15500", f":{RECEIVER_PORT}"),
        "/who -r",
        CHAT_LINE,
        "/quit",
    ]


def read_fixture(server_case: Path, mode: str) -> Report:
    """Read the fixture report and check that it is labelled as a controlled one.

    Returns
    -------
    dict[str, typing.Any]
        The report of the fixture server.
    """
    fixture = json.loads((server_case / "report.json").read_text())
    require(
        fixture["profile"] == PROFILE
        and fixture["native_conformance"] is False
        and fixture["status"] == "completed"
        and fixture["mode"] == mode,
        "Invalid controlled fixture report",
    )
    return fixture


def event_bytes(fixture: Report, event: str) -> bytes:
    """Join the bytes of the fixture events of one kind.

    Returns
    -------
    bytes
        The concatenated event bytes.
    """
    return b"".join(
        bytes.fromhex(e["hex"]) for e in fixture["events"] if e["event"] == event
    )


def check_exchange(
    case: Path, fixture: Report, report: Report, host: list[Report]
) -> Exchange:
    """Pair the traced socket bytes with the host packets and the fixture events.

    Returns
    -------
    Exchange
        The peer's port and the bytes of the session.
    """
    records = socket_io(
        (case / "syscalls.log").read_text(), server_ports=frozenset({RECEIVER_PORT})
    )
    require(
        len({(r["pid"], r["fd"], r["client_port"]) for r in records}) == 1,
        "Ambiguous receiver socket",
    )
    sent = b"".join(r["bytes"] for r in records if r["operation"] == "write")
    received = b"".join(r["bytes"] for r in records if r["operation"] == "read")
    port = records[0]["client_port"]
    client, server = (HOST_ADDRESS, port), (HOST_ADDRESS, RECEIVER_PORT)
    require(
        fixture["client_address"] == list(client)
        and fixture["server_address"] == list(server),
        "Receiver server socket identity differs",
    )
    packets = lifetime(host, client, server, records[0]["timestamp_us"])
    require(
        stream(packets, client, server) == sent
        and stream(packets, server, client) == received,
        "Independent receiver packet bytes differ",
    )
    require(
        event_bytes(fixture, "receive") == sent
        and event_bytes(fixture, "send") == received,
        "Fixture event bytes differ from real peer",
    )
    require(
        fixture["events"][-1]["event"] == "eof", "Fixture did not observe peer closure"
    )
    trace = (case / "syscalls.log").read_text()
    require(
        has_exec(trace, records[0]["pid"], report),
        "Receiver process lacks identified exec",
    )
    return Exchange(port, sent, received)


def check_requests(requests: list[Report]) -> None:
    """Check the requests that the peer sent."""
    require(
        [r["type"] for r in requests] == REQUEST_TYPES
        and [r["id"] for r in requests] == REQUEST_IDS,
        "Receiver did not reload and continue with chat",
    )
    require(
        fields(requests[0])
        == {
            FIELD_ICON: PEER_ICON,
            FIELD_LOGIN: complement(b"admin"),
            FIELD_PASSWORD: complement(PEER_PASSWORD),
            FIELD_NAME: PEER_NAME,
        },
        "Receiver fixture login bytes differ",
    )
    require(
        fields(requests[1]) == fields(requests[2]) == {}
        and fields(requests[3]) == {FIELD_DATA: CHAT_LINE.encode()},
        "Receiver continuation fields differ",
    )


def check_replies(
    mode: str, received: bytes, replies: list[Report], original: dict[str, bytes]
) -> None:
    """Check that the fixture replayed the native bytes, with its own additions."""
    bootstrap = b"".join(original[k] for k in BOOTSTRAP)
    require(received.startswith(bootstrap), "Receiver native bootstrap replay differs")
    expected_types = [
        REPLY,
        TYPE_PRIVILEGES_NOTIFICATION,
        TYPE_LOGIN_AGREEMENT,
        REPLY,
        *([TYPE_BANNER_METADATA] if "banner" in mode else []),
        REPLY,
        TYPE_CHAT_NOTIFICATION,
    ]
    require(
        [r["type"] for r in replies] == expected_types,
        "Receiver fixture response shape differs",
    )
    native_roster = frames(original["roster"])[0]["fields"]
    expected_roster = native_roster + (
        [{"id": FIELD_ROSTER_SUBJECT, "hex": SUBJECT.hex()}]
        if "subject" in mode
        else []
    )
    rosters = [r for r in replies if r["is_reply"] and r["id"] in ROSTER_IDS]
    require(
        len(rosters) == len(ROSTER_IDS)
        and all(r["fields"] == expected_roster for r in rosters),
        "Subject addition or native roster bytes differ",
    )
    require(wire(replies[-1]) == original["chat"], "Continuation chat response differs")


def check_display(
    case: Path, mode: str, original: dict[str, bytes], replies: list[Report]
) -> None:
    """Check the banner dump and the subject lines that the peer displayed."""
    terminal = (case / "stdout.bin").read_bytes()
    subject_line = b"chat 0x0 subject: " + SUBJECT
    dump = case / "work/hx.dump"
    if "banner" in mode:
        banner = next(r for r in replies if r["type"] == TYPE_BANNER_METADATA)
        require(
            wire(banner) == original["banner"]
            and dump.is_file()
            and dump.read_bytes() == original["banner"],
            "Unknown banner dump differs from exact native frame",
        )
        require(
            terminal.count(UNKNOWN_BANNER_NOTICE) == 1,
            "Peer did not report unknown banner",
        )
    else:
        require(
            not dump.exists() and UNKNOWN_BANNER_NOTICE not in terminal,
            "Control unexpectedly received a banner",
        )
    require(
        terminal.count(subject_line) == (SUBJECT_DISPLAYS if "subject" in mode else 0),
        "Peer subject display differs",
    )


def receiver(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # the callers' shape
    case: Path,
    server_case: Path,
    host: list[Report],
    original: dict[str, bytes],
    sources: set[str],
) -> Report:
    """Check one controlled receiver session against its fixture and the packets.

    Returns
    -------
    dict[str, typing.Any]
        The mode, the client port, the byte counts and the banner and subject outcomes.
    """
    mode = case.name
    report = check_terminal(case, sources, commands=receiver_commands())
    require(
        report["environment"]["controlled_receiver_fixture"]["profile"] == PROFILE,
        "Receiver fixture was mislabelled native",
    )
    fixture = read_fixture(server_case, mode)
    exchange = check_exchange(case, fixture, report, host)
    require(
        exchange.sent[:HANDSHAKE_REQUEST_BYTES] == bytes.fromhex(HANDSHAKE_REQUEST_HEX),
        "Receiver handshake differs",
    )
    requests = frames(exchange.sent[HANDSHAKE_REQUEST_BYTES:])
    replies = frames(exchange.received[HANDSHAKE_REPLY_BYTES:])
    check_requests(requests)
    check_replies(mode, exchange.received, replies, original)
    check_display(case, mode, original, replies)
    return {
        "mode": mode,
        "client_port": exchange.port,
        "sent_bytes": len(exchange.sent),
        "received_bytes": len(exchange.received),
        "banner": "unknown header, dumped, continued"
        if "banner" in mode
        else "not delivered",
        "subject": "displayed twice" if "subject" in mode else "absent",
    }
