"""Check each retained peer case against its terminal, socket and packet bytes."""

import dataclasses as dc
import json
import typing as typ

from native_wire_names import FIELD_UNNAMED_WORD
from pcap_tcp import lifetime, stream
from peer_tolerance_fixture import FIRST_PORT, UNKNOWN_LOGIN_FIELD, login_reply
from serve_shx_fixture import roster
from shx_syscalls import socket_io
from verify_native_core import require
from verify_native_shx import check_terminal, fields, frames

if typ.TYPE_CHECKING:
    from pathlib import Path

    from pcap_reader import Packet

type Report = dict[str, typ.Any]


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """The retained peer corpus and the shared inputs read once for it."""

    directory: Path
    source_hashes: set[str]
    original: dict[str, bytes]
    host: list[Packet]


def peer_commands(port: int) -> list[str]:
    """Return the terminal commands that the peer was driven with.

    Parameters
    ----------
    port : int
        The loopback port of the case.

    Returns
    -------
    list[str]
        The commands, in the order they were typed.
    """
    return [
        "/version",
        f"/server -o -l admin -p mothra19 -n shx-peer-a -i 500 127.0.0.1:{port}",
        "/who -r",
        "mothra-shx-basic-chat",
        "/quit",
    ]


def check_provenance(report: Report, case: str) -> None:
    """Require the terminal capture to name its controlled receiver fixture.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The terminal report of the case.
    case : str
        The case name.
    """
    require(
        report["environment"]["controlled_receiver_fixture"]
        == {
            "profile": "controlled-receiver-fixture",
            "case": case,
            "source_peer": "shx 0.1.48 modern terminal build",
        },
        "Peer capture provenance differs",
    )


def check_fixture(fixture: Report, case: str, port: int) -> None:
    """Require the fixture report to be a completed run on the case's endpoint.

    Parameters
    ----------
    fixture : dict[str, typing.Any]
        The fixture report of the case.
    case : str
        The case name.
    port : int
        The loopback port of the case.
    """
    require(
        fixture["profile"] == "controlled-receiver-fixture"
        and fixture["native_conformance"] is False
        and fixture["status"] == "completed"
        and fixture["case"] == case
        and fixture["endpoint"] == ["127.0.0.1", port]
        and fixture["events"][-1]["event"] == "eof",
        "Fixture status or endpoint differs",
    )


def peer_socket(capture: Path, port: int) -> list[Report]:
    """Return the peer's socket operations, requiring a single socket.

    Parameters
    ----------
    capture : pathlib.Path
        The capture of the case.
    port : int
        The loopback port of the case.

    Returns
    -------
    list[dict[str, typing.Any]]
        The socket operations of the peer, in order.
    """
    records = socket_io(
        (capture / "syscalls.log").read_text(), server_ports=frozenset({port})
    )
    require(
        len({(r["pid"], r["fd"], r["client_port"]) for r in records}) == 1,
        "Ambiguous peer socket",
    )
    return records


def check_wire(
    corpus: Corpus, records: list[Report], fixture: Report, port: int
) -> tuple[bytes, bytes]:
    """Require the packet and fixture bytes to match the peer's socket bytes.

    Parameters
    ----------
    corpus : Corpus
        The peer corpus and its shared inputs.
    records : list[dict[str, typing.Any]]
        The socket operations of the peer.
    fixture : dict[str, typing.Any]
        The fixture report of the case.
    port : int
        The loopback port of the case.

    Returns
    -------
    tuple[bytes, bytes]
        The bytes the peer sent and the bytes it received.
    """
    sent = b"".join(r["bytes"] for r in records if r["operation"] == "write")
    received = b"".join(r["bytes"] for r in records if r["operation"] == "read")
    client = ("127.0.0.1", records[0]["client_port"])
    server = ("127.0.0.1", port)
    require(
        fixture["client_address"] == list(client)
        and fixture["server_address"] == list(server),
        "Fixture socket identity differs",
    )
    packets = lifetime(corpus.host, client, server, records[0]["timestamp_us"])
    require(
        stream(packets, client, server) == sent
        and stream(packets, server, client) == received,
        "Independent packet bytes differ from peer syscalls",
    )
    require(
        b"".join(
            bytes.fromhex(e["hex"])
            for e in fixture["events"]
            if e["event"] == "receive"
        )
        == sent
        and b"".join(
            bytes.fromhex(e["hex"]) for e in fixture["events"] if e["event"] == "send"
        )
        == received,
        "Fixture bytes differ from peer syscalls",
    )
    return sent, received


def check_exchange(
    sent: bytes, received: bytes, original: dict[str, bytes], case: str
) -> list[Report]:
    """Require the handshake, request order and reply order of the exchange.

    Parameters
    ----------
    sent : bytes
        The bytes the peer sent.
    received : bytes
        The bytes the peer received.
    original : dict[str, bytes]
        The recorded frames of the fixture.
    case : str
        The case name.

    Returns
    -------
    list[dict[str, typing.Any]]
        The decoded reply frames that the peer received.
    """
    require(
        sent[:12] == bytes.fromhex("54525450484f544c00010002")
        and received[:8] == original["handshake"],
        "Peer handshake differs",
    )
    requests, replies = frames(sent[12:]), frames(received[8:])
    require(
        [frame["type"] for frame in requests] == [107, 300, 300, 105]
        and [frame["id"] for frame in requests] == [1, 2, 3, 4]
        and fields(requests[3]) == {101: b"mothra-shx-basic-chat"},
        "Peer continuation request order differs",
    )
    expected = (
        original["handshake"]
        + login_reply(original["login"], case)
        + original["privileges"]
        + original["agreement"]
    )
    if case == "early-122":
        expected += original["banner"]
    expected += (
        roster(original["roster"], 2, subject=False)
        + roster(original["roster"], 3, subject=False)
        + original["chat"]
    )
    require(received == expected, "Peer received wrong field or frame order")
    return replies


def check_login(replies: list[Report], case: str) -> None:
    """Require the login reply to carry exactly the case's claimed field bytes.

    Parameters
    ----------
    replies : list[dict[str, typing.Any]]
        The decoded reply frames that the peer received.
    case : str
        The case name.
    """
    login_fields = fields(replies[0])
    require(
        login_fields[160] == b"\0\xbe"
        and (FIELD_UNNAMED_WORD in login_fields) == (case != "omit-161")
        and login_fields.get(FIELD_UNNAMED_WORD)
        == (None if case == "omit-161" else b"\0\1" if case == "vary-161" else b"\0\0")
        and (UNKNOWN_LOGIN_FIELD in login_fields) == (case == "unknown-login"),
        "Login variant did not contain its claimed field bytes",
    )


def check_terminal_output(capture: Path, original: dict[str, bytes], case: str) -> None:
    """Require the terminal to show the roster and chat, and the banner outcome.

    Parameters
    ----------
    capture : pathlib.Path
        The capture of the case.
    original : dict[str, bytes]
        The recorded frames of the fixture.
    case : str
        The case name.
    """
    terminal = (capture / "stdout.bin").read_bytes()
    dump = capture / "work/hx.dump"
    require(
        b"shx-peer-a" in terminal and b"mothra-shx-basic-chat" in terminal,
        "Peer did not display roster and continuation chat",
    )
    if case == "early-122":
        require(
            terminal.count(b"unknown header type 0x0000007a") == 1
            and dump.is_file()
            and dump.read_bytes() == original["banner"],
            "Early native banner was not exactly dumped and tolerated",
        )
    else:
        require(
            b"unknown header type 0x0000007a" not in terminal and not dump.exists(),
            "Unexpected banner in peer control",
        )


def check_case(corpus: Corpus, index: int, case: str) -> Report:
    """Check one retained case against its terminal, socket and packet bytes.

    Parameters
    ----------
    corpus : Corpus
        The peer corpus and its shared inputs.
    index : int
        The position of the case in the matrix, which sets its port.
    case : str
        The case name.

    Returns
    -------
    dict[str, typing.Any]
        The case, its port, the byte counts and the peer's exit code.
    """
    port = FIRST_PORT + index
    capture = corpus.directory / "captures" / case
    fixture = json.loads(
        (corpus.directory / "fixtures" / case / "report.json").read_text()
    )
    report = check_terminal(capture, corpus.source_hashes, commands=peer_commands(port))
    check_provenance(report, case)
    check_fixture(fixture, case, port)
    sent, received = check_wire(corpus, peer_socket(capture, port), fixture, port)
    check_login(check_exchange(sent, received, corpus.original, case), case)
    check_terminal_output(capture, corpus.original, case)
    return {
        "case": case,
        "port": port,
        "sent_bytes": len(sent),
        "received_bytes": len(received),
        "peer_exit": report["peer_exit_code"],
    }
