#!/usr/bin/env python3
"""Serve bounded field variants to the identified shx peer on loopback."""

import datetime as dt
import json
import socket
import time
import typing as typ
from pathlib import Path

from native_plan import packet, payload
from native_wire_names import (
    FIELD_UNNAMED_WORD,
    TYPE_GET_USER_ROSTER,
    TYPE_LOGIN,
    TYPE_SEND_CHAT,
)
from script_cli import run
from serve_shx_fixture import fixture_frames, roster
from verify_native_shx import fields, frames

type Report = dict[str, typ.Any]

type CaseName = typ.Literal[
    "control", "omit-161", "vary-161", "unknown-login", "early-122"
]
CASES = typ.get_args(CaseName.__value__)
FIRST_PORT = 15600
LAST_PORT = 15609
MAX_REQUEST_BYTES = 65535
UNKNOWN_LOGIN_FIELD = 32767
PEER_CLOSED = "Peer closed before fixture request"


def fail(message: str) -> typ.NoReturn:
    """Raise the ValueError that reports a refused fixture exchange.

    Parameters
    ----------
    message : str
        The reason, as the verifier reports it.

    Raises
    ------
    ValueError
        Always, with ``message``.
    """
    raise ValueError(message)


def login_reply(original: bytes, case: str) -> bytes:
    """Build the login reply of ``case`` from the original login reply.

    Parameters
    ----------
    original : bytes
        The recorded login reply.
    case : str
        The field variant to apply.

    Returns
    -------
    bytes
        The reply with the variant's fields.
    """
    frame = frames(original)[0]
    values = [(f["id"], bytes.fromhex(f["hex"])) for f in frame["fields"]]
    match case:
        case "omit-161":
            values = [
                (key, value) for key, value in values if key != FIELD_UNNAMED_WORD
            ]
        case "vary-161":
            values = [
                (key, b"\0\1" if key == FIELD_UNNAMED_WORD else value)
                for key, value in values
            ]
        case "unknown-login":
            values.append((UNKNOWN_LOGIN_FIELD, b"mothra-unknown-login"))
    return bytes.fromhex(
        packet(frame["type"], frame["id"], payload(values), reply=frame["is_reply"])
    )


def read_exactly(connection: socket.socket, events: list[Report], size: int) -> bytes:
    """Read exactly ``size`` bytes from the peer, recording each chunk.

    Parameters
    ----------
    connection : socket.socket
        The connection to the peer.
    events : list[dict[str, typing.Any]]
        The event log that receives one entry per chunk.
    size : int
        The number of bytes to read.

    Returns
    -------
    bytes
        The bytes read.

    Raises
    ------
    EOFError
        When the peer closes before ``size`` bytes arrive.
    """
    value = bytearray()
    while len(value) < size:
        chunk = connection.recv(size - len(value))
        if not chunk:
            raise EOFError(PEER_CLOSED)
        events.append({
            "event": "receive",
            "timestamp_us": time.time_ns() // 1000,
            "hex": chunk.hex(),
        })
        value.extend(chunk)
    return bytes(value)


def send_bytes(connection: socket.socket, events: list[Report], value: bytes) -> None:
    """Send ``value`` to the peer and record it in the event log.

    Parameters
    ----------
    connection : socket.socket
        The connection to the peer.
    events : list[dict[str, typing.Any]]
        The event log that receives the entry.
    value : bytes
        The bytes to send.
    """
    connection.sendall(value)
    events.append({
        "event": "send",
        "timestamp_us": time.time_ns() // 1000,
        "hex": value.hex(),
    })


def read_request(connection: socket.socket, events: list[Report]) -> Report:
    """Read one request frame from the peer and decode it.

    A request that declares a payload above ``MAX_REQUEST_BYTES`` is refused
    with a ``ValueError`` before its payload is read.

    Parameters
    ----------
    connection : socket.socket
        The connection to the peer.
    events : list[dict[str, typing.Any]]
        The event log that receives the chunks.

    Returns
    -------
    dict[str, typing.Any]
        The decoded frame.
    """
    header = read_exactly(connection, events, 20)
    size = int.from_bytes(header[16:20], "big")
    if size > MAX_REQUEST_BYTES:
        fail("Fixture request exceeds bound")
    return frames(header + read_exactly(connection, events, size))[0]


def exchange(
    connection: socket.socket,
    report: Report,
    original: dict[str, bytes],
    case: str,
) -> None:
    """Run the fixture's side of the login, roster and chat exchange.

    Any step that the peer does not send exactly as recorded is refused with a
    ``ValueError``, and an early close raises ``EOFError``.

    Parameters
    ----------
    connection : socket.socket
        The accepted connection to the peer.
    report : dict[str, typing.Any]
        The report whose event log and login fields are recorded.
    original : dict[str, bytes]
        The recorded frames that the fixture replays.
    case : str
        The field variant to serve.
    """
    events = report["events"]
    if read_exactly(connection, events, 12) != bytes.fromhex(
        "54525450484f544c00010002"
    ):
        fail("Unexpected peer handshake")
    login = read_request(connection, events)
    if login["type"] != TYPE_LOGIN or login["id"] != 1:
        fail("Unexpected peer login")
    report["login_fields"] = sorted(fields(login))
    send_bytes(
        connection,
        events,
        original["handshake"] + login_reply(original["login"], case),
    )
    send_bytes(connection, events, original["privileges"] + original["agreement"])
    if case == "early-122":
        send_bytes(connection, events, original["banner"])
    first = read_request(connection, events)
    if first["type"] != TYPE_GET_USER_ROSTER:
        fail("Missing automatic roster")
    send_bytes(
        connection,
        events,
        roster(original["roster"], first["id"], subject=False),
    )
    reload = read_request(connection, events)
    if reload["type"] != TYPE_GET_USER_ROSTER:
        fail("Missing explicit roster reload")
    send_bytes(
        connection,
        events,
        roster(original["roster"], reload["id"], subject=False),
    )
    chat = read_request(connection, events)
    if chat["type"] != TYPE_SEND_CHAT or fields(chat) != {
        101: b"mothra-shx-basic-chat"
    }:
        fail("Peer did not continue with exact chat")
    send_bytes(connection, events, original["chat"])
    if connection.recv(1) != b"":
        fail("Unexpected trailing peer data")
    events.append({"event": "eof", "timestamp_us": time.time_ns() // 1000, "hex": ""})


def serve(evidence: Path, case: str, port: int, output: Path) -> Report:
    """Serve one field variant on a reserved loopback port and record it.

    Parameters
    ----------
    evidence : pathlib.Path
        The directory of the retained native evidence.
    case : str
        The field variant to serve.
    port : int
        The reserved loopback port to listen on.
    output : pathlib.Path
        The directory that receives the readiness and report files.

    Returns
    -------
    dict[str, typing.Any]
        The report of the exchange, also written to ``report.json``. A case or
        a port that is not reserved for this fixture is refused with a
        ``ValueError`` before anything is written.
    """
    if case not in CASES or not FIRST_PORT <= port <= LAST_PORT:
        fail("Case or reserved loopback port differs")
    original = fixture_frames(evidence)
    output.mkdir(parents=True, exist_ok=False)
    events: list[Report] = []
    report: Report = {
        "schema_version": 1,
        "profile": "controlled-receiver-fixture",
        "native_conformance": False,
        "case": case,
        "endpoint": ["127.0.0.1", port],
        "started_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "events": events,
        "status": "running",
    }
    try:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
            listener.listen(1)
            listener.settimeout(30)
            (output / "ready.json").write_text(
                json.dumps({"endpoint": ["127.0.0.1", port]}) + "\n"
            )
            connection, address = listener.accept()
            with connection:
                connection.settimeout(30)
                report["client_address"] = list(address)
                report["server_address"] = list(connection.getsockname())
                exchange(connection, report, original, case)
        report["status"] = "completed"
    except (OSError, ValueError, EOFError) as exc:
        report["status"], report["error"] = "failed", str(exc)
    finally:
        report["finished_at_utc"] = dt.datetime.now(dt.UTC).isoformat()
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def show(
    *,
    evidence: str,
    case: CaseName,
    port: int,
    output: str,
) -> None:
    """Serve one field variant, print its status and set the exit status.

    Parameters
    ----------
    evidence : str
        The directory of the retained native evidence.
    case : str
        The field variant to serve.
    port : int
        The reserved loopback port to listen on.
    output : str
        The directory that receives the readiness and report files.

    Raises
    ------
    SystemExit
        With status 1 unless the exchange completed.
    """
    result = serve(Path(evidence), case, port, Path(output))
    print(result["profile"], result["case"], result["status"])
    raise SystemExit(result["status"] != "completed")


def main() -> None:
    """Serve bounded field variants to the identified shx peer on loopback."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
