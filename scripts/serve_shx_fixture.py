#!/usr/bin/env python3
"""Deliver labelled receiver fixtures to a real peer; never a native-server oracle."""

import datetime as dt
import json
import socket
import struct
import time
import typing as typ
from pathlib import Path

from native_plan import packet, payload
from native_wire_names import (
    FIELD_ROSTER_SUBJECT,
    TYPE_BANNER_METADATA,
    TYPE_GET_USER_ROSTER,
    TYPE_LOGIN,
    TYPE_SEND_CHAT,
)
from script_cli import run
from verify_native_shx import fields, frames

type Mode = typ.Literal["control", "banner", "subject", "banner-subject"]
type Report = dict[str, typ.Any]

MODES = set(typ.get_args(Mode.__value__))
SUBJECT = b"mothra-roster-subject"
REQUEST_BOUND = 65535
PEER_CLOSED = "Peer closed before fixture request"


def fail(message: str) -> typ.NoReturn:
    """Raise the ValueError that refuses a fixture exchange.

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


def wire(frame: Report) -> bytes:
    """Encode a decoded frame as the bytes it occupies on the wire.

    Parameters
    ----------
    frame : dict[str, typing.Any]
        A decoded frame, with its header fields and ``payload_hex``.

    Returns
    -------
    bytes
        The 20-byte header followed by the payload.
    """
    return struct.pack(
        ">BBHIIII",
        frame["flags"],
        frame["is_reply"],
        frame["type"],
        frame["id"],
        frame["error"],
        frame["total_size"],
        frame["data_size"],
    ) + bytes.fromhex(frame["payload_hex"])


def fixture_frames(evidence: Path) -> dict[str, bytes]:
    """Recover exact native frames; subject addition is explicitly constructed.

    Parameters
    ----------
    evidence : pathlib.Path
        The directory of the retained native evidence.

    Returns
    -------
    dict[str, bytes]
        The handshake, login, privileges, agreement, roster, chat and banner
        bytes of the retained exchange.
    """
    report = json.loads(
        (evidence / "native-shx-01/captures/basic-empty-name/report.json").read_text()
    )
    # The peer report records terminal events, not decoded network frames.
    from shx_syscalls import socket_io

    records = socket_io(
        (evidence / "native-shx-01/captures/basic-empty-name/syscalls.log").read_text()
    )
    received = b"".join(r["bytes"] for r in records if r["operation"] == "read")
    native = frames(received[8:])
    banner_report = json.loads(
        (
            evidence / "native-login-extras-01/captures/name-a-190-delayed/report.json"
        ).read_text()
    )
    banner = next(
        f for f in banner_report["frames"] if f["type"] == TYPE_BANNER_METADATA
    )
    if report["status"] != "completed" or received[:8] != b"TRTP" + bytes(4):
        fail("Invalid retained bootstrap source")
    return {
        "handshake": received[:8],
        "login": wire(native[0]),
        "privileges": wire(native[1]),
        "agreement": wire(native[2]),
        "roster": wire(native[3]),
        "chat": wire(native[4]),
        "banner": wire(banner),
    }


def roster(original: bytes, identifier: int, subject: bool) -> bytes:  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers' shape
    """Build a roster reply from the retained roster, optionally with a subject.

    Parameters
    ----------
    original : bytes
        The retained roster frame.
    identifier : int
        The transaction identifier of the request being answered.
    subject : bool
        Whether to add the source-derived subject field.

    Returns
    -------
    bytes
        The roster reply frame.
    """
    frame = frames(original)[0]
    values = [(f["id"], bytes.fromhex(f["hex"])) for f in frame["fields"]]
    if subject:
        values.append((FIELD_ROSTER_SUBJECT, SUBJECT))
    return bytes.fromhex(packet(0, identifier, payload(values), reply=1))


class _Exchange:
    """Read and send the frames of one connection, logging each transfer."""

    def __init__(self, connection: socket.socket, events: list[Report]) -> None:
        """Hold the connection and the event log that its transfers append to.

        Parameters
        ----------
        connection : socket.socket
            The connection to the peer.
        events : list[dict[str, typing.Any]]
            The event log, which is also the report's ``events`` list.
        """
        self._connection = connection
        self._events = events

    def read(self, size: int) -> bytes:
        """Read exactly ``size`` bytes from the peer, recording each chunk.

        Parameters
        ----------
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
            chunk = self._connection.recv(size - len(value))
            if not chunk:
                raise EOFError(PEER_CLOSED)
            self._events.append({
                "event": "receive",
                "timestamp_us": time.time_ns() // 1000,
                "hex": chunk.hex(),
            })
            value.extend(chunk)
        return bytes(value)

    def send(self, value: bytes) -> None:
        """Send ``value`` to the peer and record it in the event log.

        Parameters
        ----------
        value : bytes
            The bytes to send.
        """
        self._connection.sendall(value)
        self._events.append({
            "event": "send",
            "timestamp_us": time.time_ns() // 1000,
            "hex": value.hex(),
        })

    def request(self) -> Report:
        """Read one request frame from the peer and decode it.

        Returns
        -------
        dict[str, typing.Any]
            The decoded request frame.
        """
        header = self.read(20)
        size = int.from_bytes(header[16:20], "big")
        if size > REQUEST_BOUND:
            fail("Fixture request exceeds bound")
        return frames(header + self.read(size))[0]

    def finish(self) -> None:
        """Check that the peer sent nothing more, and record the end of the stream."""
        if self._connection.recv(1) != b"":
            fail("Unexpected trailing peer data")
        self._events.append({
            "event": "eof",
            "timestamp_us": time.time_ns() // 1000,
            "hex": "",
        })


def answer_handshake(link: _Exchange) -> None:
    """Check the peer's handshake.

    Parameters
    ----------
    link : _Exchange
        The exchange with the peer.
    """
    if link.read(12) != bytes.fromhex("54525450484f544c00010002"):
        fail("Unexpected peer handshake")


def answer_login(link: _Exchange, original: dict[str, bytes]) -> None:
    """Check the peer's login and send the retained login replies.

    Parameters
    ----------
    link : _Exchange
        The exchange with the peer.
    original : dict[str, bytes]
        The retained frames, from ``fixture_frames``.
    """
    login = link.request()
    if login["type"] != TYPE_LOGIN or login["id"] != 1:
        fail("Unexpected peer login")
    link.send(
        original["handshake"]
        + original["login"]
        + original["privileges"]
        + original["agreement"]
    )


def answer_roster(link: _Exchange, original: dict[str, bytes], mode: str) -> None:
    """Answer the automatic and the explicit roster requests of the peer.

    Parameters
    ----------
    link : _Exchange
        The exchange with the peer.
    original : dict[str, bytes]
        The retained frames, from ``fixture_frames``.
    mode : str
        The receiver fixture mode, which selects the subject and banner.
    """
    first = link.request()
    if first["type"] != TYPE_GET_USER_ROSTER:
        fail("Missing automatic roster")
    link.send(roster(original["roster"], first["id"], subject="subject" in mode))
    if "banner" in mode:
        link.send(original["banner"])
    reload = link.request()
    if reload["type"] != TYPE_GET_USER_ROSTER:
        fail("Missing explicit roster reload")
    link.send(roster(original["roster"], reload["id"], subject="subject" in mode))


def answer_chat(link: _Exchange, original: dict[str, bytes]) -> None:
    """Check the peer's chat, send the retained chat reply and end the stream.

    Parameters
    ----------
    link : _Exchange
        The exchange with the peer.
    original : dict[str, bytes]
        The retained frames, from ``fixture_frames``.
    """
    chat = link.request()
    if chat["type"] != TYPE_SEND_CHAT or fields(chat) != {
        101: b"mothra-shx-basic-chat"
    }:
        fail("Peer did not continue with exact chat")
    link.send(original["chat"])
    link.finish()


def serve(evidence: Path, mode: str, output: Path) -> Report:
    """Serve one receiver fixture to the peer on loopback and write its report.

    Parameters
    ----------
    evidence : pathlib.Path
        The directory of the retained native evidence.
    mode : str
        One of ``MODES``.
    output : pathlib.Path
        The directory to create, which receives ``ready.json`` and ``report.json``.

    Returns
    -------
    dict[str, typing.Any]
        The report, whose ``status`` is ``completed`` or ``failed``.
    """
    if mode not in MODES:
        fail("Unknown receiver fixture")
    original = fixture_frames(evidence)
    output.mkdir(parents=True, exist_ok=False)
    events: list[Report] = []
    report: Report = {
        "schema_version": 1,
        "profile": "controlled-receiver-fixture",
        "native_conformance": False,
        "mode": mode,
        "started_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "scope": (
            "Full real peer receives retained native bootstrap/banner bytes and "
            "optional source-derived subject field. This listener is a controlled "
            "fixture, not native or historical SynHX server execution."
        ),
        "events": events,
        "status": "running",
    }
    try:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 15510))
            listener.listen(1)
            listener.settimeout(30)
            (output / "ready.json").write_text(
                json.dumps({"endpoint": ["127.0.0.1", 15510]})
            )
            connection, address = listener.accept()
            with connection:
                connection.settimeout(30)
                report["client_address"] = list(address)
                report["server_address"] = list(connection.getsockname())
                link = _Exchange(connection, events)
                answer_handshake(link)
                answer_login(link, original)
                answer_roster(link, original, mode)
                answer_chat(link, original)
        report["status"] = "completed"
    except (OSError, ValueError, EOFError) as exc:
        report["status"], report["error"] = "failed", str(exc)
    finally:
        report["finished_at_utc"] = dt.datetime.now(dt.UTC).isoformat()
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def show(*, evidence: str, mode: Mode, output: str) -> None:
    """Serve one receiver fixture, print its status and set the exit status.

    Parameters
    ----------
    evidence : str
        The directory of the retained native evidence.
    mode : str
        The receiver fixture to serve.
    output : str
        The directory that receives the readiness and report files.

    Raises
    ------
    SystemExit
        With status 1 unless the exchange completed.
    """
    result = serve(Path(evidence), mode, Path(output))
    print(result["profile"], result["mode"], result["status"])
    raise SystemExit(result["status"] != "completed")


def main() -> None:
    """Serve one labelled receiver fixture to a real peer on loopback."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
