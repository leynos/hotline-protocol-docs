"""Characterize the shx receiver fixture server against a scripted peer.

``serve_shx_fixture`` is a controlled listener that a real peer connects to. The
cases connect to it on the loopback interface with a scripted client that plays
the part of the peer, and record the frames the fixture builds from the retained
evidence, how it refuses a peer that departs from the script, and the report it
writes (without timestamps and the peer's ephemeral port). The endings were
recorded on the script as it stood before it was brought to the standard (commit
8a3f8cd) in ``data/characterize_serve_shx.tsv``.
"""

import hashlib
import json
import socket
import tempfile
import threading
import time
import typing as typ
from pathlib import Path

import pytest
import serve_shx_fixture as fixture
from characterize_support import Cases, record, replay
from native_plan import packet, payload
from script_loading import ROOT

TABLE = Path(__file__).with_name("data") / "characterize_serve_shx.tsv"
EVIDENCE = ROOT / "evidence/gap-remediation/2026-11-13"
PORT = 15510
HELLO = bytes.fromhex("54525450484f544c00010002")
CHAT = b"mothra-shx-basic-chat"
HEADER = 20
READY_WAIT = 10.0
TICK = 0.02


def request(kind: int, identifier: int, fields: list[tuple[int, bytes]]) -> bytes:
    """Build a request frame as the peer would send it.

    Returns
    -------
    bytes
        The frame.
    """
    return bytes.fromhex(packet(kind, identifier, payload(fields), reply=0))


def receive(peer: socket.socket, size: int) -> bytes:
    """Read exactly ``size`` bytes the fixture sends.

    Returns
    -------
    bytes
        The bytes, or fewer if the fixture closed.
    """
    data = b""
    while len(data) < size:
        chunk = peer.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data


def script(frames: dict[str, bytes], mode: str, deviation: str, output: Path) -> None:
    """Play the peer: log in, reload the roster, chat, and leave.

    ``deviation`` names the one place at which the peer departs from the script.
    """
    ready = READY_WAIT / TICK
    while ready and not (output / "ready.json").exists():
        time.sleep(TICK)
        ready -= 1
    with socket.create_connection(("127.0.0.1", PORT), timeout=READY_WAIT) as peer:
        peer.sendall(b"BAD" + HELLO[3:] if deviation == "hello" else HELLO)
        if deviation == "hello":
            return
        kind = 108 if deviation == "login" else 107
        peer.sendall(request(kind, 1, []))
        if deviation == "login":
            return
        lead = sum(
            len(frames[k]) for k in ("handshake", "login", "privileges", "agreement")
        )
        receive(peer, lead)
        peer.sendall(request(301 if deviation == "roster" else 300, 2, []))
        if deviation == "roster":
            return
        receive(peer, len(fixture.roster(frames["roster"], 2, "subject" in mode)))
        if "banner" in mode:
            receive(peer, len(frames["banner"]))
        peer.sendall(request(300, 3, []))
        receive(peer, len(fixture.roster(frames["roster"], 3, "subject" in mode)))
        text = b"other" if deviation == "chat" else CHAT
        peer.sendall(request(105, 4, [(101, text)]))
        if deviation == "chat":
            return
        receive(peer, len(frames["chat"]))
        if deviation == "trailing":
            peer.sendall(b"x")


def played(mode: str, deviation: str = "") -> object:
    """Run the fixture against the scripted peer and describe its report.

    Returns
    -------
    object
        The report without timestamps and the peer's port, and the exit-relevant
        status, as text.
    """
    frames = fixture.fixture_frames(EVIDENCE)
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "out"
        thread = threading.Thread(
            target=script, args=(frames, mode, deviation, output), daemon=True
        )
        thread.start()
        fixture.serve(EVIDENCE, mode, output)
        thread.join(READY_WAIT)
        report = json.loads((output / "report.json").read_text())
    for key in ("started_at_utc", "finished_at_utc", "client_address"):
        report.pop(key, None)
    for event in report["events"]:
        event.pop("timestamp_us", None)
    return json.dumps(report, sort_keys=True)


def frame_digests() -> object:
    """Digest each frame that the fixture recovers from the retained evidence.

    Returns
    -------
    object
        The SHA-256 of each frame by name.
    """
    return {
        name: hashlib.sha256(data).hexdigest()[:16]
        for name, data in fixture.fixture_frames(EVIDENCE).items()
    }


def rosters() -> object:
    """Digest the roster with and without the constructed subject.

    Returns
    -------
    object
        The digests, one for each choice.
    """
    original = fixture.fixture_frames(EVIDENCE)["roster"]
    return [
        hashlib.sha256(fixture.roster(original, 7, subject)).hexdigest()[:16]
        for subject in (False, True)
    ]


def existing_output() -> object:
    """Serve into an output directory that exists already.

    Returns
    -------
    object
        What ``serve`` raised.
    """
    with tempfile.TemporaryDirectory() as temporary:
        return fixture.serve(EVIDENCE, "control", Path(temporary))


CASES: Cases = {
    "frames": frame_digests,
    "rosters": rosters,
    "unknown-mode": lambda: fixture.serve(EVIDENCE, "nope", Path("unused")),
    "output-exists": existing_output,
    "control": lambda: played("control"),
    "banner": lambda: played("banner"),
    "subject": lambda: played("subject"),
    "banner-subject": lambda: played("banner-subject"),
    "refuses-hello": lambda: played("control", "hello"),
    "refuses-login": lambda: played("control", "login"),
    "refuses-roster": lambda: played("control", "roster"),
    "refuses-chat": lambda: played("control", "chat"),
    "refuses-trailing": lambda: played("control", "trailing"),
}


class ServeShxCharacterizationTests:
    """Keep the receiver fixture as it was recorded."""

    @pytest.mark.parametrize("name", sorted(CASES))
    def test_each_case_ends_as_it_did(self, name: str) -> None:
        """Each case ends with the exception or result recorded earlier."""
        now, recorded = replay(CASES, TABLE, name)
        assert now == recorded, "ending differs"


def table() -> str:
    """Say how every case ends, for the table; run it only on the earlier scripts.

    Returns
    -------
    str
        The table text.
    """
    return record(CASES)


__all__ = ["typ"]
