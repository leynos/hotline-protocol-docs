"""Read frames and bytes from the proxied sockets and relay them onward."""

import socket
import typing as typ

from classic_login_proxy_constants import MAX_FRAME
from classic_login_proxy_errors import fail
from classic_login_proxy_frames import parse_frame, transform_ack
from native_wire_names import FRAME_HEADER_BYTES, FRAME_SIZE_START

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    import threading

    from classic_login_proxy_state import Audit, RosterState


def read_exact(
    peer: socket.socket, size: int, audit: Audit, *, allow_eof: bool = False
) -> bytes | None:
    """Read exactly ``size`` bytes from a peer.

    Parameters
    ----------
    peer : socket.socket
        The socket to read from.
    size : int
        The number of bytes that must be read.
    audit : Audit
        The audit log whose flags are checked between reads.
    allow_eof : bool
        Whether a clean end of stream before any byte is returned as None.

    Returns
    -------
    bytes | None
        The bytes read, or None at a clean end of stream when allowed.
    """
    data = bytearray()
    while len(data) < size:
        audit.check()
        try:
            chunk = peer.recv(size - len(data))
        except TimeoutError:
            continue
        if not chunk:
            if allow_eof and not data:
                return None
            fail(EOFError, "Socket closed inside required bytes")
        data.extend(chunk)
    return bytes(data)


def present_bytes(value: bytes | None) -> bytes:
    """Return bytes that a read which cannot end early has produced.

    Parameters
    ----------
    value : bytes | None
        The result of a read that was not allowed to end at end of stream.

    Returns
    -------
    bytes
        ``value``, narrowed to bytes.

    Raises
    ------
    AssertionError
        If ``value`` is None.
    """
    if value is None:
        raise AssertionError
    return value


def read_frame(peer: socket.socket, audit: Audit) -> bytes | None:
    """Read and check one complete control frame.

    Parameters
    ----------
    peer : socket.socket
        The socket to read from.
    audit : Audit
        The audit log whose flags are checked between reads.

    Returns
    -------
    bytes | None
        The whole frame, or None at a clean end of stream.
    """
    header = read_exact(peer, FRAME_HEADER_BYTES, audit, allow_eof=True)
    if header is None:
        return None
    size = int.from_bytes(header[FRAME_SIZE_START:FRAME_HEADER_BYTES], "big")
    if size > MAX_FRAME:
        fail(ValueError, "Control frame exceeds bound")
    raw = header + present_bytes(read_exact(peer, size, audit))
    parse_frame(raw)
    return raw


def _first_server_frame(raw: bytes, login_id: int | None, variant: str) -> bytes:
    """Rebuild the first server frame, which must be the controlled ACK.

    Parameters
    ----------
    raw : bytes
        The first server frame, as received.
    login_id : int | None
        The observed Login107 ID, or None when no request was seen.
    variant : str
        The variant that governs the rebuild.

    Returns
    -------
    bytes
        The frame to forward.
    """
    if login_id is None:
        fail(ValueError, "Missing observed login ID")
    return transform_ack(raw, login_id, variant)


def _roster_frame(raw: bytes, label: str, roster: RosterState | None) -> bytes:
    """Correlate a later roster frame and return the frame to forward.

    Parameters
    ----------
    raw : bytes
        One frame that is not the first server frame.
    label : str
        Either ``"client"`` or ``"server"``.
    roster : RosterState | None
        The roster correlation, or None when the variant has none.

    Returns
    -------
    bytes
        The frame to forward, rewritten only for a server roster reply.
    """
    if roster is None:
        return raw
    if label == "server":
        return roster.rewrite_reply(raw)
    if label == "client":
        roster.observe_client(raw)
    return raw


def relay_frames(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # the callers' shape
    source: socket.socket,
    destination: socket.socket,
    audit: Audit,
    label: str,
    login_id: int | None,
    variant: str,
    ack_forwarded: threading.Event | None = None,
    on_ack: cabc.Callable[[bytes, bytes], object] | None = None,
    roster: RosterState | None = None,
) -> None:
    """Relay control frames from one socket to another until it closes.

    Parameters
    ----------
    source : socket.socket
        The socket that frames are read from.
    destination : socket.socket
        The socket that frames are sent to.
    audit : Audit
        The audit log that records every frame.
    label : str
        Either ``"client"`` or ``"server"``.
    login_id : int | None
        The observed Login107 ID, used for the server's first frame.
    variant : str
        The variant that governs the first server frame.
    ack_forwarded : threading.Event | None
        Set once the first server frame has been forwarded.
    on_ack : collections.abc.Callable[[bytes, bytes], object] | None
        Called with the raw and forwarded first server frame.
    roster : RosterState | None
        The roster correlation, or None when the variant has none.
    """
    first = True
    while raw := read_frame(source, audit):
        if label == "server" and first:
            forwarded = _first_server_frame(raw, login_id, variant)
        else:
            forwarded = _roster_frame(raw, label, roster)
        audit.record(label, raw, forwarded)
        destination.sendall(forwarded)
        if label == "server" and first:
            if on_ack is not None:
                on_ack(raw, forwarded)
            if ack_forwarded is not None:
                ack_forwarded.set()
        first = False
    if label == "server" and first:
        fail(ValueError, "Missing successful Login107 ACK")
    destination.shutdown(socket.SHUT_WR)


def relay_data(
    source: socket.socket, destination: socket.socket, audit: Audit, label: str
) -> None:
    """Relay raw bytes from one socket to another until it closes.

    Parameters
    ----------
    source : socket.socket
        The socket that bytes are read from.
    destination : socket.socket
        The socket that bytes are sent to.
    audit : Audit
        The audit log that records every chunk.
    label : str
        The name that the chunks are logged under.
    """
    while True:
        audit.check()
        try:
            chunk = source.recv(4096)
        except TimeoutError:
            continue
        if not chunk:
            destination.shutdown(socket.SHUT_WR)
            return
        audit.record(label, chunk, chunk)
        destination.sendall(chunk)


def accept_one(
    listener: socket.socket, audit: Audit, stop: threading.Event | None = None
) -> socket.socket | None:
    """Accept one connection, or return None once ``stop`` is set.

    Parameters
    ----------
    listener : socket.socket
        The listening socket.
    audit : Audit
        The audit log whose flags are checked between attempts.
    stop : threading.Event | None
        When set, the wait is abandoned and None is returned.

    Returns
    -------
    socket.socket | None
        The accepted client, with its read timeout set, or None.
    """
    while True:
        audit.check()
        if stop is not None and stop.is_set():
            return None
        try:
            client, _ = listener.accept()
            client.settimeout(0.25)
        except TimeoutError:
            continue
        return client
