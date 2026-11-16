"""Frame builders and the socket fake for the native roster overlap tests."""

import socket

import native_roster_overlap_cases as cases
from native_plan import packet, payload
from native_wire_names import (
    TYPE_EMPTY_ACK,
    TYPE_GET_USER_ROSTER,
    TYPE_LOGIN,
    TYPE_SET_CLIENT_INFO,
)
from protocol_capture import Recorder, decode_frame
from verify_native_auth import ADMIN

PLAIN_ROSTER_ID = 10  # roster request answered with a plain snapshot
OVERLAP_ROSTER_ID = 11  # roster request whose reply races the presence update
RENAMED_ROSTER_ID = 13  # roster request sent after the rename


def environment() -> dict:
    """Return the control-only fixture environment behind the generated plan.

    Returns
    -------
    dict
        The emulator, image and namespace identities of the plan.
    """
    return {
        "fixture_profile": "control-only",
        "emulator_pid": 9,
        "emulator_starttime": 10,
        "emulator_sha256": "a" * 64,
        "emulator_netns_inode": 11,
        "owned_working_image": "/ignored/working.dsk",
        "owned_working_image_inode": 12,
    }


def record(uid: int, icon: int, name: bytes) -> bytes:
    """Encode one user record of a roster reply.

    Returns
    -------
    bytes
        The identifier, icon, status and length-prefixed name of the record.
    """
    return (
        uid.to_bytes(2, "big")
        + icon.to_bytes(2, "big")
        + b"\0\x20"
        + len(name).to_bytes(2, "big")
        + name
    )


def reply(kind: int, identifier: int, values: list[tuple[int, bytes]]) -> bytes:
    """Encode a reply frame with the given fields.

    Returns
    -------
    bytes
        The raw reply frame.
    """
    return bytes.fromhex(packet(kind, identifier, payload(values), reply=1))


def notice(kind: int, identifier: int, values: list[tuple[int, bytes]]) -> bytes:
    """Encode a notice frame with the given fields.

    Returns
    -------
    bytes
        The raw notice frame.
    """
    return bytes.fromhex(packet(kind, identifier, payload(values)))


def roster_reply(identifier: int, *, name: bytes = cases.OLD_B, icon: int = 2) -> bytes:
    """Encode a roster reply holding user 1 and the given second user.

    Returns
    -------
    bytes
        The raw roster reply frame.
    """
    return reply(
        0, identifier, [(300, record(1, 1, cases.OLD_A)), (300, record(2, icon, name))]
    )


def decoded(raw: bytes, connection: str) -> dict:
    """Decode a raw frame and tag it with its connection.

    Returns
    -------
    dict
        The decoded frame with its connection name.
    """
    return {"connection": connection, **decode_frame(raw)}


def overlap_messages(order: str) -> tuple[bytes, bytes]:
    """Return the bytes of connections a and b for one arrival order.

    Returns
    -------
    tuple[bytes, bytes]
        The stream of connection a and the stream of connection b.
    """
    snapshot = roster_reply(11)
    update = notice(
        301,
        77,
        [(103, b"\0\x02"), (104, cases.ICON_NEW), (112, b"\0\x20"), (102, cases.NEW_B)],
    )
    barrier = reply(0, 12, [])
    if order == "ack-first":
        return snapshot + update + barrier, update + barrier
    return update + snapshot + barrier, barrier + update


class FakeNativeRecorder(Recorder):
    """Actual Recorder over socketpairs; responses follow generated requests."""

    order = "ack-first"
    late_tail = False
    latest = None

    def __init__(self, plan: dict) -> None:
        """Start the recorder with no peers and register it as the latest."""
        super().__init__(plan)
        self.peers: dict[str, socket.socket] = {}
        FakeNativeRecorder.latest = self

    def execute(self, action: int, step: dict) -> None:
        """Run one generated step, answering each request as the server would."""
        name, op = step["connection"], step["op"]
        if op == "connect":
            self._connect(action, name)
            return
        super().execute(action, step)
        match op:
            case "close":
                self.peers[name].close()
            case "shutdown_write":
                self._shutdown(name)
            case "send":
                self._send(name, step)

    def _connect(self, action: int, name: str) -> None:
        """Open the socket pair of one connection and record the event."""
        client, peer = socket.socketpair()
        self.sockets[name], self.peers[name] = client, peer
        self.event(action, name, "connect")

    def _shutdown(self, name: str) -> None:
        """Announce the late user on b's write shutdown, then close the write side."""
        if name == "b":
            self.peers["a"].sendall(notice(302, 88, [(103, b"\0\x02")]))
            if self.late_tail:
                self.peers["b"].sendall(b"late-tail")
        self.peers[name].shutdown(socket.SHUT_WR)

    def _send(self, name: str, step: dict) -> None:
        """Consume one request frame and answer it; the handshake has a fixed reply."""
        raw = bytes.fromhex(step["hex"])
        self.peers[name].recv(len(raw))
        if raw == b"TRTPHOTL\0\1\0\2":
            self.peers[name].sendall(b"TRTP\0\0\0\0")
            return
        request = decode_frame(raw)
        self._answer(name, request["type"], request["id"])

    def _answer(self, name: str, kind: int, identifier: int) -> None:
        """Answer a request by its wire type."""
        match kind:
            case _ if kind == TYPE_LOGIN:
                self._login(name)
            case _ if kind == TYPE_GET_USER_ROSTER:
                self._roster(name, identifier)
            case _ if kind == TYPE_SET_CLIENT_INFO:
                self._rename()
            case _ if kind == TYPE_EMPTY_ACK:
                self.peers[name].sendall(reply(0, identifier, []))

    def _login(self, name: str) -> None:
        """Answer a login with its reply and notices; b also announces itself to a."""
        self.peers[name].sendall(
            reply(0, 1, []) + notice(354, 2, [(110, ADMIN)]) + notice(109, 3, [])
        )
        if name == "b":
            self.peers["a"].sendall(
                notice(
                    301,
                    4,
                    [
                        (103, b"\0\x02"),
                        (102, cases.OLD_B),
                        (104, cases.ICON_B),
                        (112, b"\0\x20"),
                    ],
                )
            )

    def _roster(self, name: str, identifier: int) -> None:
        """Answer a roster request according to its identifier and arrival order."""
        if identifier == PLAIN_ROSTER_ID:
            self.peers[name].sendall(roster_reply(PLAIN_ROSTER_ID))
        elif identifier == OVERLAP_ROSTER_ID and self.order == "ack-first":
            self.peers["a"].sendall(roster_reply(OVERLAP_ROSTER_ID))
        elif identifier == RENAMED_ROSTER_ID:
            self.peers["a"].sendall(
                roster_reply(RENAMED_ROSTER_ID, name=cases.NEW_B, icon=3)
            )

    def _rename(self) -> None:
        """Send the presence update to both members, then any late roster."""
        update = notice(
            301,
            77,
            [
                (103, b"\0\x02"),
                (104, cases.ICON_NEW),
                (112, b"\0\x20"),
                (102, cases.NEW_B),
            ],
        )
        self.peers["a"].sendall(update)
        self.peers["b"].sendall(update)
        if self.order == "update-first":
            self.peers["a"].sendall(
                roster_reply(OVERLAP_ROSTER_ID, name=cases.NEW_B, icon=3)
            )
