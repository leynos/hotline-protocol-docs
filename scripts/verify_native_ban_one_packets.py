"""Check the packet views of the option-one ban witness against its frozen streams."""

import dataclasses as dc
import datetime as dt
import hashlib
import typing as typ

from native_wire_names import FIELD_USER_ID, TYPE_USER_LEFT
from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import decode_frame
from verify_native_ban_one_core import (
    BAN_REQUEST_ID,
    USER_LEFT_ID,
    fields,
    loaded,
    need,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

    from pcap_reader import Packet

type Report = dict[str, typ.Any]

# The bytes of the ACK that precede the 302 frame in the namespace stream.
ACK_BEFORE_USER_LEFT_HEX = "00010000000000210000000000000002000000020000"


@dc.dataclass(frozen=True, slots=True)
class _Socket:
    """The recorded packets of one socket family and the endpoints of its flow."""

    label: str
    packets: list[Packet]
    client: str
    server: str
    port: int


@dc.dataclass(frozen=True, slots=True)
class _Recording:
    """The verified report of the ban capture and the frozen views of the witness."""

    report: Report
    start_us: int
    frozen: Report
    uid: bytes


def _check_recorders(boot: Path, host: list[Packet], namespace: list[Packet]) -> None:
    """Check that the recorders saw no host packets and no packet drops.

    Parameters
    ----------
    boot : pathlib.Path
        The boot directory of the corpus, which holds the recorder logs.
    host : list[Packet]
        The packets of the primary host recorder.
    namespace : list[Packet]
        The packets of the lab namespace recorder.
    """
    need(not host, "Primary host recorder has packets")
    need(
        not [
            packet
            for packet in namespace
            if packet["src_port"] in {15500, 15501}
            or packet["dst_port"] in {15500, 15501}
        ],
        "Lab touched primary relay",
    )
    need(
        "0 packets dropped by kernel" in (boot / "ns-recorder.log").read_text(),
        "Namespace packet drops unknown",
    )
    need(
        "0 packets dropped by kernel" in (boot / "host-recorder.log").read_text(),
        "Host packet drops unknown",
    )


def _load_recording(corpus: Path, uid: bytes) -> _Recording:
    """Read the ban capture report and the frozen stream views.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    uid : bytes
        The two-byte UID of the dynamic target.

    Returns
    -------
    _Recording
        The report, its start time on the packet clock, and the frozen views.
    """
    report = loaded(corpus / "fixture/ban-opt1-capture/report.json")
    start_us = int(
        dt.datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1_000_000
    )
    frozen = loaded(corpus / "fixture/ban-stream-views.json")
    return _Recording(report=report, start_us=start_us, frozen=frozen, uid=uid)


def _check_notification(received: bytes, view: Report, uid: bytes) -> None:
    """Check the ACK and the 302 notification of the main connection.

    Parameters
    ----------
    received : bytes
        The bytes that the server sent on the main connection.
    view : dict[str, typing.Any]
        The frozen view of the main connection.
    uid : bytes
        The two-byte UID of the dynamic target.
    """
    need(
        received[398:420] == bytes.fromhex(ACK_BEFORE_USER_LEFT_HEX),
        "ACK bytes before 302 differ",
    )
    notification = decode_frame(received[420:])
    need(
        notification["type"] == TYPE_USER_LEFT
        and notification["id"] == USER_LEFT_ID
        and notification["is_reply"] == 0
        and fields(notification) == {FIELD_USER_ID: uid},
        "302 after ACK differs",
    )
    need(
        [(entry["type"], entry["id"], entry["fields"]) for entry in view["frames"][-2:]]
        == [
            (0, BAN_REQUEST_ID, []),
            (TYPE_USER_LEFT, USER_LEFT_ID, notification["fields"]),
        ],
        "Frozen ACK/302 view differs",
    )


def _check_close(label: str, packets: list[Packet], port: int) -> None:
    """Check that the target server closed its side of the socket.

    Parameters
    ----------
    label : str
        The name of the stream family, which selects the closing flag.
    packets : list[Packet]
        The packets of the socket lifetime.
    port : int
        The server port of the socket.
    """
    closing_flag = 1 if label == "namespace" else 4
    need(
        any(
            packet["src_port"] == port and packet["flags"] & closing_flag
            for packet in packets
        ),
        f"{label} target server close missing",
    )


def _check_socket(socket: _Socket, recording: _Recording) -> None:
    """Check each connect event of one socket family against its frozen view.

    Parameters
    ----------
    socket : _Socket
        The recorded packets and endpoints of the socket family.
    recording : _Recording
        The verified report and the frozen views of the witness.
    """
    for event in recording.report["events"]:
        if event["event"] != "connect":
            continue
        name = event["connection"]
        local = event["local_address"][1]
        packets = lifetime(
            socket.packets,
            (socket.client, local),
            (socket.server, socket.port),
            recording.start_us + event["elapsed_ns"] // 1000,
        )
        received = stream(packets, (socket.server, socket.port), (socket.client, local))
        sent = stream(packets, (socket.client, local), (socket.server, socket.port))
        view = recording.frozen[socket.label][name]
        need(
            view["local_port"] == local
            and view["sent_sha256"] == hashlib.sha256(sent).hexdigest()
            and view["received_sha256"] == hashlib.sha256(received).hexdigest(),
            f"{socket.label}/{name} packet view differs",
        )
        if name == "main":
            _check_notification(received, view, recording.uid)
        else:
            _check_close(socket.label, packets, socket.port)


def verify_packets(corpus: Path, uid: bytes) -> None:
    """Replay the packet views of the ban capture against the frozen streams.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    uid : bytes
        The two-byte UID of the dynamic target.
    """
    boot = corpus / "boot"
    host = read_packets(boot / "primary-host.pcap")
    namespace = read_packets(boot / "lab-namespace.pcap")
    _check_recorders(boot, host, namespace)
    recording = _load_recording(corpus, uid)
    guest = read_packets(boot / "lab-guest.pcap")
    sockets = (
        _Socket("namespace", namespace, "127.0.0.1", "127.0.0.1", 15720),
        _Socket("guest", guest, "10.0.2.2", "10.0.2.15", 5500),
    )
    for socket in sockets:
        _check_socket(socket, recording)
