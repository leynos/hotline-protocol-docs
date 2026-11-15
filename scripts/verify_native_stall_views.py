"""Check each packet view of the failed C35 transfer against the frozen findings.

A view is one side's packet capture. It must carry the recorded bytes, one
handshake with the expected window scale, an unbroken tail and no zero window,
and it must agree with the frozen H1 and H2 analyses.
"""

import dataclasses as dc
import datetime as dt
import json
import operator
import typing as typ

from pcap_tcp import lifetime, read_packets, stream
from verify_native_core import require
from verify_native_stall_tcp import raw_headers

if typ.TYPE_CHECKING:
    from pathlib import Path

type Json = dict[str, typ.Any]
type Packet = dict[str, typ.Any]

LOOPBACK = "127.0.0.1"
DATA_PORT = 15731
PRIMARY_PORTS = {15500, 15501}  # the primary lab's bridge ports
TCP_SYN = 2
TCP_RST = 4
TCP_ACK = 16
SEQUENCE_MASK = 0xFFFFFFFF
MICROSECONDS_PER_SECOND = 1_000_000
NANOSECONDS_PER_MICROSECOND = 1000


def load(path: Path) -> Json:
    """Read a JSON file.

    Returns
    -------
    dict[str, typing.Any]
        The parsed document.
    """
    return json.loads(path.read_text())


class View(typ.NamedTuple):
    """A packet capture of one side of the transfer.

    Attributes
    ----------
    label : str
        ``namespace`` or ``guest``.
    client : str
        The client address.
    server : str
        The server address.
    port : int
        The server's data port.
    window : int
        The last window that the client is expected to advertise.
    scale : int | None
        The window-scale shift both ends are expected to negotiate.
    """

    label: str
    client: str
    server: str
    port: int
    window: int
    scale: int | None


VIEWS = (
    View("namespace", LOOPBACK, LOOPBACK, DATA_PORT, 79872, 7),
    View("guest", "10.0.2.2", "10.0.2.15", 5501, 8760, None),
)


@dc.dataclass(frozen=True, slots=True)
class Download:
    """The failed download connection and the frozen findings about it.

    Attributes
    ----------
    corpus : pathlib.Path
        The corpus directory.
    report : dict[str, typing.Any]
        The failed capture's report.
    received : bytes
        The prefix that the recorder received.
    local : int
        The recorder's local port.
    when : int
        The connection time, in microseconds since the epoch.
    h1 : dict[str, typing.Any]
        The frozen first hypothesis analysis.
    h2 : dict[str, typing.Any]
        The frozen second hypothesis analysis.
    """

    corpus: Path
    report: Json
    received: bytes
    local: int
    when: int
    h1: Json
    h2: Json


def read_download(corpus: Path, report: Json, received: bytes) -> Download:
    """Locate the download connection and read the frozen analyses.

    Returns
    -------
    Download
        The connection and findings.
    """
    h1 = load(corpus / "h1/analysis.json")
    h2 = load(corpus / "h2/analysis.json")
    require(
        "H1 falsified" in h1["verdict"] and "H2 falsified" in h2["verdict"],
        "Frozen hypothesis classifications differ",
    )
    event = next(
        e
        for e in report["events"]
        if e["event"] == "connect" and e["connection"] == "download"
    )
    require(
        event["peer_address"] == [LOOPBACK, DATA_PORT], "Data flow endpoint differs"
    )
    started = dt.datetime.fromisoformat(report["started_at_utc"]).timestamp()
    when = (
        int(started * MICROSECONDS_PER_SECOND)
        + event["elapsed_ns"] // NANOSECONDS_PER_MICROSECOND
    )
    return Download(corpus, report, received, event["local_address"][1], when, h1, h2)


def check_stream(download: Download, view: View, flow: list[Packet]) -> int:
    """Check that a view carries exactly the recorded bytes, in both directions.

    Returns
    -------
    int
        The length of the server's application data.
    """
    client, server = (view.client, download.local), (view.server, view.port)
    application = stream(flow, server, client)
    require(
        application == download.received, f"{view.label} data differs or has suffix"
    )
    require(
        stream(flow, client, server)
        == bytes.fromhex(download.report["streams"]["download"]["sent_hex"]),
        f"{view.label} HTXF differs",
    )
    return len(application)


def sent_by(flow: list[Packet], address: str, port: int) -> list[Packet]:
    """Select the packets of a flow that one endpoint sent.

    Returns
    -------
    list[dict[str, typing.Any]]
        The packets from ``address`` and ``port``.
    """
    return [p for p in flow if p["src_ip"] == address and p["src_port"] == port]


def check_handshake(
    view: View, local: int, flow: list[Packet], heads: dict[int, Json]
) -> tuple[int | None, Packet]:
    """Check that the flow has one handshake and that both ends scale as expected.

    Returns
    -------
    tuple[int | None, dict[str, typing.Any]]
        The negotiated window-scale shift and the server's SYN-ACK packet.
    """
    syn = [
        p
        for p in sent_by(flow, view.client, local)
        if p["flags"] & TCP_SYN and not p["flags"] & TCP_ACK
    ]
    synack = [
        p
        for p in sent_by(flow, view.server, view.port)
        if p["flags"] & TCP_SYN and p["flags"] & TCP_ACK
    ]
    require(len(syn) == len(synack) == 1, "SYN association differs")
    scale = heads[syn[0]["index"]]["scale"]
    require(
        scale == heads[synack[0]["index"]]["scale"] == view.scale,
        f"{view.label} window-scale negotiation differs",
    )
    return scale, synack[0]


def check_tail(
    view: View, from_server: list[Packet], length: int, synack: Packet
) -> tuple[int, int]:
    """Check that the server's payload packets account for every byte and end last.

    Returns
    -------
    tuple[int, int]
        The first sequence number after the handshake, and the stream offset at
        which the last payload ends.
    """
    payload = [p for p in from_server if p["payload_hex"] and not p["flags"] & TCP_RST]
    require(
        sum(len(bytes.fromhex(p["payload_hex"])) for p in payload) == length,
        f"{view.label} retransmission tail differs",
    )
    base = (synack["sequence"] + 1) & SEQUENCE_MASK
    last = max(payload, key=operator.itemgetter("timestamp_us"))
    end = ((last["sequence"] - base) & SEQUENCE_MASK) + len(
        bytes.fromhex(last["payload_hex"])
    )
    require(end == length, f"{view.label} final sequence differs")
    return base, end


def effective_windows(
    acks: list[Packet], heads: dict[int, Json], scale: int | None
) -> list[int]:
    """Scale the advertised window of each acknowledgement.

    Returns
    -------
    list[int]
        The window each acknowledgement allows, in bytes.
    """
    factor = 1 << scale if scale is not None else 1
    return [heads[p["index"]]["window"] * factor for p in acks]


def check_acks(download: Download, view: View, flow: list[Packet], heads: dict) -> Json:
    """Check the window, sequence and acknowledgements of a view against H1 and H2.

    Returns
    -------
    dict[str, typing.Any]
        The packet count, byte count and last window of the view.
    """
    scale, synack = check_handshake(view, download.local, flow, heads)
    length = check_stream(download, view, flow)
    from_server = sent_by(flow, view.server, view.port)
    base, end = check_tail(view, from_server, length, synack)
    acks = [
        p
        for p in sent_by(flow, view.client, download.local)
        if p["flags"] & TCP_ACK and not p["flags"] & TCP_RST
    ]
    windows = effective_windows(acks, heads, scale)
    covered = [p for p in acks if (p["acknowledgement"] - base) & SEQUENCE_MASK >= end]
    require(
        bool(covered) and all(window > 0 for window in windows),
        f"{view.label} zero window or unacknowledged tail",
    )
    require(windows[-1] == view.window, f"{view.label} last window differs")
    check_frozen(download, view.label, length, end)
    return {
        "packets": len(flow),
        "server_bytes": length,
        "first_full_ack_index": covered[0]["index"],
        "last_effective_window": windows[-1],
        "scale": scale,
    }


def check_frozen(download: Download, label: str, length: int, end: int) -> None:
    """Check a view against the frozen H1 and H2 findings."""
    h1, h2 = download.h1["views"][label], download.h2["views"][label]
    require(
        h1["server_application_bytes"] == length
        and h1["suffix_bytes_beyond_recorder"] == 0,
        "H1 frozen view differs",
    )
    require(
        h2["last_payload_fully_acked"] and h2["zero_window_ack_count"] == 0,
        "H2 frozen view differs",
    )
    require(
        h2["last_server_payload"]["relative_end"] == end, "H2 frozen sequence differs"
    )


def check_view(download: Download, view: View) -> Json:
    """Read one packet view of the failed transfer and check it.

    Returns
    -------
    dict[str, typing.Any]
        The observations of the view.
    """
    path = download.corpus / f"capture/{view.label}.pcap"
    packets = read_packets(path)
    if view.label == "namespace":
        require(
            not any(
                p["src_port"] in PRIMARY_PORTS or p["dst_port"] in PRIMARY_PORTS
                for p in packets
            ),
            "Primary bridge was used",
        )
    flow = lifetime(
        packets, (view.client, download.local), (view.server, view.port), download.when
    )
    return check_acks(download, view, flow, raw_headers(path))
