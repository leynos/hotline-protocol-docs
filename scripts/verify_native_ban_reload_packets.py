"""Check the packet views of the persisted-ban reload witness against its streams."""

import dataclasses as dc
import datetime as dt
import hashlib
import typing as typ

from pcap_tcp import lifetime, read_packets, stream
from verify_native_ban_reload_core import (
    GUEST_PACKETS,
    NAMESPACE_PACKETS,
    read,
    require,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

    from pcap_reader import Packet

type Report = dict[str, typ.Any]


@dc.dataclass(frozen=True, slots=True)
class _Stream:
    """The recorded packets of one TCP view and the endpoints of its flow."""

    label: str
    packets: list[Packet]
    client: str
    server: str
    target: int


@dc.dataclass(frozen=True, slots=True)
class _Flow:
    """The verified probe report, the frozen view of its flow and the flow's clock."""

    report: Report
    view: Report
    port: int
    start: int


def _check_recorders(root: Path, host: list[Packet], ns: list[Packet]) -> None:
    """Check that no primary SYN was captured and that the recorders kept every packet.

    Parameters
    ----------
    root : pathlib.Path
        The ``c61`` directory of the corpus.
    host : list[Packet]
        The packets of the primary SYN capture.
    ns : list[Packet]
        The packets of the lab namespace capture.
    """
    require(not host, "Primary SYN capture is nonempty")
    require(
        not [
            p
            for p in ns
            if p["src_port"] in {15500, 15501} or p["dst_port"] in {15500, 15501}
        ],
        "Fixed primary bridge was contacted",
    )
    for label, count in (("host", 0), ("namespace", NAMESPACE_PACKETS)):
        log = (root / f"{label}-recorder.log").read_text()
        require(
            f"{count} packets captured" in log and "0 packets dropped by kernel" in log,
            f"{label} recorder count/drop differs",
        )


def _flow(report: Report, view: Report) -> _Flow:
    """Select the one fresh socket of the probe and check its flow identity.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The verified probe report.
    view : dict[str, typing.Any]
        The frozen packet views.

    Returns
    -------
    _Flow
        The report, the view, the local port and the start on the packet clock.
    """
    connect = [e for e in report["events"] if e["event"] == "connect"]
    require(
        len(connect) == 1 and connect[0]["connection"] == "main",
        "Fresh socket count differs",
    )
    event = connect[0]
    port = event["local_address"][1]
    started = int(
        dt.datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1_000_000
    )
    start = started + event["elapsed_ns"] // 1000
    require(
        view["local_port"] == port and view["connection"] == "main",
        "TCP flow identity differs",
    )
    return _Flow(report=report, view=view, port=port, start=start)


def _check_stream(spec: _Stream, flow: _Flow) -> None:
    """Check the complete scoped TCP stream of one view against its frozen record.

    Parameters
    ----------
    spec : _Stream
        The recorded packets and endpoints of the view.
    flow : _Flow
        The verified probe report, the frozen views and the flow's port and start.
    """
    life = lifetime(
        spec.packets,
        (spec.client, flow.port),
        (spec.server, spec.target),
        flow.start,
    )
    require(bool(life), f"{spec.label} TCP lifetime missing")
    sent = stream(life, (spec.client, flow.port), (spec.server, spec.target))
    received = stream(life, (spec.server, spec.target), (spec.client, flow.port))
    saved = flow.view["views"][spec.label]
    require(
        saved["packet_indices"] == [p["index"] for p in life]
        and saved["packet_count"] == len(life)
        and saved["first_us"] == life[0]["timestamp_us"]
        and saved["last_us"] == life[-1]["timestamp_us"]
        and saved["fin_packets"] == [p["index"] for p in life if p["flags"] & 1]
        and saved["rst_packets"] == [p["index"] for p in life if p["flags"] & 4]
        and saved["sent_len"] == len(sent)
        and saved["sent_sha256"] == hashlib.sha256(sent).hexdigest()
        and saved["sent_hex"]
        == sent.hex()
        == flow.report["streams"]["main"]["sent_hex"]
        and saved["received_len"] == len(received)
        and saved["received_sha256"] == hashlib.sha256(received).hexdigest()
        and saved["received_hex"]
        == received.hex()
        == flow.report["streams"]["main"]["received_hex"]
        and saved["received_tail_hex"] == received[-96:].hex(),
        f"{spec.label} complete scoped TCP stream differs",
    )


def packets(corpus: Path, report: Report) -> Report:
    """Check the packet views of the probe and count the captured packets.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    report : dict[str, typing.Any]
        The verified one-probe capture report.

    Returns
    -------
    dict[str, int]
        The packet counts of the namespace and guest views.
    """
    root = corpus / "c61"
    host = read_packets(root / "primary-syn.pcap")
    ns = read_packets(root / "lab-namespace.pcap")
    guest = read_packets(root / "lab-guest.pcap")
    _check_recorders(root, host, ns)
    view = read(corpus / "packet-views.json")
    flow = _flow(report, view)
    for spec in (
        _Stream("namespace", ns, "127.0.0.1", "127.0.0.1", 15750),
        _Stream("guest", guest, "10.0.2.2", "10.0.2.15", 5500),
    ):
        _check_stream(spec, flow)
    require(
        len(ns) == NAMESPACE_PACKETS and len(guest) == GUEST_PACKETS,
        "Unexpected TCP packet count",
    )
    return {"namespace_packets": len(ns), "guest_packets": len(guest)}
