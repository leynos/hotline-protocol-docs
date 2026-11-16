"""Check the failed A7 outcome, the download and the recorded captures."""

import datetime as dt
import hashlib
import typing as typ

from pcap_tcp import lifetime, read_packets, stream

if typ.TYPE_CHECKING:
    from pathlib import Path
from verify_native_ui_focus_core import (
    A7_ACTIONS,
    A7_STEPS,
    APP_SHA,
    DATA_PORT,
    DOWNLOAD_BYTES,
    DRIVER_SHA,
    EMULATOR_PID,
    PACKET_VIEWS,
    PREFIX_SHA,
    load,
    require,
    sha,
)


def check_plans(exp: Path) -> None:
    """Check the original and as-run A7 plans and their runtime caveat.

    Parameters
    ----------
    exp : pathlib.Path
        The experiment directory.
    """
    original = load(exp / "a7-original-plan.json")
    asrun = load(exp / "a7-as-run-plan.json")
    require(
        len(original["steps"]) == A7_STEPS and original["steps"] == asrun["steps"],
        "A7 steps differ",
    )
    for key in original.keys() - {"environment", "endpoints"}:
        require(original[key] == asrun[key], f"A7 {key} differs")
    require(
        asrun["endpoints"]
        == {
            "control": {"host": "127.0.0.1", "port": 15750},
            "data": {"host": "127.0.0.1", "port": DATA_PORT},
        },
        "A7 endpoints differ",
    )
    require(
        asrun["environment"]["emulator_pid"] == EMULATOR_PID
        and asrun["environment"]["captured_options"] is False,
        "A7 runtime or options caveat differs",
    )


def check_report(report: dict[str, typ.Any]) -> tuple[bytes, bytes]:
    """Check the failed A7 outcome and the download prefix it recorded.

    Returns
    -------
    tuple[bytes, bytes]
        The bytes the server received and the bytes it sent on the download.
    """
    require(
        (report["status"], report["completed_actions"], report["error"])
        == ("failed", A7_ACTIONS, "TimeoutError: timed out"),
        "A7 failed outcome differs",
    )
    require(
        report["driver_sha256"] == DRIVER_SHA and report["oracle_sha256"] == APP_SHA,
        "A7 source identity differs",
    )
    received = bytes.fromhex(report["streams"]["download"]["received_hex"])
    sent = bytes.fromhex(report["streams"]["download"]["sent_hex"])
    require(
        len(received) == DOWNLOAD_BYTES
        and hashlib.sha256(received).hexdigest() == PREFIX_SHA,
        "A7 download prefix differs",
    )
    return received, sent


def data_connection(report: dict[str, typ.Any]) -> tuple[int, int]:
    """Find the download connection and the time at which it opened.

    Returns
    -------
    tuple[int, int]
        The local port of the connection, and its time in microseconds.
    """
    event = next(
        e
        for e in report["events"]
        if e["connection"] == "download" and e["event"] == "connect"
    )
    require(
        event["peer_address"] == ["127.0.0.1", DATA_PORT],
        "A7 data peer differs",
    )
    local = event["local_address"][1]
    started = dt.datetime.fromisoformat(report["started_at_utc"])
    when = int(started.timestamp() * 1_000_000) + event["elapsed_ns"] // 1000
    return local, when


def packet_view(
    boot: Path,
    connection: tuple[int, int],
    streams: tuple[bytes, bytes],
    spec: tuple[str, str, str, int, str],
) -> dict[str, typ.Any]:
    """Check one recorded capture of the download and summarize it.

    Returns
    -------
    dict[str, typing.Any]
        The byte count, the stream hash and the hash of the capture file.
    """
    local, when = connection
    name, client, server, port, filename = spec
    packets = read_packets(boot / filename)
    if name == "namespace":
        require(
            not any(
                p["src_port"] in {15500, 15501} or p["dst_port"] in {15500, 15501}
                for p in packets
            ),
            "Primary bridge used",
        )
    flow = lifetime(packets, (client, local), (server, port), when)
    require(
        sum(bool(p["flags"] & 2 and not p["flags"] & 16) for p in flow) == 1,
        f"{name} SYN association differs",
    )
    body = stream(flow, (server, port), (client, local))
    require(
        body == streams[0]
        and stream(flow, (client, local), (server, port)) == streams[1],
        f"{name} packet stream differs",
    )
    return {
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "pcap_sha256": sha(boot / filename),
    }


def packet_views(
    boot: Path,
    connection: tuple[int, int],
    streams: tuple[bytes, bytes],
) -> dict[str, dict[str, typ.Any]]:
    """Check both recorded captures of the download, guest first.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        The summary of each view, keyed by view name.
    """
    views: dict[str, dict[str, typ.Any]] = {}
    for spec in PACKET_VIEWS:
        views[spec[0]] = packet_view(boot, connection, streams, spec)
    return views


def check_recorders(boot: Path) -> None:
    """Check that the primary host saw no traffic and the recorders dropped nothing.

    Parameters
    ----------
    boot : pathlib.Path
        The boot directory.
    """
    require(
        not read_packets(boot / "primary-host.pcap"), "Primary host traffic differs"
    )
    for logfile in ("host-recorder.log", "ns-recorder.log"):
        text = (boot / logfile).read_text(encoding="utf-8")
        require("0 packets dropped by kernel" in text, "Recorder drop proof differs")
