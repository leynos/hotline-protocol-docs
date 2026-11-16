"""Check the paired packet captures and the stopped state of the rate304 corpus.

The checks run in a fixed order, and the first one that fails names the error, so
the helpers below are called in the order they are listed in
:func:`paired_packets` and :func:`stopped_and_capture`.
"""

import datetime as dt
import typing as typ

from verify_native_rate304_sequence_constants import (
    ACTIVE_USER_COUNT,
    CAPTURE_DROP_LINES,
    DEADLINE,
    FLOW_COUNT,
    FORKS,
    GUEST_PACKET_COUNT,
    GUEST_PORT,
    HFS_LINE_COUNT,
    INACTIVE_UNIT_COUNT,
    INODE,
    NAMESPACE_PACKET_COUNT,
    PCAP_HEADER_SIZE,
    PORTS,
    SERVER_PORT,
)
from verify_native_rate304_sequence_support import need, read, sha

if typ.TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType

    from verify_native_rate304_sequence_support import Modules, Report


def _check_lifetimes(view: list[Report], endpoints: tuple[str, str, int]) -> None:
    """Check the SYN lifetimes and the endpoints of one capture view.

    Parameters
    ----------
    view : list[dict[str, typing.Any]]
        The parsed packets of the capture.
    endpoints : tuple[str, str, int]
        The client address, the server address and the server port of the view.
    """
    client_ip, server_ip, server_port = endpoints
    syns = [p for p in view if p["flags"] & 2 and not p["flags"] & 16]
    need(
        len(syns) == FLOW_COUNT
        and {p["src_port"] for p in syns} == set(PORTS.values()),
        "Five SYN lifetimes differ",
    )
    need(
        all(
            p["src_ip"] == client_ip
            and p["dst_ip"] == server_ip
            and p["dst_port"] == server_port
            for p in syns
        ),
        "Capture endpoint differs",
    )
    need(
        all(
            (p["src_port"] in PORTS.values() and p["dst_port"] == server_port)
            or (p["src_port"] == server_port and p["dst_port"] in PORTS.values())
            for p in view
        ),
        "Unexpected TCP lifetime",
    )


def _view_lengths(
    tcp: ModuleType,
    view: list[Report],
    endpoints: tuple[str, str, int],
    streams: Report,
) -> dict[str, dict[str, int]]:
    """Check the bytes of each flow in one capture view against the recorded streams.

    Parameters
    ----------
    tcp : types.ModuleType
        The loaded frozen TCP module.
    view : list[dict[str, typing.Any]]
        The parsed packets of the capture.
    endpoints : tuple[str, str, int]
        The client address, the server address and the server port of the view.
    streams : dict[str, typing.Any]
        The recorded streams, by flow name, with their hexadecimal bytes.

    Returns
    -------
    dict[str, dict[str, int]]
        The sent and received byte counts of each flow.
    """
    client_ip, server_ip, server_port = endpoints
    _check_lifetimes(view, endpoints)
    result: dict[str, dict[str, int]] = {}
    for name, port in PORTS.items():
        sent = tcp.stream(view, (client_ip, port), (server_ip, server_port))
        received = tcp.stream(view, (server_ip, server_port), (client_ip, port))
        need(
            sent.hex() == streams[name]["sent_hex"]
            and received.hex() == streams[name]["received_hex"],
            f"{name} PCAP/Recorder bytes or tail differ",
        )
        result[name] = {"sent": len(sent), "received": len(received)}
    return result


def _check_guest_reset(ns: list[Report], guest: list[Report]) -> None:
    """Check that the guest reset and the relay's FIN close the burst flow once each.

    Parameters
    ----------
    ns : list[dict[str, typing.Any]]
        The parsed packets of the namespace capture.
    guest : list[dict[str, typing.Any]]
        The parsed packets of the guest capture.
    """
    burst_guest_rst = [
        p
        for p in guest
        if p["src_port"] == GUEST_PORT
        and p["dst_port"] == PORTS["burst"]
        and p["flags"] & 4
    ]
    burst_ns_fin = [
        p
        for p in ns
        if p["src_port"] == SERVER_PORT
        and p["dst_port"] == PORTS["burst"]
        and p["flags"] & 1
    ]
    need(
        len(burst_guest_rst) == len(burst_ns_fin) == 1
        and bytes.fromhex(burst_guest_rst[0]["payload_hex"]) == b"tcp_disconnect",
        "Guest RST versus relay FIN differs",
    )


def paired_packets(corpus: Path, report: Report, modules: Modules) -> Report:
    """Check the namespace and guest captures against the recorded flows.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    report : dict[str, typing.Any]
        The parsed ``coordinator/report.json``.
    modules : tuple[types.ModuleType, ...]
        The frozen modules yielded by the ``frozen`` context manager.

    Returns
    -------
    dict[str, dict[str, int]]
        The sent and received byte counts of each flow.
    """
    raw = corpus / "raw/epoch"
    _, _, _, _, tcp = modules
    host = tcp.read_packets(raw / "primary-syn.pcap")
    ns = tcp.read_packets(raw / "lab-namespace.pcap")
    guest = tcp.read_packets(raw / "lab-guest.pcap")
    need(
        len(host) == 0
        and len(ns) == NAMESPACE_PACKET_COUNT
        and len(guest) == GUEST_PACKET_COUNT,
        "Capture packet inventory differs",
    )
    streams = {
        "readiness": read(raw / "readiness/report.json")["streams"]["main"]
    } | report["streams"]
    result: dict[str, dict[str, int]] = {}
    for view, endpoints in (
        (ns, ("127.0.0.1", "127.0.0.1", SERVER_PORT)),
        (guest, ("10.0.2.2", "10.0.2.15", GUEST_PORT)),
    ):
        result.update(_view_lengths(tcp, view, endpoints, streams))
    _check_guest_reset(ns, guest)
    need(
        result
        == {
            "readiness": {"sent": 231, "received": 2759},
            "observer": {"sent": 526, "received": 5897},
            "paced": {"sent": 1459, "received": 2495},
            "burst": {"sent": 1437, "received": 2418},
            "probe": {"sent": 91, "received": 76},
        },
        "Five stream lengths differ",
    )
    return result


def _check_terminal(terminal: Report) -> None:
    """Check the retired process identity and the owned image and ROM holds.

    Parameters
    ----------
    terminal : dict[str, typing.Any]
        The parsed ``terminal-identity.json``.
    """
    need(
        terminal["actual_pid_gone"]
        and terminal["oracle_lock_free"]
        and terminal["ports_absent"]
        and terminal["original_ticks"] == {"1099659": "767842", "1012834": "2357813"},
        "Retirement/original identity differs",
    )
    need(
        all(
            v["exit"] == 1 and not v["stdout"] and not v["stderr"]
            for v in terminal["fuser"].values()
        ),
        "Owned image/ROM still held",
    )


def _check_hfs(raw: Path, hfs: Report) -> None:
    """Check the stopped HFS state and its allocated catalogue.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw/epoch`` directory of the corpus.
    hfs : dict[str, typing.Any]
        The parsed ``stopped-hfs-summary.json``.
    """
    need(
        hfs["image_inode"] == INODE
        and hfs["fuser_exit"] == 1
        and hfs["full_lines"] == hfs["allocated_lines"] == HFS_LINE_COUNT
        and not hfs["banned_entries"]
        and len(hfs["active_users"]) == ACTIVE_USER_COUNT,
        "Stopped HFS state differs",
    )
    allocated = (raw / "stopped-fls-allocated.stdout").read_text().splitlines()
    users = [
        line
        for line in allocated
        if "Hotline19/Users/" in line and line.endswith("/UserData")
    ]
    need(
        users == hfs["active_users"]
        and not any("Hotline19/Banned" in line for line in allocated)
        and any(
            "11191:" in line and "Hotline19/MessageBoard.txt" in line
            for line in allocated
        ),
        "Stopped allocated HFS catalogue differs",
    )


def _check_board(raw: Path, hfs: Report) -> None:
    """Check the stopped board fork, its Finder metadata and the fork digests.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw/epoch`` directory of the corpus.
    hfs : dict[str, typing.Any]
        The parsed ``stopped-hfs-summary.json``.
    """
    istat = (raw / "stopped-istat-board.stdout").read_text()
    need(
        "Catalog Record: 11191" in istat
        and "Size:\t0" in istat
        and "Resource fork size:\t0" in istat
        and "TEXT" in istat
        and "ttxt" in istat,
        "Stopped board fork/Finder metadata differs",
    )
    for name, digest in FORKS.items():
        need(
            hfs["forks"][name]["sha256"] == digest
            and sha(raw / f"stopped-icat-{name}.stdout") == digest
            if name in {"admin", "fixture-low", "Prefs"}
            else hfs["forks"][name]["sha256"] == digest,
            f"Stopped {name} fork differs",
        )
    need(
        hfs["forks"]["board"]["bytes"] == 0
        and (raw / "stopped-icat-board.stdout").read_bytes() == b"",
        "Stopped board differs",
    )


def _check_units(raw: Path) -> None:
    """Check the stopped units, the forced retirement and the retirement deadline.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw/epoch`` directory of the corpus.
    """
    unit = (raw / "units-after-stop.txt").read_text()
    need(
        unit.count("ActiveState=inactive") == INACTIVE_UNIT_COUNT
        and "ActiveState=failed" in unit
        and "ExecMainStatus=1" in unit,
        "Owned unit terminal state differs",
    )
    need(
        read(raw / "owned-pid-term.json")["action"]
        == "SIGTERM after native app Quit; not orderly OS shutdown",
        "Forced retirement provenance differs",
    )
    need(
        dt.datetime.fromisoformat((raw / "units-stopped.utc").read_text().strip())
        < dt.datetime.fromisoformat(DEADLINE),
        "Retirement missed fixed deadline",
    )


def _check_capture(raw: Path) -> None:
    """Check the capture journal, the primary-port capture and the Git reproduction.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw/epoch`` directory of the corpus.
    """
    journal = (raw / "capture-journal-terminal.txt").read_text()
    need(
        (raw / "capture-journal-terminal.exit").read_text().strip() == "0"
        and "206 packets captured" in journal
        and "0 packets captured" in journal
        and journal.count("0 packets dropped by kernel") == CAPTURE_DROP_LINES,
        "Capture drops/counts differ",
    )
    need(
        (raw / "primary-syn.pcap").stat().st_size == PCAP_HEADER_SIZE,
        "Primary-port SYN capture differs",
    )
    need(
        (raw / "root-git-ownership-check.exit").read_text().strip() == "0"
        and (raw / "root-git-nested-sudo.exit").read_text().strip() == "128"
        and "dubious ownership" in (raw / "root-git-nested-sudo.stderr").read_text(),
        "Post-event nested-sudo Git reproduction differs",
    )


def stopped_and_capture(corpus: Path) -> None:
    """Check the stopped state, the retirement and the capture of the corpus.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    raw = corpus / "raw/epoch"
    terminal, hfs = (
        read(raw / "terminal-identity.json"),
        read(raw / "stopped-hfs-summary.json"),
    )
    _check_terminal(terminal)
    _check_hfs(raw, hfs)
    _check_board(raw, hfs)
    _check_units(raw)
    _check_capture(raw)
