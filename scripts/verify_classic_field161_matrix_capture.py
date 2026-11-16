"""Check the capture readiness receipts and the selected PCAP views of field-161."""

import json
import typing as typ

from verify_classic_field161_matrix_common import (
    CAPTURE_FD,
    CAPTURE_OWNERS,
    VARIANTS,
    digest,
    require,
)

if typ.TYPE_CHECKING:
    from pathlib import Path


def check_receipts(base: Path, label: str, pid: int, netns: int) -> None:
    """Check the ready receipts of one recorder and that its identity never drifted.

    Parameters
    ----------
    base : Path
        The corpus directory.
    label : str
        The recorder's label, ``host`` or ``ns``.
    pid : int
        The recorder's process identifier.
    netns : int
        The inode of the recorder's network namespace.
    """
    names = [f"{label}-ready-launch.json", f"{label}-ready-before-a7.json"]
    names += [f"{case}/{label}-ready-before-connect.json" for case in VARIANTS]
    starts = set()
    inodes = set()
    for name in names:
        receipt = json.loads((base / name).read_text())
        properties = receipt["unit_properties"]
        require(
            receipt["pid"] == pid
            and receipt["fd"] == CAPTURE_FD
            and receipt["netns_inode"] == netns,
            f"capture owner {name}",
        )
        require(
            properties["ActiveState"] == "active"
            and properties["SubState"] == "running"
            and properties["MainPID"] == str(pid),
            f"unit ready {name}",
        )
        require(
            properties["RuntimeMaxUSec"] == "15min"
            and properties["KillMode"] == "control-group",
            f"unit ready {name}",
        )
        require(
            receipt["header24"] == "d4c3b2a10200040000000000000000000000040001000000",
            f"capture header/deadline {name}",
        )
        require(
            receipt["deadline_utc"] == "2026-11-14T02:23:00+00:00",
            f"capture header/deadline {name}",
        )
        starts.add(receipt["start_ticks"])
        inodes.add((receipt["dev"], receipt["inode"]))
    require(len(starts) == len(inodes) == 1, f"capture identity drift {label}")


def check_journal(base: Path, label: str, pid: int) -> None:
    """Check the recorder journal for zero kernel drops and its own capture.

    Parameters
    ----------
    base : Path
        The corpus directory.
    label : str
        The recorder's label, ``host`` or ``ns``.
    pid : int
        The recorder's process identifier.
    """
    journal = (
        base / f"{'host' if label == 'host' else 'ns'}-recorder-journal.txt"
    ).read_text()
    require("0 packets dropped by kernel" in journal, f"capture drops {label}")
    require(
        f"tcpdump[{pid}]" in journal and "packets captured" in journal,
        f"capture journal {label}",
    )


def check_cleanup(base: Path) -> None:
    """Check that the capture units, PIDs and listeners were all released.

    Parameters
    ----------
    base : Path
        The corpus directory.
    """
    units = (base / "units-terminal.txt").read_text()
    for unit in (
        "mothra-b52-host-capture",
        "mothra-b52-ns-capture",
        "mothra-classic-proxy-b52-omit",
        "mothra-classic-proxy-b52-one",
        "mothra-classic-proxy-b52-four",
    ):
        require(
            f"Id={unit}.service\nActiveState=inactive\nMainPID=0" in units,
            f"unit cleanup {unit}",
        )
    require(
        (base / "former-pids-terminal.txt").read_text().strip() == "PID COMMAND",
        "former capture/proxy PID cleanup",
    )
    require(
        "15652" not in (base / "listeners-terminal.txt").read_text(),
        "owned listener cleanup",
    )


def check_readiness(base: Path, manifest: dict[str, typ.Any]) -> dict[str, typ.Any]:
    """Check the capture readiness receipts, journals and cleanup of the corpus.

    Returns
    -------
    dict[str, typing.Any]
        The number of readiness checks, the recorder PIDs and the drop verdict.
    """
    terminal = json.loads((base / "terminal.json").read_text())
    require(
        terminal["fixed_group_deadline_utc"] == "2026-11-14T02:23:00Z",
        "fixed group deadline",
    )
    require(
        terminal["live_start_utc"] == "2026-11-14T02:11:00Z"
        and terminal["live_end_utc"] == "2026-11-14T02:22:15Z",
        "group bound",
    )
    require(
        manifest["capture_gate_sha256"] == terminal["sources"]["capture_gate_sha256"],
        "capture gate identity",
    )
    for label, pid, netns in CAPTURE_OWNERS:
        check_receipts(base, label, pid, netns)
        check_journal(base, label, pid)
    check_cleanup(base)
    return {
        "readiness_checks": 10,
        "recorder_pids": [3394965, 3394975],
        "journals_zero_drops": True,
    }


def check_route(packets: list[dict[str, typ.Any]], route: dict[str, typ.Any]) -> None:
    """Check the packets of one selected route and its TCP lifetime.

    Parameters
    ----------
    packets : list[dict[str, typing.Any]]
        The packets of the selected PCAP.
    route : dict[str, typing.Any]
        The route, its packet count and its terminal flags.
    """
    src_ip, src_port, dst_ip, dst_port = route["route"]
    selected = [
        p
        for p in packets
        if (
            (p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"])
            == (src_ip, src_port, dst_ip, dst_port)
            or (p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"])
            == (dst_ip, dst_port, src_ip, src_port)
        )
    ]
    require(
        len(selected) == route["packet_count"]
        and sum(
            bool(
                p["flags"] & 2
                and not p["flags"] & 16
                and (p["src_ip"], p["src_port"]) == (src_ip, src_port)
            )
            for p in selected
        )
        == 1,
        "selected SYN lifetime",
    )
    require(
        [p["flags"] for p in selected if p["flags"] & 5] == route["terminal_flags"]
        and route["terminal_flags"],
        "selected TCP tails",
    )


def check_selection(
    base: Path, manifest: dict[str, typ.Any], packets: dict[str, typ.Any]
) -> None:
    """Check that each selected PCAP is the original capture's exact selection.

    Parameters
    ----------
    base : Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json``.
    packets : dict[str, typing.Any]
        The parsed packets of each selected PCAP, keyed by its corpus path.
    """
    inventory_report = json.loads((base / "pcap-inventory.json").read_text())["files"]
    for name, selection in manifest["selection"].items():
        chosen = base / "pcaps" / name
        require(
            chosen.stat().st_size == selection["selected_bytes"]
            and digest(chosen.read_bytes()) == selection["selected_sha256"],
            f"selected PCAP identity {name}",
        )
        require(
            len(packets["pcaps/" + name]) == len(selection["selected_record_indexes"]),
            f"selected PCAP record count {name}",
        )
        original = inventory_report[name]
        require(
            selection["original_bytes"] == original["bytes"]
            and selection["original_sha256"] == original["sha256"],
            f"original PCAP provenance {name}",
        )
        for route in selection["routes"]:
            check_route(packets["pcaps/" + name], route)
