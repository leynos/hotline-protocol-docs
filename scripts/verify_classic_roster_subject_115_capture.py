"""Check the capture receipts, the capture journals and the selected PCAP views."""

import typing as typ
from pathlib import Path

from verify_classic_roster_subject_115_common import HEADER, load, need, sha

if typ.TYPE_CHECKING:
    from verify_classic_roster_subject_115_common import Packets


def capture_unit(
    run: Path,
    manifest: dict[str, typ.Any],
    unit: tuple[str, int, str],
) -> int:
    """Check the readiness receipts, journal and cleanup of one capture unit.

    Returns
    -------
    int
        The process ID of the capture.
    """
    label, ns, service = unit
    receipts = [
        load(run / f"{label}-ready-{phase}.json")
        for phase in ("launch", "before-a7", "before-connect")
    ]
    first = receipts[0]
    need(
        first["pid"] > 0 and first["fd"] >= 0 and first["header24"] == HEADER.hex(),
        "capture PID/FD/header",
    )
    need(
        all(
            r["unit"] == service
            and r["pid"] == first["pid"]
            and r["start_ticks"] == first["start_ticks"]
            and r["fd"] == first["fd"]
            and (r["dev"], r["inode"]) == (first["dev"], first["inode"])
            and r["netns_inode"] == ns
            and r["deadline_utc"] == manifest["group_deadline_utc"]
            and r["header24"] == HEADER.hex()
            and r["unit_properties"]["ActiveState"] == "active"
            and r["unit_properties"]["SubState"] == "running"
            and r["unit_properties"]["MainPID"] == str(first["pid"])
            and r["unit_properties"]["RuntimeMaxUSec"] == "15min"
            and r["unit_properties"]["KillMode"] == "control-group"
            for r in receipts
        ),
        "capture readiness drift",
    )
    need(
        all(
            r["capture"]
            == str(
                Path(
                    "/data/leynos/Projects/mothra/state/native-sessions/native-proxy-roster-115-01"
                )
                / ("host.pcap" if label == "host" else "namespace.pcap")
            )
            for r in receipts
        ),
        "capture path",
    )
    journal = (run / f"{label}-capture-journal.txt").read_text()
    need(
        f"tcpdump[{first['pid']}]" in journal
        and "packets captured" in journal
        and "0 packets dropped by kernel" in journal,
        "capture drop/owner",
    )
    units = (run / "units-terminal.txt").read_text()
    need(
        f"Id={service}\nActiveState=inactive\nMainPID=0\nResult=success" in units,
        "capture cleanup",
    )
    return first["pid"]


def capture_check(base: Path, manifest: dict[str, typ.Any]) -> dict[str, typ.Any]:
    """Check the host and namespace capture units of the session.

    Returns
    -------
    dict[str, typing.Any]
        The capture process ID of each unit, keyed by its label.
    """
    need(
        manifest["group_deadline_utc"] == "2026-11-14T04:25:15+00:00", "group deadline"
    )
    result: dict[str, typ.Any] = {}
    for label, ns, unit in (
        ("host", 4026531840, "mothra-b62-host-capture.service"),
        ("ns", 4026532479, "mothra-b62-ns-capture.service"),
    ):
        result[label] = capture_unit(base / "run", manifest, (label, ns, unit))
    return result


def selection_route(
    view: list[dict[str, typ.Any]],
    spec: dict[str, typ.Any],
    entry: dict[str, typ.Any],
) -> None:
    """Check the SYN lifetime and terminal flags of one selected route."""
    src, port, dst, target = entry["route"]
    forward = (src, port, dst, target)
    reverse = (dst, target, src, port)
    selected = [
        p
        for p in view
        if (p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"]) == forward
        or (p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"]) == reverse
    ]
    syns = [
        p
        for p in selected
        if (p["src_ip"], p["src_port"]) == (src, port)
        and p["flags"] & 2
        and not p["flags"] & 16
    ]
    need(
        len(selected) == entry["packet_count"]
        and len(syns) == 1
        and entry["syn_index"] in spec["selected_record_indexes"]
        and syns[0]["timestamp_us"] == entry["syn_timestamp_us"],
        "selected SYN lifetime",
    )
    need(
        [p["flags"] for p in selected if p["flags"] & 5] == entry["terminal_flags"]
        and bool(entry["terminal_flags"]),
        "selected tail",
    )


def selection_view(
    base: Path,
    name: str,
    spec: dict[str, typ.Any],
    packets: Packets,
) -> None:
    """Check the identity of one selected PCAP view and each of its routes."""
    chosen = base / "pcaps" / name
    need(
        chosen.stat().st_size == spec["selected_bytes"]
        and sha(chosen.read_bytes()) == spec["selected_sha256"],
        "selected PCAP identity",
    )
    need(
        len(packets["pcaps/" + name]) == len(spec["selected_record_indexes"]),
        "selected record count",
    )
    for entry in spec["routes"]:
        selection_route(packets["pcaps/" + name], spec, entry)


def selection_check(base: Path, manifest: dict[str, typ.Any], packets: Packets) -> None:
    """Check that the selected PCAP views match the manifest selection."""
    need(
        set(manifest["selection"])
        == {
            "client-guest-post.pcap",
            "namespace.pcap",
            "host.pcap",
            "server-guest-post.pcap",
        },
        "selected view set",
    )
    for name, spec in manifest["selection"].items():
        selection_view(base, name, spec, packets)
