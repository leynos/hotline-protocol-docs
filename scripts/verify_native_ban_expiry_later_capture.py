"""Check the clock, pre-epoch, post-epoch and unit receipts of the later epoch."""

import typing as typ

from verify_native_ban_expiry_first_common import need, read, replay_view, sha, when
from verify_native_ban_expiry_later_wire import (
    DEADLINE,
    HOST_PCAP_HEADER,
    INODE,
    LOCK_FD,
    MAX_BRACKET_SECONDS,
    NS,
    PID,
    START,
)

if typ.TYPE_CHECKING:
    import types
    from pathlib import Path

# The clock readings in the order the epoch took them: the location, the
# visible menu-bar clock, the bracket files, and the nested key if any.
CLOCK_ROWS = (
    ("pre", "Sat 6:20:05 AM", "clock-before.utc", "clock-after.utc", None),
    ("post", "Sat 6:27:48 AM", "clock-before.utc", "clock-after.utc", None),
    (
        "post",
        "Sat 6:29:36 AM",
        "clock-after-probe-before.utc",
        "clock-after-probe-after.utc",
        "post_probe",
    ),
)


def generic_post(folder: Path, capture: types.ModuleType) -> dict:
    """Adapt a post-epoch case report only in a temporary generic replay view.

    Parameters
    ----------
    folder : Path
        The post-epoch case folder, which holds ``plan.json`` and ``report.json``.
    capture : types.ModuleType
        The module whose ``verify_capture`` checks the replay view.

    Returns
    -------
    dict
        The case report as it was written, before adaptation.
    """
    plan = read(folder / "plan.json")
    report = read(folder / "report.json")
    need(
        report["profile"] == "control-only"
        and report["full_file_baseline"] == "not_exercised",
        "Raw post report profile differs",
    )
    adapted = {
        **report,
        "profile": plan["profile"],
        "native_conformance": False,
        "plan_sha256": sha(folder / "plan.json"),
    }
    replay_view(folder, adapted, capture)
    return report


def clock_gate(raw: Path) -> None:
    """Check the guest clock readings against their screenshots and host brackets.

    Parameters
    ----------
    raw : Path
        The raw receipts directory.
    """
    previous = None
    for location, visible, before_name, after_name, nested in CLOCK_ROWS:
        folder = raw / location
        value = read(folder / "clock-witness.json")
        data = value[nested] if nested else value
        before, after = when(data["host_before_utc"]), when(data["host_after_utc"])
        need(
            data["visible_guest_menubar_clock"] == visible
            and data["ui_action"] == "none"
            and sha(folder / data["screenshot"]) == data["sha256"]
            and (folder / before_name).read_text().strip() == data["host_before_utc"]
            and (folder / after_name).read_text().strip() == data["host_after_utc"]
            and before <= after
            and (after - before).total_seconds() < MAX_BRACKET_SECONDS
            and (previous is None or previous < before),
            "Guest clock screenshot, host bracket or order differs",
        )
        previous = after
    need("Login successful" in data["server_log_observation"], "Post UI log differs")


def pre_gate(raw: Path) -> None:
    """Check that the missed pre-epoch window was empty, controlled and failed.

    Parameters
    ----------
    raw : Path
        The raw receipts directory.
    """
    pre = raw / "pre"
    ready = read(pre / "capture-ready.json")
    need(
        ready["emulator_pid"] == PID
        and ready["emulator_starttime"] == START
        and ready["emulator_netns_inode"] == NS
        and ready["owned_working_image_inode"] == INODE
        and ready["deadline_utc"] == "2026-11-14T06:24:00+00:00"
        and ready["epoch_started_utc"] == "2026-11-14T06:19:10Z"
        and ready["managed_lock"]["busy_exit"] == 1
        and ready["managed_lock"]["fd"] == LOCK_FD,
        "Missed pre-epoch readiness differs",
    )
    for label in ("host", "namespace"):
        need(
            (
                pre / ("primary-syn.pcap" if label == "host" else "lab-namespace.pcap")
            ).read_bytes()
            == HOST_PCAP_HEADER
            and read(pre / f"{label}-ready.json")["pid"]
            == ready[f"{label}_recorder_pid"]
            and "0 packets captured"
            in (pre / f"{label}-terminal-journal.log").read_text()
            and "0 packets dropped by kernel"
            in (pre / f"{label}-terminal-journal.log").read_text(),
            "Pre-epoch capture was not empty and controlled",
        )
    unit = (pre / "c80-failed-unit.txt").read_text()
    journal = (pre / "c80-failed-journal.log").read_text()
    need(
        "Result=exit-code" in unit
        and "ExecMainStatus=1" in unit
        and "NetworkNamespacePath=/proc/774195/ns/net" in unit
        and "ValueError: Guest/image identity changed during idle" in journal
        and not (pre / "results").exists()
        and when((pre / "terminal.utc").read_text().strip())
        < when(ready["deadline_utc"])
        and "ActiveState=inactive" in (pre / "c79-terminal-units.txt").read_text(),
        "C80 failed-before-socket receipt differs",
    )
    need(
        read(pre / "route4.json") == read(pre / "route6.json") == []
        and [link["ifname"] for link in read(pre / "links.json")] == ["lo"],
        "Pre-epoch namespace containment differs",
    )


def post_receipt_gate(raw: Path) -> dict:
    """Check the post-epoch capture receipt against the first epoch's emulator.

    Parameters
    ----------
    raw : Path
        The raw receipts directory.

    Returns
    -------
    dict
        The post-epoch capture readiness receipt.
    """
    post = raw / "post"
    receipt = read(post / "capture-ready.json")
    first = read(raw / "pre/capture-ready.json")
    for key in (
        "emulator_pid",
        "emulator_starttime",
        "emulator_sha256",
        "emulator_netns_inode",
        "owned_working_image_inode",
        "owned_working_image",
        "guest_pcap",
    ):
        need(receipt[key] == first[key], f"Live emulator continuity differs: {key}")
    need(
        receipt["emulator_pid"] == PID
        and receipt["emulator_starttime"] == START
        and receipt["emulator_netns_inode"] == NS
        and receipt["owned_working_image_inode"] == INODE
        and receipt["deadline_utc"] == DEADLINE
        and receipt["epoch_started_utc"] == "2026-11-14T06:27:04Z"
        and receipt["managed_lock"]["busy_exit"] == 1
        and receipt["managed_lock"]["fd"] == LOCK_FD
        and receipt["managed_lock"]["unit"] == "mothra-native-expiry-c81-lease.service"
        and receipt["ns_routes"] == []
        and receipt["primary_syn_count"] == 0,
        "Post-epoch emulator, lease or deadline differs",
    )
    for label in ("host", "namespace"):
        meta = read(post / f"{label}-ready.json")
        need(
            meta == receipt["managed_capture"][label]
            and meta["deadline_utc"] == DEADLINE
            and meta["unit_properties"]["ActiveState"] == "active"
            and meta["unit_properties"]["RuntimeMaxUSec"] == "15min"
            and meta["unit_properties"]["KillMode"] == "control-group"
            and meta["header24"] == HOST_PCAP_HEADER.hex(),
            f"Post-epoch {label} capture readiness differs",
        )
    need(
        read(post / "route4.json") == read(post / "route6.json") == []
        and [link["ifname"] for link in read(post / "links.json")] == ["lo"],
        "Post-epoch namespace containment differs",
    )
    return receipt


def unit_gate(post: Path, unit: str) -> None:
    """Check that a managed unit completed successfully in the namespace.

    Parameters
    ----------
    post : Path
        The post-epoch raw directory.
    unit : str
        The name of the managed unit, which prefixes its record files.
    """
    result = (post / f"{unit}-final-unit.txt").read_text()
    journal = (post / f"{unit}-journal.log").read_text()
    required = (
        "ActiveState=active",
        "SubState=exited",
        "MainPID=0",
        "Result=success",
        "ExecMainStatus=0",
        "NetworkNamespacePath=/proc/774195/ns/net",
    )
    need(
        all(value in result for value in required) and "completed" in journal,
        f"{unit} managed completion differs",
    )
