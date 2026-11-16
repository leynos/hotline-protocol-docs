"""Gates that tie the runtime, the captures and the epoch to the pinned identity."""

import datetime as dt
import typing as typ

from verify_native_path_fields_constants import (
    BASE,
    CASE_MARGIN,
    DATA,
    DEADLINE,
    EMPTY_TEXT,
    EPOCH_MAX,
    EPOCH_MIN,
    EXE,
    GUEST_FD,
    HOST_NS,
    INODE,
    NS,
    OWNER_UID,
    PCAP_HEADER,
    PID,
    ROM,
    START,
)
from verify_native_path_fields_core import need, read

if typ.TYPE_CHECKING:
    from pathlib import Path


def _runtime(epoch: Path, plan: dict, runtime: dict, receipt: dict) -> None:
    """Check the runtime record and the capture receipt against the pinned identity."""
    need(
        runtime == plan["environment"]
        and runtime["fixture_profile"] == "control-only"
        and runtime["emulator_pid"] == receipt["emulator_pid"] == PID
        and str(runtime["emulator_starttime"])
        == str(receipt["emulator_starttime"])
        == START
        and runtime["emulator_netns_inode"] == receipt["emulator_netns_inode"] == NS
        and runtime["owned_working_image_inode"]
        == receipt["owned_working_image_inode"]
        == INODE
        and runtime["emulator_sha256"] == receipt["emulator_sha256"] == EXE
        and runtime["native_data_sha256"] == receipt["native_data_sha256"] == DATA
        and runtime["source_base_sha256"] == BASE
        and runtime["rom_sha256"] == ROM
        and receipt["deadline_utc"]
        == (epoch / "case-deadline.utc").read_text().strip()
        == DEADLINE,
        "Runtime/receipt identity differs",
    )


def _devices(disk: dict, capture: dict) -> None:
    """Check the disk and guest capture records, and the guest capture boundary."""
    for value in (disk, capture):
        need(
            value["pid"] == PID
            and str(value["start_ticks"]) == START
            and value["uid"] == OWNER_UID
            and value["netns_inode"] == NS
            and value["working_inode"] == INODE
            and value["exe_sha256"] == EXE,
            "Disk/capture identity differs",
        )
    need(
        disk["phase"] == "disk"
        and capture["phase"] == "capture"
        and capture["guest_fd"] == GUEST_FD,
        "Guest capture boundary differs",
    )


def _prepared(prep: Path) -> None:
    """Check the stopped prepared assets against the pinned digests and inode."""
    prepared = read(prep / "preflight.json")["prepared"]
    need(
        prepared["base.dsk"]["sha256"] == BASE
        and prepared["working.dsk"]["sha256"] == BASE
        and prepared["rom"]["sha256"] == ROM
        and prepared["working.dsk"]["inode"] == INODE,
        "Stopped prepared asset differs",
    )


def _margins(epoch: Path) -> None:
    """Check that the fixed epoch and the case start leave the required margins."""
    epoch_start = dt.datetime.fromisoformat(
        (epoch / "epoch-start.utc").read_text().strip()
    )
    deadline = dt.datetime.fromisoformat(DEADLINE)
    case_start = dt.datetime.fromisoformat(
        read(epoch / "coordinator/report.json")["started_at_utc"]
    )
    need(
        EPOCH_MIN <= (deadline - epoch_start).total_seconds() <= EPOCH_MAX
        and (deadline - case_start).total_seconds() >= CASE_MARGIN,
        "Fixed epoch or case margin differs",
    )


def _lease(epoch: Path, receipt: dict) -> None:
    """Check the managed source and the oracle lease held by the owned unit."""
    need(
        read(epoch / "source-freeze.json")["docs_head"] != EMPTY_TEXT
        and receipt["managed_lock"]["unit"]
        == "mothra-native-path-fields-01-lease.service",
        "Managed source/lock receipt differs",
    )
    lock = receipt["managed_lock"]
    need(
        lock["pid"] > 0
        and lock["fd"] >= 0
        and lock["lock_inode"] > 0
        and lock["busy_exit"] == 1
        and lock["unit_properties"]["MainPID"] == str(lock["pid"])
        and lock["unit_properties"]["ActiveState"] == "active",
        "Managed oracle lease proof differs",
    )


def _captures(epoch: Path, receipt: dict) -> None:
    """Check the managed capture receipts of both views and the guest capture."""
    for view, expected_ns, filename in (
        ("host", HOST_NS, "primary-syn.pcap"),
        ("namespace", NS, "lab-namespace.pcap"),
    ):
        ready = read(epoch / f"{view}-ready.json")
        managed = receipt["managed_capture"][view]
        need(
            ready == managed
            and ready["unit"] == f"mothra-native-path-fields-01-{view}.service"
            and ready["pid"] > 0
            and ready["fd"] >= 0
            and ready["netns_inode"] == expected_ns
            and ready["deadline_utc"] == DEADLINE
            and ready["capture"].endswith("/" + filename)
            and ready["header24"] == (epoch / filename).read_bytes()[:PCAP_HEADER].hex()
            and ready["unit_properties"]["ActiveState"] == "active"
            and ready["unit_properties"]["MainPID"] == str(ready["pid"]),
            f"{view} managed capture receipt differs",
        )


def identity(corpus: Path, plan: dict) -> None:
    """Gate the runtime, the captures, the prepared assets and the epoch."""
    epoch, prep = corpus / "raw/epoch", corpus / "raw/preparation"
    runtime, receipt = read(epoch / "runtime.json"), read(epoch / "capture-ready.json")
    disk, capture = (
        read(epoch / "disk-ready.json"),
        read(epoch / "guest-capture-ready.json"),
    )
    _runtime(epoch, plan, runtime, receipt)
    _devices(disk, capture)
    _prepared(prep)
    _margins(epoch)
    _lease(epoch, receipt)
    _captures(epoch, receipt)
    need(
        capture["header24"]
        == (epoch / "lab-guest.pcap").read_bytes()[:PCAP_HEADER].hex()
        and capture["guest_pcap"].endswith("/lab-guest.pcap")
        and receipt["guest_pcap"] == capture["guest_pcap"],
        "Guest capture receipt differs",
    )
