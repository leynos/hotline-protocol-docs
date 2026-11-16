"""Check the stopped preparation, the emulator identity and the capture receipts.

The identity is the one that the retained runtime recorded: the process, its
image, its network namespace, the capture recorders and the managed lease.
"""

import datetime as dt
import typing as typ

from verify_native_board_checks import Report, need, read, utc
from verify_native_board_pins import (
    BASE,
    DATA,
    DEADLINE,
    EXE,
    INODE,
    NS,
    PID,
    ROM,
    START,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

ACTIVE_ACCOUNTS = 2  # the two accounts that the stopped preparation keeps active
LOCK_FD = 3  # the file descriptor of the managed oracle lease
PCAP_HEADER_BYTES = 24  # the header of a capture that holds no packet
EPOCH_MINUTES = 12  # the length of the fixed epoch that ends at the deadline


def identity(corpus: Path) -> Report:
    """Check the preparation, the runtime identity, the recorders and the lease.

    Returns
    -------
    dict[str, typing.Any]
        The capture receipt that the checks read.
    """
    raw = corpus / "raw"
    prep = read(corpus / "preparation/preflight.json")
    proof = read(raw / "actual-emulator-proof.json")
    runtime = read(raw / "runtime.json")
    receipt = read(raw / "capture-ready.json")
    need(
        prep["status"] == "prepared_stopped"
        and prep["prepared"]["base.dsk"]["sha256"] == BASE
        and prep["prepared"]["working.dsk"]["sha256"] == BASE
        and prep["prepared"]["working.dsk"]["inode"] == INODE
        and prep["prepared"]["rom"]["sha256"] == ROM
        and prep["source_before"]["base"] == prep["source_after"]["base"]
        and prep["source_before"]["rom"] == prep["source_after"]["rom"]
        and prep["catalog"]["banned_absent"]
        and len(prep["catalog"]["active_users"]) == ACTIVE_ACCOUNTS,
        "Stopped preparation, immutable source or accounts differ",
    )
    need(
        (proof["pid"], proof["starttime"], proof["netns"], proof["working_image_inode"])
        == (PID, START, NS, INODE)
        and proof["exe_sha256"] == EXE
        and proof["fd6"] == runtime["owned_working_image"]
        and proof["fd16"] == receipt["guest_pcap"]
        and receipt["emulator_pid"] == runtime["emulator_pid"] == PID
        and receipt["emulator_starttime"] == runtime["emulator_starttime"] == START
        and receipt["emulator_netns"] == runtime["emulator_netns"] == NS
        and receipt["emulator_sha256"] == runtime["emulator_sha256"] == EXE
        and receipt["owned_working_image_inode"] == INODE
        and receipt["source_base_sha256"] == BASE
        and receipt["rom_sha256"] == ROM
        and receipt["native_data_sha256"] == DATA
        and receipt["fixture_profile"] == "control-only"
        and receipt["full_file_baseline"] == "not_exercised"
        and receipt["deadline_utc"] == DEADLINE
        and receipt["ns_routes"] == []
        and receipt["primary_syn_count"] == 0
        and all(runtime[key] == receipt[key] for key in runtime),
        "Actual emulator, capture receipt or profile differs",
    )
    for name, inode in (("host", 4026531840), ("namespace", 4026532471)):
        ready = read(raw / f"{name}-ready.json")
        meta = receipt["managed_capture"][name]
        need(
            ready == meta
            and ready["netns_inode"] == inode
            and ready["header24"].startswith("d4c3b2a1")
            and ready["pid"] == receipt[f"{name}_recorder_pid"]
            and ready["start_ticks"] == receipt[f"{name}_recorder_starttime"]
            and ready["unit_properties"]["ActiveState"] == "active"
            and ready["unit_properties"]["MainPID"] == str(ready["pid"])
            and ready["unit_properties"]["RuntimeMaxUSec"] == "15min"
            and ready["deadline_utc"] == DEADLINE,
            f"Managed {name} recorder differs",
        )
    lock = receipt["managed_lock"]
    need(
        lock["unit"] == "mothra-native-board02-c100-lease.service"
        and lock["busy_exit"] == 1
        and lock["fd"] == LOCK_FD
        and lock["lock_inode"] > 0
        and lock["unit_properties"]["MainPID"] == str(lock["pid"])
        and lock["unit_properties"]["ActiveState"] == "active"
        and (raw / "lock-free.exit").read_text().strip() == "0",
        "Managed oracle lease or release differs",
    )
    need(
        utc(receipt["epoch_started_utc"]) + dt.timedelta(minutes=EPOCH_MINUTES)
        == utc(DEADLINE)
        and utc(receipt["utc"]) < utc(DEADLINE)
        and (raw / "primary-syn.pcap").stat().st_size == PCAP_HEADER_BYTES,
        "Fixed twelve-minute epoch or primary capture differs",
    )
    return receipt
