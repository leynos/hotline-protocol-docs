"""Check the packet recorders that observed the Classic field-162 runs."""

import typing as typ

from verify_classic_server_name_162_common import PCAP_HEADER_HEX, load, require

if typ.TYPE_CHECKING:
    from pathlib import Path

HOST_INODE = 4026531840
NAMESPACE_INODE = 4026532479
CAPTURE_FD = 5  # the descriptor each recorder must hold
READY_PHASES = ("launch", "before-a7", "before-connect")
B56_PIDS = {"host": 88855, "ns": 88897}
B57_PIDS = {"host": 231986, "ns": 232035}
B56_DEADLINE = "2026-11-14T03:26:00+00:00"
B57_DEADLINE = "2026-11-14T03:33:30+00:00"


def check_readiness(
    directory: Path, label: str, recorder: tuple[str, int, int]
) -> None:
    """Check the three readiness receipts of one recorder and their identity."""
    kind, inode, pid = recorder
    unit = f"mothra-{label}-{kind}-capture.service"
    deadline = B56_DEADLINE if label == "b56" else B57_DEADLINE
    starts = set()
    fd_ids = set()
    for phase in READY_PHASES:
        receipt = load(directory / f"{kind}-ready-{phase}.json")
        props = receipt["unit_properties"]
        require(
            receipt["unit"] == unit
            and receipt["pid"] == pid
            and receipt["netns_inode"] == inode
            and receipt["fd"] == CAPTURE_FD
            and receipt["deadline_utc"] == deadline
            and receipt["header24"] == PCAP_HEADER_HEX
            and props["MainPID"] == str(pid)
            and props["ActiveState"] == "active"
            and props["SubState"] == "running"
            and props["RuntimeMaxUSec"] == "15min"
            and props["KillMode"] == "control-group",
            f"{label} {kind} recorder readiness",
        )
        starts.add(receipt["start_ticks"])
        fd_ids.add((receipt["dev"], receipt["inode"]))
    require(len(starts) == len(fd_ids) == 1, f"{label} {kind} recorder identity drift")


def check_journal(directory: Path, label: str, recorder: tuple[str, int, int]) -> None:
    """Check that one recorder kept its packets and dropped none."""
    kind, _, pid = recorder
    unit = f"mothra-{label}-{kind}-capture.service"
    journal_name = (
        f"{unit.removesuffix('.service')}-journal.txt"
        if label == "b57"
        else f"{kind}-recorder-journal.txt"
    )
    journal = (directory / journal_name).read_text()
    require(
        f"tcpdump[{pid}]" in journal
        and "packets captured" in journal
        and "0 packets dropped by kernel" in journal,
        f"{label} {kind} recorder drops/ownership",
    )


def check_capture(
    base: Path, label: str, manifest: dict[str, typ.Any]
) -> dict[str, typ.Any]:
    """Check the host and namespace recorders of one run and their cleanup.

    Returns
    -------
    dict[str, typing.Any]
        The recorder process IDs and the packets the kernel dropped.
    """
    directory = base / label
    pids = B56_PIDS if label == "b56" else B57_PIDS
    for recorder in (
        ("host", HOST_INODE, pids["host"]),
        ("ns", NAMESPACE_INODE, pids["ns"]),
    ):
        check_readiness(directory, label, recorder)
        check_journal(directory, label, recorder)
    units = (directory / "units-terminal.txt").read_text()
    for kind in ("host", "ns"):
        require(
            f"Id=mothra-{label}-{kind}-capture.service\nActiveState=inactive\nMainPID=0\nResult=success"
            in units,
            f"{label} {kind} recorder cleanup",
        )
    require(
        manifest["capture_gate_sha256"]
        == "7a75f4b78f1255f4486ced44fc5fb8882d6008c7de6844a82f4c107e7299d678",
        "capture gate source identity",
    )
    return {"recorder_pids": [pids["host"], pids["ns"]], "drops": 0}
