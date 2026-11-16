"""Check that the owned units, listeners, routes, descriptors and lock were released."""

import typing as typ

from verify_classic_roster_subject_115_common import load, need

if typ.TYPE_CHECKING:
    from pathlib import Path

LOCK_PID = 492350  # the PID that held the managed oracle lock
LOCK_DEVICE = 2097  # the device number of the lock file
LOCK_INODE = 3512552451  # the inode number of the lock file
EMULATOR_POSTFLIGHT_COPIES = 2  # the emulator executable hash in both postflights


def cleanup_check(base: Path) -> dict[str, typ.Any]:
    """Check the terminal receipts that show every owned resource was released.

    Returns
    -------
    dict[str, typing.Any]
        The number of owned units stopped and the lock evidence used.
    """
    run = base / "run"
    units = (run / "units-terminal.txt").read_text()
    for unit in (
        "mothra-classic-proxy-b62.service",
        "mothra-b62-host-capture.service",
        "mothra-b62-ns-capture.service",
        "mothra-b62-oracle-lease.service",
    ):
        need(
            f"Id={unit}\nActiveState=inactive\nMainPID=0\nResult=success" in units,
            "owned service cleanup",
        )
    need(
        "15652" not in (run / "listeners-terminal.txt").read_text()
        and "15653" not in (run / "listeners-terminal.txt").read_text(),
        "proxy listener cleanup",
    )
    need(
        not (run / "ns-v4-routes-terminal.txt").read_text().strip()
        and not (run / "ns-v6-routes-terminal.txt").read_text().strip()
        and "lo" in (run / "ns-addresses-terminal.txt").read_text(),
        "isolated namespace routes",
    )
    emulator = (run / "emulators-terminal.txt").read_text()
    need(
        emulator.count(
            "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
        )
        == EMULATOR_POSTFLIGHT_COPIES,
        "emulator executable postflight",
    )
    fds = (run / "original-fds-terminal.txt").read_text()
    need(
        "/proc/1012834/fd/6" in fds
        and "/proc/1099659/fd/6" in fds
        and "/proc/1012834/fd/16" in fds
        and "/proc/1099659/fd/16" in fds,
        "original disk/PCAP FD owners",
    )
    lock = load(base / "lock-receipt.json")
    need(
        lock["pid"] == LOCK_PID
        and lock["lock_dev"] == LOCK_DEVICE
        and lock["lock_inode"] == LOCK_INODE
        and lock["proc_fd3_before"].endswith("/state/delegation/oracle.lock"),
        "managed lock identity",
    )
    need(
        lock["active_state_before"] == "active"
        and lock["independent_flock_n_before_exit"] == 1
        and lock["after_stop_state"] == "inactive"
        and lock["after_stop_main_pid"] == 0
        and lock["independent_flock_n_after_exit"] == 0,
        "managed lock busy/free",
    )
    need(
        "operator tool-output transcription" in lock["evidence_status"],
        "lock proof limitation",
    )
    journal = (run / "oracle-lease-journal.txt").read_text()
    need(
        "mothra-b62-oracle-lease.service" in journal
        and "/usr/bin/flock --exclusive --nonblock" in journal
        and "Deactivated successfully" in journal,
        "managed lock journal",
    )
    return {
        "owned_units_stopped": 4,
        "lock": "transcribed busy/free plus retained service journal",
    }
