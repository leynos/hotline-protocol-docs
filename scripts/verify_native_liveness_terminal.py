"""Check the retired processes, the owned units, the recorders and the exit codes."""

import typing as typ

from verify_native_liveness_checks import Report, need, read, utc
from verify_native_liveness_pins import DEADLINE

if typ.TYPE_CHECKING:
    from pathlib import Path

PCAP_HEADER_BYTES = 24  # the size of a capture file that holds no packet
EMPTY_TEXT = ""  # the recorded text of a command that printed nothing
DROP_REPORTS = 2  # the recorder journals, each reporting its own drops
ORIGINAL_TICKS = {"1099659": "767842", "1012834": "2357813"}
RETIRED_UNITS = (
    "mothra-native-liveness-c92-lease.service",
    "mothra-native-liveness-c92-host.service",
    "mothra-native-liveness-c92-namespace.service",
    "mothra-native-liveness-c92-readiness.service",
    "mothra-native-liveness-c93-case.service",
    "mothra-native-liveness-c93-postflight.service",
)
RETIRED_USER_UNITS = (
    "mothra-sheep-b2ee689a7fcc.service",
    "mothra-bridge-72798e9e3497.service",
    "mothra-xbridge-72798e9e3497.service",
    "mothra-display-25fab252cbac.service",
)


def _check_receipt(receipt: Report) -> None:
    """Check the terminal receipt of the retired emulator.

    Parameters
    ----------
    receipt : dict[str, typing.Any]
        The terminal receipt.
    """
    need(
        receipt["actual_emulator_gone"]
        and receipt["original_ticks"] == ORIGINAL_TICKS
        and receipt["port_exit"] == 0
        and receipt["ports_ss"].splitlines()
        == ["State Recv-Q Send-Q Local Address:Port Peer Address:Port"]
        and receipt["lock_exit"] == 0
        and receipt["fuser_exit"] == 1
        and receipt["fuser_stdout"] == EMPTY_TEXT
        and receipt["primary_pcap_size"] == PCAP_HEADER_BYTES
        and "Mac OS not shut down orderly" in receipt["retirement_kind"]
        and utc(receipt["recorded_at_utc"]) < utc(DEADLINE),
        "Retired process, original services, ports, lock or deadline differ",
    )


def _check_forks(stopped: Report, preflight: Report) -> None:
    """Check the bytes of the stopped named forks against the preflight.

    Parameters
    ----------
    stopped : dict[str, typing.Any]
        The stopped-forks record.
    preflight : dict[str, typing.Any]
        The HFS preflight record.
    """
    need(
        stopped["stopped_pid_gone"]
        and stopped["fd_free"]
        and set(stopped["files"]) == set(preflight["files"])
        and all(
            item["exit"] == 0
            and item["matches_preflight"]
            and item["sha256"] == preflight["files"][name]["sha256"]
            for name, item in stopped["files"].items()
        ),
        "Stopped named fork bytes differ",
    )


def _check_units(raw: Path) -> None:
    """Check that every owned system and user unit is inactive.

    Parameters
    ----------
    raw : pathlib.Path
        The raw evidence directory.
    """
    system = (raw / "terminal-system-units.txt").read_text()
    user = (raw / "terminal-user-units.txt").read_text()
    need(
        all(f"{unit}\nActiveState=inactive" in system for unit in RETIRED_UNITS)
        and all(f"{unit}\nActiveState=inactive" in user for unit in RETIRED_USER_UNITS),
        "Owned unit retirement differs",
    )


def _check_journal(raw: Path) -> None:
    """Check the recorder journal for kernel drops and the packet counts.

    Parameters
    ----------
    raw : pathlib.Path
        The raw evidence directory.
    """
    journal = (raw / "c92-recorder-terminal-journal.log").read_text()
    need(
        journal.count("0 packets dropped by kernel") == DROP_REPORTS
        and "0 packets captured" in journal
        and "269 packets captured" in journal,
        "Recorder drops or packet counts differ",
    )


def _check_exits(raw: Path) -> None:
    """Check the exit codes of the readiness, the case and the postflight.

    Parameters
    ----------
    raw : pathlib.Path
        The raw evidence directory.
    """
    need(
        (raw / "readiness.exit").read_text().strip() == "0"
        and (raw / "c93-run.exit").read_text().strip() == "0"
        and (raw / "postflight.exit").read_text().strip() == "0"
        and "ExecMainStatus=0" in (raw / "c93-unit-final.txt").read_text()
        and "semantic postflight PASS"
        in (raw / "c93-postflight-journal.log").read_text(),
        "Managed case, preflight or postflight exit differs",
    )


def terminal(corpus: Path) -> None:
    """Check the terminal evidence of the retired emulator and the managed units.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    raw = corpus / "raw"
    receipt = read(raw / "terminal.json")
    stopped = read(raw / "stopped-forks.json")
    preflight = read(corpus / "preparation/hfs-preflight.json")
    _check_receipt(receipt)
    _check_forks(stopped, preflight)
    _check_units(raw)
    _check_journal(raw)
    _check_exits(raw)
