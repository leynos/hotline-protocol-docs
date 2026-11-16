"""Check the retirement of the emulator, the stopped forks, the units and the lock."""

import datetime as dt
import typing as typ

from verify_native_roster_overlap_common import DEADLINE, NO_TEXT, need, read

if typ.TYPE_CHECKING:
    from pathlib import Path

# The shell status of a command that was not found.
NOT_FOUND_EXIT = 127
# The recorder units, each of which reports its own packet counts.
RECORDER_UNITS = 2
# The size of the pcap global header, which is the whole primary SYN capture.
PCAP_HEADER_BYTES = 24


def _check_forks(forks: dict[str, typ.Any], prep: dict[str, typ.Any]) -> None:
    """Check that each stopped named fork exited cleanly and matches the preflight.

    Parameters
    ----------
    forks : dict[str, typing.Any]
        The parsed ``raw/stopped-forks-corrected.json``.
    prep : dict[str, typing.Any]
        The parsed ``preparation/preflight.json``.
    """
    need(
        forks["stopped_pid_absent"]
        and all(
            item["exit"] == 0
            and item["matches_preflight"]
            and item["sha256"] == prep["files"][name]["sha256"]
            for name, item in forks["files"].items()
        )
        and set(forks["files"]) == set(prep["files"]),
        "Stopped named forks differ",
    )


def _check_assets(raw: Path) -> None:
    """Check the retained initial tool failure and the stopped assets.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw`` directory of the corpus.
    """
    first = read(raw / "stopped-forks-and-assets.json")
    need(
        all(item["exit"] == NOT_FOUND_EXIT for item in first["files"].values())
        and first["base.dsk"]["matches_preflight"]
        and first["rom"]["matches_preflight"]
        and not first["working.dsk"]["matches_preflight"],
        "Retained initial TSK tool failure or stopped assets differ",
    )


def _check_units(raw: Path) -> None:
    """Check that the owned system and user units are retired.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw`` directory of the corpus.
    """
    system = (raw / "terminal-system-units.txt").read_text()
    user = (raw / "terminal-user-units.txt").read_text()
    need(
        "mothra-native-roster-c86-host.service\nActiveState=inactive" in system
        and "mothra-native-roster-c86-namespace.service\nActiveState=inactive" in system
        and "mothra-native-roster-c86-lease.service\nActiveState=inactive" in system
        and "NetworkNamespacePath=/proc/953125/ns/net" in system
        and "mothra-sheep-ee4b4d810c5b.service\nActiveState=inactive" in user
        and "mothra-display-ed0dd3f6ab3e.service\nActiveState=inactive" in user,
        "Owned unit retirement differs",
    )


def _check_journal(raw: Path) -> None:
    """Check the recorder journal for drops and the packet count.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw`` directory of the corpus.
    """
    journal = (raw / "c86-recorder-journal.log").read_text()
    need(
        journal.count("0 packets dropped by kernel") == RECORDER_UNITS
        and "0 packets captured" in journal
        and "114 packets captured" in journal,
        "Capture drop or packet count differs",
    )


def _check_exits(raw: Path) -> None:
    """Check the managed case and postflight exit records.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw`` directory of the corpus.
    """
    need(
        (raw / "c87-run.exit").read_text().strip() == "0"
        and (raw / "c88-postflight.exit").read_text().strip() == "0"
        and "ExecMainStatus=0" in (raw / "c87-unit-final.txt").read_text()
        and "ExecMainStatus=0" in (raw / "c88-unit-final.txt").read_text(),
        "Managed case/postflight result differs",
    )


def _check_deadline(forks: dict[str, typ.Any]) -> None:
    """Check that the stopped-fork record was made before the fixed deadline.

    Parameters
    ----------
    forks : dict[str, typing.Any]
        The parsed ``raw/stopped-forks-corrected.json``.
    """
    need(
        dt.datetime.fromisoformat(forks["recorded_at_utc"])
        < dt.datetime.fromisoformat(DEADLINE),
        "Stopped-fork check exceeded fixed deadline",
    )


def _check_lock(raw: Path) -> None:
    """Check the post-retirement process, ports, image descriptor and lock.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw`` directory of the corpus.
    """
    final = read(raw / "terminal-network-lock.json")
    need(
        final["emulator_953125_absent"]
        and final["original_start_ticks"] == {"1099659": "767842", "1012834": "2357813"}
        and final["ss_exit"] == 0
        and final["listeners_ss"].splitlines()
        == ["State Recv-Q Send-Q Local Address:Port Peer Address:Port"]
        and final["image_fuser_stdout"] == NO_TEXT
        and final["image_fuser_exit"] == 1
        and final["lock_exit"] == 0
        and final["primary_syn_pcap_bytes"] == PCAP_HEADER_BYTES,
        "Post-retirement process, ports, image FD or lock differs",
    )


def terminal(corpus: Path) -> None:
    """Check the retirement of the emulator and the terminal state of the run.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    raw = corpus / "raw"
    forks = read(raw / "stopped-forks-corrected.json")
    prep = read(corpus / "preparation/preflight.json")
    _check_forks(forks, prep)
    _check_assets(raw)
    _check_units(raw)
    _check_journal(raw)
    _check_exits(raw)
    _check_deadline(forks)
    _check_lock(raw)
