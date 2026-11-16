"""Check the terminal state and the persisted ban of the isolated control witness."""

import typing as typ

from protocol_capture import verify_capture
from verify_native_ban_control_core import (
    EXPECTED,
    PCAP_HEADER_BYTES,
    PID,
    Json,
    digest,
    loaded,
    need,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

NO_DROPS = "0 packets dropped by kernel"
UNITS = 7  # the lab's managed units, all stopped at the end
BAN_CATALOG = 11771  # the catalog record of the Banned file
BAN_BYTES = 49  # the persisted ban list: one permanent record
FAILED_BASELINES = ("c35", "c45", "c50")
FAILED_ACTIONS = 21  # the full-file baselines stopped at their 22nd action
PARTIAL_DOWNLOAD_BYTES = 98_304  # what each failed download received before timing out
TIMEOUT = "TimeoutError: timed out"


def terminal_profile(result: Json) -> None:
    """Check the terminal record's profile and the emulator's retirement.

    Parameters
    ----------
    result : dict[str, typing.Any]
        The terminal record.
    """
    need(
        result["profile"] == "control-only"
        and result["full_file_baseline"] == "not_exercised"
        and result["actual_emulator_pid"] == PID
        and result["actual_pid_gone"] is True,
        "Terminal profile differs",
    )


def capture_proof(result: Json) -> None:
    """Check the capture tails and the images of the original lab.

    Parameters
    ----------
    result : dict[str, typing.Any]
        The terminal record.
    """
    need(
        result["pcap"]["primary_syn_bytes"] == PCAP_HEADER_BYTES
        and result["pcap"]["host_terminal_log_tail"][-1] == NO_DROPS
        and result["pcap"]["namespace_terminal_log_tail"][-1] == NO_DROPS
        and result["original"]["primary_fd6"]["stdout"]
        .strip()
        .endswith("hotline22-recovery/working.dsk")
        and result["original"]["client_fd6"]["stdout"]
        .strip()
        .endswith("hotline-client-isolated-01/working.dsk"),
        "Terminal original or capture proof differs",
    )


def lab_cleanup(base: Path, result: Json) -> None:
    """Check that every unit stopped, the emulator is gone and nothing was retried.

    Parameters
    ----------
    base : pathlib.Path
        The ``case-c56`` directory.
    result : dict[str, typing.Any]
        The terminal record.
    """
    need(
        len(result["units"]) == UNITS
        and all(
            "ActiveState=inactive" in item["stdout"] and "MainPID=0" in item["stdout"]
            for item in result["units"].values()
        )
        and loaded(base / "cleanup-signals.json")["pid_gone"] is True
        and result["no_case_retry"] is True
        and result["no_restart_unban_or_full_A7"] is True,
        "Lab cleanup or no-retry proof differs",
    )


def persisted_ban(base: Path, result: Json) -> Path:
    """Check the persisted ban file and the stopped image that holds it.

    Parameters
    ----------
    base : pathlib.Path
        The ``case-c56`` directory.
    result : dict[str, typing.Any]
        The terminal record.

    Returns
    -------
    pathlib.Path
        The retained bytes of the ban file.
    """
    raw = base / "Banned.data.bin"
    ban = result["ban_file"]
    need(
        ban["catalog"] == BAN_CATALOG
        and ban["path"] == "/Hotline19/Banned"
        and ban["data_bytes"] == raw.stat().st_size == BAN_BYTES
        and ban["data_sha256"] == digest(raw) == EXPECTED["banned"]
        and ban["resource_bytes"] == 0
        and ban["bak_absent"] is True
        and f"Catalog Record: {BAN_CATALOG}" in (base / "Banned.stat.txt").read_text()
        and "Resource fork size:\t0" in (base / "Banned.stat.txt").read_text()
        and result["stopped_image_sha256"] == EXPECTED["stopped"]
        and (base / "stopped-image.sha256").read_text().split()[0]
        == EXPECTED["stopped"]
        and result["image_fd_free_before_hash"] is True,
        "Stopped persisted ban bytes or image proof differs",
    )
    return raw


def terminal(corpus: Path) -> Json:
    """Check the terminal record, the lab's cleanup and the persisted ban.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The size and digest of the persisted ban bytes.
    """
    base = corpus / "case-c56"
    result = loaded(base / "terminal.json")
    terminal_profile(result)
    capture_proof(result)
    lab_cleanup(base, result)
    raw = persisted_ban(base, result)
    return {"ban_bytes": raw.stat().st_size, "ban_sha256": digest(raw)}


def failed_full_baselines(corpus: Path) -> None:
    """Check the three full-file baselines that failed, as retained.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    for label in FAILED_BASELINES:
        base = corpus / "failed-full-A7" / label
        report = verify_capture(base / "a7-capture")
        need(
            report["status"] == "failed"
            and report["completed_actions"] == FAILED_ACTIONS
            and report["error"] == TIMEOUT
            and len(bytes.fromhex(report["streams"]["download"]["received_hex"]))
            == PARTIAL_DOWNLOAD_BYTES
            and digest(base / "a7-capture/plan.json")
            == digest(base / "a7-as-run-plan.json"),
            f"{label} failed full-file baseline differs",
        )
        if (base / "a7-original-plan.json").exists():
            need(
                digest(base / "a7-original-plan.json") == EXPECTED["source_a7"],
                f"{label} original A7 source differs",
            )
