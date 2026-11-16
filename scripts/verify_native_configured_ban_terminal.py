"""Check the retired lab, the terminal oneshot and the stopped fixture bytes."""

from verify_native_configured_ban_constants import (
    ADMIN,
    BANNED,
    BANNED_BYTES,
    EMPTY_PCAP_BYTES,
    LOW,
    OWNED_USER_DATA_BYTES,
    PID,
    PREFS,
    PREFS_BYTES,
    STOPPED,
)
from verify_native_configured_ban_support import Path, need, read, sha


def terminal(corpus: Path) -> dict:
    """Check the terminal oneshot, the lab retirement and the stopped fixture bytes.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The pinned ban-list and stopped-image digests.
    """
    root = corpus / "native-configured-apply-c66"
    unit = (root / "c67-unit-retained.txt").read_text()
    need(
        all(
            item in unit
            for item in (
                "Type=oneshot",
                "User=0",
                "Group=0",
                f"NetworkNamespacePath=/proc/{PID}/ns/net",
                "TimeoutStartUSec=3min",
                "RuntimeMaxUSec=3min",
                "RemainAfterExit=yes",
                "ActiveState=active",
                "SubState=exited",
                "MainPID=0",
                "Result=success",
                "ExecMainStatus=0",
                "status=0",
                "native_configured_ban_control.py execute",
            )
        )
        and "ActiveState=inactive" in (root / "c67-unit-cleanup.txt").read_text()
        and "MainPID=0" in (root / "c67-unit-cleanup.txt").read_text(),
        "Retained terminal oneshot or cleanup differs",
    )
    done = read(root / "terminal.json")
    need(
        done["actual_lab_pid_gone"] is True
        and done["host_primary_syn_pcap_bytes"] == EMPTY_PCAP_BYTES
        and done["host_drop_count"] == done["namespace_drop_count"] == 0
        and done["display114_absent"] is True
        and done["owned_ports_absent"] is True
        and done["oracle_lease_released"] is True
        and done["originals"]["primary"]["starttime"] == "767842"
        and done["originals"]["client"]["starttime"] == "2357813",
        "Lab retirement, zero contact or original processes differ",
    )
    hashes = read(root / "stopped-files/summary.json")
    need(
        set(hashes)
        == {
            "Hotline19/Banned",
            "Hotline19/Prefs",
            "Hotline19/Users/admin/UserData",
            "Hotline19/Users/fixture-low/UserData",
            "Hotline19/Users/m-ban-apply-only/UserData",
        }
        and hashes["Hotline19/Banned"]["size"] == BANNED_BYTES
        and hashes["Hotline19/Banned"]["sha256"] == BANNED
        and hashes["Hotline19/Prefs"]["size"] == PREFS_BYTES
        and hashes["Hotline19/Prefs"]["sha256"] == PREFS
        and hashes["Hotline19/Users/admin/UserData"]["sha256"] == ADMIN
        and hashes["Hotline19/Users/fixture-low/UserData"]["sha256"] == LOW
        and hashes["Hotline19/Users/m-ban-apply-only/UserData"]["size"]
        == OWNED_USER_DATA_BYTES
        and (root / "stopped-working.sha256").read_text().split()[0] == STOPPED,
        "Stopped Banned, Prefs, UserData or image bytes differ",
    )
    for item in hashes.values():
        need(
            sha(root / "stopped-files" / item["file"]) == item["sha256"],
            "Stopped stored file bytes differ",
        )
    need(
        "Banned.bak" not in (root / "stopped-files/catalog.txt").read_text(),
        "Unexpected Banned.bak evidence",
    )
    return {
        "ban_bytes": BANNED_BYTES,
        "ban_sha256": BANNED,
        "stopped_image_sha256": STOPPED,
    }
