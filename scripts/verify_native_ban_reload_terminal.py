"""Check the retirement of the reload witness and its original processes."""

import typing as typ

from verify_native_ban_reload_core import (
    BAN,
    IMAGE_AFTER,
    MANAGED_UNITS,
    NS,
    PID,
    START,
    read,
    require,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]


def terminal(corpus: Path, ready: Report) -> None:
    """Check the terminal profile, the forced retirement and the original processes.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    ready : dict[str, typing.Any]
        The parsed ``ui-ready.json``, which holds the original identities.
    """
    root = corpus / "c61"
    t = read(root / "terminal.json")
    signals = read(root / "cleanup-signals.json")
    require(
        t["profile"] == "persisted-ban-reload-readonly"
        and t["full_file_baseline"] == "not_exercised"
        and t["actual_emulator_pid"] == PID
        and t["actual_pid_gone"] is True
        and t["server_quit_normal"] is True
        and t["guest_emulator_forced_term"] is True
        and t["working_fd_holders"] == []
        and t["stopped_image_sha256"] == IMAGE_AFTER
        and t["Banned"] == {"bytes": 49, "sha256": BAN}
        and t["owned_ports_absent"] is True
        and t["probe_reruns"] == 0
        and t["account_or_ban_mutations"] is False,
        "Terminal profile, forced retirement or ban bytes differ",
    )
    require(
        signals["pid_gone"] is True
        and signals["observed"]["starttime"] == START
        and signals["observed"]["netns"] == NS
        and [e["action"] for e in signals["events"]] == ["TERM"]
        and len(t["units"]) == MANAGED_UNITS
        and all(
            "ActiveState=inactive" in v and "MainPID=0" in v
            for v in t["units"].values()
        )
        and all(
            "0 packets dropped by kernel" in v[-1]
            for v in (t["host_recorder_log_tail"], t["namespace_recorder_log_tail"])
        ),
        "Cleanup PID, managed units or packet drops differ",
    )
    for label, pid, start in (
        ("primary", 1099659, "767842"),
        ("client", 1012834, "2357813"),
    ):
        original = t["original"][label]
        require(
            original["pid"] == pid
            and original["starttime"] == start
            and original["fd6"] == ready["original"][label]["fd6"]
            and original["fd16"] == ready["original"][label]["fd16"],
            f"Original {label} identity changed",
        )
