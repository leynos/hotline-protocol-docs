"""Check the observer, the terminal record, the cleanup and the emulator."""

import typing as typ

if typ.TYPE_CHECKING:
    from pathlib import Path

from verify_native_ui_focus_core import (
    A7_ACTIONS,
    AS_PREPARED_SHA,
    BASE_SHA,
    DOWNLOAD_BYTES,
    EMULATOR_PID,
    EXE_SHA,
    OBSERVER_SHA,
    PCAP_HEADER_BYTES,
    ROM_SHA,
    STOP_EXIT_ANOMALY,
    load,
    require,
    sha,
)


def check_observer(corpus: Path, exp: Path) -> None:
    """Check the corrected focus observer and the launch that ran it.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    exp : pathlib.Path
        The experiment directory.
    """
    prep = corpus / "preparation"
    revision = load(prep / "event-probe-revision.json")
    require(
        sha(prep / "observer-corrected.py.txt")
        == revision["corrected_sha256"]
        == OBSERVER_SHA,
        "Corrected observer differs",
    )
    require(
        sha(prep / "observer-as-prepared.py.txt")
        == revision["original_sha256"]
        == AS_PREPARED_SHA,
        "As-prepared observer differs",
    )
    corrected = (prep / "observer-corrected.py.txt").read_text(encoding="utf-8")
    old = (prep / "observer-as-prepared.py.txt").read_text(encoding="utf-8")
    require(
        old.replace(
            "XTestFakeMotionEvent(display, -1, 450, 180, 0, 0)",
            "XTestFakeMotionEvent(display, -1, 450, 180, 0)",
        )
        == corrected,
        "Observer correction scope differs",
    )
    launch = load(exp / "observer-launch.json")
    argv = launch["argv"]
    require(
        argv[16:18] == ["--a7-pid", str(load(exp / "a7-main.json")["main_pid"])],
        "Observer runner binding differs",
    )
    require(
        argv[11].endswith("/event_probe.py") and launch["exit"] == 0,
        "Corrected observer launch differs",
    )


def check_terminal(
    exp: Path,
    result: dict[str, typ.Any],
    views: dict[str, dict[str, typ.Any]],
) -> dict[str, typ.Any]:
    """Check the outcome summary and the terminal record of the lab.

    Returns
    -------
    dict[str, typing.Any]
        The terminal record.
    """
    outcome, terminal = load(exp / "outcome.json"), load(exp / "terminal.json")
    require(
        outcome["download_bytes"] == DOWNLOAD_BYTES
        and outcome["observer_status"] == result["status"]
        and outcome["event_count"] == 1,
        "Outcome summary differs",
    )
    require(
        terminal["actual_pid_gone"]
        and terminal["source_base_stat_unchanged"]
        and terminal["option_two_executed"] is False,
        "Lab retirement or option-two scope differs",
    )
    require(
        terminal["a7_status"] == "failed"
        and terminal["a7_completed_actions"] == A7_ACTIONS,
        "Terminal A7 status differs",
    )
    require(
        all(
            terminal["views"][name]["pcap_sha256"] == views[name]["pcap_sha256"]
            and terminal["views"][name]["bytes"] == DOWNLOAD_BYTES
            for name in views
        ),
        "Terminal packet proof differs",
    )
    require(
        terminal["primary_host_pcap_bytes"] == PCAP_HEADER_BYTES
        and terminal["primary_bridge_used"] is False,
        "Primary port proof differs",
    )
    return terminal


def check_cleanup(exp: Path, terminal: dict[str, typ.Any]) -> None:
    """Check that the owned process and units were retired as recorded.

    Parameters
    ----------
    exp : pathlib.Path
        The experiment directory.
    terminal : dict[str, typing.Any]
        The terminal record.
    """
    signals = load(exp / "cleanup-signals.json")
    stops = load(exp / "unit-stops.json")
    require(
        signals["pid_gone"]
        and len(signals["events"]) == 1
        and signals["events"][0]["signal"] == "TERM"
        and signals["events"][0]["exit"] == 0,
        "Owned PID cleanup differs",
    )
    require(
        "stop exit5" in terminal["cleanup_note"]
        and any(
            x["unit"].startswith("mothra-sheep-") and x["exit"] == STOP_EXIT_ANOMALY
            for x in stops["results"]
        ),
        "Cleanup anomaly lost",
    )
    require(
        all("MainPID=0" in state for state in terminal["units"].values()),
        "Owned unit remains active",
    )


def check_emulator(boot: Path, terminal: dict[str, typ.Any]) -> dict[str, typ.Any]:
    """Check the boot observer, the emulator identity and the lab isolation.

    Returns
    -------
    dict[str, typing.Any]
        The emulator identity record.
    """
    ready = load(boot / "readiness.json")
    identity = load(boot / "identity.json")
    require(
        ready["observer_sha256"] == OBSERVER_SHA and ready["no_frontend_contact"],
        "Boot observer identity differs",
    )
    require(
        ready["gui"]["sha256"] == sha(boot / "server-ready-initial.png")
        and ready["gui"]["log_title_gold_pixels"] == 0,
        "Boot GUI state differs",
    )
    require(
        identity["pid"] == ready["actual_emulator"]["pid"] == EMULATOR_PID
        and identity["starttime"] == "4261101"
        and identity["exe_sha256"] == EXE_SHA,
        "Emulator identity differs",
    )
    require(
        identity["netns"] == "net:[4026532615]"
        and identity["routes"] == ""  # pylint: disable=use-implicit-booleaness-not-comparison-to-string  # routes is compared, not tested for truth: a non-string value must still fail
        and "127.0.0.1/8" in identity["addr"],
        "Lab route isolation differs",
    )
    require(
        identity["fd6"].endswith("native-eventlab-one-01/working.dsk")
        and identity["fd16"].endswith("native-eventlab-c49/lab-guest.pcap"),
        "Owned emulator FDs differ",
    )
    require(
        ready["original"]["primary"]["netns"] != identity["netns"]
        and ready["original"]["client"]["netns"] != identity["netns"],
        "Lab peer isolation differs",
    )
    require(
        terminal["peers"] == ready["original"]
        and terminal["actual_pid"] == identity["pid"],
        "Primary or client identity changed",
    )
    require(
        all(
            "0 packets dropped by kernel" in "\n".join(lines)
            for lines in terminal["recorder_logs"].values()
        ),
        "Terminal recorder drops unknown",
    )
    return identity


def check_runtime(corpus: Path, exp: Path, identity: dict[str, typ.Any]) -> None:
    """Check the preflight, the emulator build, the assets and the disk copy.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    exp : pathlib.Path
        The experiment directory.
    identity : dict[str, typing.Any]
        The emulator identity record.
    """
    preflight = load(exp / "preflight.json")
    require(
        preflight["observer_sha256"] == OBSERVER_SHA
        and preflight["emulator_pid"] == identity["pid"]
        and preflight["starttime"] == identity["starttime"],
        "Experiment identity differs",
    )
    manifest = load(corpus / "runtime/build-manifest.json")
    require(manifest["binary_sha256"] == EXE_SHA, "Emulator build differs")
    assets = load(corpus / "runtime/assets.json")
    require(
        assets["base_disk_sha256"] == BASE_SHA and assets["rom_sha256"] == ROM_SHA,
        "Base or ROM differs",
    )
    prepared = load(corpus / "preparation" / "postflight.json")
    require(
        prepared["source_unchanged"]
        and prepared["target"]["base.dsk"]["sha256"] == BASE_SHA
        and prepared["target"]["working.dsk"]["sha256"] == BASE_SHA
        and prepared["target"]["rom"]["sha256"] == ROM_SHA,
        "Prepared source differs",
    )
    require(
        prepared["target"]["base.dsk"]["inode"]
        != prepared["source_after"]["base.dsk"]["inode"],
        "Owned disk copy differs",
    )
    prefs = (corpus / "runtime/prefs.txt").read_text(encoding="utf-8")
    require("ramsize 536870912" in prefs, "RAM configuration differs")
