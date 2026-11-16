"""Check the retained case: its captures, its replies, its timing and its requests."""

import datetime as dt
import typing as typ

import native_configured_ban_control as control
import native_control_readiness as base
from protocol_capture import decode_frame, verify_capture
from verify_native_configured_ban_constants import (
    EXE,
    FORBIDDEN_TYPES,
    GATE_ACTION,
    MAX_SAVE_RETURN_SECONDS,
    MAX_TRIGGER_SECONDS,
    MIN_REQUEST_HEX_CHARS,
    NOTICE_ACTIONS,
    NS,
    PHASES,
    PID,
    SAVE_ACTION,
    START,
)
from verify_native_configured_ban_support import Path, instant, need, read, sha


def case(corpus: Path, ready: dict) -> dict[str, dict]:
    """Check the retained case and return the verified report of each phase.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    ready : dict[str, typing.Any]
        The readiness record of the boot.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        The verified report of each source-plan phase.
    """
    root = corpus / "native-configured-apply-c66"
    _check_capture_identity(root, ready)
    hashes = read(root / "plans-asrun/source-hashes.json")
    need(set(hashes) == set(PHASES), "Actual plan inventory differs")
    reports = _read_phase_reports(root, hashes)
    base.readiness(reports["readiness"])
    control.account_gate(reports["guard"], absent=True)
    control.account_gate(reports["seed"], absent=False)
    _check_held(root, reports, hashes)
    return reports


def _check_capture_identity(root: Path, ready: dict[str, typ.Any]) -> None:
    """Check that the case capture names the lab emulator and its recorders.

    Parameters
    ----------
    root : pathlib.Path
        The retained case directory.
    ready : dict[str, typing.Any]
        The readiness record of the boot.
    """
    capture = read(root / "capture-ready.json")
    need(
        capture["emulator_pid"] == PID
        and capture["emulator_starttime"] == START
        and capture["emulator_netns"] == NS
        and capture["emulator_sha256"] == EXE
        and capture["owned_working_image"].endswith(
            "native-configured-apply-01/working.dsk"
        )
        and capture["host_recorder_pid"] == ready["capture_pids"]["host"]
        and capture["namespace_recorder_pid"] == ready["capture_pids"]["namespace"]
        and capture["ns_routes"] == []
        and capture["primary_syn_count"] == 0,
        "Actual case capture identity differs",
    )


def _read_phase_reports(
    root: Path, hashes: dict[str, typ.Any]
) -> dict[str, dict[str, typ.Any]]:
    """Check the source plan and the capture of each phase, and verify each capture.

    Parameters
    ----------
    root : pathlib.Path
        The retained case directory.
    hashes : dict[str, typing.Any]
        The retained digest of each source plan.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        The verified report of each source-plan phase.
    """
    reports = {}
    for phase, actions in PHASES.items():
        path = root / "plans-asrun" / f"{phase}.json"
        plan = read(path)
        need(
            sha(path) == hashes[phase]
            and plan["environment"]["emulator_pid"] == PID
            and plan["environment"]["emulator_starttime"] == START
            and plan["environment"]["source_a7_sha256"]
            == "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"
            and plan["environment"]["fixture_profile"] == "control-only"
            and plan["environment"]["full_file_baseline"] == "not_exercised"
            and plan["endpoints"] == {"control": {"host": "127.0.0.1", "port": 15770}}
            and len(plan["steps"]) == actions
            and sha(root / "captures" / phase / "plan.json") == hashes[phase],
            f"{phase} source plan identity or profile differs",
        )
        report = verify_capture(root / "captures" / phase)
        need(
            report["status"] == "completed"
            and report["completed_actions"] == actions
            and report.get("controller_uid", 0) == 0,
            f"{phase} capture incomplete or not root",
        )
        reports[phase] = report
    return reports


def _check_held(
    root: Path,
    reports: dict[str, dict[str, typ.Any]],
    hashes: dict[str, typ.Any],
) -> None:
    """Check the held-apply gate, its outcome and the reviewed Save trigger.

    Parameters
    ----------
    root : pathlib.Path
        The retained case directory.
    reports : dict[str, dict[str, typing.Any]]
        The verified report of each source-plan phase.
    hashes : dict[str, typing.Any]
        The retained digest of each source plan.
    """
    held = reports["held-apply"]
    gate = read(root / "captures/held-apply/held-ready.json")
    need(
        gate
        == {
            "source_plan_sha256": hashes["held-apply"],
            "completed_actions": 17,
            "target_uid_hex": "0005",
            "controller_uid": 0,
        }
        and control.identity_gate(held["frames"]) == b"\0\5",
        "Held current target UID, access or roster differs",
    )
    control.outcome(held, read(root / "plans-asrun/held-apply.json"))
    need(
        (root / "reviewed-save.trigger").read_bytes() == b"reviewed-save\n",
        "Reviewed Save trigger bytes differ",
    )
    _check_requests(reports)


def _check_requests(reports: dict[str, dict[str, typ.Any]]) -> None:
    """Check that no sent request is one the fixture forbids.

    Parameters
    ----------
    reports : dict[str, dict[str, typing.Any]]
        The verified report of each source-plan phase.
    """
    requests = [
        decode_frame(bytes.fromhex(e["hex"]))
        for report in reports.values()
        for e in report["events"]
        if e["event"] == "send"
        and len(e["hex"]) >= MIN_REQUEST_HEX_CHARS
        and not e["hex"].startswith("54525450")
    ]
    need(
        not any(f["type"] in FORBIDDEN_TYPES for f in requests),
        "Forbidden ban request or full-file operation observed",
    )


def timeline(corpus: Path, reports: dict[str, dict]) -> None:
    """Check the order and the timing of the held case and its screenshots.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    reports : dict[str, dict[str, typing.Any]]
        The verified report of each source-plan phase.
    """
    root = corpus / "native-configured-apply-c66"
    save_return = _check_save_timing(root, reports["held-apply"])
    deadline = dt.datetime.fromisoformat(
        read(root / "deadline.json")["fixed_deadline_utc"]
    )
    need(
        save_return < instant(root / "server-quit.utc") < deadline,
        "Global case deadline or retirement order differs",
    )
    need(
        sha(root / "after-one-add.png")
        == "630fdd66396cb7a9774ff8864de7256e8d133001b222e91e1cd43ed3e5d6acee"
        and sha(root / "held-ip-before-add.png")
        == "b22f350ac4a3b47b57ddf699ea662287553561ebd75cd4c56ded25eb49bc6522",
        "Checked row or pre-Add UI screenshot differs",
    )


def _check_save_timing(root: Path, held: dict[str, typ.Any]) -> dt.datetime:
    """Check that the Add click, the reviewed Save and the first notice are in order.

    Parameters
    ----------
    root : pathlib.Path
        The retained case directory.
    held : dict[str, typing.Any]
        The verified report of the held-apply phase.

    Returns
    -------
    datetime.datetime
        The instant at which the Save click returned.
    """
    started = dt.datetime.fromisoformat(held["started_at_utc"])
    last_gate = max(
        started + dt.timedelta(microseconds=e["elapsed_ns"] // 1000)
        for e in held["events"]
        if e["action"] == GATE_ACTION
    )
    first_notice = min(
        started + dt.timedelta(microseconds=e["elapsed_ns"] // 1000)
        for e in held["events"]
        if e["action"] in NOTICE_ACTIONS and e["event"] == "receive"
    )
    add, trigger, save_return = (
        instant(root / name)
        for name in ("add-click.utc", "save-trigger.utc", "save-click-return.utc")
    )
    need(
        last_gate < add < trigger < first_notice < save_return
        and 0 < (trigger - add).total_seconds() < MAX_TRIGGER_SECONDS
        and 0 < (save_return - trigger).total_seconds() < MAX_SAVE_RETURN_SECONDS
        and not any(
            e["action"] >= SAVE_ACTION
            for e in held["events"]
            if e["event"] == "receive"
            and started + dt.timedelta(microseconds=e["elapsed_ns"] // 1000) < trigger
        ),
        "Add, reviewed Save or early-data timing differs",
    )
    return save_return
