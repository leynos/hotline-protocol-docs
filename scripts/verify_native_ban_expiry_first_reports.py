"""Check the source plans, readiness, case reports and timing of the first epoch."""

import typing as typ

from verify_native_ban_expiry_first_common import need, read, replay_view, sha, when
from verify_native_ban_expiry_first_wire import (
    CONTROL_PORT,
    DEADLINE,
    FIRST,
    INODE,
    MAX_ACK_SECONDS,
    PID,
    SETTLE_SECONDS,
)

if typ.TYPE_CHECKING:
    import types
    from pathlib import Path

ALL_NAMES = ("readiness", *FIRST, "pre-probe", "post-probe")


def generic_report(folder: Path, capture: types.ModuleType) -> dict:
    """Adapt the B68 case metadata only in a temporary generic replay view.

    Parameters
    ----------
    folder : Path
        The case folder, which holds ``plan.json`` and ``report.json``.
    capture : types.ModuleType
        The module whose ``verify_capture`` checks the replay view.

    Returns
    -------
    dict
        The case report as it was written, before adaptation.
    """
    plan = read(folder / "plan.json")
    raw = read(folder / "report.json")
    need(
        raw["profile"] == "control-only"
        and raw["full_file_baseline"] == "not_exercised"
        and raw["oracle_sha256"] == plan["oracle_sha256"],
        "B68 raw case profile differs",
    )
    adapted = {
        **raw,
        "profile": plan["profile"],
        "native_conformance": False,
        "plan_sha256": sha(folder / "plan.json"),
    }
    replay_view(folder, adapted, capture)
    return raw


def plan_gate(raw: Path, control: types.ModuleType) -> dict:
    """Check the source plan of each of the twelve cases of the first epoch.

    Parameters
    ----------
    raw : Path
        The raw receipts directory.
    control : types.ModuleType
        The frozen controller, which regenerates each plan.

    Returns
    -------
    dict
        The source hash of each plan, by case name.
    """
    plans = raw / "plans"
    hashes = read(plans / "source-hashes.json")
    need(set(hashes) == set(ALL_NAMES), "Twelve-plan inventory differs")
    env = read(raw / "runtime-asrun.json")
    for name in ALL_NAMES:
        path = plans / f"{name}.json"
        plan = read(path)
        need(sha(path) == hashes[name], f"{name} source plan hash differs")
        need(
            plan
            == control.cases.plan(name, control.cases.plans()[name], env, CONTROL_PORT)
            and plan["endpoints"]
            == {"control": {"host": "127.0.0.1", "port": CONTROL_PORT}}
            and plan["environment"] == env,
            f"{name} source plan differs",
        )
    return hashes


def readiness_report(
    raw: Path, capture: types.ModuleType, base: types.ModuleType
) -> dict:
    """Verify the readiness capture of the first epoch against its source plan.

    Parameters
    ----------
    raw : Path
        The raw receipts directory.
    capture : types.ModuleType
        The module whose ``verify_capture`` checks the readiness capture.
    base : types.ModuleType
        The module whose ``readiness`` checks the verified capture.

    Returns
    -------
    dict
        The verified readiness report.
    """
    plans = raw / "plans"
    ready_path = raw / "captures/readiness"
    need(
        read(ready_path / "plan.json") == read(plans / "readiness.json"),
        "Readiness source plan differs",
    )
    ready = capture.verify_capture(ready_path)
    base.readiness(ready)
    return ready


def case_gate(raw: Path, hashes: dict, modules: tuple) -> tuple[dict, dict]:
    """Check the summary and each case report of the first epoch.

    Parameters
    ----------
    raw : Path
        The raw receipts directory.
    hashes : dict
        The source hash of each plan, by case name.
    modules : tuple
        The frozen controller and the capture module, in that order.

    Returns
    -------
    tuple[dict, dict]
        The summary of the epoch and the verified report of each case.
    """
    control, capture = modules
    plans = raw / "plans"
    results = raw / "results-first-c77"
    summary = read(results / "summary.json")
    need(
        summary["status"] == "completed"
        and summary["phase"] == "first"
        and summary.get("error") is None
        and tuple(summary["cases"]) == FIRST
        and summary["post_readiness_settle"]["elapsed_seconds"] >= SETTLE_SECONDS
        and summary["post_readiness_settle"]["runner_socket_actions_during_wait"] == 0,
        "First-epoch status, sequence or settle differs",
    )
    reports = {}
    for name in FIRST:
        folder = results / name
        need(
            read(folder / "plan.json") == read(plans / f"{name}.json"),
            f"{name} as-run plan differs",
        )
        report = generic_report(folder, capture)
        control.outcome_gate(report, name)
        need(
            summary["cases"][name]
            == {"status": "completed", "error": "", "plan_sha256": hashes[name]},
            f"{name} summary differs",
        )
        reports[name] = report
    return summary, reports


def reports_gate(raw: Path, receipt: dict, modules: tuple) -> dict:
    """Check the plans, readiness, cases and ban timing of the first epoch.

    Parameters
    ----------
    raw : Path
        The raw receipts directory.
    receipt : dict
        The capture readiness receipt of the epoch.
    modules : tuple
        The frozen controller, readiness, and capture modules, in that order.

    Returns
    -------
    dict
        The verified report of the readiness capture and of each case.
    """
    control, base, capture = modules
    hashes = plan_gate(raw, control)
    reports = {"readiness": readiness_report(raw, capture, base)}
    summary, cases = case_gate(raw, hashes, (control, capture))
    reports.update(cases)
    bound = control.ban_timing(reports["tempban"], receipt)
    need(
        bound.to_json() == read(raw / "results-first-c77/ban-clock.json")
        and bound.image_inode == INODE
        and bound.emulator_pid == PID
        and 0 <= (bound.ack_utc - bound.request_utc).total_seconds() <= MAX_ACK_SECONDS,
        "Ban request/ACK bracket differs",
    )
    need(
        when(summary["post_readiness_settle"]["started_utc"])
        < when(summary["post_readiness_settle"]["completed_utc"])
        < when(reports["guard-zero"]["started_at_utc"])
        < bound.request_utc
        < bound.ack_utc
        < when(DEADLINE),
        "First-epoch timing order or deadline differs",
    )
    return reports
