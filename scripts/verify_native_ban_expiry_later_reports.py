"""Check the post probe, owned cleanup and postflight receipts of the later epoch."""

import datetime as dt
import typing as typ

from verify_native_ban_expiry_first_common import need, read, sha, when
from verify_native_ban_expiry_later_capture import generic_post, unit_gate
from verify_native_ban_expiry_later_wire import (
    ACK_TOLERANCE,
    CONTROL_PORT,
    DEADLINE,
    DELETE_ACTIONS,
    DELETE_SENDS,
    GUARD_ACTIONS,
    HOST_WINDOW_MAX,
    HOST_WINDOW_MIN,
    INODE,
    NS,
    PID,
    POST_ACK_SECONDS,
    POST_EVENTS,
    POSTFLIGHT_ACTIONS,
)

if typ.TYPE_CHECKING:
    import types
    from pathlib import Path


def probe_plan_gate(
    corpus: Path, first: Path, receipt: dict, control: types.ModuleType
) -> dict:
    """Check the immutable post-probe plan against the first epoch's runtime.

    Parameters
    ----------
    corpus : Path
        The later corpus directory.
    first : Path
        The first-epoch corpus directory.
    receipt : dict
        The post-epoch capture readiness receipt.
    control : types.ModuleType
        The frozen controller, which regenerates the post-probe plan.

    Returns
    -------
    dict
        The first epoch's runtime record, which later checks reuse.
    """
    first_raw = first / "raw"
    env = read(first_raw / "runtime-asrun.json")
    plan = read(first_raw / "plans/post-probe.json")
    need(
        plan
        == control.cases.plan(
            "post-probe", control.cases.plans()["post-probe"], env, CONTROL_PORT
        )
        and plan == read(corpus / "raw/post/results/post-probe/plan.json")
        and receipt["emulator_starttime"] == env["emulator_starttime"],
        "Immutable post plan or runtime differs",
    )
    return env


def timing_gate(
    corpus: Path, first: Path, report: dict, control: types.ModuleType
) -> None:
    """Check the post probe's summary, host-relative window and ban bracket.

    Parameters
    ----------
    corpus : Path
        The later corpus directory.
    first : Path
        The first-epoch corpus directory, which holds the ban clock.
    report : dict
        The verified post-probe report.
    control : types.ModuleType
        The frozen controller, which derives the timing bounds.
    """
    post = corpus / "raw/post"
    first_raw = first / "raw"
    summary = read(post / "results/summary.json")
    ban_clock = read(first_raw / "results-first-c77/ban-clock.json")
    bound = control.TimingBounds.from_json(ban_clock)
    # The run's preflight timing gate happened before its first socket.
    gate = summary["timing_gate"]
    need(
        summary["phase"] == "post"
        and summary["status"] == "completed"
        and summary["full_file_baseline"] == "not_exercised"
        and summary["capture_receipt_sha256"] == sha(post / "capture-ready.json")
        and summary["readiness_report_sha256"] is None
        and summary["preprobe_baseline"] == "not_exercised_preserve_first_lookup"
        and summary["cases"]
        == {
            "post-probe": {
                "status": "completed",
                "error": "",
                "plan_sha256": sha(first_raw / "plans/post-probe.json"),
            }
        }
        and gate["phase"] == "post"
        and gate["host_window"] == [HOST_WINDOW_MIN, HOST_WINDOW_MAX]
        and gate["native_getdatetime_seconds_proven"] is False
        and HOST_WINDOW_MIN <= gate["host_elapsed_seconds"] < HOST_WINDOW_MAX
        and abs((bound.ack_utc - bound.request_utc).total_seconds() - POST_ACK_SECONDS)
        < ACK_TOLERANCE
        and bound.emulator_pid == PID
        and bound.image_inode == INODE
        and bound.namespace_inode == NS,
        "Post first lookup, timing bracket or no-readiness scope differs",
    )
    need(
        when(report["started_at_utc"])
        > bound.ack_utc + dt.timedelta(seconds=HOST_WINDOW_MIN)
        and when(report["started_at_utc"])
        < bound.ack_utc + dt.timedelta(seconds=HOST_WINDOW_MAX)
        and when(report["recorded_at_utc"]) < when(DEADLINE),
        "Post capture is outside host-relative window",
    )


def probe_gate(corpus: Path, first: Path, modules: tuple) -> dict:
    """Check the post-probe case report, its timing and its parent acceptance.

    Parameters
    ----------
    corpus : Path
        The later corpus directory.
    first : Path
        The first-epoch corpus directory.
    modules : tuple
        The frozen controller, cleanup, readiness, capture and TCP modules.

    Returns
    -------
    dict
        The verified post-probe report.
    """
    control, _, _, capture, _ = modules
    post = corpus / "raw/post"
    report = generic_post(post / "results/post-probe", capture)
    control.outcome_gate(report, "post-probe")
    timing_gate(corpus, first, report, control)
    parent = read(post / "parent-post-acceptance.json")
    need(
        parent["status"] == "parent_post_probe_semantics_and_paired_bytes_accepted"
        and parent["missed_pre_window"] is True
        and parent["exact_native1800_boundary_measured"] is False
        and parent["connections"] == 1
        and parent["cleanup_not_started"] is True,
        "Parent post-scope receipt differs",
    )
    unit_gate(post, "post")
    return report


def guard_gate(corpus: Path, env: dict, modules: tuple) -> dict:
    """Check the owned guard plan, its acceptance and its managed completion.

    Parameters
    ----------
    corpus : Path
        The later corpus directory.
    env : dict
        The first epoch's runtime record.
    modules : tuple
        The frozen controller, cleanup, readiness, capture and TCP modules.

    Returns
    -------
    dict
        The verified owned guard capture.
    """
    cleanup, capture = modules[1], modules[3]
    post = corpus / "raw/post"
    guard_source = read(post / "cleanup-guard-plan/plan.json")
    post_sha = sha(post / "results/post-probe/report.json")
    need(
        guard_source == cleanup.make_plan("guard", env, post_sha, None)
        and guard_source == read(post / "cleanup-guard/plan.json"),
        "Owned guard source plan differs",
    )
    guard = capture.verify_capture(post / "cleanup-guard")
    cleanup.semantic(guard, "guard")
    parent = read(post / "parent-guard-acceptance.json")
    need(
        parent["status"] == "parent_exact_owned_guard_accepted"
        and parent["completed_actions"] == GUARD_ACTIONS
        and parent["original_accounts_not_selected"] is True
        and parent["delete_not_started"] is True,
        "Parent guard approval scope differs",
    )
    unit_gate(post, "guard")
    return guard


def delete_gate(corpus: Path, env: dict, modules: tuple) -> dict:
    """Check the owned delete plan, its readback and its managed completion.

    Parameters
    ----------
    corpus : Path
        The later corpus directory.
    env : dict
        The first epoch's runtime record.
    modules : tuple
        The frozen controller, cleanup, readiness, capture and TCP modules.

    Returns
    -------
    dict
        The verified owned delete capture.
    """
    cleanup, capture = modules[1], modules[3]
    post = corpus / "raw/post"
    post_sha = sha(post / "results/post-probe/report.json")
    delete_source = read(post / "cleanup-delete-plan/plan.json")
    need(
        delete_source
        == cleanup.make_plan(
            "delete", env, post_sha, sha(post / "cleanup-guard/report.json")
        )
        and delete_source == read(post / "cleanup-delete/plan.json")
        and [
            step["op"] for step in delete_source["steps"] if step["op"] == "send"
        ].count("send")
        == DELETE_SENDS,
        "Owned delete/readback source plan differs",
    )
    deleted = capture.verify_capture(post / "cleanup-delete")
    cleanup.semantic(deleted, "delete")
    unit_gate(post, "delete")
    return deleted


def postflight_gate(corpus: Path, first: Path, modules: tuple) -> dict:
    """Check the control-only postflight capture and its managed completion.

    Parameters
    ----------
    corpus : Path
        The later corpus directory.
    first : Path
        The first-epoch corpus directory, whose readiness plan is reused.
    modules : tuple
        The frozen controller, cleanup, readiness, capture and TCP modules.

    Returns
    -------
    dict
        The verified postflight capture.
    """
    readiness, capture = modules[2], modules[3]
    post = corpus / "raw/post"
    need(
        read(post / "postflight/plan.json") == read(first / "raw/plans/readiness.json"),
        "Control-only postflight source differs",
    )
    after = capture.verify_capture(post / "postflight")
    readiness.readiness(after)
    unit_gate(post, "postflight")
    return after


def reports_gate(corpus: Path, first: Path, receipt: dict, modules: tuple) -> dict:
    """Check the post probe, the owned cleanup and the postflight in order.

    Parameters
    ----------
    corpus : Path
        The later corpus directory.
    first : Path
        The first-epoch corpus directory.
    receipt : dict
        The post-epoch capture readiness receipt.
    modules : tuple
        The frozen controller, cleanup, readiness, capture and TCP modules.

    Returns
    -------
    dict
        The verified post, guard, delete and postflight captures.
    """
    env = probe_plan_gate(corpus, first, receipt, modules[0])
    report = probe_gate(corpus, first, modules)
    guard = guard_gate(corpus, env, modules)
    deleted = delete_gate(corpus, env, modules)
    after = postflight_gate(corpus, first, modules)
    need(
        len(report["events"]) == POST_EVENTS
        and guard["completed_actions"] == GUARD_ACTIONS
        and deleted["completed_actions"] == DELETE_ACTIONS
        and after["completed_actions"] == POSTFLIGHT_ACTIONS
        and when(report["recorded_at_utc"])
        < when(guard["started_at_utc"])
        < when(deleted["started_at_utc"])
        < when(after["started_at_utc"]),
        "Post, guard, delete, postflight chronology differs",
    )
    return {
        "post": report,
        "guard": guard,
        "delete": deleted,
        "postflight": after,
    }
