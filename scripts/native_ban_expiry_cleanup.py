#!/usr/bin/env python3
"""Prepare separately gated cleanup of the two owned ban-expiry accounts."""

import argparse
import json
import typing as typ
from pathlib import Path

import native_ban_expiry_cases as expiry
import native_ban_expiry_control as expiry_control
from native_auth_cases import complement
from native_ban_expiry_control import digest as sha
from native_ban_expiry_control import load, require
from native_control_readiness import BASELINE_FIELDS, field_digest
from native_plan import close, login
from protocol_capture import ORACLE_SHA256, validate_plan, verify_capture
from verify_native_auth import reply
from verify_native_shx import fields


def accepted_post(post: Path, environment: dict) -> str:
    """Require the frozen B68 successful first lookup, not an earlier login.

    Parameters
    ----------
    post : pathlib.Path
        The post epoch directory.
    environment : dict
        The runtime environment the post-probe plan must have been made for.

    Returns
    -------
    str
        The SHA-256 of the accepted post-probe report.
    """
    case = post / "post-probe"
    source = (case / "plan.json").read_bytes()
    planned = load(case / "plan.json")
    require(
        planned
        == expiry.plan("post-probe", expiry.plans()["post-probe"], environment, 15800),
        "Post-probe plan/runtime differs",
    )
    summary = load(post / "summary.json")
    require(
        summary["phase"] == "post"
        and summary["status"] == "completed"
        and summary["cases"]
        == {
            "post-probe": {
                "status": "completed",
                "error": "",
                "plan_sha256": sha(source),
            }
        },
        "Post epoch was not accepted",
    )
    report = load(case / "report.json")
    expiry_control.outcome_gate(report, "post-probe")
    require(
        report["streams"] == _streams(planned, report["events"]),
        "Post-probe event streams differ",
    )
    return sha((case / "report.json").read_bytes())


def _streams(plan: dict, events: list[dict]) -> dict:
    """Rebuild the event streams of a plan from its recorded events.

    Returns
    -------
    dict
        The streams the recorder derives from ``events``.
    """
    recorder = expiry_control.Recorder(plan)
    recorder.events = events
    return recorder.streams()


def steps(stage: str) -> list[dict]:
    """List the plan steps of one cleanup stage.

    Parameters
    ----------
    stage : str
        ``guard`` or ``delete``.

    Returns
    -------
    list[dict]
        The login, the stage's exchanges and the close.

    Raises
    ------
    ValueError
        If the stage is neither ``guard`` nor ``delete``.
    """
    if stage == "guard":
        return (
            login()
            + expiry.exchange(352, 20, [(105, expiry.ZERO_KEY)])
            + expiry.exchange(352, 21, [(105, expiry.PROTECTED_KEY)])
            + [close()]
        )
    if stage == "delete":
        return (
            login()
            + expiry.exchange(351, 20, [(105, complement(expiry.ZERO_KEY))])
            + expiry.exchange(351, 21, [(105, complement(expiry.PROTECTED_KEY))])
            + expiry.exchange(352, 22, [(105, expiry.ZERO_KEY)])
            + expiry.exchange(352, 23, [(105, expiry.PROTECTED_KEY)])
            + expiry.exchange(348, 24, [])
            + [close()]
        )
    message = "Only guard or delete is prepared"
    raise ValueError(message)


def semantic(report: dict, stage: str) -> None:
    """Check a completed cleanup capture against what the stage should observe.

    Parameters
    ----------
    report : dict
        The verified capture report.
    stage : str
        ``guard`` or ``delete``.
    """
    require(
        report["status"] == "completed"
        and report["completed_actions"] == len(steps(stage)),
        "Cleanup capture incomplete",
    )
    for identifier, key, name, access in (
        (20, expiry.ZERO_KEY, expiry.ZERO_NAME, expiry.ZERO_ACCESS),
        (21, expiry.PROTECTED_KEY, expiry.PROTECTED_NAME, expiry.PROTECTED_ACCESS),
    ):
        frame = reply(report, identifier)
        if stage == "guard":
            require(
                frame["error"] == 0
                and fields(frame)
                == {102: name, 105: complement(key), 106: b"x", 110: access},
                "Owned account readback differs",
            )
        else:
            require(
                frame["error"] == 0 and fields(frame) == {},
                "Owned deletion ACK differs",
            )
            missing = reply(report, identifier + 2)
            require(
                missing["error"] == 1
                and fields(missing)
                == {100: b"No account with login \xd2" + key + b"\xd3."},
                "Owned deletion readback differs",
            )
    if stage == "delete":
        frame = reply(report, 24)
        require(
            frame["error"] == 0 and field_digest(frame) == BASELINE_FIELDS[348],
            "Original two-account enumeration differs",
        )


def make_plan(
    stage: str, environment: dict, post_sha: str, guard_sha: str | None
) -> dict:
    """Build the plan of one cleanup stage.

    Parameters
    ----------
    stage : str
        ``guard`` or ``delete``.
    environment : dict
        The runtime environment; it must be the control-only profile.
    post_sha : str
        The SHA-256 of the accepted post-probe report.
    guard_sha : str | None
        The SHA-256 of the accepted guard report, for the delete stage.

    Returns
    -------
    dict
        The validated plan.
    """
    require(
        environment.get("fixture_profile") == "control-only"
        and environment.get("full_file_baseline") == "not_exercised",
        "Wrong fixture profile",
    )
    result = {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": "A58 owned ban-expiry cleanup, separate live grant required",
        "oracle_sha256": ORACLE_SHA256,
        "gap_ids": ["GAP-074"],
        "environment": environment,
        "endpoints": {"control": {"host": "127.0.0.1", "port": 15800}},
        "steps": steps(stage),
        "expectation": {
            "stage": stage,
            "accepted_post_report_sha256": post_sha,
            "guard_report_sha256": guard_sha,
        },
    }
    validate_plan(result)
    return result


class Locations(typ.NamedTuple):
    """The directories and files a cleanup plan is prepared from and written to."""

    post: Path
    runtime: Path
    output: Path
    guard: Path | None


def prepare(stage: str, where: Locations) -> None:
    """Write the plan of one cleanup stage, after its inputs are accepted.

    Parameters
    ----------
    stage : str
        ``guard`` or ``delete``.
    where : Locations
        The accepted post epoch, the runtime record, the output directory and,
        for deletion, the accepted guard capture.

    Raises
    ------
    ValueError
        If deletion is requested without an accepted guard capture.
    """
    post, runtime, output, guard = where
    environment = load(runtime)
    post_sha = accepted_post(post, environment)
    guard_sha = None
    if stage == "delete":
        if guard is None:
            message = "Deletion requires accepted guard capture"
            raise ValueError(message)
        previous = load(guard / "plan.json")
        require(
            previous == make_plan("guard", environment, post_sha, None),
            "Guard source/runtime differs",
        )
        observed = verify_capture(guard)
        semantic(observed, "guard")
        guard_sha = sha((guard / "report.json").read_bytes())
    require(not output.exists(), "Refuse existing plan output")
    output.mkdir(parents=True)
    (output / "plan.json").write_text(
        json.dumps(make_plan(stage, environment, post_sha, guard_sha), indent=2) + "\n"
    )


def main() -> None:
    """Prepare a cleanup plan from the command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", choices=("guard", "delete"), required=True)
    parser.add_argument("--post", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--guard", type=Path)
    args = parser.parse_args()
    prepare(args.stage, Locations(args.post, args.runtime, args.output, args.guard))


if __name__ == "__main__":
    main()
