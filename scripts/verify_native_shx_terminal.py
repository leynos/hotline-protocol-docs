"""Check the peer process and terminal record of one retained shx session."""

import json
import typing as typ

from protocol_capture import ORACLE_SHA256
from verify_native_core import require
from verify_native_shx_frames import LOGIN, PEER, REVISION, sha

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

LISTING_CASES = {"root-listing", "fork-download"}
REFUSED_CREDENTIAL = "wrong-shx-pass"
CLEAN_EXIT = b"0"
PEER_VERSION = b"hx version 0.1.48"


def expected_commands(name: str) -> list[str]:
    """List the commands that the plan of a case types into the peer.

    Returns
    -------
    list[str]
        The commands, ending with the quit command.
    """
    commands = ["/version", LOGIN, "/who"]
    if name in LISTING_CASES:
        commands.append("/ls")
    match name:
        case "fork-download":
            commands.append("/get mothra-fork-fixture")
        case "basic-empty-name":
            commands.append("mothra-shx-basic-chat")
        case "ambiguous-text":
            commands.append("/who")
        case "wrong-password":
            commands = ["/version", LOGIN.replace("mothra19", REFUSED_CREDENTIAL)]
    commands.append("/quit")
    return commands


def check_identity(
    case: Path, report: Report, source_hashes: set[str]
) -> tuple[Report, Report]:
    """Check the process outcome, the identities and the hashes of a capture.

    Returns
    -------
    tuple[dict[str, typing.Any], dict[str, typing.Any]]
        The plan and the peer profile of the capture.
    """
    plan = json.loads((case / "plan.json").read_text())
    profile = json.loads((case / "peer-profile.json").read_text())
    require(
        report["status"] == "completed" and report["peer_exit_code"] == 0,
        "Peer process failed",
    )
    require(
        report["native_conformance"] is False,
        "Driver cannot certify native conformance",
    )
    require(
        report["oracle_sha256"] == ORACLE_SHA256
        and report["peer_binary_sha256"] == PEER,
        "Peer/oracle identity differs",
    )
    require(
        profile["source_commit"] == REVISION and profile["binary_sha256"] == PEER,
        "Compiled profile differs",
    )
    require(
        report["plan_sha256"] == sha(case / "plan.json")
        and report["peer_profile_sha256"] == sha(case / "peer-profile.json"),
        "Plan/profile hash differs",
    )
    require(report["driver_sha256"] in source_hashes, "Missing exact peer driver")
    require(
        report["host_home_file_before"] == report["host_home_file_after"],
        "Real home file changed",
    )
    require(report["completed_steps"] == len(plan["steps"]), "Incomplete peer commands")
    return plan, profile


def check_events(case: Path, report: Report, commands: list[str]) -> None:
    """Check that the recorded terminal events match the commands and the output."""
    events = report["events"]
    require(
        b"".join(bytes.fromhex(e["hex"]) for e in events if e["event"] == "output")
        == (case / "stdout.bin").read_bytes(),
        "Raw terminal event bytes differ",
    )
    inputs = [bytes.fromhex(e["hex"]) for e in events if e["event"] == "input"]
    require(
        inputs == [(c + "\n").encode() for c in commands],
        "Sent terminal commands differ",
    )
    require(
        any(
            e["event"] == "process-exit" and bytes.fromhex(e["hex"]) == CLEAN_EXIT
            for e in events
        ),
        "Missing successful process-exit event",
    )


def check_terminal(
    case: Path, source_hashes: set[str], *, commands: list[str] | None = None
) -> Report:
    """Check one capture of the peer process and its terminal.

    Returns
    -------
    dict[str, typing.Any]
        The report of the capture.
    """
    report = json.loads((case / "report.json").read_text())
    plan, _profile = check_identity(case, report, source_hashes)
    if commands is None:
        commands = expected_commands(case.name)
    require(
        [s["command"] for s in plan["steps"]] == commands, "Peer command matrix differs"
    )
    require(
        plan["steps"][-1].get("expect_exit") == 0, "Missing normal exit requirement"
    )
    check_events(case, report, commands)
    terminal = (case / "stdout.bin").read_bytes()
    require(PEER_VERSION in terminal, "Missing running peer version")
    require((case / "home/.hxvars").is_file(), "Missing private exit-save file")
    return report
