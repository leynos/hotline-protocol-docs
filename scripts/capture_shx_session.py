#!/usr/bin/env python3
"""Capture a compiled shx terminal session inside a repository-backed namespace.

The report records which scripts made the capture (decision D31):
``driver_sha256`` is the digest of the modules of ``CAPTURE_MODULES`` and
``driver_identity`` holds the commit and the hash of each. A report made before
that decision holds the hash of this one file in ``driver_sha256``.
"""

import argparse
import datetime as dt
import json
import os
import shutil
from pathlib import Path

import capture_identity
from capture_shx_session_support import (  # digest is imported from here by tests
    Inputs,
    Report,
    Sandbox,
    check_steps,
    digest,
    home_file_state,
    sandbox_command,
    write_results,
)
from capture_shx_session_terminal import Session, start
from mothra_root import mothra_root
from protocol_capture import ORACLE_SHA256

# The scripts that make this capture, in the fixed order of its identity digest.
CAPTURE_MODULES = (
    "capture_shx_session.py",
    "capture_shx_session_support.py",
    "capture_shx_session_terminal.py",
)

SOURCE_COMMIT = "adb1bf8c8cb12f7eb2fa2c01673295a6312f262b"
IDENTITY_SCOPE = (
    "Local hashes checked; remote native process identity remains operator-reported"
)

__all__ = ["CAPTURE_MODULES", "Session", "capture", "digest", "main"]


def _check_inputs(
    plan_path: Path, binary: Path, profile_path: Path, oracle: Path
) -> tuple[Report, Report]:
    """Check the plan, the profile and the identities of the peer and oracle.

    Returns
    -------
    tuple[dict[str, typing.Any], dict[str, typing.Any]]
        The parsed plan and profile.

    Raises
    ------
    ValueError
        If the peer or oracle differs from what is recorded, the source
        profile is unknown, or the plan's commands are not acceptable.
    """
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    if digest(oracle) != ORACLE_SHA256 or digest(binary) != profile["binary_sha256"]:
        message = "Peer or oracle identity mismatch"
        raise ValueError(message)
    if profile["source_commit"] != SOURCE_COMMIT:
        message = "Unknown historical source profile"
        raise ValueError(message)
    check_steps(plan)
    return plan, profile


def _programs() -> tuple[str, str]:
    """Find the sandbox and tracing programs.

    Returns
    -------
    tuple[str, str]
        The paths of ``bwrap`` and ``strace``.

    Raises
    ------
    ValueError
        If either is missing.
    """
    bwrap, strace = shutil.which("bwrap"), shutil.which("strace")
    if not bwrap or not strace:
        message = "Require bwrap and strace"
        raise ValueError(message)
    return bwrap, strace


def _prepare(args: tuple[Path, Path, Path, Path, Path]) -> Inputs:
    """Check everything that can be checked before the output directory exists.

    Parameters
    ----------
    args : tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]
        The plan, peer binary, profile, oracle binary and output directory.

    Returns
    -------
    Inputs
        The checked inputs, with the binary and output resolved.

    Raises
    ------
    ValueError
        If a path is outside the checkout, an input is not acceptable, or
        ``bwrap`` or ``strace`` is missing.
    """
    plan_path, binary, profile_path, oracle, output = args
    root = mothra_root().resolve()
    binary, output = binary.resolve(), output.resolve()
    if any(not path.is_relative_to(root) for path in [binary, output]):
        message = "Peer binary and capture output must be inside mothra"
        raise ValueError(message)
    plan, profile = _check_inputs(plan_path, binary, profile_path, oracle)
    programs = _programs()
    return Inputs(plan, profile, Sandbox(*programs, root, output, binary))


def _driver_fields() -> Report:
    """Identify the scripts that are running this capture.

    Returns
    -------
    dict[str, typing.Any]
        ``driver_sha256``, the digest of the module set, and ``driver_identity``,
        the record behind it.
    """
    identity = capture_identity.identity(CAPTURE_MODULES)
    return {"driver_sha256": identity["digest"], "driver_identity": identity}


def _initial_report(
    inputs: Inputs, paths: tuple[Path, Path], command: list[str], before: Report
) -> Report:
    """Build the report as it stands before the peer starts.

    Parameters
    ----------
    inputs : Inputs
        The checked inputs.
    paths : tuple[pathlib.Path, pathlib.Path]
        The plan file and the profile file.
    command : list[str]
        The sandbox command.
    before : dict[str, typing.Any]
        The state of the guarded home file before the capture.

    Returns
    -------
    dict[str, typing.Any]
        The report, with status ``"running"``.
    """
    plan_path, profile_path = paths
    return {
        "schema_version": 1,
        "profile": "compiled-historical-peer",
        "native_conformance": False,
        "identity_scope": IDENTITY_SCOPE,
        "oracle_sha256": ORACLE_SHA256,
        "peer_binary_sha256": digest(inputs.sandbox.binary),
        "plan_sha256": digest(plan_path),
        "peer_profile_sha256": digest(profile_path),
        **_driver_fields(),
        "started_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "environment": inputs.plan["environment"],
        "terminal_environment": {
            **{key: os.environ.get(key) for key in ["LANG", "LC_ALL", "LC_CTYPE"]},
            "TERM": "dumb",
        },
        "command": command,
        "events": [],
        "completed_steps": 0,
        "status": "running",
        "error": "",
        "host_home_file_before": before,
    }


def _run(inputs: Inputs, report: Report, guard: tuple[Path, Report]) -> Report:
    """Run the peer and finish the report.

    Returns
    -------
    dict[str, typing.Any]
        The report, which is also written to the capture directory.
    """
    guarded, before = guard
    session = start(report["command"])
    report["controller_child_pid"] = session.pid
    report["events"] = session.events
    try:
        session.run(inputs.plan)
        report["status"] = "completed"
    except (OSError, RuntimeError, ValueError) as exc:
        report["status"], report["error"] = "failed", f"{type(exc).__name__}: {exc}"
    finally:
        report["completed_steps"] = session.completed
        session.stop()
        report["host_home_file_after"] = home_file_state(guarded)
        if report["host_home_file_after"] != before:
            report["status"], report["error"] = (
                "failed",
                "Host home-file state changed during capture",
            )
        report["peer_exit_code"] = session.code
        report["finished_at_utc"] = dt.datetime.now(dt.UTC).isoformat()
        write_results(inputs.sandbox.output, bytes(session.raw), report)
    return report


def capture(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # the callers' shape: five paths, as the runner passes them
    plan_path: Path, binary: Path, profile_path: Path, oracle: Path, output: Path
) -> Report:
    """Capture a compiled peer's terminal session in a sandbox.

    Parameters
    ----------
    plan_path : pathlib.Path
        The plan of commands to type.
    binary : pathlib.Path
        The compiled peer, inside the checkout.
    profile_path : pathlib.Path
        The peer profile that records the binary's hash.
    oracle : pathlib.Path
        The oracle binary.
    output : pathlib.Path
        A new directory inside the checkout.

    Returns
    -------
    dict[str, typing.Any]
        The report, which is also written to ``output``.
    """
    inputs = _prepare((plan_path, binary, profile_path, oracle, output))
    output = inputs.sandbox.output
    output.mkdir(parents=True, exist_ok=False)
    for name in ["home", "tmp", "work"]:
        (output / name).mkdir()
    (output / "plan.json").write_bytes(plan_path.read_bytes())
    (output / "peer-profile.json").write_bytes(profile_path.read_bytes())
    guarded = Path.home() / ".hxvars"
    before = home_file_state(guarded)
    command = sandbox_command(inputs.sandbox, str(Path.home()))
    report = _initial_report(inputs, (plan_path, profile_path), command, before)
    return _run(inputs, report, (guarded, before))


def main() -> None:
    """Capture a session from the command line.

    Raises
    ------
    SystemExit
        With a true status unless the capture completed.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--peer-profile", type=Path, required=True)
    parser.add_argument("--oracle-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = capture(
        args.plan, args.binary, args.peer_profile, args.oracle_binary, args.output
    )
    line = f"Compiled peer: {report['status']}; {report['completed_steps']} steps; "
    print(f"{line}{report['error']}")
    raise SystemExit(report["status"] != "completed")


if __name__ == "__main__":
    main()
