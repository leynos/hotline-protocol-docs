#!/usr/bin/env python3
"""Run the finite shx receiver matrix with private HOME and loopback capture.

The manifest records which scripts made the run (decision D31):
``source_runner_sha256`` and ``source_fixture_sha256`` are the digests of the
module sets, with the records ``source_runner_identity`` and
``source_fixture_identity`` beside them, and every module of those sets and of
the capture driver is copied into the corpus. A manifest made before that
decision holds the hash of one file in each field.
"""

import argparse
import functools
import json
import signal
import socket
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # starts the recorder, fixtures and sessions
import time
import typing as typ
from pathlib import Path

from capture_shx_session import CAPTURE_MODULES as SESSION_MODULES
from peer_tolerance_fixture import CASES
from peer_tolerance_run_support import (
    EVIDENCE_DAY,
    FIRST_PORT,
    FIXTURE_MODULES,
    Layout,
    case_plan,
    check_outputs,
    fixture_command,
    freeze,
    home_state,
    session_command,
    sha,
    source_fields,
)
from protocol_capture import ORACLE_SHA256
from verify_native_shx import PEER

# The scripts that make this run, in the fixed order of its identity digest.
CAPTURE_MODULES = ("peer_tolerance_run.py", "peer_tolerance_run_support.py")
# Everything copied into the corpus, in the order it is copied.
COPIED = (
    *FIXTURE_MODULES,
    *CAPTURE_MODULES,
    "verify_peer_tolerance.py",
    *SESSION_MODULES,
)

RECORDER_SECONDS = 1
FIXTURE_START_SECONDS = 10
FIXTURE_POLL_SECONDS = 0.1
FIXTURE_END_SECONDS = 35

type Json = dict[str, typ.Any]
type HomeState = tuple[str, int, int] | None

__all__ = ["CAPTURE_MODULES", "CASES", "free", "main", "run", "sha"]


def free(port: int) -> None:
    """Require that a loopback port can be bound.

    Parameters
    ----------
    port : int
        The port.
    """
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", port))


def _check_identity(layout: Layout) -> None:
    """Require the recorded peer and oracle.

    Raises
    ------
    ValueError
        If the peer or oracle differs, or the profile names another peer.
    """
    if sha(layout.binary) != PEER or sha(layout.oracle) != ORACLE_SHA256:
        message = "Peer/oracle identity mismatch"
        raise ValueError(message)
    recorded = json.loads(layout.profile.read_text(encoding="utf-8"))
    if recorded["binary_sha256"] != PEER:
        message = "Recorded profile does not match the running peer"
        raise ValueError(message)


def _recorder(work: Path) -> subprocess.Popen[bytes]:
    """Start the loopback packet recorder as root.

    Returns
    -------
    subprocess.Popen[bytes]
        The running recorder.
    """
    return subprocess.Popen(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv
        [  # ruff: ignore[start-process-with-partial-path]  # sudo from PATH, as the recipe did
            "sudo",
            "-n",
            "tcpdump",
            "-i",
            "lo",
            "-y",
            "EN10MB",
            "-s",
            "0",
            "-U",
            "-Z",
            "leynos",
            "-w",
            str(work / "host.pcap"),
            "tcp",
            "and",
            "portrange",
            "15600-15609",
        ],
        stdout=(work / "tcpdump.stdout").open("w", encoding="utf-8"),
        stderr=(work / "tcpdump.stderr").open("w", encoding="utf-8"),
    )


def _await_ready(server: subprocess.Popen[bytes], fixture: Path, case: str) -> None:
    """Wait for a fixture to signal that it listens.

    Raises
    ------
    RuntimeError
        If the fixture exits or ten seconds pass first.
    """
    deadline = time.monotonic() + FIXTURE_START_SECONDS
    while not (fixture / "ready.json").exists():
        if server.poll() is not None or time.monotonic() > deadline:
            message = f"Fixture did not start: {case}"
            raise RuntimeError(message)
        time.sleep(FIXTURE_POLL_SECONDS)


def _finish_server(server: subprocess.Popen[bytes], case: str) -> int:
    """Wait for a fixture to end, terminating it if it lingers.

    Returns
    -------
    int
        The fixture's exit code.

    Raises
    ------
    RuntimeError
        If the fixture is still running after its session.
    """
    try:
        return server.wait(timeout=FIXTURE_END_SECONDS)
    except subprocess.TimeoutExpired:
        server.send_signal(signal.SIGTERM)
        server.wait(timeout=5)
        message = f"Fixture remained live: {case}"
        raise RuntimeError(message) from None


def _run_case(layout: Layout, template: Json, index: int) -> None:
    """Run one case: its fixture, its plan and its captured session.

    Raises
    ------
    RuntimeError
        If the fixture or the session fails.
    """
    case = CASES[index]
    port = FIRST_PORT + index
    plan_file = layout.work / f"plan-{case}.json"
    plan_file.write_text(
        json.dumps(case_plan(template, case, port), indent=2) + "\n", encoding="utf-8"
    )
    with (layout.work / f"fixture-{case}.log").open("w", encoding="utf-8") as log:
        server = subprocess.Popen(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv  # pylint: disable=consider-using-with  # waited on in _finish_server
            fixture_command(layout, case, port),
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        _await_ready(server, layout.work / "fixtures" / case, case)
        result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv
            session_command(layout, case, plan_file),
            capture_output=True,
            text=True,
            check=False,
        )
        (layout.work / f"capture-{case}.log").write_text(
            result.stdout + result.stderr, encoding="utf-8"
        )
        server_code = _finish_server(server, case)
        if result.returncode or server_code:
            message = f"Session failed: {case}; preserved at {layout.work}"
            raise RuntimeError(message)
    print(f"Completed full peer session: {case}", flush=True)


def _run_cases(layout: Layout, template: Json) -> None:
    """Run every case while the loopback recorder is running.

    Raises
    ------
    RuntimeError
        If the recorder exits early or a case fails.
    """
    capture = _recorder(layout.work)
    try:
        time.sleep(RECORDER_SECONDS)
        if capture.poll() is not None:
            message = "Loopback recorder exited before first session"
            raise RuntimeError(message)
        for index in range(len(CASES)):
            _run_case(layout, template, index)
    finally:
        capture.send_signal(signal.SIGINT)
        capture.wait(timeout=10)


def _manifest(layout: Layout, home: tuple[HomeState, HomeState]) -> Json:
    """Describe the run.

    Returns
    -------
    dict[str, typing.Any]
        The manifest, in the order its keys are written.
    """
    before, after = home
    profile = json.loads(layout.profile.read_text(encoding="utf-8"))
    return {
        "schema_version": 1,
        "profile": "compiled-historical-peer and controlled-receiver-fixture",
        "native_conformance": False,
        "source_commit": profile["source_commit"],
        "peer_binary_sha256": PEER,
        "oracle_sha256": ORACLE_SHA256,
        "cases": list(CASES),
        "ports": list(range(FIRST_PORT, FIRST_PORT + len(CASES))),
        "real_home_file_before": before,
        "real_home_file_after": after,
        **source_fields(layout, CAPTURE_MODULES),
    }


def run(root: Path, evidence: Path, work: Path, destination: Path) -> None:
    """Run every case, then freeze the evidence.

    Parameters
    ----------
    root : pathlib.Path
        The checkout.
    evidence : pathlib.Path
        The tree whose ``scripts/`` are run and copied.
    work : pathlib.Path
        The private run directory, which must not exist.
    destination : pathlib.Path
        The owned evidence directory, which must not exist.

    Raises
    ------
    RuntimeError
        If the real ``.hxvars`` changed during the run.
    """
    layout = Layout(*(path.resolve() for path in (root, evidence, work, destination)))
    owned = check_outputs(layout)
    _check_identity(layout)
    for port in range(FIRST_PORT, FIRST_PORT + len(CASES)):
        free(port)
    layout.work.mkdir(parents=True)
    (layout.work / "captures").mkdir()
    (layout.work / "fixtures").mkdir()
    plan_source = (
        layout.root / f"{EVIDENCE_DAY}/native-shx-02/receivers/control/plan.json"
    )
    template = json.loads(plan_source.read_text(encoding="utf-8"))
    before = home_state()
    _run_cases(layout, template)
    after = home_state()
    if after != before:
        message = "Real HOME/.hxvars changed; preserve private run and escalate"
        raise RuntimeError(message)
    manifest = functools.partial(_manifest, layout, (before, after))
    freeze(layout, (owned, COPIED), manifest)


def main() -> None:
    """Run the matrix from the command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    run(args.root, args.protocol, args.work, args.destination)


if __name__ == "__main__":
    main()
