"""Check the controlled execution, unit, log and capture of the full gate."""

import json
import re
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # reads Git, no shell
import typing as typ

from verify_mxd_direct_ack_common import (
    BUILD_JOBS,
    CAPTURE_LIMIT,
    CONTROLS,
    COUNTS,
    DOCTESTS,
    FINAL,
    INVOCATION,
    TEST_THREADS,
    UNIT,
    Manifest,
    fail,
    properties,
    sha256,
)

if typ.TYPE_CHECKING:
    from pathlib import Path


def check_execution(evidence: Path, gate: Manifest) -> None:
    """Check the controlled execution and the script that ran the full gate.

    Parameters
    ----------
    evidence : pathlib.Path
        The package directory.
    gate : dict[str, typing.Any]
        The ``execution`` section of the manifest.
    """
    if (
        gate["unit"],
        gate["invocation_id"],
        gate["unit_derived_exit"],
        gate["nextest_test_threads"],
        gate["pg_data_dir"],
    ) != (UNIT, INVOCATION, 0, TEST_THREADS, "unset"):
        fail("controlled execution differs")
    if gate["cargo_net_offline"] is not True or gate["cargo_build_jobs"] != BUILD_JOBS:
        fail("offline or single-job control differs")
    script = (evidence / "run-full.sh").read_text()
    for required in CONTROLS:
        if required not in script:
            fail(f"missing execution control: {required}")


def check_unit(evidence: Path) -> None:
    """Check the managed unit's identity, timers and retained exit result.

    Parameters
    ----------
    evidence : pathlib.Path
        The package directory.
    """
    initial = properties(evidence / "unit-initial-props.txt")
    final = properties(evidence / "unit-final-props.txt")
    identity = {
        "Id": UNIT,
        "InvocationID": INVOCATION,
        "Type": "oneshot",
        "TimeoutStartUSec": "40min",
        "TimeoutStopUSec": "30s",
        "RemainAfterExit": "yes",
    }
    for record in (initial, final):
        if not identity.items() <= record.items():
            fail("unit identity or timers differ")
    result = {
        "ActiveState": "active",
        "SubState": "exited",
        "Result": "success",
        "ExecMainCode": "1",
        "ExecMainStatus": "0",
        "MainPID": "0",
    }
    if not result.items() <= final.items():
        fail("retained unit does not prove exit zero")


def check_log(evidence: Path, gate: Manifest) -> None:
    """Check the nextest and doctest summaries of the full log and its digest.

    Parameters
    ----------
    evidence : pathlib.Path
        The package directory.
    gate : dict[str, typing.Any]
        The ``execution`` section of the manifest.
    """
    log = (evidence / "full.log").read_text()
    counts = [
        tuple(map(int, row))
        for row in re.findall(
            r"Summary \[[^\]]+\] (\d+) tests run: (\d+) passed, (\d+) skipped", log
        )
    ]
    docs = [
        tuple(map(int, row))
        for row in re.findall(
            r"test result: ok\. (\d+) passed; 0 failed; (\d+) ignored;", log
        )
    ]
    if counts != COUNTS or docs != DOCTESTS:
        fail("suite or doctest summary differs")
    if sha256(evidence / "full.log") != gate["full_log_sha256"]:
        fail("raw full log digest differs")


def check_capture(evidence: Path, manifest: Manifest) -> None:
    """Check the watcher capture and the recorded limitation of the proof.

    Parameters
    ----------
    evidence : pathlib.Path
        The package directory.
    manifest : Manifest
        The parsed ``manifest.json``.
    """
    capture = (evidence / "watch-capture.jsonl").read_text().splitlines()
    if (
        not json.loads(capture[-1])["stop_requested"]
        or len("\n".join(capture)) >= CAPTURE_LIMIT
    ):
        fail("watcher termination or size differs")
    if "No Kani/native peer run" not in manifest["limitations"]:
        fail("unrun proof limitation missing")


def git(mxd: Path, *arguments: str) -> str:
    """Run one read-only git command in the live mxd checkout.

    Parameters
    ----------
    mxd : pathlib.Path
        The checkout that git reads.
    *arguments : str
        The git subcommand and its options.

    Returns
    -------
    str
        The standard output of the command, stripped.
    """
    return subprocess.check_output(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv, no shell
        ["git", "-C", str(mxd), *arguments],  # ruff: ignore[start-process-with-partial-path]  # git is resolved from PATH, as the original argv was
        text=True,
    ).strip()


def check_live(mxd: Path, changed: Manifest) -> None:
    """Check that the live checkout is at the final revision with the frozen sources.

    Parameters
    ----------
    mxd : pathlib.Path
        The live mxd checkout.
    changed : dict[str, typing.Any]
        The frozen candidate source hashes.
    """
    head = git(mxd, "rev-parse", "HEAD")
    dirty = git(mxd, "status", "--porcelain=v1", "--untracked-files=no")
    if head != FINAL or dirty:
        fail("live mxd revision or tracked tree differs")
    for name, digest in changed.items():
        if sha256(mxd / name) != digest:
            fail(f"live source differs: {name}")
