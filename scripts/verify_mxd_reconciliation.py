"""Verify the pinned mxd test run and its source provenance.

Example: python3 scripts/verify_mxd_reconciliation.py evidence/gap-remediation/2026-11-13/delegated-mxd-01
"""  # ruff: ignore[line-too-long]  # the example is one path, which the help text must keep whole

import hashlib
import json
import re
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # the fixed argv runs git with no shell
import typing as typ
from pathlib import Path

from script_cli import run

EXPECTED_HEAD = "2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131"
EXPECTED_COMMANDS = {
    "compat-tests": ("cargo test --offline --locked --lib wireframe::compat", [31]),
    "roster-tests": ("cargo test --offline --locked --lib user_name_list", [3]),
    "scenario-tests": (
        (
            "cargo test --offline --locked --features test-support "
            "--test wireframe_login_compat --test wireframe_xor_compat "
            "--test wireframe_compat_guardrails_bdd"
        ),
        [6, 9, 5],
    ),
    "presence-tests": (
        (
            "cargo test --offline --locked --features test-support "
            "--test wireframe_presence_bdd"
        ),
        [1],
    ),
}
RESULT = re.compile(r"test result: ok\. (\d+) passed; 0 failed;")
CLAIMED_TOTAL = 55  # the mxd tests that the recorded run claims to pass


def refuse(message: str) -> typ.Never:
    """Refuse the evidence with a ValueError that carries ``message``.

    Parameters
    ----------
    message : str
        The reason the evidence is refused.

    Raises
    ------
    ValueError
        Always, with ``message``.
    """
    raise ValueError(message)


def git(mxd: Path, *args: str) -> str:
    """Return Git output from the identified checkout.

    Example: ``git(path, "rev-parse", "HEAD")`` returns its commit hash.

    Parameters
    ----------
    mxd : pathlib.Path
        The checkout to query.
    *args : str
        The Git arguments that follow ``-C`` and the checkout.

    Returns
    -------
    str
        The standard output of the command, stripped of surrounding whitespace.
    """
    output = subprocess.check_output(["git", "-C", str(mxd), *args], text=True)  # ruff: ignore[subprocess-without-shell-equals-true, start-process-with-partial-path]  # fixed argv, no shell
    return output.strip()


def check_checkout(mxd: Path, manifest: dict[str, typ.Any]) -> None:
    """Check that the live mxd checkout is at the recorded revision and status.

    Parameters
    ----------
    mxd : pathlib.Path
        The live mxd checkout.
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json`` of the evidence.
    """
    if git(mxd, "rev-parse", "HEAD") != EXPECTED_HEAD:
        refuse("mxd checkout revision differs from the recorded revision")
    current_status = git(mxd, "status", "--porcelain=v1")
    if current_status != manifest["source_worktree_status_final"]:
        refuse("mxd checkout status differs from the recorded status")


def check_inputs(
    evidence: Path,
    manifest: dict[str, typ.Any],
    mxd: Path | None,
) -> None:
    """Check each frozen source snapshot and, when given, its live counterpart.

    Parameters
    ----------
    evidence : pathlib.Path
        The evidence directory.
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json`` of the evidence.
    mxd : pathlib.Path | None
        A live mxd checkout to compare with the snapshots, if any.
    """
    for source in manifest["inputs"]:
        snapshot = evidence / source["snapshot"]
        actual = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        if actual != source["sha256"]:
            refuse(f"source snapshot hash mismatch: {source['path']}")
        if mxd is not None:
            live = hashlib.sha256((mxd / source["path"]).read_bytes()).hexdigest()
            if live != source["sha256"]:
                refuse(f"live source hash mismatch: {source['path']}")


def check_run(
    evidence: Path,
    record: dict[str, typ.Any],
    name: str,
    expected_counts: list[int],
) -> int:
    """Check the exit and the pass counts of one recorded test command.

    Parameters
    ----------
    evidence : pathlib.Path
        The evidence directory.
    record : dict[str, typing.Any]
        The manifest entry of the command.
    name : str
        The name of the command, as in ``EXPECTED_COMMANDS``.
    expected_counts : list[int]
        The pass count of each test binary that the command runs.

    Returns
    -------
    int
        The number of tests that the command passed.
    """
    if (
        record["exit_file"] != f"{name}.exit"
        or (evidence / record["exit_file"]).read_text().strip() != "0"
    ):
        refuse(f"test command failed: {name}")
    log = (evidence / record["log"]).read_text()
    counts = [int(value) for value in RESULT.findall(log)]
    if counts != expected_counts or "test result: FAILED" in log:
        refuse(f"test counts differ from claim: {name}")
    return sum(counts)


def check_commands(evidence: Path, manifest: dict[str, typ.Any]) -> int:
    """Check every recorded test command and the total of the run.

    Parameters
    ----------
    evidence : pathlib.Path
        The evidence directory.
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json`` of the evidence.

    Returns
    -------
    int
        The total number of tests that the run passed.
    """
    observed_names: set[str] = set()
    total = 0
    for record in manifest["commands"]:
        name = record["log"].removesuffix(".log")
        observed_names.add(name)
        expected_command, expected_counts = EXPECTED_COMMANDS[name]
        if (
            record["command"] != expected_command
            or record["passed_tests"] != expected_counts
        ):
            refuse(f"unexpected command or expected counts: {name}")
        total += check_run(evidence, record, name, expected_counts)
    if observed_names != set(EXPECTED_COMMANDS):
        refuse("test command set or total differs from claim")
    if manifest["total_passed_tests"] != total:
        refuse("test command set or total differs from claim")
    if total != CLAIMED_TOTAL:
        refuse("test command set or total differs from claim")
    return total


def verify(evidence: Path, mxd: Path | None = None) -> int:
    """Check the frozen source and test records, optionally checking live mxd.

    Example: a complete run returns 55; a changed log raises ValueError.

    Parameters
    ----------
    evidence : pathlib.Path
        The evidence directory.
    mxd : pathlib.Path | None
        A live mxd checkout to compare with the evidence, if any.

    Returns
    -------
    int
        The total number of tests that the run passed.
    """
    manifest = json.loads((evidence / "manifest.json").read_text())
    if manifest["source_git_head"] != EXPECTED_HEAD:
        refuse("recorded mxd revision differs from pinned revision")
    if mxd is not None:
        check_checkout(mxd, manifest)
    check_inputs(evidence, manifest, mxd)
    return check_commands(evidence, manifest)


def show(evidence: str, *, mxd: str | None = None) -> None:
    """Verify an evidence directory and print its count of passed tests.

    Parameters
    ----------
    evidence : str
        The evidence directory to verify.
    mxd : str | None
        A live mxd checkout to compare with the evidence as well.
    """
    total = verify(Path(evidence), None if mxd is None else Path(mxd))
    print(f"verified {total} mxd tests at {EXPECTED_HEAD}")


def main() -> None:
    """Parse paths, verify the run and print its count.

    Example: ``verify_mxd_reconciliation.py evidence`` prints 55.
    """
    run(show, __doc__)


if __name__ == "__main__":
    main()
