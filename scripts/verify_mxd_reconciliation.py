"""Verify the pinned mxd test run and its source provenance.

Example: python3 scripts/verify_mxd_reconciliation.py ../mothra/evidence/gap-remediation/2026-11-13/delegated-mxd-01
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

EXPECTED_HEAD = "2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131"
EXPECTED_COMMANDS = {
    "compat-tests": ("cargo test --offline --locked --lib wireframe::compat", [31]),
    "roster-tests": ("cargo test --offline --locked --lib user_name_list", [3]),
    "scenario-tests": (
        "cargo test --offline --locked --features test-support --test wireframe_login_compat --test wireframe_xor_compat --test wireframe_compat_guardrails_bdd",
        [6, 9, 5],
    ),
    "presence-tests": (
        "cargo test --offline --locked --features test-support --test wireframe_presence_bdd",
        [1],
    ),
}
RESULT = re.compile(r"test result: ok\. (\d+) passed; 0 failed;")


def git(mxd: Path, *args: str) -> str:
    """Return Git output from the identified checkout.

    Example: ``git(path, "rev-parse", "HEAD")`` returns its commit hash.
    """
    return subprocess.check_output(["git", "-C", str(mxd), *args], text=True).strip()


def verify(evidence: Path, mxd: Path | None = None) -> int:
    """Check the frozen source and test records, optionally checking live mxd.

    Example: a complete run returns 55; a changed log raises ValueError.
    """
    manifest = json.loads((evidence / "manifest.json").read_text())
    if manifest["source_git_head"] != EXPECTED_HEAD:
        raise ValueError("recorded mxd revision differs from pinned revision")
    if mxd is not None:
        if git(mxd, "rev-parse", "HEAD") != EXPECTED_HEAD:
            raise ValueError("mxd checkout revision differs from the recorded revision")
        current_status = git(mxd, "status", "--porcelain=v1")
        if current_status != manifest["source_worktree_status_final"]:
            raise ValueError("mxd checkout status differs from the recorded status")

    for source in manifest["inputs"]:
        snapshot = evidence / source["snapshot"]
        actual = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        if actual != source["sha256"]:
            raise ValueError(f"source snapshot hash mismatch: {source['path']}")
        if mxd is not None:
            live = hashlib.sha256((mxd / source["path"]).read_bytes()).hexdigest()
            if live != source["sha256"]:
                raise ValueError(f"live source hash mismatch: {source['path']}")

    observed_names = set()
    total = 0
    for record in manifest["commands"]:
        name = record["log"].removesuffix(".log")
        observed_names.add(name)
        expected_command, expected_counts = EXPECTED_COMMANDS[name]
        if (
            record["command"] != expected_command
            or record["passed_tests"] != expected_counts
        ):
            raise ValueError(f"unexpected command or expected counts: {name}")
        if (
            record["exit_file"] != f"{name}.exit"
            or (evidence / record["exit_file"]).read_text().strip() != "0"
        ):
            raise ValueError(f"test command failed: {name}")
        log = (evidence / record["log"]).read_text()
        counts = [int(value) for value in RESULT.findall(log)]
        if counts != expected_counts or "test result: FAILED" in log:
            raise ValueError(f"test counts differ from claim: {name}")
        total += sum(counts)

    if (
        observed_names != set(EXPECTED_COMMANDS)
        or manifest["total_passed_tests"] != total
        or total != 55
    ):
        raise ValueError("test command set or total differs from claim")
    return total


def main() -> None:
    """Parse paths, verify the run and print its count.

    Example: ``verify_mxd_reconciliation.py evidence`` prints 55.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--mxd", type=Path, help="also check a live mxd checkout")
    args = parser.parse_args()
    print(f"verified {verify(args.evidence, args.mxd)} mxd tests at {EXPECTED_HEAD}")


if __name__ == "__main__":
    main()
