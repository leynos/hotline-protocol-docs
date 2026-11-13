"""Verify C2 mxd limit witnesses from frozen source and test transcripts.

Example: python3 scripts/verify_mxd_limits.py ../mothra/evidence/gap-remediation/2026-11-13/mxd-limits-01
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

BASE = "2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131"
GREEN_COUNTS = {
    "green-framed-final": 17,
    "codec-tests": 21,
    "reader-tests": 3,
    "memory-tests": 3,
}
GREEN_CASES = (
    "case_1_physical_ceiling",
    "case_2_first_logical_byte",
    "case_3_logical_ceiling",
    "case_1_over_logical_limit",
    "case_2_overflow_word",
    "rejects_oversized_physical_fragment_before_buffering",
    "preassembled_constructor_keeps_logical_limit_and_length_checks",
)


def sha256(path: Path) -> str:
    """Hash one frozen input.

    Example: an unchanged snapshot matches its manifest digest.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(evidence: Path, mxd: Path | None = None) -> int:
    """Check red/green results and source snapshots, returning green count.

    Example: the accepted focused run returns 44.
    """
    manifest = json.loads((evidence / "manifest.json").read_text())
    if manifest["mxd_base"] != BASE:
        raise ValueError("unexpected mxd base revision")
    if manifest["candidate_committed"] is not False:
        raise ValueError("candidate must remain uncommitted")
    if (
        sha256(evidence / manifest["candidate_patch"])
        != manifest["candidate_patch_sha256"]
    ):
        raise ValueError("candidate patch hash mismatch")
    for source in manifest["sources"]:
        frozen = evidence / source["snapshot"]
        if sha256(frozen) != source["sha256"]:
            raise ValueError(f"source snapshot hash mismatch: {source['path']}")
        if (
            mxd is not None
            and source["phase"] == "final"
            and sha256(mxd / source["path"]) != source["sha256"]
        ):
            raise ValueError(f"live source hash mismatch: {source['path']}")

    if mxd is not None:
        head = subprocess.check_output(
            ["git", "-C", str(mxd), "rev-parse", "HEAD"], text=True
        ).strip()
        if head != manifest["mxd_head"]:
            raise ValueError("live mxd revision differs")
        status = subprocess.check_output(
            ["git", "-C", str(mxd), "status", "--porcelain=v1"], text=True
        ).strip("\n")
        if status != manifest["candidate_git_status"]:
            raise ValueError("live candidate status differs")

    red = (evidence / "red-framed.log").read_text()
    if (evidence / "red-framed.exit").read_text().strip() != "101":
        raise ValueError("red run did not fail with Cargo test status 101")
    if "test result: FAILED. 1 passed; 2 failed" not in red:
        raise ValueError("red boundary counts differ")
    for case in ("case_2_first_logical_byte", "case_3_logical_ceiling"):
        if not re.search(rf"test .*{case} \.\.\. FAILED", red):
            raise ValueError(f"missing red witness: {case}")
    if "case_1_physical_ceiling ... ok" not in red:
        raise ValueError("red control at physical ceiling did not pass")

    total = 0
    for name, expected in GREEN_COUNTS.items():
        log = (evidence / f"{name}.log").read_text()
        if (evidence / f"{name}.exit").read_text().strip() != "0":
            raise ValueError(f"focused command failed: {name}")
        if not re.search(rf"test result: ok\. {expected} passed; 0 failed;", log):
            raise ValueError(f"focused test count differs: {name}")
        total += expected
    framed = (evidence / "green-framed-final.log").read_text()
    for case in GREEN_CASES:
        if not re.search(rf"test .*{case} \.\.\. ok", framed):
            raise ValueError(f"missing green boundary witness: {case}")
    if total != 44 or manifest["focused_passed"] != total:
        raise ValueError("focused total differs")

    if (evidence / "make-test.exit").exists():
        raise ValueError("interrupted pre-restart gate must remain without an exit")
    if manifest["interrupted_run"]["disposition"] != "unknown after host restart":
        raise ValueError("interrupted gate disposition differs")
    for name in ("make-test-resumed", "make-test-serialized"):
        if (evidence / f"{name}.exit").read_text().strip() != "2":
            raise ValueError(f"full gate exit differs: {name}")
        if "ld terminated with signal 11" not in (evidence / f"{name}.log").read_text():
            raise ValueError(f"linker failure missing: {name}")
    if not manifest["full_gate_status"].startswith("environment-blocked"):
        raise ValueError("full gate status differs")
    return total


def main() -> None:
    """Check an exported corpus, with optional live mxd comparison.

    Example: ``verify_mxd_limits.py evidence`` prints the passing count.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--mxd", type=Path)
    args = parser.parse_args()
    print(f"verified {verify(args.evidence, args.mxd)} focused mxd limit tests")


if __name__ == "__main__":
    main()
