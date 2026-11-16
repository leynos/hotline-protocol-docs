"""Verify C2 mxd limit witnesses from frozen source and test transcripts.

Example: ``python3 scripts/verify_mxd_limits.py`` followed by the corpus
directory, ``evidence/gap-remediation/2026-11-13/mxd-limits-01``.
"""

import hashlib
import json
import re
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # reads Git, no shell
import typing as typ
from pathlib import Path

from script_cli import run

type Manifest = dict[str, typ.Any]

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
FOCUSED_TOTAL = 44  # the sum of GREEN_COUNTS, as the manifest also reports


def sha256(path: Path) -> str:
    """Hash one frozen input.

    Example: an unchanged snapshot matches its manifest digest.

    Returns
    -------
    str
        The hexadecimal SHA-256 digest of the file's bytes.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(message: str) -> typ.NoReturn:
    """Stop verification with the failed check's message.

    Parameters
    ----------
    message : str
        The text that names the failed check.

    Raises
    ------
    ValueError
        Always, with ``message``.
    """
    raise ValueError(message)


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
        The standard output of the command, as text.
    """
    return subprocess.check_output(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv, no shell
        ["git", "-C", str(mxd), *arguments],  # ruff: ignore[start-process-with-partial-path]  # git is resolved from PATH, as the original argv was
        text=True,
    )


def check_candidate(evidence: Path, manifest: Manifest) -> None:
    """Check the base revision, the uncommitted state and the candidate patch.

    Parameters
    ----------
    evidence : pathlib.Path
        The exported corpus.
    manifest : Manifest
        The parsed ``manifest.json``.
    """
    if manifest["mxd_base"] != BASE:
        fail("unexpected mxd base revision")
    if manifest["candidate_committed"] is not False:
        fail("candidate must remain uncommitted")
    if (
        sha256(evidence / manifest["candidate_patch"])
        != (manifest["candidate_patch_sha256"])
    ):
        fail("candidate patch hash mismatch")


def check_sources(evidence: Path, manifest: Manifest, mxd: Path | None) -> None:
    """Check each frozen source snapshot, and each final source in the live checkout.

    Parameters
    ----------
    evidence : pathlib.Path
        The exported corpus.
    manifest : Manifest
        The parsed ``manifest.json``.
    mxd : pathlib.Path | None
        The live checkout, or ``None`` when only the corpus is compared.
    """
    for source in manifest["sources"]:
        frozen = evidence / source["snapshot"]
        if sha256(frozen) != source["sha256"]:
            fail(f"source snapshot hash mismatch: {source['path']}")
        if mxd is None or source["phase"] != "final":
            continue
        if sha256(mxd / source["path"]) != source["sha256"]:
            fail(f"live source hash mismatch: {source['path']}")


def check_live(mxd: Path, manifest: Manifest) -> None:
    """Check that the live checkout is still at the recorded revision and status.

    Parameters
    ----------
    mxd : pathlib.Path
        The live mxd checkout.
    manifest : Manifest
        The parsed ``manifest.json``.
    """
    head = git(mxd, "rev-parse", "HEAD").strip()
    if head != manifest["mxd_head"]:
        fail("live mxd revision differs")
    status = git(mxd, "status", "--porcelain=v1").strip("\n")
    if status != manifest["candidate_git_status"]:
        fail("live candidate status differs")


def check_red(evidence: Path) -> None:
    """Check that the red run failed on the boundary witnesses.

    Parameters
    ----------
    evidence : pathlib.Path
        The exported corpus.
    """
    red = (evidence / "red-framed.log").read_text()
    if (evidence / "red-framed.exit").read_text().strip() != "101":
        fail("red run did not fail with Cargo test status 101")
    if "test result: FAILED. 1 passed; 2 failed" not in red:
        fail("red boundary counts differ")
    for case in ("case_2_first_logical_byte", "case_3_logical_ceiling"):
        if not re.search(rf"test .*{case} \.\.\. FAILED", red):
            fail(f"missing red witness: {case}")
    if "case_1_physical_ceiling ... ok" not in red:
        fail("red control at physical ceiling did not pass")


def check_green(evidence: Path) -> int:
    """Check the focused green runs and the green boundary witnesses.

    Parameters
    ----------
    evidence : pathlib.Path
        The exported corpus.

    Returns
    -------
    int
        The number of focused tests that the green runs report.
    """
    total = 0
    for name, expected in GREEN_COUNTS.items():
        log = (evidence / f"{name}.log").read_text()
        if (evidence / f"{name}.exit").read_text().strip() != "0":
            fail(f"focused command failed: {name}")
        if not re.search(rf"test result: ok\. {expected} passed; 0 failed;", log):
            fail(f"focused test count differs: {name}")
        total += expected
    framed = (evidence / "green-framed-final.log").read_text()
    for case in GREEN_CASES:
        if not re.search(rf"test .*{case} \.\.\. ok", framed):
            fail(f"missing green boundary witness: {case}")
    return total


def check_gate(evidence: Path, manifest: Manifest) -> None:
    """Check the interrupted gate and the environment-blocked full gate.

    Parameters
    ----------
    evidence : pathlib.Path
        The exported corpus.
    manifest : Manifest
        The parsed ``manifest.json``.
    """
    if (evidence / "make-test.exit").exists():
        fail("interrupted pre-restart gate must remain without an exit")
    if manifest["interrupted_run"]["disposition"] != "unknown after host restart":
        fail("interrupted gate disposition differs")
    for name in ("make-test-resumed", "make-test-serialized"):
        if (evidence / f"{name}.exit").read_text().strip() != "2":
            fail(f"full gate exit differs: {name}")
        log = (evidence / f"{name}.log").read_text()
        if "ld terminated with signal 11" not in log:
            fail(f"linker failure missing: {name}")
    if not manifest["full_gate_status"].startswith("environment-blocked"):
        fail("full gate status differs")


def verify(evidence: Path, mxd: Path | None = None) -> int:
    """Check red/green results and source snapshots, returning green count.

    Example: the accepted focused run returns 44.

    Parameters
    ----------
    evidence : pathlib.Path
        The exported corpus.
    mxd : pathlib.Path | None
        The live mxd checkout to compare with, or ``None``.

    Returns
    -------
    int
        The number of focused tests that the green runs report.
    """
    manifest = json.loads((evidence / "manifest.json").read_text())
    check_candidate(evidence, manifest)
    check_sources(evidence, manifest, mxd)
    if mxd is not None:
        check_live(mxd, manifest)
    check_red(evidence)
    total = check_green(evidence)
    if total != FOCUSED_TOTAL or manifest["focused_passed"] != total:
        fail("focused total differs")
    check_gate(evidence, manifest)
    return total


def show(evidence: str, *, mxd: str | None = None) -> None:
    """Check an exported corpus, optionally against a live mxd, and print the count.

    Parameters
    ----------
    evidence : str
        The exported corpus directory.
    mxd : str | None
        The live mxd checkout to compare with, or none.
    """
    count = verify(Path(evidence), None if mxd is None else Path(mxd))
    print(f"verified {count} focused mxd limit tests")


def main() -> None:
    """Check an exported corpus, with optional live mxd comparison.

    Example: ``verify_mxd_limits.py evidence`` prints the passing count.
    """
    run(show, __doc__)


if __name__ == "__main__":
    main()
