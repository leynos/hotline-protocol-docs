"""Verify the portable C5 mxd correction acceptance corpus."""

import hashlib
import json
import re
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # reads Git, no shell
import typing as typ
from pathlib import Path

from script_cli import run

type Manifest = dict[str, typ.Any]

BASE = "2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131"
WATCHDOG_COMMIT = "50360bebff2c79a54272453ce734251be619c274"
FINAL = "481294915b48f4db06943c8af86cf31b7e47597a"
INVOCATION = "9fa39dd46475409997f67334987f67a6"
UNIT = "mxd-c5-full-20261113-1619.service"
PREFIX = "evidence/gap-remediation/2026-11-13/mxd-correction-01/"
CHANGED = {
    "src/db/migrations_tests.rs": (
        "047a5672988d447763b7bc1f496816a38496b629ff970b69bf6301122ed05121"
    ),
    "src/wireframe/codec/mod.rs": (
        "27bbaed8cdb079897dea1df2ec9a404982a3f50ec698c8e5cfaa394d29830f6d"
    ),
    "src/wireframe/codec/framed_tests.rs": (
        "baeda0e0889489d9d80c7d1334d785634614a29c40bc3d7b439fe7f78776e79d"
    ),
}
FINAL_CONTEXT = (
    "src/wireframe/codec/framed.rs",
    "src/wireframe/codec/physical_frame.rs",
    "src/transaction/frame.rs",
    "src/transaction/mod.rs",
)
COUNTS = (544, 548, 530, 3, 69, 8, 7)
SKIPS = (0, 0, 0, 0, 1, 0, 0)
DOCTEST_RUNS = 2  # the two doctest summaries that the full gate retains


def sha256(path: Path) -> str:
    """Hash an evidence file or live source file.

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


def check_sums(evidence: Path) -> None:
    """Check every root-relative package entry, including isolated copies.

    Parameters
    ----------
    evidence : pathlib.Path
        The exported package.
    """
    listed: set[Path] = set()
    for line in (evidence / "SHA256SUMS").read_text().splitlines():
        digest, relative = line.split("  ", 1)
        if not relative.startswith(PREFIX):
            fail("checksum path leaves acceptance package")
        part = Path(relative.removeprefix(PREFIX))
        if ".." in part.parts or part.is_absolute():
            fail("duplicate or unsafe checksum path")
        if part in listed:
            fail("duplicate or unsafe checksum path")
        listed.add(part)
        if sha256(evidence / part) != digest:
            fail(f"checksum mismatch: {part}")
    actual = {p.relative_to(evidence) for p in evidence.rglob("*") if p.is_file()}
    if listed != actual - {Path("SHA256SUMS")}:
        fail("checksum inventory differs")


def properties(path: Path) -> dict[str, str]:
    """Read retained systemd properties from a frozen transcript.

    Returns
    -------
    dict[str, str]
        The properties, keyed by name.
    """
    return dict(line.split("=", 1) for line in path.read_text().splitlines())


def check_pins(manifest: Manifest) -> None:
    """Check the pinned revisions and the changed-source digests.

    Parameters
    ----------
    manifest : Manifest
        The parsed ``manifest.json``.
    """
    pins = (
        ("mxd_base", BASE),
        ("watchdog_test_commit", WATCHDOG_COMMIT),
        ("codec_commit", FINAL),
        ("mxd_final_head", FINAL),
        ("candidate_source_hashes", CHANGED),
    )
    for key, expected in pins:
        if manifest[key] != expected:
            fail("unexpected source revision or changed-source digest")


def snapshot_names() -> set[str]:
    """Name the frozen base and final snapshots that the manifest must list.

    Returns
    -------
    set[str]
        The manifest keys of the base and final source snapshots.
    """
    expected = {f"inputs/base/{path}.txt" for path in CHANGED}
    expected |= {f"inputs/final/{path}.txt" for path in (*CHANGED, *FINAL_CONTEXT)}
    return expected


def check_snapshots(evidence: Path, manifest: Manifest, expected: set[str]) -> None:
    """Check the snapshot inventory, each snapshot's bytes and the tested digests.

    Parameters
    ----------
    evidence : pathlib.Path
        The exported package.
    manifest : Manifest
        The parsed ``manifest.json``.
    expected : set[str]
        The snapshot names that the manifest must list.
    """
    if set(manifest["source_snapshots"]) != expected:
        fail("source snapshot inventory differs")
    for name, digest in manifest["source_snapshots"].items():
        if sha256(evidence / name) != digest:
            fail(f"source snapshot hash mismatch: {name}")
    for path, digest in CHANGED.items():
        if manifest["source_snapshots"][f"inputs/final/{path}.txt"] != digest:
            fail(f"tested source digest differs: {path}")


def check_live(mxd: Path, manifest: Manifest, expected: set[str]) -> None:
    """Check that the live checkout is at the final revision, with a clean tree.

    Parameters
    ----------
    mxd : pathlib.Path
        The live mxd checkout.
    manifest : Manifest
        The parsed ``manifest.json``.
    expected : set[str]
        The snapshot names, whose final entries are compared with the checkout.
    """
    head = git(mxd, "rev-parse", "HEAD").strip()
    status = git(mxd, "status", "--porcelain=v1", "--untracked-files=no")
    if head != FINAL or status.strip():
        fail("live mxd revision or tracked tree differs")
    for name in expected:
        if name.startswith("inputs/final/"):
            source = name.removeprefix("inputs/final/").removesuffix(".txt")
            if sha256(mxd / source) != manifest["source_snapshots"][name]:
                fail(f"live source hash mismatch: {source}")


def check_tests(evidence: Path, results: Manifest) -> None:
    """Check the focused test run, the watchdog control and the format gate.

    Parameters
    ----------
    evidence : pathlib.Path
        The exported package.
    results : Manifest
        The ``results`` section of ``manifest.json``.
    """
    focused = (evidence / "focused-tests.log").read_text()
    if results["focused_tests"] != {"exit": 0, "passed": 5} or not re.search(
        r"test result: ok\. 5 passed; 0 failed;", focused
    ):
        fail("focused test result differs")
    if (
        "migration_watchdog_cancels_work_and_reports_the_applied_timeout ... ok"
        not in focused
    ):
        fail("watchdog control missing")
    lint = (evidence / "fmt-lint-summary.txt").read_text()
    if results["format_lint"] != {"exit": 0} or "\nexit=0\n" not in lint:
        fail("format/lint gate differs")


def check_full_gate(gate: Manifest) -> None:
    """Check the full gate's unit, invocation, counts and doctest facts.

    Parameters
    ----------
    gate : Manifest
        The ``full_gate`` section of ``results``.
    """
    if gate["unit"] != UNIT:
        fail("full gate manifest differs")
    if gate["invocation_id"] != INVOCATION:
        fail("full gate manifest differs")
    if gate["unit_result"] != "success":
        fail("full gate manifest differs")
    if gate["unit_derived_exit"] != 0:
        fail("full gate manifest differs")
    if tuple(gate["nextest_passed_by_profile"]) != COUNTS:
        fail("full gate manifest differs")
    if gate["nextest_verification_skipped"] != 1:
        fail("full gate manifest differs")
    if gate["doctests"] != {
        "mxd_concurrency_passed": 7,
        "mxd_passed": 5,
        "mxd_ignored": 4,
    }:
        fail("full gate manifest differs")


def check_unit(evidence: Path) -> None:
    """Check the managed unit's identity, timers, result and exit provenance.

    Parameters
    ----------
    evidence : pathlib.Path
        The exported package.
    """
    initial = properties(evidence / "unit-initial-props.txt")
    final = properties(evidence / "unit-final-props.txt")
    common = {
        "Id": UNIT,
        "InvocationID": INVOCATION,
        "Type": "oneshot",
        "TimeoutStartUSec": "40min",
        "TimeoutStopUSec": "30s",
        "RemainAfterExit": "yes",
    }
    for props in (initial, final):
        if not common.items() <= props.items():
            fail("managed unit identity or timers differ")
    final_result = {
        "ActiveState": "active",
        "SubState": "exited",
        "MainPID": "0",
        "Result": "success",
        "ExecMainCode": "1",
        "ExecMainStatus": "0",
    }
    if not final_result.items() <= final.items():
        fail("retained unit result differs")
    if (evidence / "full-test.exit").read_text().strip() != "0":
        fail("unit-derived exit differs")
    provenance = (evidence / "exit-provenance.txt").read_text()
    if not all(
        x in provenance
        for x in (UNIT, "Result=success", "ExecMainStatus=0", "MainPID=0")
    ):
        fail("unit exit provenance differs")


def check_summary(evidence: Path, manifest: Manifest) -> tuple[list, list]:
    """Check the full gate's nextest and doctest summaries against the corpus.

    Parameters
    ----------
    evidence : pathlib.Path
        The exported package.
    manifest : Manifest
        The parsed ``manifest.json``.

    Returns
    -------
    tuple[list, list]
        The nextest profile matches and the doctest matches, in that order.
    """
    summary = (evidence / "full-gate-summary.txt").read_text()
    if f"source_sha256={manifest['raw_local_log_sha256']['full']}" not in summary:
        fail("full gate source provenance differs")
    profiles = re.findall(
        r"^\d+:\s+Summary \[[^\]]+\] (\d+) tests run: (\d+) passed, (\d+) skipped$",
        summary,
        re.MULTILINE,
    )
    if profiles != [
        (str(n), str(n), str(skip)) for n, skip in zip(COUNTS, SKIPS, strict=True)
    ]:
        fail("nextest profile summaries differ")
    docs = re.findall(
        r"^\d+: test result: ok\. (\d+) passed; 0 failed; (\d+) ignored;",
        summary,
        re.MULTILINE,
    )
    if docs != [("7", "0"), ("5", "4")] or summary.count("all doctests ran") != (
        DOCTEST_RUNS
    ):
        fail("doctest summaries differ")
    return profiles, docs


def verify(evidence: Path, mxd: Path | None = None) -> tuple[int, int]:
    """Validate source, gate and unit evidence without needing mxd.

    Parameters
    ----------
    evidence : pathlib.Path
        The exported package.
    mxd : pathlib.Path | None
        The live mxd checkout to compare with, or ``None``.

    Returns
    -------
    tuple[int, int]
        The number of nextest profile summaries and of doctest summaries.
    """
    check_sums(evidence)
    manifest = json.loads((evidence / "manifest.json").read_text())
    check_pins(manifest)
    expected = snapshot_names()
    check_snapshots(evidence, manifest, expected)
    if mxd is not None:
        check_live(mxd, manifest, expected)
    results = manifest["results"]
    check_tests(evidence, results)
    check_full_gate(results["full_gate"])
    check_unit(evidence)
    profiles, docs = check_summary(evidence, manifest)
    if "No Kani run in C5" not in manifest["limitations"]:
        fail("Kani limitation missing")
    return len(profiles), len(docs)


def show(evidence: str, *, mxd: str | None = None) -> None:
    """Verify an exported package, optionally against a live mxd checkout.

    Parameters
    ----------
    evidence : str
        The exported package directory.
    mxd : str | None
        The live mxd checkout to compare with, or none.
    """
    profiles, docs = verify(Path(evidence), None if mxd is None else Path(mxd))
    print(f"verified {profiles} profiles and {docs} doctest summaries at {FINAL}")


def main() -> None:
    """Verify an exported package, optionally comparing live mxd."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
