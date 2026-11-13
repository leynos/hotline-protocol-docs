"""Verify the portable C5 mxd correction acceptance corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

BASE = "2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131"
WATCHDOG_COMMIT = "50360bebff2c79a54272453ce734251be619c274"
FINAL = "481294915b48f4db06943c8af86cf31b7e47597a"
INVOCATION = "9fa39dd46475409997f67334987f67a6"
UNIT = "mxd-c5-full-20261113-1619.service"
PREFIX = "evidence/gap-remediation/2026-11-13/mxd-correction-01/"
CHANGED = {
    "src/db/migrations_tests.rs": "047a5672988d447763b7bc1f496816a38496b629ff970b69bf6301122ed05121",
    "src/wireframe/codec/mod.rs": "27bbaed8cdb079897dea1df2ec9a404982a3f50ec698c8e5cfaa394d29830f6d",
    "src/wireframe/codec/framed_tests.rs": "baeda0e0889489d9d80c7d1334d785634614a29c40bc3d7b439fe7f78776e79d",
}
FINAL_CONTEXT = (
    "src/wireframe/codec/framed.rs",
    "src/wireframe/codec/physical_frame.rs",
    "src/transaction/frame.rs",
    "src/transaction/mod.rs",
)
COUNTS = (544, 548, 530, 3, 69, 8, 7)
SKIPS = (0, 0, 0, 0, 1, 0, 0)


def sha256(path: Path) -> str:
    """Hash an evidence file or live source file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_sums(evidence: Path) -> None:
    """Check every root-relative package entry, including isolated copies."""
    listed: set[Path] = set()
    for line in (evidence / "SHA256SUMS").read_text().splitlines():
        digest, relative = line.split("  ", 1)
        if not relative.startswith(PREFIX):
            raise ValueError("checksum path leaves acceptance package")
        part = Path(relative.removeprefix(PREFIX))
        if ".." in part.parts or part.is_absolute() or part in listed:
            raise ValueError("duplicate or unsafe checksum path")
        listed.add(part)
        if sha256(evidence / part) != digest:
            raise ValueError(f"checksum mismatch: {part}")
    actual = {p.relative_to(evidence) for p in evidence.rglob("*") if p.is_file()}
    if listed != actual - {Path("SHA256SUMS")}:
        raise ValueError("checksum inventory differs")


def properties(path: Path) -> dict[str, str]:
    """Read retained systemd properties from a frozen transcript."""
    return dict(line.split("=", 1) for line in path.read_text().splitlines())


def verify(evidence: Path, mxd: Path | None = None) -> tuple[int, int]:
    """Validate source, gate and unit evidence without needing mxd."""
    check_sums(evidence)
    manifest = json.loads((evidence / "manifest.json").read_text())
    if (
        manifest["mxd_base"] != BASE
        or manifest["watchdog_test_commit"] != WATCHDOG_COMMIT
        or manifest["codec_commit"] != FINAL
        or manifest["mxd_final_head"] != FINAL
        or manifest["candidate_source_hashes"] != CHANGED
    ):
        raise ValueError("unexpected source revision or changed-source digest")
    expected = {f"inputs/base/{path}.txt" for path in CHANGED}
    expected |= {f"inputs/final/{path}.txt" for path in (*CHANGED, *FINAL_CONTEXT)}
    if set(manifest["source_snapshots"]) != expected:
        raise ValueError("source snapshot inventory differs")
    for name, digest in manifest["source_snapshots"].items():
        if sha256(evidence / name) != digest:
            raise ValueError(f"source snapshot hash mismatch: {name}")
    for path, digest in CHANGED.items():
        if manifest["source_snapshots"][f"inputs/final/{path}.txt"] != digest:
            raise ValueError(f"tested source digest differs: {path}")
    if mxd is not None:
        head = subprocess.check_output(
            ["git", "-C", str(mxd), "rev-parse", "HEAD"], text=True
        ).strip()
        status = subprocess.check_output(
            ["git", "-C", str(mxd), "status", "--porcelain=v1", "--untracked-files=no"],
            text=True,
        )
        if head != FINAL or status.strip():
            raise ValueError("live mxd revision or tracked tree differs")
        for name in expected:
            if name.startswith("inputs/final/"):
                source = name.removeprefix("inputs/final/").removesuffix(".txt")
                if sha256(mxd / source) != manifest["source_snapshots"][name]:
                    raise ValueError(f"live source hash mismatch: {source}")

    results = manifest["results"]
    focused = (evidence / "focused-tests.log").read_text()
    if results["focused_tests"] != {"exit": 0, "passed": 5} or not re.search(
        r"test result: ok\. 5 passed; 0 failed;", focused
    ):
        raise ValueError("focused test result differs")
    if (
        "migration_watchdog_cancels_work_and_reports_the_applied_timeout ... ok"
        not in focused
    ):
        raise ValueError("watchdog control missing")
    lint = (evidence / "fmt-lint-summary.txt").read_text()
    if results["format_lint"] != {"exit": 0} or "\nexit=0\n" not in lint:
        raise ValueError("format/lint gate differs")

    gate = results["full_gate"]
    if (
        gate["unit"] != UNIT
        or gate["invocation_id"] != INVOCATION
        or gate["unit_result"] != "success"
        or gate["unit_derived_exit"] != 0
        or tuple(gate["nextest_passed_by_profile"]) != COUNTS
        or gate["nextest_verification_skipped"] != 1
        or gate["doctests"]
        != {"mxd_concurrency_passed": 7, "mxd_passed": 5, "mxd_ignored": 4}
    ):
        raise ValueError("full gate manifest differs")
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
            raise ValueError("managed unit identity or timers differ")
    final_result = {
        "ActiveState": "active",
        "SubState": "exited",
        "MainPID": "0",
        "Result": "success",
        "ExecMainCode": "1",
        "ExecMainStatus": "0",
    }
    if not final_result.items() <= final.items():
        raise ValueError("retained unit result differs")
    if (evidence / "full-test.exit").read_text().strip() != "0":
        raise ValueError("unit-derived exit differs")
    provenance = (evidence / "exit-provenance.txt").read_text()
    if not all(
        x in provenance
        for x in (UNIT, "Result=success", "ExecMainStatus=0", "MainPID=0")
    ):
        raise ValueError("unit exit provenance differs")
    summary = (evidence / "full-gate-summary.txt").read_text()
    if f"source_sha256={manifest['raw_local_log_sha256']['full']}" not in summary:
        raise ValueError("full gate source provenance differs")
    profiles = re.findall(
        r"^\d+:\s+Summary \[[^\]]+\] (\d+) tests run: (\d+) passed, (\d+) skipped$",
        summary,
        re.MULTILINE,
    )
    if profiles != [(str(n), str(n), str(skip)) for n, skip in zip(COUNTS, SKIPS)]:
        raise ValueError("nextest profile summaries differ")
    docs = re.findall(
        r"^\d+: test result: ok\. (\d+) passed; 0 failed; (\d+) ignored;",
        summary,
        re.MULTILINE,
    )
    if docs != [("7", "0"), ("5", "4")] or summary.count("all doctests ran") != 2:
        raise ValueError("doctest summaries differ")
    if "No Kani run in C5" not in manifest["limitations"]:
        raise ValueError("Kani limitation missing")
    return len(profiles), len(docs)


def main() -> None:
    """Verify an exported package, optionally comparing live mxd."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--mxd", type=Path)
    args = parser.parse_args()
    profiles, docs = verify(args.evidence, args.mxd)
    print(f"verified {profiles} profiles and {docs} doctest summaries at {FINAL}")


if __name__ == "__main__":
    main()
