"""Verify the portable C7/C9 direct-reply acceptance corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

BASE = "481294915b48f4db06943c8af86cf31b7e47597a"
FINAL = "20e891a059de7dd9dec5a657d7099570987d860d"
UNIT = "mxd-c9-full-20261113-1835.service"
INVOCATION = "cb3d33916da34bcb863e8185b15cd417"
PREFIX = "evidence/gap-remediation/2026-11-13/mxd-direct-ack-02/"
COUNTS = [
    (557, 557, 0),
    (561, 561, 0),
    (543, 543, 0),
    (3, 3, 0),
    (69, 69, 1),
    (8, 8, 0),
    (7, 7, 0),
]
DEFAULT = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/mxd-direct-ack-02"
)


def sha256(path: Path) -> str:
    """Hash an evidence or source file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_sums(evidence: Path, prefix: str) -> None:
    """Check a complete root-relative package inventory."""
    listed: set[Path] = set()
    for line in (evidence / "SHA256SUMS").read_text().splitlines():
        digest, relative = line.split("  ", 1)
        if not relative.startswith(prefix):
            raise ValueError("checksum path leaves package")
        part = Path(relative.removeprefix(prefix))
        if part.is_absolute() or ".." in part.parts or part in listed:
            raise ValueError("unsafe or duplicate checksum path")
        listed.add(part)
        if sha256(evidence / part) != digest:
            raise ValueError(f"checksum mismatch: {part}")
    actual = {p.relative_to(evidence) for p in evidence.rglob("*") if p.is_file()}
    if listed != actual - {Path("SHA256SUMS")}:
        raise ValueError("checksum inventory differs")


def check_c8(evidence: Path) -> None:
    """Check the copied raw C8 corpus and its original local checksum list."""
    c8 = evidence / "c8"
    listed: set[Path] = set()
    for line in (c8 / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        part = Path(name)
        if part.is_absolute() or ".." in part.parts or part in listed:
            raise ValueError("unsafe C8 checksum path")
        listed.add(part)
        if sha256(c8 / part) != digest:
            raise ValueError(f"C8 checksum mismatch: {part}")
    actual = {p.relative_to(c8) for p in c8.rglob("*") if p.is_file()}
    if listed != actual - {Path("SHA256SUMS")} or len(actual) != 18:
        raise ValueError("C8 raw inventory differs")


def properties(path: Path) -> dict[str, str]:
    """Read retained systemd properties."""
    return dict(line.split("=", 1) for line in path.read_text().splitlines())


def verify(evidence: Path, mxd: Path | None = None) -> None:
    """Check provenance and gates without requiring a live mxd checkout."""
    check_sums(evidence, PREFIX)
    check_c8(evidence)
    manifest = json.loads((evidence / "manifest.json").read_text())
    if (
        manifest["mxd_base"],
        manifest["mxd_final_head"],
        manifest["source_commit"],
    ) != (BASE, FINAL, FINAL):
        raise ValueError("source revisions differ")
    prior = evidence.parent / "mxd-direct-ack-01"
    if (
        sha256(prior / "manifest.json")
        != manifest["prior_failed_evidence"]["manifest_sha256"]
    ):
        raise ValueError("prior failed-gate manifest differs")
    check_sums(prior, "evidence/gap-remediation/2026-11-13/mxd-direct-ack-01/")
    previous = json.loads((prior / "manifest.json").read_text())
    changed = manifest["candidate_source_hashes"]
    if changed != previous["candidate_source_hashes"] or len(changed) != 19:
        raise ValueError("frozen candidate source hashes differ")
    for name, digest in changed.items():
        if sha256(prior / "inputs/candidate" / f"{name}.txt") != digest:
            raise ValueError(f"candidate snapshot differs: {name}")
    commit = (evidence / "source-commit-object.txt").read_bytes()
    object_id = hashlib.sha1(
        b"commit " + str(len(commit)).encode() + b"\0" + commit
    ).hexdigest()
    if object_id != FINAL or f"parent {BASE}\n".encode() not in commit:
        raise ValueError("commit object or parent differs")
    tree_lines = (evidence / "source-tree.txt").read_text().splitlines()
    if len(tree_lines) != 19:
        raise ValueError("source tree inventory differs")
    for line in tree_lines:
        mode_kind, name = line.split("\t", 1)
        mode, kind, blob_id = mode_kind.split()
        if mode != "100644" or kind != "blob" or name not in changed:
            raise ValueError("unexpected source tree entry")
        data = (prior / "inputs/candidate" / f"{name}.txt").read_bytes()
        actual = hashlib.sha1(
            b"blob " + str(len(data)).encode() + b"\0" + data
        ).hexdigest()
        if actual != blob_id:
            raise ValueError(f"committed blob differs: {name}")
    if (
        sha256(evidence / "source-base-to-commit.patch")
        != manifest["source_patch_sha256"]
    ):
        raise ValueError("base-to-commit patch differs")
    if (evidence / "source-tracked-status.txt").read_text():
        raise ValueError("private source was dirty after commit")
    gate = manifest["execution"]
    if (
        gate["unit"],
        gate["invocation_id"],
        gate["unit_derived_exit"],
        gate["nextest_test_threads"],
        gate["pg_data_dir"],
    ) != (UNIT, INVOCATION, 0, 2, "unset"):
        raise ValueError("controlled execution differs")
    if gate["cargo_net_offline"] is not True or gate["cargo_build_jobs"] != 1:
        raise ValueError("offline or single-job control differs")
    script = (evidence / "run-full.sh").read_text()
    for required in (
        "NEXTEST_TEST_THREADS=2",
        "CARGO_NET_OFFLINE=true",
        "CARGO_BUILD_JOBS=1",
        "unset PG_DATA_DIR",
        "PG_EMBED_ROOT=",
        "PG_RUNTIME_DIR=/var/tmp/pg-embed-1000/install",
        "test-rstest-bdd-ui: export CARGO_TARGET_DIR",
    ):
        if required not in script:
            raise ValueError(f"missing execution control: {required}")
    initial = properties(evidence / "unit-initial-props.txt")
    final = properties(evidence / "unit-final-props.txt")
    for record in (initial, final):
        if (
            not {
                "Id": UNIT,
                "InvocationID": INVOCATION,
                "Type": "oneshot",
                "TimeoutStartUSec": "40min",
                "TimeoutStopUSec": "30s",
                "RemainAfterExit": "yes",
            }.items()
            <= record.items()
        ):
            raise ValueError("unit identity or timers differ")
    if (
        not {
            "ActiveState": "active",
            "SubState": "exited",
            "Result": "success",
            "ExecMainCode": "1",
            "ExecMainStatus": "0",
            "MainPID": "0",
        }.items()
        <= final.items()
    ):
        raise ValueError("retained unit does not prove exit zero")
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
    if counts != COUNTS or docs != [(7, 0), (5, 4)]:
        raise ValueError("suite or doctest summary differs")
    if sha256(evidence / "full.log") != gate["full_log_sha256"]:
        raise ValueError("raw full log digest differs")
    capture = (evidence / "watch-capture.jsonl").read_text().splitlines()
    if (
        not json.loads(capture[-1])["stop_requested"]
        or len("\n".join(capture)) >= 8_000_000
    ):
        raise ValueError("watcher termination or size differs")
    if "No Kani/native peer run" not in manifest["limitations"]:
        raise ValueError("unrun proof limitation missing")
    if mxd is not None:
        head = subprocess.check_output(
            ["git", "-C", str(mxd), "rev-parse", "HEAD"], text=True
        ).strip()
        dirty = subprocess.check_output(
            ["git", "-C", str(mxd), "status", "--porcelain=v1", "--untracked-files=no"],
            text=True,
        ).strip()
        if head != FINAL or dirty:
            raise ValueError("live mxd revision or tracked tree differs")
        for name, digest in changed.items():
            if sha256(mxd / name) != digest:
                raise ValueError(f"live source differs: {name}")


class FaultControls(unittest.TestCase):
    """Show that plausible forged acceptance records are rejected."""

    def setUp(self) -> None:
        """Copy the small corpus for an isolated mutation."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.evidence = Path(self.temp.name) / "mxd-direct-ack-02"
        shutil.copytree(DEFAULT, self.evidence)
        shutil.copytree(
            DEFAULT.parent / "mxd-direct-ack-01",
            self.evidence.parent / "mxd-direct-ack-01",
        )

    def rewrite_sums(self) -> None:
        """Keep checksums valid so tests reach semantic checks."""
        root = self.evidence
        files = sorted(
            p for p in root.rglob("*") if p.is_file() and p != root / "SHA256SUMS"
        )
        (root / "SHA256SUMS").write_text(
            "".join(f"{sha256(p)}  {PREFIX}{p.relative_to(root)}\n" for p in files)
        )

    def test_corpus_passes_offline(self) -> None:
        """Verify the unchanged exported corpus."""
        verify(self.evidence)

    def test_forged_unit_exit_is_rejected(self) -> None:
        """Reject a falsely reported successful managed unit."""
        path = self.evidence / "unit-final-props.txt"
        path.write_text(
            path.read_text().replace("ExecMainStatus=0", "ExecMainStatus=2")
        )
        self.rewrite_sums()
        with self.assertRaisesRegex(ValueError, "retained unit"):
            verify(self.evidence)

    def test_missing_suite_is_rejected(self) -> None:
        """Reject a manifest with an omitted nextest profile."""
        path = self.evidence / "full.log"
        lines = path.read_text().splitlines()
        path.write_text("\n".join(x for x in lines if "561 tests run:" not in x) + "\n")
        manifest_path = self.evidence / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["execution"]["full_log_sha256"] = sha256(path)
        manifest_path.write_text(json.dumps(manifest) + "\n")
        self.rewrite_sums()
        with self.assertRaisesRegex(ValueError, "suite or doctest"):
            verify(self.evidence)

    def test_source_hash_mismatch_is_rejected(self) -> None:
        """Reject a candidate hash that differs from the frozen source."""
        path = self.evidence / "manifest.json"
        manifest = json.loads(path.read_text())
        name = next(iter(manifest["candidate_source_hashes"]))
        manifest["candidate_source_hashes"][name] = "0" * 64
        path.write_text(json.dumps(manifest) + "\n")
        self.rewrite_sums()
        with self.assertRaisesRegex(ValueError, "frozen candidate"):
            verify(self.evidence)


def main() -> None:
    """Verify a portable corpus or its live checkout."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path, nargs="?", default=DEFAULT)
    parser.add_argument("--mxd", type=Path)
    args = parser.parse_args()
    verify(args.evidence, args.mxd)
    print(f"verified seven profiles and two doctest groups at {FINAL}")


if __name__ == "__main__":
    main()
