"""Verify the portable C11 native 1.9 login-extras correction corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

BASE = "20e891a059de7dd9dec5a657d7099570987d860d"
FINAL = "cb907885cc2a61df2d708f38a3cf42da85c2a016"
UNIT = "mxd-c11-full-20261113-1922.service"
INVOCATION = "892ffaf601ef444c9d0e421f760e795b"
CORPUS = "evidence/gap-remediation/2026-11-13/mxd-login-extras-01"
PINNED = {
    "candidate.patch": "04668a20d58222e8d80df57baebb10f255e3800c7f1a54f200225b3568eafd47",
    "source-sha256.txt": "4b0982cf1cb8c79d8a358fde1e34ad025c14c9383a00237041661162f2bc8cda",
    "changed-paths.txt": "5d15f97e1965840adf7e32f9dc90c8c793e7113c0599c2c765a34dc63424799f",
    "full/run-full.sh": "3156b45b3a87be6f0ff90f116d5e2550cfe40081ffcc89fc56e75ae44c343084",
}
COUNTS = (
    (565, 565, 0),
    (569, 569, 0),
    (551, 551, 0),
    (3, 3, 0),
    (69, 69, 1),
    (8, 8, 0),
    (7, 7, 0),
)
FOCUSED = {
    "focused-final-router": 12,
    "focused-final-bdd": (6, 9),
    "focused-policy": 18,
    "focused-config": 5,
    "focused-cli": 4,
}
EXITS = (
    "check-fmt-final",
    "lint-4",
    "markdown",
    "focused-final-router",
    "focused-final-bdd",
    "focused-policy",
    "focused-config",
    "focused-cli",
)


def sha256(path: Path) -> str:
    """Hash a frozen file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def properties(path: Path) -> dict[str, str]:
    """Parse retained systemd property lines without querying the current host."""
    return dict(line.split("=", 1) for line in path.read_text().splitlines())


def check_inventory(evidence: Path) -> None:
    """Check every entry and reject missing, extra, repeated, or unsafe names."""
    listed: set[Path] = set()
    for line in (evidence / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or relative in listed:
            raise ValueError("unsafe or repeated checksum path")
        listed.add(relative)
        if sha256(evidence / relative) != digest:
            raise ValueError(f"checksum mismatch: {name}")
    actual = {p.relative_to(evidence) for p in evidence.rglob("*") if p.is_file()}
    if listed != actual - {Path("SHA256SUMS")}:
        raise ValueError("checksum inventory differs")
    for name, digest in PINNED.items():
        if sha256(evidence / name) != digest:
            raise ValueError(f"pinned correction input differs: {name}")


def source_contract(evidence: Path) -> tuple[set[str], dict[str, str]]:
    """Bind the pinned patch and source digest list to all 28 snapshots."""
    manifest = json.loads((evidence / "manifest.json").read_text())
    if (
        manifest.get("schema"),
        manifest.get("mxd_base"),
        manifest.get("mxd_commit"),
    ) != (1, BASE, FINAL):
        raise ValueError("mxd source revisions differ")
    if (
        manifest.get("source_only_kani") is not True
        or manifest.get("native_parity_complete") is not False
    ):
        raise ValueError("proof or native-parity scope differs")
    paths = (evidence / "changed-paths.txt").read_text().splitlines()
    if len(paths) != 28 or len(set(paths)) != 28 or paths != sorted(paths):
        raise ValueError("changed source path set differs")
    expected: dict[str, str] = {}
    for line in (evidence / "source-sha256.txt").read_text().splitlines():
        digest, path = line.split("  ", 1)
        if path in expected:
            raise ValueError("duplicate source hash path")
        expected[path] = digest
    if set(paths) != set(expected):
        raise ValueError("changed path and source hash sets differ")
    patch_paths = re.findall(
        r"^diff --git a/(.+?) b/\1$",
        (evidence / "candidate.patch").read_text(),
        re.MULTILINE,
    )
    if set(patch_paths) != set(paths) or len(patch_paths) != len(paths):
        raise ValueError("patch path set differs")
    snapshots = manifest.get("source_snapshots")
    if not isinstance(snapshots, list) or len(snapshots) != len(paths):
        raise ValueError("source snapshot manifest differs")
    entries = {item["path"]: item["sha256"] for item in snapshots}
    if len(entries) != len(paths) or set(entries) != set(paths):
        raise ValueError("source snapshot path set differs")
    for path in paths:
        if (
            entries[path] != expected[path]
            or sha256(evidence / "snapshots" / path) != expected[path]
        ):
            raise ValueError(f"source snapshot digest differs: {path}")
    codec = (evidence / "snapshots/src/wireframe/compat_policy/mod.rs").read_text()
    if "const OPAQUE_LOGIN_FIELD_161: [u8; 2] = [0, 0];" not in codec:
        raise ValueError("two-byte field 161 contract missing")
    return set(paths), expected


def gate_contract(evidence: Path) -> None:
    """Read gate exits, profile counts, doctests, and retained unit identity."""
    for name in EXITS:
        if (evidence / f"{name}.exit").read_text().strip() != "0":
            raise ValueError(f"scoped gate exit differs: {name}")
    for name, count in FOCUSED.items():
        summaries = re.findall(
            r"test result: ok\. (\d+) passed; 0 failed;",
            (evidence / f"{name}.log").read_text(),
        )
        expected = (count,) if isinstance(count, int) else count
        if tuple(map(int, summaries)) != expected:
            raise ValueError(f"focused test count differs: {name}")
    fmt = (evidence / "check-fmt-final.log").read_text()
    lint = (evidence / "lint-4.log").read_text()
    markdown = (evidence / "markdown.log").read_text()
    if "cargo fmt --all -- --check" not in fmt or "files left unchanged" not in fmt:
        raise ValueError("format gate transcript differs")
    if "cargo clippy" not in lint or "whitaker --all" not in lint:
        raise ValueError("lint gate transcript differs")
    if (
        "Summary: 0 error(s)" not in markdown
        or "All diagrams validated successfully" not in markdown
    ):
        raise ValueError("Markdown gate transcript differs")
    script = (evidence / "full/run-full.sh").read_text()
    required = (
        "export CARGO_NET_OFFLINE=true",
        "export CARGO_BUILD_JOBS=1",
        "export NEXTEST_TEST_THREADS=2",
        'export PG_EMBED_ROOT="$base/root"',
        "export PG_RUNTIME_DIR=/var/tmp/pg-embed-1000/install",
        "unset PG_DATA_DIR RUSTFLAGS CARGO_ENCODED_RUSTFLAGS",
        "test-rstest-bdd-ui: export CARGO_TARGET_DIR :=",
        "--no-print-directory",
        ' test > "$base/full.log"',
    )
    if not all(value in script for value in required):
        raise ValueError("controlled full-gate command or environment differs")
    full = (evidence / "full/full.log").read_text()
    counts = tuple(
        tuple(map(int, row))
        for row in re.findall(
            r"Summary \[.*?\] (\d+) tests run: (\d+) passed, (\d+) skipped", full
        )
    )
    if counts != COUNTS:
        raise ValueError("seven nextest profile summaries differ")
    if (
        "test result: ok. 7 passed; 0 failed; 0 ignored" not in full
        or "test result: ok. 5 passed; 0 failed; 4 ignored" not in full
    ):
        raise ValueError("doctest summaries differ")
    initial = properties(evidence / "full/unit-initial-props.txt")
    final = properties(evidence / "full/unit-final-props.txt")
    terminal = properties(evidence / "full/terminal-mainpid.txt")
    for props in (initial, final, terminal):
        if props.get("Id") != UNIT or props.get("InvocationID") != INVOCATION:
            raise ValueError("retained unit identity differs")
    if not all(
        final.get(key) == value
        for key, value in {
            "ActiveState": "active",
            "SubState": "exited",
            "Type": "oneshot",
            "TimeoutStartUSec": "40min",
            "TimeoutStopUSec": "30s",
            "RemainAfterExit": "yes",
            "Result": "success",
            "ExecMainCode": "1",
            "ExecMainStatus": "0",
        }.items()
    ):
        raise ValueError("retained unit-derived exit differs")
    if (
        terminal.get("MainPID") != "0"
        or terminal.get("Result") != "success"
        or terminal.get("ExecMainStatus") != "0"
    ):
        raise ValueError("retained terminal process state differs")
    if (evidence / "full/full.exit").read_text().strip() != "0":
        raise ValueError("full gate script exit differs")
    manifest = json.loads((evidence / "manifest.json").read_text())
    if (
        manifest.get("full_unit") != UNIT
        or manifest.get("invocation_id") != INVOCATION
        or manifest.get("controlled_test_threads") != 2
    ):
        raise ValueError("manifest unit or controlled thread count differs")


def verify(evidence: Path, mxd: Path | None = None) -> tuple[int, int]:
    """Verify the portable package and optionally compare the live mxd tree."""
    check_inventory(evidence)
    paths, digests = source_contract(evidence)
    gate_contract(evidence)
    if mxd is not None:
        head = subprocess.check_output(
            ["git", "-C", str(mxd), "rev-parse", "HEAD"], text=True
        ).strip()
        status = subprocess.check_output(
            ["git", "-C", str(mxd), "status", "--porcelain=v1", "--untracked-files=no"],
            text=True,
        )
        if head != FINAL or status.strip():
            raise ValueError("live mxd revision or tracked source differs")
        patch = subprocess.check_output(
            ["git", "-C", str(mxd), "diff", BASE, FINAL, "--binary"]
        )
        if patch != (evidence / "candidate.patch").read_bytes():
            raise ValueError("live mxd patch differs")
        for path in paths:
            if sha256(mxd / path) != digests[path]:
                raise ValueError(f"live mxd source digest differs: {path}")
    return len(COUNTS), 2


def main() -> None:
    """Run default offline verification or add a live mxd checkout comparison."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence",
        type=Path,
        default=Path(__file__).resolve().parents[1] / CORPUS,
    )
    parser.add_argument("--mxd", type=Path)
    args = parser.parse_args()
    profiles, doctest_groups = verify(args.evidence, args.mxd)
    print(f"verified {profiles} nextest profiles and {doctest_groups} doctest groups")


if __name__ == "__main__":
    main()
