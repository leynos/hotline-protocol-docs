"""Verify the portable C11 native 1.9 login-extras correction corpus."""

import hashlib
import json
import re
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # the fixed argv runs git with no shell
import typing as typ
from pathlib import Path

from script_cli import run
from verify_mxd_login_extras_gates import (
    CONTROLLED_THREADS,
    COUNTS,
    EXITS,
    FOCUSED,
    INVOCATION,
    UNIT,
    gate_contract,
    properties,
    refuse,
)

# The gate checks live in verify_mxd_login_extras_gates. The names above stay
# importable from this module because the original defined them publicly. The
# consumers are scripts/tests/test_mxd_login_extras.py, which imports CORPUS and
# verify, and tests/test_peer_corpus_faults.py, which runs this file.
__all__ = [
    "BASE",
    "CONTROLLED_THREADS",
    "CORPUS",
    "COUNTS",
    "EXITS",
    "FINAL",
    "FOCUSED",
    "INVOCATION",
    "PINNED",
    "UNIT",
    "check_inventory",
    "gate_contract",
    "main",
    "properties",
    "refuse",
    "sha256",
    "show",
    "source_contract",
    "verify",
]

BASE = "20e891a059de7dd9dec5a657d7099570987d860d"
FINAL = "cb907885cc2a61df2d708f38a3cf42da85c2a016"
CORPUS = "evidence/gap-remediation/2026-11-13/mxd-login-extras-01"
PINNED = {
    "candidate.patch": (
        "04668a20d58222e8d80df57baebb10f255e3800c7f1a54f200225b3568eafd47"
    ),
    "source-sha256.txt": (
        "4b0982cf1cb8c79d8a358fde1e34ad025c14c9383a00237041661162f2bc8cda"
    ),
    "changed-paths.txt": (
        "5d15f97e1965840adf7e32f9dc90c8c793e7113c0599c2c765a34dc63424799f"
    ),
    "full/run-full.sh": (
        "3156b45b3a87be6f0ff90f116d5e2550cfe40081ffcc89fc56e75ae44c343084"
    ),
}
SOURCE_COUNT = 28  # the changed source paths in the pinned candidate patch


def sha256(path: Path) -> str:
    """Hash a frozen file.

    Parameters
    ----------
    path : pathlib.Path
        The file to hash.

    Returns
    -------
    str
        The lowercase hexadecimal SHA-256 digest of the file.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_text(mxd: Path, *args: str) -> str:
    """Return the text output of a Git command run in the live mxd checkout.

    Parameters
    ----------
    mxd : pathlib.Path
        The live mxd checkout.
    *args : str
        The Git arguments that follow ``-C`` and the checkout.

    Returns
    -------
    str
        The standard output of the command, decoded as text.
    """
    return subprocess.check_output(["git", "-C", str(mxd), *args], text=True)  # ruff: ignore[subprocess-without-shell-equals-true, start-process-with-partial-path]  # fixed argv, no shell


def git_bytes(mxd: Path, *args: str) -> bytes:
    """Return the raw output of a Git command run in the live mxd checkout.

    Parameters
    ----------
    mxd : pathlib.Path
        The live mxd checkout.
    *args : str
        The Git arguments that follow ``-C`` and the checkout.

    Returns
    -------
    bytes
        The standard output of the command, undecoded.
    """
    return subprocess.check_output(["git", "-C", str(mxd), *args])  # ruff: ignore[subprocess-without-shell-equals-true, start-process-with-partial-path]  # fixed argv, no shell


def check_inventory(evidence: Path) -> None:
    """Check every entry and reject missing, extra, repeated, or unsafe names.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.
    """
    listed: set[Path] = set()
    for line in (evidence / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        relative = Path(name)
        escapes = relative.is_absolute() or ".." in relative.parts
        if escapes or relative in listed:
            refuse("unsafe or repeated checksum path")
        listed.add(relative)
        if sha256(evidence / relative) != digest:
            refuse(f"checksum mismatch: {name}")
    actual = {p.relative_to(evidence) for p in evidence.rglob("*") if p.is_file()}
    if listed != actual - {Path("SHA256SUMS")}:
        refuse("checksum inventory differs")
    for name, digest in PINNED.items():
        if sha256(evidence / name) != digest:
            refuse(f"pinned correction input differs: {name}")


def check_revisions(manifest: dict[str, typ.Any]) -> None:
    """Check the recorded mxd revisions and the proof and parity scope.

    Parameters
    ----------
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json`` of the corpus.
    """
    if (
        manifest.get("schema"),
        manifest.get("mxd_base"),
        manifest.get("mxd_commit"),
    ) != (1, BASE, FINAL):
        refuse("mxd source revisions differ")
    if (
        manifest.get("source_only_kani") is not True
        or manifest.get("native_parity_complete") is not False
    ):
        refuse("proof or native-parity scope differs")


def read_changed_paths(evidence: Path) -> list[str]:
    """Read the 28 changed source paths and check that they are unique and sorted.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.

    Returns
    -------
    list[str]
        The changed source paths, in order.
    """
    paths = (evidence / "changed-paths.txt").read_text().splitlines()
    if len(paths) != SOURCE_COUNT or len(set(paths)) != SOURCE_COUNT:
        refuse("changed source path set differs")
    if paths != sorted(paths):
        refuse("changed source path set differs")
    return paths


def read_source_digests(evidence: Path) -> dict[str, str]:
    """Read the source digest list, rejecting a path that repeats.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, str]
        The recorded SHA-256 digest of each source path.
    """
    expected: dict[str, str] = {}
    for line in (evidence / "source-sha256.txt").read_text().splitlines():
        digest, path = line.split("  ", 1)
        if path in expected:
            refuse("duplicate source hash path")
        expected[path] = digest
    return expected


def check_patch_paths(evidence: Path, paths: list[str]) -> None:
    """Check that the candidate patch names exactly the changed source paths.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.
    paths : list[str]
        The changed source paths.
    """
    patch_paths = re.findall(
        r"^diff --git a/(.+?) b/\1$",
        (evidence / "candidate.patch").read_text(),
        re.MULTILINE,
    )
    if set(patch_paths) != set(paths) or len(patch_paths) != len(paths):
        refuse("patch path set differs")


def check_snapshots(
    evidence: Path,
    manifest: dict[str, typ.Any],
    paths: list[str],
    expected: dict[str, str],
) -> None:
    """Check that each snapshot matches its manifest entry and recorded digest.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json`` of the corpus.
    paths : list[str]
        The changed source paths.
    expected : dict[str, str]
        The recorded SHA-256 digest of each source path.
    """
    snapshots = manifest.get("source_snapshots")
    if not isinstance(snapshots, list) or len(snapshots) != len(paths):
        refuse("source snapshot manifest differs")
    entries = {item["path"]: item["sha256"] for item in snapshots}
    if len(entries) != len(paths) or set(entries) != set(paths):
        refuse("source snapshot path set differs")
    for path in paths:
        if (
            entries[path] != expected[path]
            or sha256(evidence / "snapshots" / path) != expected[path]
        ):
            refuse(f"source snapshot digest differs: {path}")


def source_contract(evidence: Path) -> tuple[set[str], dict[str, str]]:
    """Bind the pinned patch and source digest list to all 28 snapshots.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.

    Returns
    -------
    tuple[set[str], dict[str, str]]
        The changed source paths and the recorded digest of each.
    """
    manifest = json.loads((evidence / "manifest.json").read_text())
    check_revisions(manifest)
    paths = read_changed_paths(evidence)
    expected = read_source_digests(evidence)
    if set(paths) != set(expected):
        refuse("changed path and source hash sets differ")
    check_patch_paths(evidence, paths)
    check_snapshots(evidence, manifest, paths, expected)
    codec = (evidence / "snapshots/src/wireframe/compat_policy/mod.rs").read_text()
    if "const OPAQUE_LOGIN_FIELD_161: [u8; 2] = [0, 0];" not in codec:
        refuse("two-byte field 161 contract missing")
    return set(paths), expected


def check_live_mxd(
    mxd: Path,
    evidence: Path,
    paths: set[str],
    digests: dict[str, str],
) -> None:
    """Compare the live mxd checkout with the frozen revision and sources.

    Parameters
    ----------
    mxd : pathlib.Path
        The live mxd checkout.
    evidence : pathlib.Path
        The corpus directory.
    paths : set[str]
        The changed source paths.
    digests : dict[str, str]
        The recorded SHA-256 digest of each source path.
    """
    head = git_text(mxd, "rev-parse", "HEAD").strip()
    status = git_text(mxd, "status", "--porcelain=v1", "--untracked-files=no")
    if head != FINAL or status.strip():
        refuse("live mxd revision or tracked source differs")
    patch = git_bytes(mxd, "diff", BASE, FINAL, "--binary")
    if patch != (evidence / "candidate.patch").read_bytes():
        refuse("live mxd patch differs")
    for path in paths:
        if sha256(mxd / path) != digests[path]:
            refuse(f"live mxd source digest differs: {path}")


def verify(evidence: Path, mxd: Path | None = None) -> tuple[int, int]:
    """Verify the portable package and optionally compare the live mxd tree.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.
    mxd : pathlib.Path | None
        A live mxd checkout to compare with the corpus, if any.

    Returns
    -------
    tuple[int, int]
        The number of nextest profiles and the number of doctest groups.
    """
    check_inventory(evidence)
    paths, digests = source_contract(evidence)
    gate_contract(evidence)
    if mxd is not None:
        check_live_mxd(mxd, evidence, paths, digests)
    return len(COUNTS), 2


def show(*, evidence: str | None = None, mxd: str | None = None) -> None:
    """Verify a corpus and print its profile and doctest counts.

    Parameters
    ----------
    evidence : str | None
        The corpus directory; by default the retained corpus of this repository.
    mxd : str | None
        A live mxd checkout to compare with the corpus as well.
    """
    root = Path(__file__).resolve().parents[1]
    corpus = root / CORPUS if evidence is None else Path(evidence)
    profiles, doctest_groups = verify(corpus, None if mxd is None else Path(mxd))
    print(f"verified {profiles} nextest profiles and {doctest_groups} doctest groups")


def main() -> None:
    """Run default offline verification or add a live mxd checkout comparison."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
