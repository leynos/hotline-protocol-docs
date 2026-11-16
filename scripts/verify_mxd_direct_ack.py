"""Verify the portable C7/C9 direct-reply acceptance corpus."""

import json
from pathlib import Path

from script_cli import run
from verify_mxd_direct_ack_common import (
    BASE,
    C8_FILES,
    COUNTS,
    FINAL,
    INVOCATION,
    PREFIX,
    SOURCE_FILES,
    UNIT,
    Manifest,
    check_sums,
    fail,
    git_object,
    properties,
    sha256,
)
from verify_mxd_direct_ack_gate import (
    check_capture,
    check_execution,
    check_live,
    check_log,
    check_unit,
)

# The test imports DEFAULT, PREFIX, sha256 and verify. The other names are kept
# importable because the original module, scripts/test_mxd_direct_ack.py, defined
# them at module level; the helper modules hold their definitions now.
__all__ = [
    "BASE",
    "COUNTS",
    "DEFAULT",
    "FINAL",
    "INVOCATION",
    "PREFIX",
    "UNIT",
    "check_c8",
    "check_sums",
    "main",
    "properties",
    "sha256",
    "verify",
]

DEFAULT = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/mxd-direct-ack-02"
)


def check_c8(evidence: Path) -> None:
    """Check the copied raw C8 corpus and its original local checksum list.

    Parameters
    ----------
    evidence : pathlib.Path
        The package directory, which holds ``c8``.
    """
    c8 = evidence / "c8"
    listed: set[Path] = set()
    for line in (c8 / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        part = Path(name)
        if part.is_absolute() or ".." in part.parts:
            fail("unsafe C8 checksum path")
        if part in listed:
            fail("unsafe C8 checksum path")
        listed.add(part)
        if sha256(c8 / part) != digest:
            fail(f"C8 checksum mismatch: {part}")
    actual = {p.relative_to(c8) for p in c8.rglob("*") if p.is_file()}
    if listed != actual - {Path("SHA256SUMS")} or len(actual) != C8_FILES:
        fail("C8 raw inventory differs")


def check_revisions(manifest: Manifest) -> None:
    """Check the base, final and source revisions of the manifest.

    Parameters
    ----------
    manifest : Manifest
        The parsed ``manifest.json``.
    """
    if (
        manifest["mxd_base"],
        manifest["mxd_final_head"],
        manifest["source_commit"],
    ) != (BASE, FINAL, FINAL):
        fail("source revisions differ")


def check_prior(evidence: Path, manifest: Manifest) -> tuple[Path, Manifest]:
    """Check the prior failed-gate package and the frozen candidate hashes.

    Parameters
    ----------
    evidence : pathlib.Path
        The package directory.
    manifest : Manifest
        The parsed ``manifest.json``.

    Returns
    -------
    tuple[pathlib.Path, dict[str, typing.Any]]
        The prior package directory and the frozen candidate source hashes.
    """
    prior = evidence.parent / "mxd-direct-ack-01"
    if (
        sha256(prior / "manifest.json")
        != manifest["prior_failed_evidence"]["manifest_sha256"]
    ):
        fail("prior failed-gate manifest differs")
    check_sums(prior, "evidence/gap-remediation/2026-11-13/mxd-direct-ack-01/")
    previous = json.loads((prior / "manifest.json").read_text())
    changed = manifest["candidate_source_hashes"]
    if changed != previous["candidate_source_hashes"] or len(changed) != SOURCE_FILES:
        fail("frozen candidate source hashes differ")
    for name, digest in changed.items():
        if sha256(prior / "inputs/candidate" / f"{name}.txt") != digest:
            fail(f"candidate snapshot differs: {name}")
    return prior, changed


def check_tree(evidence: Path, prior: Path, changed: Manifest) -> None:
    """Check the source tree inventory against the frozen candidate snapshots.

    Parameters
    ----------
    evidence : pathlib.Path
        The package directory.
    prior : pathlib.Path
        The prior package directory, which holds the snapshots.
    changed : dict[str, typing.Any]
        The frozen candidate source hashes.
    """
    tree_lines = (evidence / "source-tree.txt").read_text().splitlines()
    if len(tree_lines) != SOURCE_FILES:
        fail("source tree inventory differs")
    for line in tree_lines:
        mode_kind, name = line.split("\t", 1)
        mode, kind, blob_id = mode_kind.split()
        if mode != "100644" or kind != "blob":
            fail("unexpected source tree entry")
        if name not in changed:
            fail("unexpected source tree entry")
        data = (prior / "inputs/candidate" / f"{name}.txt").read_bytes()
        if git_object("blob", data) != blob_id:
            fail(f"committed blob differs: {name}")


def check_source(evidence: Path, prior: Path, manifest: Manifest) -> None:
    """Check the source commit object, its tree, its patch and its clean status.

    Parameters
    ----------
    evidence : pathlib.Path
        The package directory.
    prior : pathlib.Path
        The prior package directory, which holds the snapshots.
    manifest : Manifest
        The parsed ``manifest.json``.
    """
    commit = (evidence / "source-commit-object.txt").read_bytes()
    if (
        git_object("commit", commit) != FINAL
        or f"parent {BASE}\n".encode() not in commit
    ):
        fail("commit object or parent differs")
    check_tree(evidence, prior, manifest["candidate_source_hashes"])
    if (
        sha256(evidence / "source-base-to-commit.patch")
        != manifest["source_patch_sha256"]
    ):
        fail("base-to-commit patch differs")
    if (evidence / "source-tracked-status.txt").read_text():
        fail("private source was dirty after commit")


def verify(evidence: Path, mxd: Path | None = None) -> None:
    """Check provenance and gates without requiring a live mxd checkout.

    Parameters
    ----------
    evidence : pathlib.Path
        The package directory.
    mxd : pathlib.Path | None
        A live mxd checkout to compare as well, if any.
    """
    check_sums(evidence, PREFIX)
    check_c8(evidence)
    manifest = json.loads((evidence / "manifest.json").read_text())
    check_revisions(manifest)
    prior, changed = check_prior(evidence, manifest)
    check_source(evidence, prior, manifest)
    check_execution(evidence, manifest["execution"])
    check_unit(evidence)
    check_log(evidence, manifest["execution"])
    check_capture(evidence, manifest)
    if mxd is not None:
        check_live(mxd, changed)


def show(evidence: str = str(DEFAULT), *, mxd: str | None = None) -> None:
    """Verify a portable corpus or its live checkout.

    Parameters
    ----------
    evidence : str
        The corpus directory (default: the retained package).
    mxd : str | None
        A live mxd checkout to compare as well.
    """
    verify(Path(evidence), Path(mxd) if mxd is not None else None)
    print(f"verified seven profiles and two doctest groups at {FINAL}")


def main() -> None:
    """Verify the direct-reply acceptance corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
