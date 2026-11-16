"""Gates on the corpus inventory and on the approved sources, before any import."""

import os
from pathlib import Path

from verify_native_path_fields_constants import (
    APPROVED_MODULES,
    CASE_FRAMES,
    CASE_REQUESTS,
    CASE_VIEWS,
    CASES,
    CONTROL,
    HELPER_APPROVAL,
    HELPER_MODULES,
    MUTATION_COUNT,
    NAME_PARTS,
    PREFIX,
    READINESS_ACTIONS,
    SOURCE_APPROVAL,
)
from verify_native_path_fields_core import need, pins, read, sha


def _portable(corpus: Path) -> None:
    """Refuse a corpus root that is a link, or any link below it."""
    need(corpus.is_dir() and not corpus.is_symlink(), "Corpus root is a symlink")
    for root, dirs, files in os.walk(corpus, followlinks=False):
        for name in (*dirs, *files):
            need(
                not (Path(root) / name).is_symlink(),
                f"Corpus symlink is not portable: {Path(root) / name}",
            )


def _scope(manifest: dict) -> None:
    """Check the manifest records the completed case and its counts."""
    need(
        manifest["case_status"] == "completed"
        and manifest["readiness_status"] == "completed"
        and manifest["readiness_actions"] == READINESS_ACTIONS
        and manifest["case_request_count"] == CASE_REQUESTS
        and manifest["mutation_count"] == MUTATION_COUNT
        and manifest["case_frames"] == CASE_FRAMES
        and manifest["case_views"] == CASE_VIEWS,
        "Corpus scope differs",
    )


def _inventory(corpus: Path, files: dict) -> None:
    """Check the files on disk are the manifest's files, with its digests."""
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(actual == set(files), "Corpus inventory differs")
    for name, digest in files.items():
        need(
            not Path(name).is_absolute()
            and ".." not in Path(name).parts
            and sha(corpus / name) == digest,
            f"Corpus file differs: {name}",
        )


def _sums(corpus: Path, files: dict) -> None:
    """Check the root-relative SHA256SUMS file lists every corpus file once."""
    expected = {**files, "manifest.json": sha(corpus / "manifest.json")}
    lines = (corpus / "SHA256SUMS").read_text().splitlines()
    need(
        len(lines) == len(expected)
        and set(lines)
        == {f"{digest}  {PREFIX}{name}" for name, digest in expected.items()},
        "Root-relative SHA inventory differs",
    )


def inventory(corpus: Path) -> dict:
    """Gate the corpus tree, its manifest and its checksum file.

    Returns
    -------
    dict
        The manifest of the corpus.
    """
    _portable(corpus)
    manifest = read(corpus / "manifest.json")
    _scope(manifest)
    files = manifest["files"]
    _inventory(corpus, files)
    _sums(corpus, files)
    return manifest


def _approvals(prep: Path) -> tuple[dict[str, str], dict[str, str]]:
    """Check the approval pins by digest, then parse them.

    Returns
    -------
    tuple[dict[str, str], dict[str, str]]
        The pinned source closure and the pinned helper modules.
    """
    source_pin = prep / "approved-source-closure.sha256"
    helper_pin = prep / "approved-helpers.sha256"
    need(
        sha(source_pin) == SOURCE_APPROVAL and sha(helper_pin) == HELPER_APPROVAL,
        "Trusted source approval changed before import",
    )
    return pins(source_pin), pins(helper_pin)


def _pin_names(approved: dict[str, str], helpers: dict[str, str]) -> None:
    """Check the counts, the names and the owned modules of the approved pins."""
    need(
        len(approved) == APPROVED_MODULES
        and len(helpers) == HELPER_MODULES
        and all(
            name.startswith("scripts/")
            and len(Path(name).parts) == NAME_PARTS
            and Path(name).suffix == ".py"
            for name in (*approved, *helpers)
        )
        and approved["scripts/native_path_fields_cases.py"] == CASES
        and approved["scripts/native_path_fields_control.py"] == CONTROL,
        "Trusted source names/ownership differ",
    )


def _frozen_folders(
    epoch: Path, prep: Path, approved: dict[str, str], helpers: dict[str, str]
) -> None:
    """Check that each frozen and proposed folder holds exactly the pinned files."""
    for folder, expected in (
        (epoch / "sources", set(approved)),
        (epoch / "helper-sources", set(helpers)),
        (prep / "proposed-sources", set(approved) | set(helpers)),
    ):
        need(
            folder.is_dir()
            and not folder.is_symlink()
            and {f"scripts/{path.name}" for path in folder.iterdir()} == expected
            and all(
                path.is_file() and not path.is_symlink() for path in folder.iterdir()
            ),
            "Frozen source directory inventory differs",
        )


def _closure(
    epoch: Path, prep: Path, approved: dict[str, str], helpers: dict[str, str]
) -> None:
    """Check the frozen closure against the approval, then each pinned byte."""
    freeze = read(epoch / "source-freeze.json")
    proposed = read(prep / "proposed-source-closure.json")["hashes"]
    need(
        freeze["hashes"]
        == proposed
        == {Path(name).name: digest for name, digest in approved.items()}
        and freeze["helper_hashes"]
        == {Path(name).name: digest for name, digest in helpers.items()},
        "Frozen closure differs from trusted approval",
    )
    for name, digest in (*approved.items(), *helpers.items()):
        basename = Path(name).name
        need(
            sha(epoch / "sources" / basename) == digest
            if name in approved
            else sha(epoch / "helper-sources" / basename) == digest,
            f"Approved frozen byte differs: {name}",
        )
        need(
            sha(prep / "proposed-sources" / basename) == digest,
            f"Approved proposed byte differs: {name}",
        )


def trusted_sources(corpus: Path) -> None:
    """Authenticate approved names and bytes before importing retained Python."""
    prep, epoch = corpus / "raw/preparation", corpus / "raw/epoch"
    approved, helpers = _approvals(prep)
    _pin_names(approved, helpers)
    _frozen_folders(epoch, prep, approved, helpers)
    _closure(epoch, prep, approved, helpers)
