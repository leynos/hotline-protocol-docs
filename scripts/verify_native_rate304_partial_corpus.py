"""Check the corpus inventory, the as-run sources and the scoped runtime identity."""

import typing as typ

from verify_native_rate304_partial_core import (
    CASES,
    CONTROL_PORT,
    DATA,
    PLAN,
    RUNNER,
    need,
    read,
    sha,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

SOURCE_CLOSURE_COUNT = 35  # the files of the as-run source closure
EMULATOR_PID = 1956254  # the emulator process of the failed first pair
EMULATOR_NETNS_INODE = 4026533669  # the network namespace of that emulator
OWNED_IMAGE_INODE = 2226400708  # the inode of the owned working image


def inventory(corpus: Path) -> dict:
    """Check that the corpus holds exactly the manifest's files, with their hashes.

    Returns
    -------
    dict
        The parsed manifest.
    """
    manifest = read(corpus / "manifest.json")
    need(manifest["schema"] == "native-rate304-first-pair-01", "Corpus schema differs")
    need(manifest["case_status"] == "failed", "Case status must remain failed")
    files = manifest["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(actual == set(files), "Corpus inventory differs")
    for name, digest in files.items():
        need(sha(corpus / name) == digest, f"Corpus SHA differs: {name}")
    need(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{digest}  {name}" for name, digest in sorted(files.items())],
        "SHA256SUMS differs",
    )
    return manifest


def sources(raw: Path) -> None:
    """Check the as-run source closure, the helpers and the approved launch."""
    freeze = read(raw / "source-freeze.json")
    need(len(freeze["hashes"]) == SOURCE_CLOSURE_COUNT, "As-run source closure differs")
    for name, digest in freeze["hashes"].items():
        need(sha(raw / "sources" / name) == digest, f"As-run source differs: {name}")
    for name, digest in freeze["helper_hashes"].items():
        need(sha(raw / "helper-sources" / name) == digest, f"Helper differs: {name}")
    need(
        freeze["hashes"]["native_rate304_cases.py"] == CASES
        and freeze["hashes"]["native_rate304_control.py"] == RUNNER
        and sha(raw / "run-case-c107.sh")
        == "8a2f16948545742c82b2b87a387ce0cea5ae7cf624c061d0b7b944e152f18e79",
        "Approved runner or exact case launch differs",
    )


def scoped_identity(raw: Path) -> None:
    """Check the runtime identity, the fixed deadline and the failed unit."""
    runtime, receipt = read(raw / "runtime.json"), read(raw / "capture-ready.json")
    need(
        runtime["emulator_pid"] == receipt["emulator_pid"] == EMULATOR_PID
        and runtime["emulator_starttime"] == receipt["emulator_starttime"] == "7658344"
        and runtime["emulator_netns_inode"]
        == receipt["emulator_netns_inode"]
        == EMULATOR_NETNS_INODE
        and runtime["owned_working_image_inode"]
        == receipt["owned_working_image_inode"]
        == OWNED_IMAGE_INODE
        and runtime["native_data_sha256"] == DATA
        and runtime["full_file_baseline"] == "not_exercised"
        and receipt["deadline_utc"] == "2026-11-14T10:36:36.309570+00:00",
        "Runtime identity or fixed deadline differs",
    )
    need(
        sha(raw / "rate304-plan/plan.json") == PLAN
        and read(raw / "rate304-plan/plan.json")["endpoint"]["port"] == CONTROL_PORT,
        "As-run case plan differs",
    )
    props = (raw / "case-unit-terminal.txt").read_text()
    need(
        "ActiveState=failed" in props
        and "ExecMainStatus=1" in props
        and "NetworkNamespacePath=/proc/1956254/ns/net" in props,
        "Failed unit provenance differs",
    )
