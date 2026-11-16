"""Check the corpus inventory, the frozen sources and the identity of the run."""

import typing as typ

from verify_native_roster_overlap_common import (
    A7,
    BASE,
    DEADLINE,
    EXE,
    INODE,
    NS,
    ORACLE,
    PID,
    ROM,
    RSRC,
    SCHEMA,
    SOURCE_HEAD,
    START,
    need,
    read,
    sha,
)

if typ.TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType

# The manifest and the checksum file describe the inventory, so they are not in it.
RECORD_FILES = 2
MAX_CORPUS_FILES = 250
MAX_CORPUS_BYTES = 80 * 1024 * 1024
# The as-run directory that the B71 source hash record names for each source.
AS_RUN_SOURCE_ROOT = "/data/leynos/Projects/hotline-protocol-docs/scripts/"
# The active-users catalogue of the preparation has this many lines.
ACTIVE_USER_LINES = 2


def inventory(corpus: Path) -> dict[str, typ.Any]:
    """Check the corpus identity, its file inventory, its size and its hashes.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The parsed ``manifest.json``.
    """
    manifest = read(corpus / "manifest.json")
    need(
        corpus.name == SCHEMA
        and manifest["schema"] == SCHEMA
        and manifest["source_head"] == SOURCE_HEAD
        and manifest["profile"] == "control-only"
        and manifest["full_file_baseline"] == "not_exercised"
        and manifest["actual_runner_proc_netns"]
        == "not_observed_before_two_second_exit",
        "Corpus identity or profile differs",
    )
    files = manifest["files"]
    actual = {
        str(p.relative_to(corpus))
        for p in corpus.rglob("*")
        if p.is_file() and p.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(
        actual == set(files) and len(files) + RECORD_FILES <= MAX_CORPUS_FILES,
        "Corpus inventory differs",
    )
    need(
        sum((corpus / name).stat().st_size for name in files) <= MAX_CORPUS_BYTES,
        "Corpus size bound exceeded",
    )
    for name, expected in files.items():
        need(sha(corpus / name) == expected, f"Corpus SHA differs: {name}")
    need(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{digest}  {name}" for name, digest in sorted(files.items())],
        "SHA256SUMS differs",
    )
    return manifest


def _check_freeze(
    raw: Path, freeze: dict[str, typ.Any], manifest: dict[str, typ.Any]
) -> None:
    """Check the as-run source HEAD, the frozen source snapshot and the B71 record.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw`` directory of the corpus.
    freeze : dict[str, typing.Any]
        The parsed ``raw/source-freeze.json``.
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json``.
    """
    need(freeze["source_head"] == SOURCE_HEAD, "As-run source HEAD differs")
    need(
        {name: sha(raw / "sources" / name) for name in freeze["files"]}
        == freeze["files"],
        "Frozen source snapshot differs",
    )
    need(
        freeze["files"]["native_roster_overlap_cases.py"] == manifest["cases_sha256"]
        and freeze["files"]["native_roster_overlap_control.py"]
        == manifest["controller_sha256"]
        and freeze["files"]["native_control_readiness.py"]
        == manifest["readiness_sha256"]
        and (raw / "b71-source.sha256").read_text().splitlines()
        == [
            f"{freeze['files'][name]}  {AS_RUN_SOURCE_ROOT}{name}"
            for name in (
                "native_roster_overlap_cases.py",
                "native_roster_overlap_control.py",
            )
        ],
        "B71 source hash record differs",
    )


def source_gate(
    corpus: Path, manifest: dict[str, typ.Any], modules: tuple[ModuleType, ...]
) -> None:
    """Check the frozen sources and the prepared source plan of the corpus.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json``.
    modules : tuple[types.ModuleType, ...]
        The frozen modules from :func:`verify_native_roster_overlap_common.frozen`.
    """
    raw = corpus / "raw"
    freeze = read(raw / "source-freeze.json")
    _check_freeze(raw, freeze, manifest)
    control, cases, _, capture, _ = modules
    plan = control.prepared(raw / "roster-plan")
    need(
        sha(raw / "roster-plan/plan.json") == manifest["plan_sha256"]
        and plan == cases.source_plan(plan["environment"], cases.MAX_PORT)
        and plan["oracle_sha256"] == capture.ORACLE_SHA256 == ORACLE,
        "Prepared source plan differs",
    )


def _check_preparation(prep: dict[str, typ.Any]) -> None:
    """Check the stopped preparation against the pinned images and the catalogue.

    Parameters
    ----------
    prep : dict[str, typing.Any]
        The parsed ``preparation/preflight.json``.
    """
    need(
        prep["base.dsk"]["sha256"] == BASE
        and prep["working.dsk"]["sha256"] == BASE
        and prep["working.dsk"]["inode"] == INODE
        and prep["rom"]["sha256"] == ROM
        and prep["files"]["server-data"]["sha256"] == ORACLE
        and prep["files"]["server-rsrc"]["sha256"] == RSRC
        and prep["banned_absent"]
        and len(prep["active_users_catalog_lines"]) == ACTIVE_USER_LINES,
        "Stopped preparation differs",
    )


def _check_proof(proof: dict[str, typ.Any]) -> None:
    """Check the runtime proof names the emulator and the original services.

    Parameters
    ----------
    proof : dict[str, typing.Any]
        The parsed ``raw/runtime-proof.json``.
    """
    need(
        (
            proof["actual_pid"],
            proof["start_ticks"],
            proof["netns"],
            proof["image_inode"],
        )
        == (PID, START, NS, INODE)
        and proof["exe_sha256"] == EXE
        and proof["deadline_utc"] == DEADLINE
        and proof["fd6"].endswith("native-roster-overlap-01/working.dsk")
        and proof["fd16"].endswith("native-roster-overlap-01/lab-guest.pcap")
        and proof["original_pids"] == {"1099659": "767842", "1012834": "2357813"},
        "Actual emulator or original-service identity differs",
    )


def _check_receipt(receipt: dict[str, typ.Any], runtime: dict[str, typ.Any]) -> None:
    """Check the capture receipt against the runtime record and the emulator.

    Parameters
    ----------
    receipt : dict[str, typing.Any]
        The parsed ``raw/capture-ready.json``.
    runtime : dict[str, typing.Any]
        The parsed ``raw/runtime-asrun.json``.
    """
    need(
        receipt["emulator_pid"] == PID
        and str(receipt["emulator_starttime"]) == START
        and receipt["emulator_netns"] == NS
        and receipt["emulator_sha256"] == EXE
        and receipt["owned_working_image_inode"] == INODE
        and receipt["deadline_utc"] == DEADLINE
        and receipt["fixture_profile"] == "control-only"
        and receipt["full_file_baseline"] == "not_exercised"
        and receipt["source_a7_sha256"] == A7
        and receipt["ns_routes"] == []
        and receipt["primary_syn_count"] == 0
        and all(runtime[k] == receipt[k] for k in runtime),
        "Runtime/capture receipt identity differs",
    )


def _check_recorder(raw: Path, label: str) -> None:
    """Check the readiness record of one recorder.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw`` directory of the corpus.
    label : str
        The recorder name, which prefixes its readiness file.
    """
    ready = read(raw / f"{label}-ready.json")
    need(
        ready["deadline_utc"] == DEADLINE
        and ready["unit_properties"]["ActiveState"] == "active"
        and ready["unit_properties"]["KillMode"] == "control-group"
        and ready["header24"].startswith("d4c3b2a1"),
        f"{label} recorder readiness differs",
    )


def _check_routes(raw: Path) -> None:
    """Check that neither route table holds an entry.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw`` directory of the corpus.
    """
    need(
        read(raw / "route4.json") == [] and read(raw / "route6.json") == [],
        "Routes differ",
    )


def identity(corpus: Path) -> dict[str, typ.Any]:
    """Check the stopped preparation, the emulator identity and the recorders.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The parsed ``raw/capture-ready.json`` receipt.
    """
    raw = corpus / "raw"
    prep = read(corpus / "preparation/preflight.json")
    proof = read(raw / "runtime-proof.json")
    receipt = read(raw / "capture-ready.json")
    runtime = read(raw / "runtime-asrun.json")
    _check_preparation(prep)
    _check_proof(proof)
    _check_receipt(receipt, runtime)
    for label in ("host", "namespace"):
        _check_recorder(raw, label)
    _check_routes(raw)
    return receipt
