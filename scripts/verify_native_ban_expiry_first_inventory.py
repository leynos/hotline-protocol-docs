"""Check the corpus inventory, frozen sources and raw receipts of the first epoch."""

import importlib
import sys
import typing as typ

from verify_native_ban_expiry_first_common import need, read, sha
from verify_native_ban_expiry_first_wire import (
    INODE,
    MAX_CORPUS_BYTES,
    MAX_FILES,
    NS,
    ORACLE,
    ORIGINAL_USERS,
    SCHEMA,
)

if typ.TYPE_CHECKING:
    import types
    from pathlib import Path


def inventory(corpus: Path) -> dict:
    """Check the manifest, the inventory and the hashes of the first corpus.

    Parameters
    ----------
    corpus : Path
        The corpus directory.

    Returns
    -------
    dict
        The manifest of the corpus.
    """
    manifest = read(corpus / "manifest.json")
    need(
        corpus.name == SCHEMA
        and manifest["schema"] == SCHEMA
        and manifest["profile"] == "control-only"
        and manifest["full_file_baseline"] == "not_exercised"
        and manifest["source_protocol_head"]
        == "e23c4e03102d04c8724d09bca715c74862134cb9"
        and manifest["source_controller_sha256"]
        == "f5e46930ec466030dca62ee12ca79f8af856aa29ef88de34afaac50f4b0f0210"
        and manifest["source_cases_sha256"]
        == "b55180ed77b4eb780e2a28decbb113db3442f939410a0c78e1ce9567296e3bc2"
        and manifest["guest_pcap_scope"].startswith("prefix snapshot"),
        "Corpus profile or source identity differs",
    )
    files = manifest["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(
        actual == set(files) and len(files) + 2 <= MAX_FILES,
        "Corpus inventory differs",
    )
    need(
        sum((corpus / name).stat().st_size for name in files) <= MAX_CORPUS_BYTES,
        "Corpus exceeds size bound",
    )
    for name, expected in files.items():
        need(sha(corpus / name) == expected, f"Corpus SHA differs: {name}")
    need(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{digest}  {name}" for name, digest in sorted(files.items())],
        "SHA256SUMS differs",
    )
    return manifest


def source_gate(corpus: Path, manifest: dict) -> None:
    """Check the frozen as-run sources and the stopped preparation baseline.

    Parameters
    ----------
    corpus : Path
        The corpus directory.
    manifest : dict
        The manifest of the corpus, which names the source identity.
    """
    sources = corpus / "sources/protocol"
    frozen = read(corpus / "sources/asrun-source-freeze.json")
    closure = read(corpus / "sources/dependency-closure.json")
    need(
        frozen["source_head"] == manifest["source_protocol_head"]
        and closure["hashes"]["native_ban_expiry_control.py"]
        == manifest["source_controller_sha256"]
        and closure["hashes"]["native_ban_expiry_cases.py"]
        == manifest["source_cases_sha256"]
        and closure["module_count"] == len(closure["hashes"])
        and set(frozen["hashes"]).issubset(closure["hashes"]),
        "Frozen as-run source set differs",
    )
    for name, digest in closure["hashes"].items():
        need(sha(sources / name) == digest, "Frozen source snapshot differs")
    for name, digest in frozen["hashes"].items():
        need(sha(sources / name) == digest, "As-run B68 source differs")
    prep = read(corpus / "preparation/preflight.json")
    need(
        prep["banned_absent"]
        and prep["owned_account_names_absent"]
        and prep["original_user_count"] == ORIGINAL_USERS
        and prep["files"]["server-data"]["sha256"] == ORACLE
        and prep["working.dsk"]["inode"] == INODE,
        "Stopped preparation source or baseline differs",
    )


def frozen_modules(corpus: Path) -> tuple[types.ModuleType, ...]:
    """Import the frozen controller and the capture modules of the first corpus.

    Parameters
    ----------
    corpus : Path
        The corpus directory whose frozen sources are imported.

    Returns
    -------
    tuple[types.ModuleType, ...]
        The control, readiness, capture and TCP modules, in that order.
    """
    sys.dont_write_bytecode = True
    path = str(corpus / "sources/protocol")
    if path not in sys.path:
        sys.path.insert(0, path)
    control = importlib.import_module("native_ban_expiry_control")
    base = importlib.import_module("native_control_readiness")
    capture = importlib.import_module("protocol_capture")
    tcp = importlib.import_module("pcap_tcp")
    return control, base, capture, tcp


def raw_gate(corpus: Path) -> Path:
    """Check the raw receipts of the first epoch against their freeze record.

    Parameters
    ----------
    corpus : Path
        The corpus directory.

    Returns
    -------
    Path
        The raw receipts directory.
    """
    raw = corpus / "raw"
    frozen = read(corpus / "raw-freeze.json")
    need(
        frozen["snapshot_scope"].startswith("first epoch raw receipts")
        and set(frozen["files"])
        == {str(p.relative_to(raw)) for p in raw.rglob("*") if p.is_file()},
        "Raw freeze inventory differs",
    )
    for name, meta in frozen["files"].items():
        path = raw / name
        need(
            path.stat().st_size == meta["copied_size"]
            and sha(path) == meta["sha256"]
            and meta["copied_size"] <= meta["source_size_after"],
            f"Raw source snapshot differs: {name}",
        )
    need(
        frozen["files"]["lab-guest.pcap"]["copied_size"]
        == frozen["files"]["lab-guest.pcap"]["source_size_after"],
        "Guest snapshot was not stable at copy boundary",
    )
    return raw


def failed_launch_gate(corpus: Path, raw: Path) -> None:
    """Check that the failed first launch was followed by the corrected launch.

    Parameters
    ----------
    corpus : Path
        The corpus directory.
    raw : Path
        The raw receipts directory.
    """
    failed = read(raw / "results-first/summary.json")
    guard = read(raw / "results-first/guard-zero/report.json")
    c76 = (corpus / "operator/c76-unit-final.txt").read_text()
    c77 = (corpus / "operator/c77-unit-final.txt").read_text()
    need(
        failed["status"] == "failed"
        and "ConnectionRefusedError" in failed["error"]
        and set(failed["cases"]) == {"guard-zero"}
        and guard["status"] == "failed"
        and guard["completed_actions"] == 0
        and guard["events"] == guard["frames"] == []
        and (raw / "first.exit").read_text() == "1\n"
        and "NetworkNamespacePath=" in c76
        and "NetworkNamespacePath=/proc/774195/ns/net" not in c76
        and "Result=exit-code" in c76
        and "ExecMainStatus=1" in c76
        and "NetworkNamespacePath=/proc/774195/ns/net" in c77
        and "Result=success" in c77
        and "ExecMainStatus=0" in c77
        and (raw / "c77-runner-netns.txt").read_text() == NS + "\n"
        and read(raw / "c77-runner-ready.json")["netns"] == NS,
        "Failed C76 or corrected C77 launch identity differs",
    )
