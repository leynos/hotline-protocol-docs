"""Check the later corpus inventory, its prior witness and its frozen sources."""

import importlib
import json
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # the first witness is this repository's own verifier, launched by its path
import sys
import typing as typ
from pathlib import Path

from verify_native_ban_expiry_first_common import need, read, sha
from verify_native_ban_expiry_later_wire import (
    BASE,
    FIRST_CASES,
    FIRST_CONNECTIONS,
    MAX_CORPUS_BYTES,
    MAX_FILES,
    POST_SOURCES,
    ROM,
    SCHEMA,
    WORKING,
)

if typ.TYPE_CHECKING:
    import types


def inventory(corpus: Path, first: Path) -> dict:
    """Check the manifest, the inventory and the prior witness of the later corpus.

    Parameters
    ----------
    corpus : Path
        The later corpus directory.
    first : Path
        The first-epoch corpus, whose verifier is run as the prior witness.

    Returns
    -------
    dict
        The manifest of the later corpus.
    """
    m = read(corpus / "manifest.json")
    need(
        corpus.name == SCHEMA
        and m["schema"] == SCHEMA
        and m["profile"] == "control-only"
        and m["full_file_baseline"] == "not_exercised"
        and m["pre_window"] == "missed_no_probe"
        and m["exact_1800_boundary_proven"] is False
        and m["first_corpus_manifest_sha256"] == sha(first / "manifest.json")
        and m["first_corpus_sha256s_sha256"] == sha(first / "SHA256SUMS")
        and m["pre_controller_sha256"]
        == "6275f634be00487b7ba08415dea15b85aee0ed7218bc4f5ef99f3962971421b7"
        and m["post_controller_sha256"]
        == "7f58d3c6cf105bcd591910828000c24fca3110d90b9a0b08ba277b1d369b112d"
        and m["cleanup_sha256"]
        == "641a0c221b68bf1099df3e0f54e8fae51ccf649e176524a31f7d83dc9a315c40"
        and m["working_sha256"] == WORKING
        and m["immutable_base_sha256"] == BASE
        and m["rom_sha256"] == ROM,
        "Corpus profile, source or prior witness identity differs",
    )
    files = m["files"]
    actual = {
        str(p.relative_to(corpus))
        for p in corpus.rglob("*")
        if p.is_file() and p.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(
        actual == set(files) and len(files) + 2 <= MAX_FILES,
        "Corpus inventory differs",
    )
    need(
        sum((corpus / name).stat().st_size for name in files) <= MAX_CORPUS_BYTES,
        "Corpus size exceeds bound",
    )
    for name, digest in files.items():
        need(sha(corpus / name) == digest, f"Corpus SHA differs: {name}")
    need(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{digest}  {name}" for name, digest in sorted(files.items())],
        "SHA256SUMS differs",
    )
    first_result = json.loads(
        subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # the arguments are a fixed list with no shell, and the path is this module's sibling
            [
                sys.executable,
                str(Path(__file__).with_name("verify_native_ban_expiry_first.py")),
                str(first),
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    need(
        first_result["status"] == "verified_first_epoch_only"
        and first_result["cases"] == FIRST_CASES
        and first_result["connections"] == FIRST_CONNECTIONS
        and first_result["expiry_proven"] is False,
        "First-epoch witness differs",
    )
    return m


def source_gate(corpus: Path, manifest: dict) -> None:
    """Check the post-epoch source snapshot and the start-tick correction.

    Parameters
    ----------
    corpus : Path
        The later corpus directory.
    manifest : dict
        The manifest of the later corpus, which names the source identities.
    """
    pre = corpus / "raw/pre"
    post = corpus / "raw/post"
    old = (pre / "controller-before-starttick-fix.py.as-run.txt").read_text()
    new = (post / "sources/native_ban_expiry_control.py").read_text()
    original = '                receipt["emulator_starttime"],'
    corrected = '                int(str(receipt["emulator_starttime"])), '
    need(
        old.count(original) == 1
        and old.replace(original, corrected.rstrip()) == new
        and sha(pre / "controller-before-starttick-fix.py.as-run.txt")
        == manifest["pre_controller_sha256"]
        and sha(post / "sources/native_ban_expiry_control.py")
        == manifest["post_controller_sha256"],
        "C80 one-line start-tick correction differs",
    )
    freeze = read(post / "source-freeze.json")
    need(
        freeze["source_head_at_freeze"] == manifest["post_source_protocol_head"]
        and freeze["hashes"]["native_ban_expiry_cleanup.py"]
        == manifest["cleanup_sha256"]
        and freeze["hashes"]["native_ban_expiry_control.py"]
        == manifest["post_controller_sha256"]
        and len(freeze["hashes"]) == POST_SOURCES,
        "Post source snapshot identity differs",
    )
    for name, digest in freeze["hashes"].items():
        need(sha(post / "sources" / name) == digest, f"Post source differs: {name}")
    need(
        'receipt | {"emulator_starttime": "111"}'
        in (post / "sources/test_native_ban_expiry.py").read_text()
        and 'receipt | {"emulator_starttime": "112"}'
        in (post / "sources/test_native_ban_expiry.py").read_text(),
        "Start-tick regression source differs",
    )


def frozen(corpus: Path) -> tuple[types.ModuleType, ...]:
    """Import the frozen controller, cleanup, readiness and capture modules.

    Parameters
    ----------
    corpus : Path
        The later corpus directory, whose post-epoch sources are imported.

    Returns
    -------
    tuple[types.ModuleType, ...]
        The control, cleanup, readiness, capture and TCP modules, in that order.
    """
    sys.dont_write_bytecode = True
    source = str(corpus / "raw/post/sources")
    if source not in sys.path:
        sys.path.insert(0, source)
    control = importlib.import_module("native_ban_expiry_control")
    cleanup = importlib.import_module("native_ban_expiry_cleanup")
    readiness = importlib.import_module("native_control_readiness")
    capture = importlib.import_module("protocol_capture")
    tcp = importlib.import_module("pcap_tcp")
    return control, cleanup, readiness, capture, tcp
