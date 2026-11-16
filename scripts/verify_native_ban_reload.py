#!/usr/bin/env python3
"""Replay one native persisted-ban UI and Login107 witness offline."""

import json
import sys
import typing as typ
from pathlib import Path

from native_control_readiness import probe
from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import verify_capture
from script_cli import run
from verify_native_ban_control import verify as verify_control
from verify_native_ban_reload_core import (
    BAN,
    BASE,
    C56_MANIFEST,
    CORPUS,
    DATA,
    EMULATOR,
    IMAGE_AFTER,
    IMAGE_BEFORE,
    INPUT,
    NOTICE,
    NS,
    PID,
    PREPARED,
    ROM,
    RSRC,
    START,
    UI_IMAGE,
    read,
    require,
    sha,
)
from verify_native_ban_reload_packets import packets
from verify_native_ban_reload_preflight import preflight
from verify_native_ban_reload_probe import check_probe
from verify_native_ban_reload_terminal import terminal
from verify_native_ban_reload_ui import ready_and_ui

type Report = dict[str, typ.Any]

# The names below stay importable from this module. The shared constants and file
# readers live in verify_native_ban_reload_core, the preboot checks in
# verify_native_ban_reload_preflight, the UI checks in verify_native_ban_reload_ui,
# the probe in verify_native_ban_reload_probe, the packet views in
# verify_native_ban_reload_packets and the cleanup in verify_native_ban_reload_terminal.
__all__ = [
    "BAN",
    "BASE",
    "C56_MANIFEST",
    "CORPUS",
    "DATA",
    "EMULATOR",
    "IMAGE_AFTER",
    "IMAGE_BEFORE",
    "INPUT",
    "NOTICE",
    "NS",
    "PID",
    "PREPARED",
    "ROM",
    "RSRC",
    "START",
    "UI_IMAGE",
    "check_probe",
    "inventory",
    "lifetime",
    "main",
    "packets",
    "preflight",
    "probe",
    "read",
    "read_packets",
    "ready_and_ui",
    "require",
    "sha",
    "show",
    "stream",
    "terminal",
    "verify",
    "verify_capture",
    "verify_control",
]


def inventory(corpus: Path) -> None:
    """Check the profile, the file inventory and the source snapshot of the corpus.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    m = read(corpus / "manifest.json")
    require(
        corpus.name == CORPUS
        and m["schema"] == CORPUS
        and m["profile"] == "persisted-ban-reload-readonly"
        and m["full_file_baseline"] == "not_exercised"
        and m["failed_full_A7"] == ["C35", "C45", "C50"]
        and m["source_native_data_sha256"] == DATA
        and m["source_native_rsrc_sha256"] == RSRC
        and m["source_c56_manifest_sha256"] == C56_MANIFEST
        and m["source_c56_corpus"] == "../native-ban-control-01",
        "Profile or source manifest differs",
    )
    files = m["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    require(actual == set(files), "Corpus inventory differs")
    for path, digest in files.items():
        require(sha(corpus / path) == digest, f"Corpus SHA differs: {path}")
    require(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{digest}  {path}" for path, digest in sorted(files.items())],
        "SHA256SUMS differs",
    )
    c56 = corpus.parent / "native-ban-control-01"
    require(sha(c56 / "manifest.json") == C56_MANIFEST, "C56 source manifest differs")
    require(
        verify_control(c56)["status"]
        == "verified_control_only_option_two_notice_and_login_rejection",
        "C56 control corpus differs",
    )
    require(
        all(
            sha(corpus / "sources" / name) == sha(c56 / "sources" / name)
            for name in (
                "protocol_capture.py",
                "pcap_tcp.py",
                "native_control_readiness.py",
                "native_ban_control_cases.py",
            )
        )
        and sha(corpus / "sources/capture_readiness.py")
        == "7a75f4b78f1255f4486ced44fc5fb8882d6008c7de6844a82f4c107e7299d678",
        "Captured source snapshot differs",
    )


def verify(corpus: Path) -> Report:
    """Replay the persisted-ban reload witness from its frozen corpus.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The verified status and the counts of the witness.
    """
    corpus = corpus.resolve()
    inventory(corpus)
    preflight(corpus)
    ready = ready_and_ui(corpus)
    report = check_probe(corpus, ready)
    packet_counts = packets(corpus, report)
    terminal(corpus, ready)
    return {
        "status": "verified_one_persisted_ban_reload_ui_and_login107",
        "full_file_baseline": "not_exercised",
        "connected_session_application_104": "not_exercised",
        "login_error_bytes": len(NOTICE),
        "primary_syn_packets": 0,
        **packet_counts,
        "lab_retired": True,
        "guest_emulator_forced_term": True,
    }


def show(corpus: str) -> None:
    """Print the JSON summary of the verification of a corpus.

    Parameters
    ----------
    corpus : str
        The corpus directory.
    """
    sys.stdout.write(json.dumps(verify(Path(corpus)), indent=2) + "\n")


def main() -> None:
    """Verify a persisted-ban reload corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
