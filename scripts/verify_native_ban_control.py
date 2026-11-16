#!/usr/bin/env python3
"""Replay the isolated native option-two control witness from frozen bytes."""

import json
import sys
from pathlib import Path

from script_cli import run
from verify_native_ban_control_boot import boot
from verify_native_ban_control_case import case
from verify_native_ban_control_core import (
    EXPECTED,
    NS,
    PHASES,
    PID,
    START,
    Json,
    digest,
    loaded,
    need,
)
from verify_native_ban_control_packets import packets
from verify_native_ban_control_terminal import failed_full_baselines, terminal

# The shared constants and readers live in verify_native_ban_control_core, the boot
# checks in _boot, the as-run case in _case, the packet views in _packets and the
# terminal state in _terminal. The names that this module defined before they moved
# stay importable from here; verify_native_ban_reload takes ``verify`` from it.
__all__ = [
    "EXPECTED",
    "NS",
    "PHASES",
    "PID",
    "START",
    "boot",
    "case",
    "digest",
    "failed_full_baselines",
    "inventory",
    "loaded",
    "main",
    "need",
    "packets",
    "terminal",
    "verify",
]

SCHEMA = "native-ban-control-01"
FAILED_FULL_A7 = ["C35", "C45", "C50"]
VERIFIED = "verified_control_only_option_two_notice_and_login_rejection"


def file_inventory(corpus: Path, manifest: Json) -> None:
    """Check that the manifest, the files and ``SHA256SUMS`` agree.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The corpus manifest.
    """
    files = manifest["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(actual == set(files), "Corpus inventory differs")
    for name, sha in files.items():
        need(digest(corpus / name) == sha, f"Corpus SHA differs: {name}")
    need(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{sha}  {name}" for name, sha in sorted(files.items())],
        "SHA256SUMS differs",
    )


def inventory(corpus: Path) -> Json:
    """Check the corpus inventory, its profile and the controller source.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The manifest.
    """
    manifest = loaded(corpus / "manifest.json")
    need(manifest["schema"] == SCHEMA, "Corpus schema differs")
    file_inventory(corpus, manifest)
    need(
        manifest["full_file_baseline"] == "not_exercised"
        and manifest["failed_full_A7"] == FAILED_FULL_A7
        and manifest["root_controller_source_sha256"] == EXPECTED["controller"]
        and manifest["source_a7_sha256"] == EXPECTED["source_a7"]
        and manifest["native_data_sha256"] == EXPECTED["data"]
        and manifest["native_rsrc_sha256"] == EXPECTED["rsrc"],
        "Evidence profile or source identity differs",
    )
    need(
        digest(corpus / "sources/native_control_readiness.py")
        == EXPECTED["controller"],
        "Controller source differs",
    )
    return manifest


def verify(corpus: Path) -> Json:
    """Replay the whole witness offline.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The status, the connection and packet counts and the persisted ban.
    """
    corpus = corpus.resolve()
    inventory(corpus)
    ready = boot(corpus)
    reports = case(corpus, ready)
    packet_result = packets(corpus, reports)
    stopped = terminal(corpus)
    failed_full_baselines(corpus)
    return {
        "status": VERIFIED,
        "full_file_baseline": "not_exercised",
        **packet_result,
        **stopped,
        "primary_syn": 0,
        "lab_retired": True,
    }


def show(corpus: str) -> None:
    """Print the JSON result of replaying a corpus.

    Parameters
    ----------
    corpus
        The corpus directory.
    """
    sys.stdout.write(json.dumps(verify(Path(corpus)), indent=2) + "\n")


def main() -> None:
    """Run the command line; a successful run returns instead of exiting.

    Raises
    ------
    SystemExit
        With a non-zero status when the command line cannot be used.
    """
    try:
        run(show, __doc__)
    except SystemExit as stop:
        if stop.code:  # the command line library exits with 0 on success
            raise


if __name__ == "__main__":
    main()
