#!/usr/bin/env python3
"""Replay the disposable native option-one ban witness from frozen files."""

import json
import sys
import typing as typ
from pathlib import Path

from native_filp import decode, metadata
from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import decode_frame, verify_capture
from script_cli import run
from verify_native_ban_one_a7 import verify_a7
from verify_native_ban_one_ban import verify_ban
from verify_native_ban_one_core import (
    APP_DATA_SHA,
    APP_RSRC_SHA,
    BASE_PLAN_SHA,
    NOTICE,
    ROM_SHA,
    SOURCE_DISK_SHA,
    digest,
    fields,
    frame,
    loaded,
    need,
)
from verify_native_ban_one_packets import verify_packets

# The names below stay importable from this module. The A7 baseline lives in
# verify_native_ban_one_a7, the ban request in verify_native_ban_one_ban, the packet
# views in verify_native_ban_one_packets and the shared checks in
# verify_native_ban_one_core. verify is imported by test_native_ban_one.
__all__ = [
    "APP_DATA_SHA",
    "APP_RSRC_SHA",
    "BASE_PLAN_SHA",
    "NOTICE",
    "ROM_SHA",
    "SOURCE_DISK_SHA",
    "decode",
    "decode_frame",
    "digest",
    "fields",
    "frame",
    "inventory",
    "lifetime",
    "loaded",
    "main",
    "metadata",
    "need",
    "read_packets",
    "show",
    "stream",
    "verify",
    "verify_a7",
    "verify_ban",
    "verify_capture",
    "verify_packets",
]


def inventory(corpus: Path) -> dict[str, typ.Any]:
    """Check the corpus manifest, its file inventory and its checksum list.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The parsed ``manifest.json``.
    """
    manifest = loaded(corpus / "manifest.json")
    need(manifest["schema"] == "native-ban-one-01", "Manifest schema differs")
    expected = manifest["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(actual == set(expected), "Corpus file inventory differs")
    for name, sha in expected.items():
        need(digest(corpus / name) == sha, f"Corpus SHA differs: {name}")
    lines = (corpus / "SHA256SUMS").read_text().splitlines()
    need(
        lines == [f"{sha}  {name}" for name, sha in sorted(expected.items())],
        "SHA256SUMS differs from manifest",
    )
    return manifest


def verify(corpus: Path) -> dict[str, typ.Any]:
    """Replay the whole option-one ban witness from its frozen corpus.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The verified status and the counts and identities of the witness.
    """
    corpus = corpus.resolve()
    inventory(corpus)
    mothra = corpus.parents[3]
    prep = loaded(corpus / "preparation/postflight.json")
    need(
        prep["source_after"]["sha256"] == SOURCE_DISK_SHA
        and prep["target_base"]["sha256"] == SOURCE_DISK_SHA
        and prep["target_working"]["sha256"] == SOURCE_DISK_SHA,
        "Prepared disk provenance differs",
    )
    need(
        prep["rom_after"]["sha256"] == ROM_SHA
        and prep["target_rom"]["sha256"] == ROM_SHA,
        "ROM provenance differs",
    )
    extracted = loaded(corpus / "preparation/preboot-app/extraction.json")
    need(
        len(extracted["records"]) == 1
        and extracted["records"][0]["path"] == "/Hotline19/HLserver19",
        "App catalogue differs",
    )
    need(
        digest(corpus / "preparation/preboot-app/catalog-11183.data") == APP_DATA_SHA
        and digest(corpus / "preparation/preboot-app/catalog-11183.rsrc")
        == APP_RSRC_SHA,
        "App forks differ",
    )
    a7 = verify_a7(corpus, mothra)
    ban = verify_ban(corpus)
    verify_packets(corpus, bytes.fromhex(ban["target_uid_hex"]))
    terminal = loaded(corpus / "fixture/terminal.json")
    need(
        not terminal["processes"]["lab"]["exists"]
        and all(value["syn_lines"] == 0 for value in terminal["primary_syn"].values()),
        "Lab retirement or zero-primary proof differs",
    )
    need(
        terminal["processes"]["primary"]["fd6"].endswith(
            "hotline22-recovery/working.dsk"
        )
        and terminal["processes"]["client"]["fd6"].endswith(
            "hotline-client-isolated-01/working.dsk"
        ),
        "Original runtime FD identities differ",
    )
    return {
        "status": "verified_option_one_notice_only",
        "a7": a7,
        **ban,
        "primary_syn": 0,
        "lab_retired": True,
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
    """Verify an option-one native ban corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
