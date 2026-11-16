#!/usr/bin/env python3
"""Verify complete shx field variants against socket, packet and terminal bytes."""

import hashlib
import json
from pathlib import Path

from capture_acceptance import role_in
from pcap_tcp import read_packets
from peer_tolerance_fixture import CASES, FIRST_PORT
from script_cli import run
from serve_shx_fixture import fixture_frames
from verify_native_core import require
from verify_native_shx import PEER, REVISION
from verify_peer_tolerance_checks import Corpus, Report, check_case

# The per-case checks live in verify_peer_tolerance_checks. This module keeps
# the public names of the original verifier, which scripts/tests/
# test_peer_tolerance.py imports from it: sha, verify and main.


def sha(path: Path) -> str:
    """Return the SHA-256 digest of the bytes of ``path``.

    Returns
    -------
    str
        The lower-case hexadecimal digest.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_manifest(manifest: Report) -> None:
    """Require the peer manifest to name the pinned peer, revision and HOME.

    Parameters
    ----------
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json``.
    """
    require(
        manifest["cases"] == list(CASES)
        and manifest["ports"] == list(range(FIRST_PORT, FIRST_PORT + len(CASES)))
        and manifest["peer_binary_sha256"] == PEER
        and manifest["source_commit"] == REVISION
        and manifest["native_conformance"] is False
        and manifest["real_home_file_before"] == manifest["real_home_file_after"],
        "Peer manifest, identity or real HOME guard differs",
    )


def check_sources(directory: Path, manifest: Report) -> set[str]:
    """Require the exact fixture and runner sources, and return their digests.

    Parameters
    ----------
    directory : pathlib.Path
        The peer corpus directory.
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json``.

    Returns
    -------
    set[str]
        The digest of every retained source file.
    """
    source_hashes = {sha(p) for p in (directory / "sources").iterdir()}
    require(
        role_in(manifest, "source_fixture", source_hashes)
        and role_in(manifest, "source_runner", source_hashes),
        "Missing exact fixture or runner source",
    )
    return source_hashes


def check_inventory(directory: Path) -> None:
    """Require the captures and fixtures to hold exactly the recorded cases.

    Parameters
    ----------
    directory : pathlib.Path
        The peer corpus directory.
    """
    require(
        {p.name for p in (directory / "captures").iterdir()} == set(CASES)
        and {p.name for p in (directory / "fixtures").iterdir()} == set(CASES),
        "Peer case inventory differs",
    )


def check_checksums(directory: Path) -> None:
    """Require the checksum file to list exactly the corpus's other files.

    Parameters
    ----------
    directory : pathlib.Path
        The peer corpus directory.
    """
    sums = (directory / "SHA256SUMS").read_text().splitlines()
    prefix = Path("evidence/gap-remediation/2026-11-13/delegated-peer-01")
    expected_sums = {
        f"{sha(path)}  {prefix / path.relative_to(directory)}"
        for path in directory.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    require(set(sums) == expected_sums, "Evidence checksums differ")


def verify(directory: Path, source: Path) -> Report:
    """Verify the frozen full-process peer corpus against the fixture source.

    Parameters
    ----------
    directory : pathlib.Path
        The frozen peer corpus directory.
    source : pathlib.Path
        The directory of the native evidence that the fixture replays.

    Returns
    -------
    dict[str, typing.Any]
        The verdict, the packet count and the result of every case.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    check_manifest(manifest)
    source_hashes = check_sources(directory, manifest)
    check_inventory(directory)
    original = fixture_frames(source)
    corpus = Corpus(
        directory,
        source_hashes,
        original,
        read_packets(directory / "host.pcap"),
    )
    results = [check_case(corpus, index, case) for index, case in enumerate(CASES)]
    check_checksums(directory)
    return {"status": "verified", "packet_count": len(corpus.host), "cases": results}


def show(directory: str, *, source: str) -> None:
    """Verify a peer corpus and print its summary as JSON.

    Parameters
    ----------
    directory : str
        The frozen peer corpus directory.
    source : str
        The directory of the native evidence that the fixture replays.
    """
    print(json.dumps(verify(Path(directory), Path(source)), indent=2))


def main() -> None:
    """Verify complete shx field variants against socket, packet and terminal bytes."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
