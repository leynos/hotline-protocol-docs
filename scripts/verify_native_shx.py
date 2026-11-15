#!/usr/bin/env python3
"""Verify full shx peer terminal, syscall, paired packet and saved-fork evidence."""

import json
import typing as typ
from pathlib import Path

from native_packet_evidence import reconcile
from native_wire_names import (
    FIELD_DATA,
    TYPE_CHAT_NOTIFICATION,
    TYPE_LOGIN,
    TYPE_SEND_CHAT,
)
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from script_cli import run
from verify_native_core import require
from verify_native_shx_frames import (
    CHAT,
    HANDSHAKE_REQUEST_BYTES,
    LOGIN,
    PEER,
    REVISION,
    Corpus,
    fields,
    frames,
    read_agreement,
    sha,
)
from verify_native_shx_packets import check_packets
from verify_native_shx_semantics import check_semantics
from verify_native_shx_terminal import check_terminal

type Report = dict[str, typ.Any]

# verify_native_shx_extras, peer_tolerance_run, verify_peer_tolerance and
# test_native_shx import these names from this module, and about fifty verifiers
# and planners import fields; the names stay importable from here.
__all__ = [
    "CHAT",
    "LOGIN",
    "PEER",
    "REVISION",
    "check_packets",
    "check_semantics",
    "check_terminal",
    "fields",
    "frames",
    "main",
    "sha",
    "verify",
]

CASES = {
    "basic-empty-name",
    "root-listing",
    "fork-download",
    "ambiguous-text",
    "wrong-password",
}
HOST_PACKETS = 170  # the host recorder's packet count
PAIRED_CONNECTIONS = 7
WITNESS_TYPES = [TYPE_LOGIN, TYPE_SEND_CHAT]
SCOPE = (
    "One modern build of historical source; native160/161, roster/chat/list/"
    "download and opaque high-byte output. No universal peer, rendering,162/122 "
    "or optional-profile acceptance claim."
)


def check_inventory(directory: Path, manifest: Report) -> None:
    """Check the cases of the corpus and the identities that its manifest records."""
    require(
        set(manifest["cases"]) == CASES
        and {p.name for p in (directory / "captures").iterdir()} == CASES,
        "Full-peer corpus inventory differs",
    )
    require(
        manifest["peer_binary_sha256"] == PEER
        and manifest["oracle_sha256"] == ORACLE_SHA256,
        "Corpus identity differs",
    )


def open_corpus(directory: Path, manifest: Report) -> Corpus:
    """Read the sources, packet captures and build record, and check them.

    Returns
    -------
    Corpus
        The corpus.
    """
    sources = {sha(p) for p in (directory / "sources").iterdir()} | {
        sha(directory / "capture_shx_session.guarded.py.txt")
    }
    agreement = read_agreement(directory)
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    build = json.loads(
        (directory.parent / "shx-build-01/build/manifest.json").read_text()
    )
    require(
        build["binary_sha256"] == PEER and build["source_commit"] == REVISION,
        "Missing identified build provenance",
    )
    require(
        len(host) == manifest["host_capture_packets"] == HOST_PACKETS
        and manifest["host_kernel_drops"] == 0,
        "Host recorder inventory differs",
    )
    return Corpus(directory, sources, agreement, host, guest, build)


def observe_case(corpus: Corpus, name: str) -> Report:
    """Check one captured session and summarize its connections.

    Returns
    -------
    dict[str, typing.Any]
        The case name, its semantic observation and its connections.
    """
    case = corpus.directory / "captures" / name
    require(
        json.loads((case / "peer-profile.json").read_text()) == corpus.build,
        "Captured peer build profile differs",
    )
    check_terminal(case, corpus.sources)
    connections = check_packets(case, corpus.host, corpus.guest)
    semantic = check_semantics(case, connections, corpus.agreement)
    return {
        "case": name,
        **semantic,
        "connections": [
            {k: v for k, v in c.items() if k not in {"sent", "received"}}
            | {
                "sent_bytes": len(c["sent"]),
                "received_bytes": len(c["received"]),
            }
            for c in connections
        ],
    }


def check_witness(corpus: Corpus) -> None:
    """Check the controlled witness that sends the high-byte chat."""
    witness = verify_capture(corpus.directory / "witness")
    require(witness["status"] == "completed", "Controlled witness failed")
    require(witness["driver_sha256"] in corpus.sources, "Missing exact witness driver")
    reconcile(witness, corpus.host, corpus.guest)
    requests = frames(
        bytes.fromhex(witness["streams"]["main"]["sent_hex"])[HANDSHAKE_REQUEST_BYTES:]
    )
    require(
        [f["type"] for f in requests] == WITNESS_TYPES
        and fields(requests[-1]) == {FIELD_DATA: CHAT},
        "Controlled witness input differs",
    )
    require(
        any(
            f["type"] == TYPE_CHAT_NOTIFICATION
            and CHAT in fields(f).get(FIELD_DATA, b"")
            for f in witness["frames"]
        ),
        "Witness chat evidence missing",
    )


def verify(directory: Path) -> Report:
    """Verify every capture and the controlled witness of a shx corpus.

    Returns
    -------
    dict[str, typing.Any]
        The case count, the observations and the scope they support.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    check_inventory(directory, manifest)
    corpus = open_corpus(directory, manifest)
    observations = [observe_case(corpus, name) for name in sorted(CASES)]
    check_witness(corpus)
    return {
        "cases": len(CASES),
        "paired_connections": PAIRED_CONNECTIONS,
        "observations": observations,
        "scope": SCOPE,
    }


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a shx corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
