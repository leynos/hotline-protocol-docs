#!/usr/bin/env python3
"""Keep actual native name tests distinct from controlled banner/subject delivery."""

import json
import typing as typ
from pathlib import Path

from capture_acceptance import driver_in
from native_packet_evidence import reconcile
from native_wire_names import TYPE_BANNER_METADATA
from pcap_tcp import read_packets
from protocol_capture import verify_capture
from script_cli import run
from serve_shx_fixture import MODES, fixture_frames
from verify_native_core import require
from verify_native_login_extras import preferences
from verify_native_shx_frames import (
    LOGIN,
    PEER,
    Corpus,
    frames,
    read_agreement,
    sha,
)
from verify_native_shx_packets import check_packets
from verify_native_shx_receiver import receiver
from verify_native_shx_semantics import check_semantics
from verify_native_shx_terminal import check_terminal

type Report = dict[str, typ.Any]

# test_native_shx_extras imports receiver and verify from this module.
__all__ = ["main", "receiver", "verify"]

NAMES = {"ascii": b"mothra-peer-name", "macroman": b"mothra-peer-\x9a", "restored": b""}
COMMANDS = ["/version", LOGIN, "/who", "mothra-shx-basic-chat", "/quit"]
HOST_PACKETS = 230  # the host recorder's packet count
NATIVE_SESSIONS = 3
RECEIVER_SESSIONS = 4
BANNER_BYTES = 71  # the native 122 frame that the fixture replays
SCOPE = (
    "Native162 tolerance; controlled full-process delivery of native122 and "
    "source-derived115. One modern historical-source build; no original "
    "distributed binary, live SynHX server, banner UI or universal fallback claim."
)


def check_inventory(directory: Path, manifest: Report) -> None:
    """Check the native and receiver cases that the corpus holds."""
    require(
        set(manifest["native_cases"]) == set(NAMES)
        and {p.name for p in (directory / "captures").iterdir()} == set(NAMES),
        "Native name session inventory differs",
    )
    require(
        set(manifest["receiver_cases"]) == MODES
        and {p.name for p in (directory / "receivers").iterdir()} == MODES
        and {p.name for p in (directory / "fixture-servers").iterdir()} == MODES,
        "Controlled receiver inventory differs",
    )
    require(manifest["peer_binary_sha256"] == PEER, "Receiver build differs")


def open_corpus(directory: Path, manifest: Report) -> Corpus:
    """Read the sources, packet captures, agreement and build record.

    Returns
    -------
    Corpus
        The corpus.
    """
    sources = {sha(p) for p in (directory / "sources").iterdir()}
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == manifest["host_capture_packets"] == HOST_PACKETS
        and manifest["host_kernel_drops"] == 0,
        "Host recording inventory differs",
    )
    agreement = read_agreement(directory)
    build = json.loads(
        (directory.parent / "shx-build-01/build/manifest.json").read_text()
    )
    return Corpus(directory, sources, agreement, host, guest, build)


def check_native_name(corpus: Corpus, name: str, expected: bytes) -> Report:
    """Check one native session whose server name is the preference name.

    Returns
    -------
    dict[str, typing.Any]
        The case name, the name and the semantic observation.
    """
    directory = corpus.directory
    case = directory / "captures" / name
    require(
        json.loads((case / "peer-profile.json").read_text()) == corpus.build,
        "Native name build profile differs",
    )
    require(
        preferences(directory / ("native-" + name))["name"] == expected,
        "Native preference name differs",
    )
    check_terminal(case, corpus.sources, commands=COMMANDS)
    connections = check_packets(case, corpus.host, corpus.guest)
    result = check_semantics(
        case,
        connections,
        corpus.agreement,
        kind="basic-empty-name",
        login_name=expected,
    )
    return {"case": name, "name_hex": expected.hex(), **result}


def check_flushes(corpus: Corpus) -> None:
    """Check the setup controls that flushed the preferences between sessions."""
    directory = corpus.directory
    require(
        {p.name for p in (directory / "flushes").iterdir()}
        == {"peer-" + n for n in NAMES},
        "Native setup control inventory differs",
    )
    for case in (directory / "flushes").iterdir():
        report = verify_capture(case)
        require(
            report["status"] == "completed" and driver_in(report, corpus.sources),
            "Native setup control failed",
        )
        reconcile(report, corpus.host, corpus.guest)


def check_receivers(corpus: Corpus) -> list[Report]:
    """Check each controlled receiver mode against the replayed native bytes.

    Returns
    -------
    list[dict[str, typing.Any]]
        The observation of each mode.
    """
    directory = corpus.directory
    original = fixture_frames(directory.parent)
    require(
        frames(original["banner"])[0]["type"] == TYPE_BANNER_METADATA
        and len(original["banner"]) == BANNER_BYTES,
        "Missing exact native banner source",
    )
    receivers = []
    for mode in sorted(MODES):
        case = directory / "receivers" / mode
        require(
            json.loads((case / "peer-profile.json").read_text()) == corpus.build,
            "Controlled receiver build profile differs",
        )
        receivers.append(
            receiver(
                case,
                directory / "fixture-servers" / mode,
                corpus.host,
                original,
                corpus.sources,
            )
        )
    return receivers


def verify(directory: Path) -> Report:
    """Verify the native name sessions and the controlled receiver sessions.

    Returns
    -------
    dict[str, typing.Any]
        The session counts, the observations and the scope they support.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    check_inventory(directory, manifest)
    corpus = open_corpus(directory, manifest)
    native = [check_native_name(corpus, n, expected) for n, expected in NAMES.items()]
    require(
        preferences(directory / "native-restored")["bytes"]
        == preferences(directory.parent / "native-login-extras-01/native-restored")[
            "bytes"
        ],
        "Native baseline preferences were not restored",
    )
    check_flushes(corpus)
    receivers = check_receivers(corpus)
    return {
        "native_sessions": NATIVE_SESSIONS,
        "controlled_receiver_sessions": RECEIVER_SESSIONS,
        "native_names": native,
        "receiver_matrix": receivers,
        "scope": SCOPE,
    }


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify an extras corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
