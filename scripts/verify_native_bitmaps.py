#!/usr/bin/env python3
"""Verify native field-110 walking bits, width controls and account cleanup."""

import dataclasses as dc
import json
import typing as typ
from pathlib import Path

from capture_acceptance import driver_is
from native_packet_evidence import reconcile
from native_wire_names import TYPE_PRESENCE_UPDATE, TYPE_USER_LEFT
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, decode_frame, verify_capture
from script_cli import run
from verify_native_bitmap_checks import (
    NAMES,
    account,
    ordered_replies,
    replacement,
    semantic,
    sent,
)
from verify_native_core import require
from verify_native_shx import sha

type Report = dict[str, typ.Any]
type Packets = list[dict[str, typ.Any]]

# The checks live in verify_native_bitmap_checks; the names below stay importable
# from this module. semantic and verify are imported by test_native_bitmaps and by
# the executed copies under evidence/; NAMES, account, ordered_replies,
# replacement and sent are kept because the original module defined them publicly.
__all__ = [
    "EXE_SHA256",
    "NAMES",
    "account",
    "main",
    "ordered_replies",
    "replacement",
    "semantic",
    "sent",
    "verify",
]

EXE_SHA256 = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
RUNTIME_PID = 1259319
HOST_PACKETS = 582
PAIRED_CONNECTIONS = 14
TAIL_TYPES = (("main", TYPE_PRESENCE_UPDATE), ("owned", TYPE_USER_LEFT))


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """The corpus directory with its manifest, runtime, packets and unread tails."""

    directory: Path
    manifest: Report
    runtime: Report
    host: Packets
    guest: Packets
    tails: Report


def open_corpus(directory: Path) -> Corpus:
    """Read the manifest, runtime, packets and unread tails, and check them.

    Returns
    -------
    Corpus
        The checked corpus.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    require(
        manifest["reports"] == list(NAMES)
        and {p.parent.name for p in directory.glob("*/report.json")} == set(NAMES),
        "Bitmap evidence inventory differs",
    )
    runtime = json.loads((directory / "runtime.json").read_text())
    require(
        runtime["emulator_pid"] == RUNTIME_PID
        and runtime["running_executable_sha256"] == EXE_SHA256,
        "Bitmap runtime identity differs",
    )
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == HOST_PACKETS
        and "0 packets dropped by kernel"
        in (directory / "host-capture-statistics.txt").read_text(),
        "Bitmap host capture count/drop differs",
    )
    tails = json.loads((directory / "unread-tails.json").read_text())
    require(set(tails) == {"all-ones"}, "Bitmap unread tail inventory differs")
    return Corpus(directory, manifest, runtime, host, guest, tails)


def replay_report(corpus: Corpus, name: str) -> tuple[Report, int]:
    """Check one report against its provenance and the packets.

    Returns
    -------
    tuple[dict, int]
        The verified report and its number of paired connections.
    """
    path = corpus.directory / name
    report = verify_capture(path)
    plan = json.loads((path / "plan.json").read_text())
    require(
        report["status"] == "completed"
        and report["profile"] == "native-mac-oracle"
        and report["oracle_sha256"] == ORACLE_SHA256
        and driver_is(report, corpus.manifest["driver_sha256"])
        and plan["environment"] == corpus.runtime,
        "Bitmap plan/oracle provenance differs",
    )
    view_tails = corpus.tails.get(name, {})
    observations = reconcile(
        report,
        corpus.host,
        corpus.guest,
        unread_output={
            k: bytes.fromhex(v) for k, v in view_tails.get("host", {}).items()
        },
        guest_unread_output={
            k: bytes.fromhex(v) for k, v in view_tails.get("guest", {}).items()
        },
    )
    return report, len(observations)


def check_tails(tails: Report) -> None:
    """Check that the host and the guest saw the same unread tails."""
    for connection, expected_type in TAIL_TYPES:
        host_tail = tails["all-ones"]["host"][connection]
        guest_tail = tails["all-ones"]["guest"][connection]
        require(
            host_tail == guest_tail
            and decode_frame(bytes.fromhex(host_tail))["type"] == expected_type,
            "Bitmap unread host/guest tail differs",
        )


def verify(directory: Path) -> Report:
    """Verify the retained bitmap corpus.

    Returns
    -------
    dict[str, typing.Any]
        The report and connection counts, and the bit and width outcomes.
    """
    corpus = open_corpus(directory)
    reports = {}
    paired = 0
    for name in NAMES:
        reports[name], count = replay_report(corpus, name)
        paired += count
    check_tails(corpus.tails)
    require(paired == PAIRED_CONNECTIONS, "Bitmap paired TCP lifetime count differs")
    require(
        sha(directory / "sources/native_bitmap_cases.py")
        == corpus.manifest["generator_sha256"],
        "Bitmap plan generator source differs",
    )
    result = semantic(reports)
    require(
        json.loads((directory / "per-bit.json").read_text()) == result["walking_rows"],
        "Published per-bit evidence differs",
    )
    result.pop("walking_rows")
    return {
        "completed_reports": len(reports),
        "paired_connections": paired,
        **result,
    }


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a native bitmap corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
