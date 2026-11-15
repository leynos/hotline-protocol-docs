#!/usr/bin/env python3
"""Verify native RFLT boundaries, continuation bytes and inconsistent clients."""

import dataclasses as dc
import hashlib
import json
import typing as typ
from pathlib import Path

from native_packet_evidence import reconcile
from native_resume_cases import downloads, upload_continuations, upload_probes
from native_resume_rflt import RESUME_INCONSISTENT_NAME, RESUME_PARTIAL_NAME
from native_wire_names import (
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from pcap_tcp import read_packets
from protocol_capture import verify_capture
from script_cli import run
from verify_native_core import require
from verify_native_framing import check_quiet

# verify_native_console_broadcast imports reply from this module, and
# test_native_resume imports check_download.
from verify_native_resume_checks import (
    DATA,
    RESOURCE,
    RESOURCE_OFFSET,
    check_download,
    check_upload,
    reply,
)

type Report = dict[str, typ.Any]

__all__ = ["check_download", "main", "reply", "verify"]

# The login bootstrap of every case: the ACK, then the 354 and 109 notices.
BOOTSTRAP = [
    (0, 1, 0),
    (TYPE_PRIVILEGES_NOTIFICATION, 0, 0),
    (TYPE_LOGIN_AGREEMENT, 0, 0),
]
BOOTSTRAP_FRAMES = 3
INITIAL_PROBES = 7
FAILED_INITIAL_PROBES = 3
SCOPE = (
    "23 final bounded observations plus7 initial attempts; native tolerance, not "
    "a safe malformed-input policy or restart-durability proof"
)
DOWNLOAD_PREFIX = "resume-download-"


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """What a resume corpus holds besides its cases.

    Attributes
    ----------
    directory : pathlib.Path
        The corpus directory.
    host : list[dict[str, typing.Any]]
        The host packet capture.
    guest : list[dict[str, typing.Any]]
        The guest packet capture.
    sources : set[str]
        The hashes of the retained capture drivers.
    unread : dict[str, dict[str, str]]
        The retained unread output, by case.
    """

    directory: Path
    host: list[dict[str, typ.Any]]
    guest: list[dict[str, typ.Any]]
    sources: set[str]
    unread: dict[str, dict[str, str]]


def verify_case(corpus: Corpus, name: str, planned: tuple) -> Report:
    """Verify one captured case of a resume corpus.

    Returns
    -------
    dict[str, typing.Any]
        The case name, its connections and its outcome.
    """
    steps, expectation = planned
    case = corpus.directory / "transcripts" / name
    plan = json.loads((case / "plan.json").read_text())
    report = verify_capture(case)
    require(report["status"] == "completed", "Final resume capture failed")
    require(
        plan["steps"] == steps and plan["expectation"] == expectation,
        "Resume plan differs",
    )
    require(
        report["driver_sha256"] in corpus.sources,
        "Missing exact resume driver source",
    )
    require(
        [
            (f["type"], f["is_reply"], f["error"])
            for f in report["frames"][:BOOTSTRAP_FRAMES]
        ]
        == BOOTSTRAP,
        "Login bootstrap differs",
    )
    require(
        str(case.relative_to(corpus.directory)) not in corpus.unread,
        "Unexpected final unread output",
    )
    packets = reconcile(report, corpus.host, corpus.guest)
    check_quiet(report, plan)
    outcome = (
        check_download(name, report, expectation, packets)
        if name.startswith(DOWNLOAD_PREFIX)
        else check_upload(report, expectation, packets)
    )
    return {"case": name, "connections": packets, **outcome}


def check_native_files(directory: Path) -> None:
    """Check the native files, listed before and after resuming, against the forks."""
    for stage, name, data, resource in [
        ("before", RESUME_PARTIAL_NAME, DATA, RESOURCE[:RESOURCE_OFFSET]),
        ("after", RESUME_PARTIAL_NAME, DATA, RESOURCE),
        (
            "after",
            RESUME_INCONSISTENT_NAME,
            DATA + DATA,
            RESOURCE[:RESOURCE_OFFSET] + RESOURCE,
        ),
    ]:
        base = directory / "native-files" / stage
        stem = name.decode()
        require(
            (base / (stem + ".data")).read_bytes() == data,
            "Native resumed DATA differs",
        )
        require(
            (base / (stem + ".rsrc")).read_bytes() == resource,
            "Native resumed MACR differs",
        )
        stat = (base / (stem + ".stat.txt")).read_text()
        require(
            ("HTft" if stage == "before" else "TEXT") in stat,
            "Native resume file type differs",
        )
        require(
            f"Resource fork size:\t{len(resource)}" in stat,
            "Native resource catalogue differs",
        )


def check_initial_probes(corpus: Corpus) -> list[Report]:
    """Replay the initial attempts that preceded the final observations.

    Returns
    -------
    list[dict[str, typing.Any]]
        The case, status and error of each attempt.
    """
    directory = corpus.directory
    initial = []
    for path in sorted((directory / "initial-probes").rglob("report.json")):
        report = verify_capture(path.parent)
        require(
            report["driver_sha256"] in corpus.sources, "Missing initial resume source"
        )
        case = str(path.parent.relative_to(directory))
        suffixes = {k: bytes.fromhex(v) for k, v in corpus.unread.get(case, {}).items()}
        reconcile(report, corpus.host, corpus.guest, suffixes)
        initial.append({
            "case": case,
            "status": report["status"],
            "error": report["error"],
        })
    require(
        len(initial) == INITIAL_PROBES
        and sum(c["status"] == "failed" for c in initial) == FAILED_INITIAL_PROBES,
        "Initial resume attempts changed",
    )
    return initial


def verify(directory: Path) -> Report:
    """Verify every case of a retained resume corpus.

    Returns
    -------
    dict[str, typing.Any]
        The observations of each case, the initial attempts and the scope.
    """
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    expected = downloads() | upload_probes() | upload_continuations()
    require(
        {p.name for p in (directory / "transcripts").iterdir()} == set(expected),
        "Resume corpus inventory differs",
    )
    sources = {
        hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (directory / "sources").glob("protocol_capture*.txt")
    }
    unread = json.loads((directory / "unread-output.json").read_text())
    corpus = Corpus(directory, host, guest, sources, unread)
    observations = [
        verify_case(corpus, name, planned) for name, planned in expected.items()
    ]
    check_native_files(directory)
    return {
        "cases": observations,
        "initial_probes": check_initial_probes(corpus),
        "scope": SCOPE,
    }


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a resume corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
