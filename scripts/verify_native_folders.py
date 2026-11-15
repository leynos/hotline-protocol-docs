#!/usr/bin/env python3
"""Verify native folder state transitions, item streams and filesystem effects."""

import hashlib
import json
from pathlib import Path

from native_folder_cases import downloads, skip_all, upload_fresh
from native_folder_clock_checks import download_clock, upload_clock
from native_folder_files import verify_files
from native_folder_timing import uploads as timed_uploads
from native_folder_upload_cases import empty_uploads, partial_seed, resumed_uploads
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import verify_capture
from script_cli import run
from verify_native_core import require
from verify_native_folder_downloads import check_download
from verify_native_folder_probes import check_auxiliary, check_initial_probes
from verify_native_folder_support import (
    Cases,
    Connections,
    Corpus,
    Report,
    response,
    summarize,
)
from verify_native_folder_uploads import check_upload
from verify_native_framing import check_quiet

# scripts/tests/test_native_folders.py imports check_upload and verify. The
# evidence-held copies under evidence/gap-remediation/2026-11-12/native-folder-01
# name the same functions. response, summarize and check_download are
# re-exported from here, where the original module defined them.
__all__ = [
    "check_download",
    "check_upload",
    "main",
    "response",
    "summarize",
    "verify",
]

DELAYED_CHOICE_CASE = "folder-download-delayed-choice"
AUXILIARY_CAPTURES = 1


def expected_cases() -> Cases:
    """Plan every transcript of the folder corpus, merged in the original order.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The steps and the expectation of each transcript.
    """
    return (
        upload_fresh()
        | skip_all()
        | empty_uploads()
        | partial_seed()
        | downloads()
        | resumed_uploads()
        | timed_uploads()
    )


def open_corpus(directory: Path) -> Corpus:
    """Read the packet captures, the inventory and the hashes of the corpus.

    Returns
    -------
    Corpus
        The corpus, read once and shared by the checks.
    """
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    expected = expected_cases()
    require(
        {p.name for p in (directory / "transcripts").iterdir()} == set(expected),
        "Folder corpus inventory differs",
    )
    source_hashes = {
        hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (directory / "sources").glob("protocol_capture*.txt")
    }
    unread = json.loads((directory / "unread-output.json").read_text())
    timer_host, timer_guest = (
        read_packets(directory / "timers-host.pcap"),
        read_packets(directory / "timers-guest.pcap"),
    )
    return Corpus(
        directory=directory,
        host=host,
        guest=guest,
        timer_host=timer_host,
        timer_guest=timer_guest,
        source_hashes=source_hashes,
        unread=unread,
        expected=expected,
    )


def load_transcript(
    corpus: Corpus,
    name: str,
    steps: list[Report],
    expectation: Report,
) -> tuple[Report, Report]:
    """Verify one transcript's capture and check that its plan is the planned one.

    Returns
    -------
    tuple[dict[str, typing.Any], dict[str, typing.Any]]
        The verified capture report and the plan that it recorded.
    """
    case = corpus.directory / "transcripts" / name
    report = verify_capture(case)
    plan = json.loads((case / "plan.json").read_text())
    require(
        report["status"] == "completed"
        and report["driver_sha256"] in corpus.source_hashes,
        "Incomplete folder capture or missing source",
    )
    require(
        plan["steps"] == steps and plan["expectation"] == expectation,
        "Folder plan differs",
    )
    require(
        str(case.relative_to(corpus.directory)) not in corpus.unread,
        "Unexpected final unread output",
    )
    return report, plan


def check_plain_transcript(name: str, report: Report, packets: Connections) -> Report:
    """Check a transcript that is not timed, as a download or an upload.

    Returns
    -------
    dict[str, typing.Any]
        The outcome of the download or upload check.
    """
    if name.startswith("folder-download-"):
        return check_download(name, report, packets)
    return check_upload(name, report, packets)


def check_transcript(corpus: Corpus, name: str, report: Report, plan: Report) -> Report:
    """Check one transcript's connections, quiet frames and outcome.

    Returns
    -------
    dict[str, typing.Any]
        The case, its connection reconciliation and its outcome.
    """
    timed = name in timed_uploads() or name == DELAYED_CHOICE_CASE
    case_host, case_guest = (
        (corpus.timer_host, corpus.timer_guest)
        if timed
        else (corpus.host, corpus.guest)
    )
    packets = reconcile(report, case_host, case_guest)
    check_quiet(report, plan)
    if name in timed_uploads():
        require(
            packets["folder"]["guest_server_initiated_close"],
            "Timed folder did not close natively",
        )
        outcome = upload_clock(name, report, plan, case_guest)
    else:
        outcome = check_plain_transcript(name, report, packets)
        if name == DELAYED_CHOICE_CASE:
            outcome.update(download_clock(report, plan, case_guest))
    return {"case": name, "connections": packets, **outcome}


def check_transcripts(corpus: Corpus) -> list[Report]:
    """Check every planned transcript, in the planned order.

    Returns
    -------
    list[dict[str, typing.Any]]
        The observation of each transcript.
    """
    observations: list[Report] = []
    for name, (steps, expectation) in corpus.expected.items():
        report, plan = load_transcript(corpus, name, steps, expectation)
        observations.append(check_transcript(corpus, name, report, plan))
    return observations


def verify(directory: Path) -> Report:
    """Verify the folder corpus in ``directory`` and return its observations.

    Returns
    -------
    dict[str, typing.Any]
        The transcript observations, the native files, the initial probes, the
        auxiliary count and the scope of the claim.
    """
    corpus = open_corpus(directory)
    observations = check_transcripts(corpus)
    native_files = verify_files(directory)
    initial = check_initial_probes(corpus)
    check_auxiliary(corpus)
    return {
        "cases": observations,
        "native_files": native_files,
        "initial_probes": initial,
        "auxiliary_captures": AUXILIARY_CAPTURES,
        "scope": (
            "Fourteen final direction-specific folder cases; positive direct "
            "catalogue states, not exhaustive listing or restart-durability proof; "
            "admission failures excluded from folder semantics"
        ),
    }


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a folder corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
