#!/usr/bin/env python3
"""Verify matched-reference transfers, forks and observed completion boundaries."""

import dataclasses as dc
import hashlib
import json
import typing as typ
from pathlib import Path

from capture_acceptance import driver_in
from native_packet_evidence import reconcile
from native_transfer_cases import downloads, resource_fork, transfers
from pcap_tcp import read_packets
from protocol_capture import verify_capture
from script_cli import run
from verify_native_core import require
from verify_native_fork_support import check_file_info, check_metadata, fields
from verify_native_fork_transfers import (
    Transfer,
    check_download,
    check_empty_preview,
    check_upload,
)
from verify_native_framing import check_quiet

type Report = dict[str, typ.Any]

# verify_native_folders and its helpers import check_file_info, check_metadata and
# fields from this module, verify_native_cleanup and other verifiers import fields
# and check_metadata, and test_native_forks imports verify.
__all__ = ["check_file_info", "check_metadata", "fields", "main", "verify"]

FILE_DATA = b"data-fork\r\n\x00\xff"
FORK_FIXTURE = "mothra-fork-fixture"
EMPTY_FIXTURE = "mothra-empty-fixture"
EMPTY_FIXTURE_NAME = EMPTY_FIXTURE.encode()
INITIAL_HYPOTHESES = 8
FAILED_HYPOTHESES = 5
# The recorder closed this control socket before consuming a queued 301. The
# complete independently observed suffix is pinned; the report is not altered.
EMPTY_DOWNLOAD_UNREAD = {
    "main": bytes.fromhex(
        "0000012d000000030000000000000027000000270004"
        "006700020060006800020001007000020012"
        "0066000f6672616d696e672d66697874757265"
    )
}
SCOPE = (
    "Two successful uploads, eight download modes; completion bytes and observed "
    "cleanup, not restart durability or full transfer conformance"
)
LOGIN_FRAMES = 3  # the login reply and its two notifications


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """What a fork corpus holds besides its transcripts.

    Attributes
    ----------
    directory : pathlib.Path
        The corpus directory.
    host : list[dict[str, typing.Any]]
        The host packet capture.
    guest : list[dict[str, typing.Any]]
        The guest packet capture.
    sources : set[str]
        The hashes of the capture drivers that were kept with the corpus.
    """

    directory: Path
    host: list[Report]
    guest: list[Report]
    sources: set[str]


def verify_plan(
    corpus: Corpus, name: str, case: tuple[list[Report], Report]
) -> tuple[Report, Report]:
    """Verify one capture and check that it ran the planned steps.

    Returns
    -------
    tuple[dict[str, typing.Any], dict[str, typing.Any]]
        The verified report and the recorded plan.
    """
    steps, expectation = case
    capture = corpus.directory / "transcripts" / name
    plan = json.loads((capture / "plan.json").read_text())
    report = verify_capture(capture)
    require(report["status"] == "completed", name + ": capture failed")
    require(
        plan["steps"] == steps and plan["expectation"] == expectation,
        "Plan differs",
    )
    require(driver_in(report, corpus.sources), "Missing exact capture source")
    return report, plan


def load_transfer(
    name: str, report: Report, expectation: Report, connections: Report
) -> Transfer:
    """Gather the frames, the file name and the expected forks of a transfer.

    Returns
    -------
    Transfer
        The transfer, ready for its upload or download checks.
    """
    frames = report["frames"][LOGIN_FRAMES:]
    values = fields(frames[0])
    filename = bytes.fromhex(expectation["name_hex"])
    empty = filename == EMPTY_FIXTURE_NAME
    data = b"" if empty else FILE_DATA
    resource = b"" if empty else resource_fork()
    return Transfer(
        name, report, expectation, connections, frames, values, filename, data, resource
    )


def observe(corpus: Corpus, name: str, case: tuple[list[Report], Report]) -> Report:
    """Check one captured transfer against its plan and the packet captures.

    Returns
    -------
    dict[str, typing.Any]
        The case name, its connections and what the transfer observed.
    """
    report, plan = verify_plan(corpus, name, case)
    unread = EMPTY_DOWNLOAD_UNREAD if name == "download-empty" else None
    connections = reconcile(report, corpus.host, corpus.guest, unread)
    check_quiet(report, plan)
    transfer = load_transfer(name, report, case[1], connections)
    observed: Report = {"case": name, "connections": connections}
    if case[1]["kind"] == "upload":
        observed["file_info"] = check_upload(transfer)
    elif name == "download-empty-preview":
        check_empty_preview(transfer)
    else:
        observed |= check_download(transfer)
    return observed


def sources_of(directory: Path) -> set[str]:
    """Hash the capture drivers that were kept with the corpus.

    Returns
    -------
    set[str]
        The hexadecimal digests.
    """
    return {
        hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (directory / "sources").glob("protocol_capture*.txt")
    }


def check_native_file(directory: Path, name: str, data: bytes, resource: bytes) -> None:
    """Check the fork bytes and catalogue entry that the native side holds."""
    files = directory / "native-files"
    require(
        (files / (name + ".data")).read_bytes() == data,
        "Native data fork differs",
    )
    if resource:
        require(
            (files / (name + ".rsrc")).read_bytes() == resource,
            "Native resource fork differs",
        )
    else:
        extraction = json.loads((files / "extraction.json").read_text())
        record = next(f for f in extraction["files"] if f["name"] == name)
        require(
            record["resource_exit_code"] != 0,
            "Absent resource extraction misreported",
        )
        require(
            "Attribute 4353-1 not found"
            in (files / (name + ".rsrc.stderr")).read_text(),
            "Missing absent-resource evidence",
        )
    stat = (files / (name + ".stat.txt")).read_text()
    require(
        "File Path: /Hotline19/Files/" + name in stat
        and "TEXT" in stat
        and "MOTH" in stat,
        "Native catalogue identity differs",
    )
    require(
        f"Resource fork size:\t{len(resource)}" in stat,
        "Catalogue resource length differs",
    )


def check_initial(
    directory: Path, host: list[Report], guest: list[Report]
) -> list[Report]:
    """Check the exploratory captures that preceded the final cases.

    Returns
    -------
    list[dict[str, typing.Any]]
        The status and error of each exploratory capture.
    """
    initial = []
    for case in sorted((directory / "initial-eof-hypotheses").iterdir()):
        report = verify_capture(case)
        reconcile(report, host, guest)
        initial.append({
            "case": case.name,
            "status": report["status"],
            "error": report["error"],
        })
    require(
        len(initial) == INITIAL_HYPOTHESES
        and sum(c["status"] == "failed" for c in initial) == FAILED_HYPOTHESES,
        "Initial EOF hypothesis inventory differs",
    )
    return initial


def verify(directory: Path) -> Report:
    """Verify every transfer, the native files and the exploratory captures.

    Returns
    -------
    dict[str, typing.Any]
        The observation of each case, the exploratory captures and the scope.
    """
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    expected = transfers() | downloads()
    require(
        {p.name for p in (directory / "transcripts").iterdir() if p.is_dir()}
        == set(expected),
        "Transfer corpus inventory differs",
    )
    corpus = Corpus(directory, host, guest, sources_of(directory))
    observations = [observe(corpus, name, case) for name, case in expected.items()]
    for name, data, resource in [
        (FORK_FIXTURE, FILE_DATA, resource_fork()),
        (EMPTY_FIXTURE, b"", b""),
    ]:
        check_native_file(directory, name, data, resource)
    return {
        "cases": observations,
        "initial_eof_hypotheses": check_initial(directory, host, guest),
        "scope": SCOPE,
    }


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a fork corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
