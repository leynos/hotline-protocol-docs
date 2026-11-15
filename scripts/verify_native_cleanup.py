#!/usr/bin/env python3
"""Verify download cancellation races without treating ACK as receive rollback."""

import dataclasses as dc
import hashlib
import json
import typing as typ
from pathlib import Path

from native_cleanup_cases import (
    FILENAME,
    UPLOAD_DATA,
    UPLOAD_FILENAME,
    data_fork,
    downloads,
    seed,
    upload_cleanup,
)
from native_filp import decode
from native_packet_evidence import reconcile
from native_transfer_cases import resource_fork
from native_wire_names import TYPE_USER_LEFT
from pcap_tcp import read_packets
from protocol_capture import decode_frame, verify_capture
from script_cli import run
from verify_native_cleanup_checks import check_download, check_upload, reply
from verify_native_cleanup_timing import bytes_after, flow, request_time
from verify_native_core import require
from verify_native_forks import check_metadata
from verify_native_framing import check_quiet

type Report = dict[str, typ.Any]

# The checks live in verify_native_cleanup_checks and the packet timeline in
# verify_native_cleanup_timing; the names below stay importable from this module.
# flow is imported by native_folder_clock_checks and verify_native_folder_probes;
# bytes_after, check_download, flow, reply and verify by test_native_cleanup;
# request_time and check_upload are kept because the original module defined
# them publicly.
__all__ = [
    "bytes_after",
    "check_download",
    "check_upload",
    "flow",
    "main",
    "reply",
    "request_time",
    "verify",
]

DEPARTURE_BYTES = 28  # the length of the retained unread departure notice
REQUEST_HEADER_HEX = 40  # the 20-byte header of a request, in hex digits
ID_START = 4  # the header's transaction ID, bytes 4 to 8
ID_END = 8
SCOPE = (
    "Ten finite ordinary-file cases; buffered-prefix and observed packet "
    "ordering, not a universal race byte count or cancellation deadline"
)


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """What each case is checked against: packets, hashes and the baseline."""

    directory: Path
    host: list[Report]
    guest: list[Report]
    unread: Report
    source_hashes: set[str]
    baseline: bytes


def check_baseline(directory: Path) -> bytes:
    """Check the baseline download's forks and metadata.

    Returns
    -------
    bytes
        The baseline stream, which every other download is a prefix of.
    """
    baseline_report = verify_capture(directory / "transcripts/cleanup-baseline")
    baseline = bytes.fromhex(baseline_report["streams"]["reference"]["received_hex"])
    forks = decode(baseline)
    require(
        forks["DATA"] == data_fork() and forks["MACR"] == resource_fork(),
        "Native baseline fork bytes differ",
    )
    check_metadata(forks["INFO"], FILENAME, uploaded=False)
    return baseline


def check_unread(directory: Path) -> Report:
    """Check the retained unread output, which holds one departure notice.

    Returns
    -------
    dict[str, typing.Any]
        The unread output by case and connection.
    """
    unread = json.loads((directory / "unread-output.json").read_text())
    require(
        set(unread) == {"cleanup-nonowner"}
        and set(unread["cleanup-nonowner"]) == {"a"},
        "Unread cleanup inventory differs",
    )
    suffix = bytes.fromhex(unread["cleanup-nonowner"]["a"])
    departure = decode_frame(suffix)
    require(
        len(suffix) == DEPARTURE_BYTES
        and departure["type"] == TYPE_USER_LEFT
        and departure["is_reply"] == 0,
        "Unread departure differs",
    )
    return unread


def check_inventory(report: Report, steps: list[Report]) -> None:
    """Check that each connection received one reply per request it sent."""
    for owner in {f["connection"] for f in report["frames"]}:
        requests = [
            int.from_bytes(
                bytes.fromhex(s["hex"][:REQUEST_HEADER_HEX])[ID_START:ID_END], "big"
            )
            for s in steps
            if s["op"] == "send"
            and s["connection"] == owner
            and len(s["hex"]) >= REQUEST_HEADER_HEX
        ]
        replies = [
            f["id"]
            for f in report["frames"]
            if f["connection"] == owner and f["is_reply"]
        ]
        require(
            sorted(requests) == sorted(replies),
            "Cleanup request/reply inventory differs",
        )


def check_case(
    corpus: Corpus, name: str, steps: list[Report], expectation: Report
) -> Report:
    """Check one recorded case.

    Returns
    -------
    dict[str, typing.Any]
        The case, its connections' packet reconciliation and its measurements.
    """
    case = corpus.directory / "transcripts" / name
    plan = json.loads((case / "plan.json").read_text())
    report = verify_capture(case)
    require(report["status"] == "completed", "Cleanup capture failed")
    require(
        report["driver_sha256"] in corpus.source_hashes,
        "Missing cleanup capture source",
    )
    require(
        plan["steps"] == steps and plan["expectation"] == expectation,
        "Cleanup plan differs",
    )
    packets = reconcile(
        report,
        corpus.host,
        corpus.guest,
        {k: bytes.fromhex(v) for k, v in corpus.unread.get(name, {}).items()},
    )
    check_quiet(report, plan)
    check_inventory(report, steps)
    outcome = (
        check_download(report, expectation, corpus.baseline, packets, corpus.guest)
        if expectation["kind"] == "cleanup-download"
        else check_upload(report, expectation, packets)
    )
    return {"case": name, "connections": packets, **outcome}


def check_races(observations: list[Report], baseline: bytes) -> None:
    """Check that the corpus saw a cancellation race and buffered delivery."""
    require(
        any(
            c.get("guest_bytes_first_observed_after_owner_request", 0) > 0
            and c["received_stream_bytes"] < len(baseline)
            for c in observations
        ),
        "No observed in-progress cancellation race",
    )
    require(
        any(
            c.get("application_bytes_read_after_owner_ack", 0) > 0 for c in observations
        ),
        "No observed buffered receive after cleanup ACK",
    )


def check_native_files(directory: Path) -> None:
    """Check that the native file store still holds the uploaded fork bytes."""
    for name, data in [
        (FILENAME.decode(), data_fork()),
        (UPLOAD_FILENAME.decode(), UPLOAD_DATA),
    ]:
        require(
            (directory / "native-files" / (name + ".data")).read_bytes() == data,
            "Native cleanup DATA differs",
        )
        require(
            (directory / "native-files" / (name + ".rsrc")).read_bytes()
            == resource_fork(),
            "Native cleanup MACR differs",
        )


def verify(directory: Path) -> Report:
    """Verify the retained cleanup corpus.

    Returns
    -------
    dict[str, typing.Any]
        The observations of every case and the scope of the claim.
    """
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    expected = seed() | downloads() | upload_cleanup()
    require(
        {p.name for p in (directory / "transcripts").iterdir()} == set(expected),
        "Cleanup corpus inventory differs",
    )
    source_hashes = {
        hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (directory / "sources").glob("protocol_capture*.txt")
    }
    baseline = check_baseline(directory)
    unread = check_unread(directory)
    corpus = Corpus(directory, host, guest, unread, source_hashes, baseline)
    observations = [
        check_case(corpus, name, steps, expectation)
        for name, (steps, expectation) in expected.items()
    ]
    check_races(observations, baseline)
    check_native_files(directory)
    return {
        "cases": observations,
        "baseline_stream_bytes": len(baseline),
        "scope": SCOPE,
    }


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a native cleanup corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
