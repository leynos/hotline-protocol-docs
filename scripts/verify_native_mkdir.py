#!/usr/bin/env python3
"""Verify native205 inputs, actual effects, paired streams and owned Trash cleanup."""

import dataclasses as dc
import datetime as dt
import json
import typing as typ
from pathlib import Path

from capture_acceptance import driver_in
from native_mkdir_cases import cleanup, creation, empty_root, finalization, seed, specs
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from script_cli import run
from verify_native_core import require
from verify_native_mkdir_catalogue import catalogue
from verify_native_mkdir_checks import (
    FAILURES,
    check_creation,
    check_root_empty,
    created_name,
    creation_quiet,
    listing,
    uploaded,
)
from verify_native_mkdir_views import (
    check_auxiliary,
    check_final_views,
    check_oracle_queries,
)
from verify_native_shx import sha

type Report = dict[str, typ.Any]
type Listing = dict[bytes, bytes]
type Plans = dict[str, tuple[list[Report], Report]]

# The checks live in verify_native_mkdir_checks, verify_native_mkdir_catalogue
# and verify_native_mkdir_views; the names below stay importable from this
# module. listing is imported by about twenty verify_native_*, native_* and
# evidence scripts (native_diagnostic_load_cases as file_listing); creation_quiet
# by verify_native_moves, verify_native_aliases, verify_native_news,
# verify_native_metadata and test_native_moves, test_native_metadata and
# test_native_news; catalogue, check_creation, check_root_empty and creation_quiet
# by test_native_mkdir; FAILURES, created_name and uploaded are kept because the
# original module defined them publicly.
__all__ = [
    "FAILURES",
    "catalogue",
    "check_creation",
    "check_root_empty",
    "created_name",
    "creation_quiet",
    "listing",
    "main",
    "uploaded",
    "verify",
]

CASE_COUNT = 47  # the creation matrix: 38 successes and 15 expected failures
HOST_CAPTURE_PACKETS = 1417  # the packet count that the recorder must report


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """The inputs that every native creation capture of a corpus shares.

    Attributes
    ----------
    directory : pathlib.Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The corpus manifest.
    host : list[dict[str, typing.Any]]
        The host packet capture.
    guest : list[dict[str, typing.Any]]
        The guest packet capture.
    sources : set[str]
        The hashes of the retained capture drivers.
    agreement : bytes
        The native agreement text, with its line endings normalised.
    """

    directory: Path
    manifest: Report
    host: list[Report]
    guest: list[Report]
    sources: set[str]
    agreement: bytes


def check_inventory(directory: Path, manifest: Report, cases: Plans) -> None:
    """Check the creation matrix and the auxiliary inventory of the corpus."""
    require(
        set(manifest["cases"]) == set(cases)
        and {p.name for p in (directory / "captures").iterdir()} == set(cases)
        and len(cases) == CASE_COUNT,
        "Creation matrix inventory differs",
    )
    require(
        set(manifest["auxiliary"]) == {"seed", "final", "cleanup", "root-empty"},
        "Auxiliary inventory differs",
    )


def check_recorder(host: list[Report], manifest: Report) -> None:
    """Check the packet count and the kernel drops of the recorder."""
    require(
        len(host) == manifest["host_capture_packets"] == HOST_CAPTURE_PACKETS
        and manifest["host_kernel_drops"] == 0,
        "Recorder inventory differs",
    )


def open_corpus(directory: Path, manifest: Report) -> Corpus:
    """Read the packet captures, the source hashes and the agreement text.

    Returns
    -------
    Corpus
        The inputs that the native creation captures share.
    """
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    check_recorder(host, manifest)
    sources = {sha(p) for p in (directory / "sources").iterdir()}
    agreement = (
        (directory.parent / "native-agreement-01/original-agreement.data")
        .read_bytes()
        .replace(b"\r\n", b"\r")
    )
    return Corpus(directory, manifest, host, guest, sources, agreement)


def planned_captures(cases: Plans) -> Plans:
    """Plan the auxiliary operations, then every creation capture in order.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The expected steps and expectation of each named capture.
    """
    expected_all = {
        "seed": next(iter(seed().values())),
        "final": next(iter(finalization().values())),
        "cleanup": next(iter(cleanup().values())),
        "root-empty": next(iter(empty_root().values())),
    }
    expected_all.update({"captures/" + name: value for name, value in cases.items()})
    return expected_all


def verify_run(
    corpus: Corpus, key: str, steps: list[Report], expectation: Report
) -> tuple[Report, int]:
    """Verify one captured run against its plan and the paired packets.

    Returns
    -------
    tuple[dict[str, typing.Any], int]
        The verified report and the number of paired connections it holds.
    """
    case = corpus.directory / key
    plan = json.loads((case / "plan.json").read_text())
    require(
        plan["steps"] == steps and plan["expectation"] == expectation,
        "Native creation plan differs",
    )
    report = verify_capture(case)
    require(
        report["profile"] == "native-mac-oracle"
        and report["status"] == "completed"
        and report["oracle_sha256"] == ORACLE_SHA256
        and driver_in(report, corpus.sources),
        "Invalid native creation provenance",
    )
    reconcile(report, corpus.host, corpus.guest)
    streams = len(report["streams"])
    creation_quiet(report, plan)
    return report, streams


def run_captures(corpus: Corpus, planned: Plans) -> tuple[dict[str, Report], int]:
    """Verify every planned run, and count the paired connections of all of them.

    Returns
    -------
    tuple[dict[str, dict[str, typing.Any]], int]
        The verified report of each run, and the total of paired connections.
    """
    reports = {}
    connections = 0
    for key, (steps, expectation) in planned.items():
        report, streams = verify_run(corpus, key, steps, expectation)
        connections += streams
        reports[key] = report
    return reports, connections


def check_timeline(reports: dict[str, Report], cases: Plans) -> None:
    """Check the execution order and the chronology of the creation captures."""
    timeline = sorted(cases, key=lambda n: reports["captures/" + n]["started_at_utc"])
    require(
        timeline == [c["case"] for c in specs()], "Creation execution order differs"
    )
    require(
        dt.datetime.fromisoformat(reports["seed"]["recorded_at_utc"])
        < dt.datetime.fromisoformat(
            reports["captures/" + timeline[0]]["started_at_utc"]
        )
        and reports["captures/" + timeline[-1]]["recorded_at_utc"]
        < reports["final"]["started_at_utc"]
        < reports["cleanup"]["started_at_utc"],
        "Native setup/final/cleanup chronology differs",
    )


def check_observations(reports: dict[str, Report], agreement: bytes) -> list[Report]:
    """Check every creation capture and collect its observation.

    Returns
    -------
    list[dict[str, typing.Any]]
        The observation of each creation case, in the order of the matrix.
    """
    return [
        check_creation(reports["captures/" + c["case"]], c, agreement) for c in specs()
    ]


def check_root_controls(reports: dict[str, Report], initial: Listing) -> None:
    """Check the empty-root controls, which must run after the cleanup."""
    check_root_empty(reports["root-empty"], initial)
    require(
        reports["cleanup"]["recorded_at_utc"] < reports["root-empty"]["started_at_utc"],
        "Post-cleanup root controls were reordered",
    )


def check_merged_capture(directory: Path) -> None:
    """Check that the host capture is the initial and empty recordings joined."""
    require(
        (directory / "host.pcap").read_bytes()
        == (directory / "host-initial.pcap").read_bytes()
        + (directory / "host-empty.pcap").read_bytes()[24:],
        "Merged capture differs from literal recorder files",
    )


def verify(directory: Path) -> Report:
    """Verify a retained native mkdir corpus against its planned creations.

    Returns
    -------
    dict[str, typing.Any]
        The case counts, the paired connections, the observations and the
        catalogue snapshots, with the scope that they support.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    cases = creation()
    check_inventory(directory, manifest, cases)
    corpus = open_corpus(directory, manifest)
    reports, connections = run_captures(corpus, planned_captures(cases))
    check_timeline(reports, cases)
    observed = check_observations(reports, corpus.agreement)
    initial = check_auxiliary(reports)
    check_final_views(reports["final"], reports["cleanup"], initial)
    check_root_controls(reports, initial)
    check_merged_capture(directory)
    snapshots = catalogue(directory)
    check_oracle_queries(directory)
    return {
        "cases": 47,
        "auxiliary_reports": 4,
        "paired_connections": connections,
        "successes": 38,
        "expected_failures": 15,
        "root_empty_negative_inputs": 6,
        "observations": observed,
        "catalogue": snapshots,
        "scope": "Native205 on the recorded OS9 profile; field202 cases do not prove "
        "field212/325 equivalence, alias containment, portable name rules or all "
        "delete failures.",
    }


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a native mkdir corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
