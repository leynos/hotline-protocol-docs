"""Check the retained alias corpus: its plans, recorder, reports and catalogue."""

import dataclasses as dc
import json
import typing as typ

from native_alias_cases import (
    ROOT,
    cleanup,
    create,
    damage,
    downloads,
    information,
    seed,
    supplementary,
)
from native_mkdir_cases import exchange
from native_packet_evidence import reconcile
from native_plan import close, login
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_alias_checks import creation, download, metadata, transfer_quiet
from verify_native_auth import reply
from verify_native_core import require
from verify_native_mkdir import creation_quiet, listing

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]
type Plans = dict[str, tuple[list[Report], Report | None]]

FAILED_CASE = "initial/download-eof-file-alias"
COMPLETED_REPORTS = 44
FAILED_REPORTS = 1
PAIRED_CONNECTIONS = 66
HOST_PACKETS = 1504
INITIAL_ACTIONS = 12
INITIAL_RECEIVED = 496
CATALOGUE_RECORDS = 33
POSITIVE_AFTER = 3
PARTIAL_TRASH_RECORDS = 3
RESOURCE_MINIMUM = 540


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """What the alias checks need from the retained corpus.

    Attributes
    ----------
    directory : pathlib.Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The corpus manifest.
    expected : dict
        The planned steps and expectation of each report, by report key.
    host : list[dict[str, typing.Any]]
        The host packet capture.
    guest : list[dict[str, typing.Any]]
        The guest packet capture.
    sources : set[str]
        The hashes of the capture drivers that were kept with the corpus.
    """

    directory: Path
    manifest: Report
    expected: Plans
    host: list[Report]
    guest: list[Report]
    sources: set[str]


def expected_plans() -> Plans:
    """Plan every case of the corpus, with its baseline, seeding and cleanup.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any] | None]]
        The steps and the expectation of each report, by report key.
    """
    expected: Plans = {
        "baseline": (
            login()
            + exchange(200, 10, [(202, b"\0\0")])
            + exchange(500, 90, [])
            + [close()],
            None,
        ),
        "seed": next(iter(seed().values())),
        "cleanup": next(iter(cleanup().values())),
    }
    for group, cases in [
        ("create", create()),
        ("info", information()),
        ("download", downloads()),
        ("damage", damage()),
        ("supplementary", supplementary()),
    ]:
        expected.update({group + "/" + key: value for key, value in cases.items()})
    for step in expected["baseline"][0]:
        step.pop("match_frame", None)
    return expected


def check_inventory(directory: Path, manifest: Report, expected: Plans) -> None:
    """Check that the manifest and the directory name the same reports."""
    require(
        set(manifest["reports"]) == set(expected) | {FAILED_CASE},
        "Alias report inventory differs",
    )
    require(
        {str(p.parent.relative_to(directory)) for p in directory.rglob("report.json")}
        == set(manifest["reports"]),
        "Unexpected/missing capture report",
    )


def read_captures(directory: Path) -> tuple[list[Report], list[Report]]:
    """Read the host and the guest packet captures of the corpus.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], list[dict[str, typing.Any]]]
        The host packets and the guest packets.
    """
    host = read_packets(directory / "host.pcap")
    guest = read_packets(directory / "guest.pcap")
    return host, guest


def check_recorder(manifest: Report, host: list[Report]) -> None:
    """Check the host recorder's packet count and its absence of kernel drops."""
    require(
        len(host) == manifest["host_capture_packets"] == HOST_PACKETS
        and manifest["host_kernel_drops"] == 0,
        "Alias host recorder inventory differs",
    )


def check_provenance(report: Report, sources: set[str]) -> None:
    """Check that a capture came from the native oracle and its kept driver."""
    require(
        report["profile"] == "native-mac-oracle"
        and report["oracle_sha256"] == ORACLE_SHA256
        and report["driver_sha256"] in sources,
        "Alias capture provenance differs",
    )


def check_initial_failure(report: Report) -> None:
    """Check the exploratory capture that ends with the expected EOF timeout."""
    require(
        report["completed_actions"] == INITIAL_ACTIONS
        and report["error"].startswith("TimeoutError:"),
        "Initial EOF failure differs",
    )
    require(
        len(bytes.fromhex(report["streams"]["transfer"]["received_hex"]))
        == INITIAL_RECEIVED,
        "Initial transfer was not complete before EOF timeout",
    )


def check_planned(planned: tuple[list[Report], Report | None], plan: Report) -> None:
    """Check that a recorded plan is the planned steps and expectation."""
    steps, expectation = planned
    require(
        plan["steps"] == steps
        and (expectation is None or plan["expectation"] == expectation),
        "Alias plan differs",
    )


def check_report(corpus: Corpus, key: str) -> tuple[Report, Report]:
    """Check one capture against its provenance, its plan and the packets.

    Returns
    -------
    tuple[dict[str, typing.Any], dict[str, typing.Any]]
        The verified report and its recorded plan.
    """
    case = corpus.directory / key
    report = verify_capture(case)
    plan = json.loads((case / "plan.json").read_text())
    check_provenance(report, corpus.sources)
    require(
        report["status"]
        == corpus.manifest["reports"][key]
        == ("failed" if key == FAILED_CASE else "completed"),
        "Alias report disposition differs",
    )
    if key == FAILED_CASE:
        check_initial_failure(report)
    else:
        check_planned(corpus.expected[key], plan)
    reconcile(report, corpus.host, corpus.guest)
    return report, plan


def check_case(report: Report, key: str, plan: Report) -> None:
    """Check one report with the checks of its kind."""
    if key.startswith("create/"):
        creation(report, plan["expectation"])
        creation_quiet(report, plan)
    elif key.startswith("info/"):
        metadata(
            report,
            key.split("/")[1],
            bytes.fromhex(plan["expectation"]["name_hex"]),
        )
        listing(reply(report, 11))
    elif key.startswith("download/"):
        download(report, folder=plan["expectation"]["folder"])
        transfer_quiet(report, plan)


def check_reports(corpus: Corpus) -> tuple[dict[str, Report], int]:
    """Check every report in turn, and count its paired connections.

    Returns
    -------
    tuple[dict[str, typing.Any], int]
        The verified reports by key, and the number of paired connections.
    """
    reports: dict[str, Report] = {}
    connections = 0
    for key in sorted(corpus.manifest["reports"]):
        report, plan = check_report(corpus, key)
        connections += len(report["streams"])
        reports[key] = report
        check_case(report, key, plan)
    return reports, connections


def check_totals(manifest: Report, connections: int) -> None:
    """Check the aggregate counts of the connections and the reports."""
    require(
        connections == manifest["paired_connections"] == PAIRED_CONNECTIONS
        and manifest["completed_reports"] == COMPLETED_REPORTS
        and manifest["failed_reports"] == FAILED_REPORTS,
        "Alias aggregate counts differ",
    )


def check_physical_aliases(
    snapshot: Path, records: dict[str, Report], prefix: str
) -> None:
    """Check the fork bytes of the five alias entries that remain on disk."""
    physical = [
        ("/A/file", b""),
        ("/B/file", b""),
        ("/self", b"self-source"),
        ("/C/same", b"collision-destination"),
        ("/A/dir", b""),
    ]
    for suffix, data in physical:
        record = records[prefix + suffix]
        key = record["key"]
        stat = (snapshot / (key + ".stat.txt")).read_text()
        require(
            not record["directory"]
            and "Is alias\n" in stat
            and "Type: alis" in stat
            and "ID: 0" in stat,
            "Missing physical alias flag/resource",
        )
        require(
            (snapshot / (key + ".data")).read_bytes() == data,
            "Alias physical data fork differs",
        )
        require(
            len((snapshot / (key + ".rsrc")).read_bytes()) >= RESOURCE_MINIMUM,
            "Missing physical alias resource bytes",
        )
        if suffix == "/A/dir":
            require(
                "66647270  fdrp" in stat and "4d414353  MACS" in stat,
                "Directory alias physical tags differ",
            )


def check_ordinary_children(
    snapshot: Path, records: dict[str, Report], prefix: str
) -> None:
    """Check that the ordinary directory children kept their own bytes."""
    for suffix, data in [("/dir/leaf", b"dir-leaf"), ("/C/dir/keep", b"keep")]:
        require(
            (snapshot / (records[prefix + suffix]["key"] + ".data")).read_bytes()
            == data,
            "Alias changed ordinary directory child",
        )


def check_partial_trash(directory: Path) -> None:
    """Check the partial observation of the owned tree in the Trash."""
    partial = json.loads((directory / "native-cleanup/extraction.json").read_text())[
        "records"
    ]
    require(
        len(partial) == PARTIAL_TRASH_RECORDS
        and all(r["path"].startswith("/Trash/" + ROOT.decode() + "/") for r in partial),
        "Partial Trash observation differs",
    )


def catalogue(directory: Path) -> Report:
    """Check the positive fork catalogue and the partial Trash observation.

    Returns
    -------
    dict[str, typing.Any]
        The record counts before and after cleanup, and the coverage statement.
    """
    snapshot = directory / "native-final"
    records = json.loads((snapshot / "extraction.json").read_text())["records"]
    require(
        len(records) == CATALOGUE_RECORDS,
        "Final positive catalogue inventory differs",
    )
    records = {r["path"]: r for r in records}
    prefix = "/Hotline19/Files/" + ROOT.decode()
    check_physical_aliases(snapshot, records, prefix)
    check_ordinary_children(snapshot, records, prefix)
    check_partial_trash(directory)
    return {
        "positive_before": CATALOGUE_RECORDS,
        "positive_after": POSITIVE_AFTER,
        "cleanup_disk_coverage": "Partial; not a persistence or exhaustive Trash proof",
    }
