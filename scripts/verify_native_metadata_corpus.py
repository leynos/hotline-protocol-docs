"""Check the retained native metadata corpus, one stage at a time.

The inventory, the merged host recording, the as-run plans, the combined-empty
cases, the owned accounts and entries, and the aggregate counts. The stages run
in the order that verify_native_metadata calls them; their reads and requires
must not be reordered.
"""

import dataclasses as dc
import json
import typing as typ

from capture_acceptance import driver_in
from native_auth_cases import complement
from native_metadata_cases import (
    ACCOUNTS,
    ROOT,
    account_cleanup,
    boundaries,
    cleanup,
    combined_empty,
    final_name,
    finalization,
    mutations,
    preflight,
    seed,
    specs,
)
from native_packet_evidence import reconcile
from native_plan import packet, payload
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_ERROR_TEXT,
    FIELD_LOGIN,
    TYPE_DELETE_ACCOUNT,
)
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_auth import reply
from verify_native_core import require
from verify_native_metadata_checks import expected_comment, info
from verify_native_mkdir import creation_quiet, listing
from verify_native_shx import fields, sha

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]
type Plans = dict[str, tuple[list[Report], Report]]
type Reports = dict[str, Report]

PCAP_HEADER_BYTES = 24  # the global header that a merged recording repeats
HOST_CAPTURE_PACKETS = 2161  # the packets of the merged host recording
BASELINE_FILE_COUNT = 41  # the entries of the owned tree before the corpus writes
REPORT_COUNT = 49  # the completed reports of the corpus
CONNECTION_COUNT = 72  # the paired connections of the corpus
MUTATION_CASE_COUNT = 36  # the account-write cases of the table
COMBINED_EMPTY_CASE_COUNT = 6  # the combined empty-field cases
BOUNDARY_WRITE_COUNT = 22  # the comment-boundary writes, for a file and a folder
ORACLE_QUERY_COUNT = 13  # the oracle queries, one for each recorded address
ORACLE_ADDRESSES = {
    "100170c0",
    "1002c690",
    "1002bc30",
    "1002c070",
    "1002f600",
    "100564c0",
    "10056c70",
    "10008ab0",
    "1002e120",
    "1007ea90",
    "1002c740",
    "1007ee40",
    "1007ed00",
}
ORACLE_QUERY_PREFIX = "MT-D-"


@dc.dataclass(frozen=True, slots=True)
class Recordings:
    """The two recordings of the corpus and the hashes of its retained sources.

    Attributes
    ----------
    host : list[dict[str, typing.Any]]
        The packets of the merged host recording.
    guest : list[dict[str, typing.Any]]
        The packets of the guest recording.
    sources : set[str]
        The SHA-256 hash of every retained source file.
    """

    host: list[Report]
    guest: list[Report]
    sources: set[str]


def expected_plans() -> Plans:
    """Plan every case of the corpus, and correct the recorded cleanup mistake.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The steps and the expectation of each case, keyed by its directory.
    """
    expected = {
        "preflight": next(iter(preflight().values())),
        "seed": next(iter(seed().values())),
        "final": next(iter(finalization().values())),
        "cleanup": next(iter(cleanup().values())),
        "account-cleanup": next(iter(account_cleanup().values())),
    }
    expected.update({"mutations/" + k: v for k, v in mutations().items()})
    expected.update({"boundaries/" + k: v for k, v in boundaries().items()})
    expected.update({"combined-empty/" + k: v for k, v in combined_empty().items()})
    # Preserve the actual initial mistake rather than silently replacing its plan.
    for identifier, (name, _) in enumerate(ACCOUNTS.values(), 30):
        encoded = packet(
            TYPE_DELETE_ACCOUNT, identifier, payload([(FIELD_LOGIN, complement(name))])
        )
        for step in expected["cleanup"][0]:
            if step.get("hex") == encoded:
                step["hex"] = packet(
                    TYPE_DELETE_ACCOUNT, identifier, payload([(FIELD_LOGIN, name)])
                )
    return expected


def check_inventory(directory: Path, manifest: Report, expected: Plans) -> None:
    """Check that the manifest, the plans and the directory list the same reports."""
    require(
        set(manifest["reports"])
        == set(expected)
        == {
            str(p.parent.relative_to(directory)) for p in directory.rglob("report.json")
        },
        "Metadata corpus inventory differs",
    )


def check_merged_capture(directory: Path) -> None:
    """Check that the merged host recording repeats the literal recordings."""
    require(
        (directory / "host.pcap").read_bytes()
        == (directory / "host-initial.pcap").read_bytes()
        + (directory / "host-account-cleanup.pcap").read_bytes()[PCAP_HEADER_BYTES:]
        + (directory / "host-combined-empty.pcap").read_bytes()[PCAP_HEADER_BYTES:],
        "Merged host capture differs from literal recordings",
    )


def read_recordings(directory: Path, manifest: Report) -> Recordings:
    """Read the host and guest recordings and hash the retained sources.

    Returns
    -------
    Recordings
        The two recordings and the set of retained source hashes.
    """
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == manifest["host_capture_packets"] == HOST_CAPTURE_PACKETS
        and manifest["host_kernel_drops"] == 0,
        "Metadata host recorder inventory differs",
    )
    sources = {sha(p) for p in (directory / "sources").iterdir()}
    return Recordings(host, guest, sources)


def check_case(
    directory: Path,
    key: str,
    planned: tuple[list[Report], Report],
    recordings: Recordings,
) -> Report:
    """Check one case's as-run plan, its capture and its reconciliation.

    Returns
    -------
    dict[str, typing.Any]
        The verified capture report of the case.
    """
    steps, expectation = planned
    case = directory / key
    plan = json.loads((case / "plan.json").read_text())
    require(
        plan["steps"] == steps and plan["expectation"] == expectation,
        "Metadata as-run plan differs",
    )
    report = verify_capture(case)
    require(
        report["status"] == "completed"
        and report["profile"] == "native-mac-oracle"
        and report["oracle_sha256"] == ORACLE_SHA256
        and driver_in(report, recordings.sources),
        "Metadata provenance/completion differs",
    )
    reconcile(report, recordings.host, recordings.guest)
    if key.startswith("mutations/"):
        creation_quiet(report, plan)
    return report


def check_plans(
    directory: Path, expected: Plans, recordings: Recordings
) -> tuple[Reports, int]:
    """Check every case of the corpus, in the planned order.

    Returns
    -------
    tuple[dict[str, dict[str, typing.Any]], int]
        The verified report of each case, and the number of paired connections.
    """
    reports, connections = {}, 0
    for key, planned in expected.items():
        report = check_case(directory, key, planned, recordings)
        connections += len(report["streams"])
        reports[key] = report
    return reports, connections


def check_baseline(reports: Reports) -> dict[bytes, bytes]:
    """Check that the owned tree was empty before the corpus wrote to it.

    Returns
    -------
    dict[bytes, bytes]
        The listing of the owned tree in the preflight reply.
    """
    baseline = listing(reply(reports["preflight"], 10))
    require(
        len(baseline) == BASELINE_FILE_COUNT and ROOT not in baseline,
        "Owned tree preflight was not empty",
    )
    return baseline


def check_combined_case(
    report: Report, expectation: Report, baseline: dict[bytes, bytes]
) -> None:
    """Check the observations of one combined empty-field case."""
    name, final = (
        bytes.fromhex(expectation["name_hex"]),
        bytes.fromhex(expectation["final_hex"]),
    )
    require(
        name not in baseline and final not in baseline,
        "Supplementary owned name was not absent",
    )
    info(reply(report, 10), name, expectation["folder"], b"base-comment")
    require(
        reply(report, 12)["error"] == 0 and fields(reply(report, 12)) == {},
        "Combined empty mutation failed",
    )
    info(
        reply(report, 21),
        final,
        expectation["folder"],
        bytes.fromhex(expectation["comment_hex"]) or None,
    )
    if name != final:
        require(reply(report, 20)["error"] == 1, "Combined clear/rename left old name")
    require(
        reply(report, 40)["error"] == 0
        and listing(reply(report, 9)) == listing(reply(report, 90)) == baseline,
        "Combined empty cleanup did not restore Files",
    )


def check_combined(
    directory: Path, reports: Reports, baseline: dict[bytes, bytes]
) -> None:
    """Check each combined empty-field case and the plan that it ran."""
    for label, (_, expectation) in combined_empty().items():
        report = reports["combined-empty/" + label]
        check_combined_case(report, expectation, baseline)
        creation_quiet(
            report,
            json.loads(
                (directory / "combined-empty" / label / "plan.json").read_text()
            ),
        )


def check_owned_account(
    reports: Reports, identifier: int, name: bytes, privileges: bytes
) -> None:
    """Check one owned account through its preflight, seed, cleanup and absence."""
    absent = {FIELD_ERROR_TEXT: b"No account with login \xd2" + name + b"\xd3."}
    require(
        reply(reports["preflight"], identifier)["error"] == 1
        and fields(reply(reports["preflight"], identifier)) == absent,
        "Owned account preflight was not empty",
    )
    require(
        reply(reports["seed"], identifier)["error"] == 0
        and fields(reply(reports["seed"], identifier + 10))[FIELD_ACCESS_BITMAP]
        == privileges,
        "Seed account creation/bitmap differs",
    )
    require(
        reply(reports["cleanup"], identifier + 10)["error"] == 1
        and reply(reports["cleanup"], identifier + 20)["error"] == 0,
        "Initial cleanup mistake was not preserved",
    )
    require(
        reply(reports["account-cleanup"], identifier + 10)["error"] == 0,
        "Corrected account deletion failed",
    )
    gone = reply(reports["account-cleanup"], identifier + 20)
    require(
        gone["error"] == 1 and fields(gone) == absent,
        "Owned account remains after corrected cleanup",
    )


def check_accounts(reports: Reports) -> None:
    """Check each owned account in the order of the account table."""
    for identifier, (name, privileges) in enumerate(ACCOUNTS.values(), 20):
        check_owned_account(reports, identifier, name, privileges)


def check_finals(reports: Reports) -> None:
    """Check the final name, comment and type of each table row's entry."""
    for identifier, spec in enumerate(specs(), 100):
        info(
            reply(reports["final"], identifier),
            final_name(spec),
            spec["folder"],
            expected_comment(spec),
        )


def check_restored(reports: Reports, baseline: dict[bytes, bytes]) -> None:
    """Check that the owned cleanup restored the Files wire listing."""
    require(
        reply(reports["cleanup"], 20)["error"] == 0
        and listing(reply(reports["cleanup"], 90))
        == listing(reply(reports["account-cleanup"], 90))
        == baseline,
        "Owned cleanup did not restore Files wire listing",
    )


def check_aggregates(manifest: Report, reports: Reports, connections: int) -> None:
    """Check the completed report and paired connection counts."""
    require(
        manifest["completed_reports"] == len(reports) == REPORT_COUNT
        and manifest["paired_connections"] == connections == CONNECTION_COUNT,
        "Metadata aggregate counts differ",
    )


def check_oracle(directory: Path) -> None:
    """Check the oracle queries: their inventory, program hash and code."""
    queries = list((directory / "oracle-queries").glob("*.json"))
    require(
        len(queries) == ORACLE_QUERY_COUNT
        and {p.stem.removeprefix(ORACLE_QUERY_PREFIX) for p in queries}
        == ORACLE_ADDRESSES,
        "Metadata oracle inventory differs",
    )
    for p in queries:
        q = json.loads(p.read_text())
        require(
            q["program"]["sha256"] == ORACLE_SHA256
            and not q["result"].get("isError", False)
            and q["result"]["structuredContent"]["code"]
            == p.with_suffix(".c").read_text(),
            "Metadata oracle identity/code differs",
        )
