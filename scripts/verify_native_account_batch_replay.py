"""Open the account-batch corpus and replay every report against its plan.

The order of the checks in each function is the order in which a corrupt corpus
is refused, so a function reads its evidence in the sequence that it always has.
"""

import dataclasses as dc
import datetime as dt
import itertools as it
import json
import typing as typ

import native_account_batch_cases as cases
import native_account_batch_model as model
from native_packet_evidence import reconcile
from native_wire_names import FIELD_TRANSFER_REFERENCE
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_auth import reply
from verify_native_core import require
from verify_native_live_accounts import waits
from verify_native_shx import fields, sha

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]
type Plan = tuple[list[Report], Report]
type Packets = tuple[list[Report], list[Report]]

RUNTIME_PID = 1259319
RUNTIME_EXECUTABLE_SHA256 = (
    "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
)
HOST_PACKETS = 1967
REFERENCE_ID = 80
REFERENCE_REPORTS = {"seed", "final", "distinct-seed", "distinct-final", "publish"}


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """The corpus directory with what its manifest and the planners expect."""

    directory: Path
    manifest: Report
    runtime: Report
    specifications: list[Report]
    distinct: Report
    inventory: list[str]
    expected: dict[str, Plan]


def planned_reports(
    specifications: list[Report], distinct: Report, inventory: list[str]
) -> dict[str, Plan]:
    """Plan every report that the corpus holds, in recording order.

    Returns
    -------
    dict[str, tuple[list, dict]]
        The planned steps and expectation of each report, by directory name.
    """
    expected = {"preflight": cases.preflight(), "seed": cases.seed()}
    for spec in specifications:
        expected["before-" + spec["case"]] = cases.inspect(spec)
        expected["batch-" + spec["case"]] = cases.batch(spec)
        expected["after-" + spec["case"]] = cases.inspect(spec)
    expected.update({
        "nul-password-login": cases.probe_nul(),
        "final": cases.finalization(),
        "distinct-preflight": cases.inspect(distinct),
        "distinct-seed": cases.supplementary_seed(),
        "distinct-before": cases.inspect(distinct),
        "distinct-batch": cases.batch(distinct),
        "distinct-after": cases.inspect(distinct),
    })
    expected.update({
        "distinct-login-" + name: cases.supplementary_probe(name)
        for name in ["source", "destination-source", "destination-old"]
    })
    expected.update({
        "distinct-final": cases.supplementary_final(),
        "cleanup": cases.cleanup(inventory),
        "publish": cases.publish_cleanup(),
        "remove-publisher": cases.remove_publisher(),
    })
    return expected


def open_corpus(directory: Path) -> Corpus:
    """Read the manifest and runtime and plan every report.

    Returns
    -------
    Corpus
        The corpus with its plans.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    runtime = json.loads((directory / "runtime.json").read_text())
    require(
        runtime["emulator_pid"] == RUNTIME_PID
        and runtime["running_executable_sha256"] == RUNTIME_EXECUTABLE_SHA256
        and cases.OWNED == model.OWNED
        and cases.EXTRA == model.EXTRA,
        "Batch runtime/owned inventory differs",
    )
    specifications = cases.specifications()
    require(
        [s["case"] for s in specifications] == list(model.effects()),
        "Batch case order/inventory differs",
    )
    distinct = cases.supplementary_spec()
    inventory = json.loads((directory / "cleanup-inventory.json").read_text())
    expected = planned_reports(specifications, distinct, inventory)
    return Corpus(
        directory, manifest, runtime, specifications, distinct, inventory, expected
    )


def check_report_inventory(corpus: Corpus) -> None:
    """Check that the planned, manifest and retained report names agree."""
    directory = corpus.directory
    require(
        set(corpus.expected)
        == set(corpus.manifest["reports"])
        == {
            str(p.parent.relative_to(directory)) for p in directory.rglob("report.json")
        },
        "Batch report inventory differs",
    )


def read_captures(directory: Path) -> tuple[list[Report], list[Report]]:
    """Read the host and guest packets, and check the recorder's drop count.

    Returns
    -------
    tuple[list, list]
        The host packets and the guest packets.
    """
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == HOST_PACKETS
        and "0 packets dropped by kernel"
        in (directory / "host-capture-statistics.txt").read_text(),
        "Batch packet recorder count/drop differs",
    )
    return host, guest


def check_sent(report: Report, steps: list[Report], key: str) -> None:
    """Check that each connection sent exactly the bytes that the plan sent."""
    reference = (
        fields(reply(report, REFERENCE_ID))[FIELD_TRANSFER_REFERENCE].hex()
        if key in REFERENCE_REPORTS
        else ""
    )
    for connection, recorded in report["streams"].items():
        sent = "".join(
            bytes.fromhex(s["hex"].replace("{ref80}", reference)).hex()
            for s in steps
            if s["op"] == "send" and s["connection"] == connection
        )
        require(
            recorded["sent_hex"] == sent, "Batch recorded request differs from plan"
        )


def replay_report(corpus: Corpus, key: str, packets: Packets) -> Report:
    """Check one report against its plan, provenance, sent bytes and packets.

    Returns
    -------
    dict[str, typing.Any]
        The verified report.
    """
    steps, expectation = corpus.expected[key]
    directory = corpus.directory
    case = directory / key
    plan = json.loads((case / "plan.json").read_text())
    require(
        plan["steps"] == steps
        and plan["expectation"] == expectation
        and plan["environment"] == corpus.runtime,
        "Batch as-run plan differs",
    )
    report = verify_capture(case)
    require(
        report["status"] == corpus.manifest["reports"][key] == "completed"
        and report["profile"] == "native-mac-oracle"
        and report["oracle_sha256"] == ORACLE_SHA256
        and report["driver_sha256"] == sha(directory / "sources/protocol_capture.py"),
        "Batch capture provenance/completion differs",
    )
    check_sent(report, steps, key)
    reconcile(report, *packets)
    waits(report, steps)
    return report


def replay(corpus: Corpus, packets: Packets) -> tuple[dict[str, Report], int]:
    """Check every report, and that the captures follow one another in time.

    Returns
    -------
    tuple[dict[str, dict], int]
        The reports by name, and the number of paired connections.
    """
    reports, connections = {}, 0
    for key in corpus.expected:
        report = replay_report(corpus, key, packets)
        connections += len(report["streams"])
        reports[key] = report
    require(
        all(
            dt.datetime.fromisoformat(reports[a]["recorded_at_utc"])
            <= dt.datetime.fromisoformat(reports[b]["started_at_utc"])
            for a, b in it.pairwise(corpus.expected)
        ),
        "Batch capture chronology differs",
    )
    return reports, connections
