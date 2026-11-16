"""Plan the account corpus cases and check each against its capture."""

import dataclasses as dc
import datetime as dt
import json
import typing as typ
from itertools import pairwise

import native_account_update_cases as cases
from capture_acceptance import driver_in
from native_packet_evidence import reconcile
from native_wire_names import FIELD_TRANSFER_REFERENCE
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_account_update_checks import BASE_PASSWORD, LABELS, PASSWORDS
from verify_native_article_deletion import measured_wait
from verify_native_auth import reply
from verify_native_core import require
from verify_native_shx import fields, sha

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]
type Plan = tuple[list[Report], Report]

EMULATOR_PID = 1259319
RUNNING_EXECUTABLE_SHA256 = (
    "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
)
RECORDER_PACKETS = 732
ORACLE_QUERIES = 11


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """What every case of the account corpus is checked against.

    Attributes
    ----------
    directory : pathlib.Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The corpus manifest.
    runtime : dict[str, typing.Any]
        The runtime record that every as-run plan must match.
    host : list[dict[str, typing.Any]]
        The packets that the host recorder captured.
    guest : list[dict[str, typing.Any]]
        The packets that the guest recorder captured.
    sources : set[str]
        The digests of the source files that the corpus retained.
    """

    directory: Path
    manifest: Report
    runtime: Report
    host: list[Report]
    guest: list[Report]
    sources: set[str]


def check_identity(runtime: Report) -> None:
    """Check that the corpus was run by the emulator and case set it names."""
    require(
        cases.LABELS == LABELS
        and runtime["emulator_pid"] == EMULATOR_PID
        and runtime["running_executable_sha256"] == RUNNING_EXECUTABLE_SHA256,
        "Account case/runtime identity differs",
    )


def expected_plans() -> dict[str, Plan]:
    """Plan every case of the account corpus, in capture order.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The steps and the expectation of each case, by case name.
    """
    expected: dict[str, Plan] = {
        "preflight": cases.preflight(),
        "seed": cases.seed(),
        "base32-login": cases.probe("preserve32", b"q" * 32, success=True),
    }
    for label in LABELS:
        expected["mutation-" + label] = cases.mutate(label)
        expected["login-" + label] = cases.probe(label, PASSWORDS[label], success=True)
        old = b"q" * 32 if label == "preserve32" else BASE_PASSWORD
        wrong = old if old != PASSWORDS[label] else b"wrong-account26"
        expected["reject-" + label] = cases.probe(label, wrong, success=False)
    expected.update({
        "final": cases.finalization(),
        "cleanup": cases.cleanup(),
        "publish": cases.publish_cleanup(),
        "remove-publisher": cases.remove_publisher(),
    })
    return expected


def check_inventory(
    directory: Path, manifest: Report, expected: dict[str, Plan]
) -> None:
    """Check that the planned cases are the reports that the corpus holds."""
    require(
        set(expected)
        == set(manifest["reports"])
        == {
            str(p.parent.relative_to(directory)) for p in directory.rglob("report.json")
        },
        "Account report inventory differs",
    )


def open_corpus(directory: Path, manifest: Report, runtime: Report) -> Corpus:
    """Read both packet recordings and the source digests of the corpus.

    Returns
    -------
    Corpus
        The corpus.
    """
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(len(host) == RECORDER_PACKETS, "Account packet recorder count differs")
    statistics = (directory / "host-capture-statistics.txt").read_text()
    require(
        "732 packets captured" in statistics
        and "0 packets dropped by kernel" in statistics,
        "Account capture drops/count differ",
    )
    sources = {sha(p) for p in (directory / "sources").iterdir()}
    return Corpus(directory, manifest, runtime, host, guest, sources)


def check_case(corpus: Corpus, key: str, plan: Plan) -> Report:
    """Check the as-run plan, the capture and the recorded input of one case.

    Returns
    -------
    dict[str, typing.Any]
        The capture report of the case.
    """
    steps, expectation = plan
    case = corpus.directory / key
    as_run = json.loads((case / "plan.json").read_text())
    require(
        as_run["steps"] == steps
        and as_run["expectation"] == expectation
        and as_run["environment"] == corpus.runtime,
        "Account as-run plan differs",
    )
    report = verify_capture(case)
    require(
        report["status"] == corpus.manifest["reports"][key] == "completed"
        and report["profile"] == "native-mac-oracle"
        and report["oracle_sha256"] == ORACLE_SHA256
        and driver_in(report, corpus.sources),
        "Account capture provenance/completion differs",
    )
    reference = (
        fields(reply(report, 80))[FIELD_TRANSFER_REFERENCE].hex()
        if key in {"seed", "final", "publish"}
        else ""
    )
    for connection, recorded in report["streams"].items():
        sent = "".join(
            bytes.fromhex(s["hex"].replace("{ref80}", reference)).hex()
            for s in steps
            if s["op"] == "send" and s["connection"] == connection
        )
        require(
            recorded["sent_hex"] == sent, "Account recorded input differs from plan"
        )
    reconcile(report, corpus.host, corpus.guest)
    return report


def check_cases(
    corpus: Corpus, expected: dict[str, Plan]
) -> tuple[dict[str, Report], int]:
    """Check every case of the corpus and wait for each recorded quiet period.

    Returns
    -------
    tuple[dict[str, typing.Any], int]
        The capture report of each case, by name, and the paired connections.
    """
    reports: dict[str, Report] = {}
    connections = 0
    for key, plan in expected.items():
        report = check_case(corpus, key, plan)
        connections += len(report["streams"])
        reports[key] = report
        if key == "seed":
            measured_wait(report, "pause")
        if key.startswith(("mutation-", "login-", "reject-")) or key == "base32-login":
            measured_wait(report, "expect_quiet")
    return reports, connections


def check_chronology(reports: dict[str, Report], order: list[str]) -> None:
    """Check that each case was recorded before the next one started."""
    require(
        all(
            dt.datetime.fromisoformat(reports[a]["recorded_at_utc"])
            <= dt.datetime.fromisoformat(reports[b]["started_at_utc"])
            for a, b in pairwise(order)
        ),
        "Account fixture chronology differs",
    )


def check_oracle(directory: Path) -> None:
    """Check the oracle queries that the corpus retained for its addresses."""
    addresses = {
        "10014df0",
        "100146f0",
        "10014bc0",
        "100149e0",
        "100073c0",
        "100075e0",
        "100071a0",
        "10005d30",
        "10005f90",
        "10011960",
        "10007340",
    }
    queries = list((directory / "oracle-queries").glob("*.json"))
    require(
        len(queries) == ORACLE_QUERIES
        and {p.stem.removeprefix("AC-D-") for p in queries} == addresses,
        "Account oracle inventory differs",
    )
    for p in queries:
        q = json.loads(p.read_text())
        require(
            q["program"]["sha256"] == ORACLE_SHA256
            and not q["result"].get("isError", False)
            and q["result"]["structuredContent"]["code"]
            == p.with_suffix(".c").read_text(),
            "Account oracle identity/code differs",
        )
