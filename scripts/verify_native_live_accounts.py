#!/usr/bin/env python3
"""Verify live account events, orderly close and application restart persistence."""

import dataclasses as dc
import datetime as dt
import itertools as it
import json
import typing as typ
from pathlib import Path

import native_live_account_cases as cases
from native_packet_evidence import reconcile
from native_wire_names import FIELD_TRANSFER_REFERENCE
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from script_cli import run
from verify_native_auth import reply
from verify_native_core import require
from verify_native_live_checks import (
    check_baseline,
    check_enumerations,
    check_files,
    check_logins,
    check_oracle_queries,
    check_persistence,
    check_restart_journal,
)
from verify_native_live_edits import check_delete, check_edit, subjects
from verify_native_live_storage import native_record, stopped, storage
from verify_native_shx import fields, sha

type Report = dict[str, typ.Any]
type Plan = tuple[list[Report], Report]

# The edit and deletion checks live in verify_native_live_edits, the storage and
# witness checks in verify_native_live_storage and the later checks in
# verify_native_live_checks; the names below stay importable from this module.
# waits is imported by verify_native_account_batches, verify_native_account_identity
# and verify_native_rooms; check_delete, check_edit, stopped, storage and verify by
# test_native_live_accounts; native_record and subjects are kept because the
# original module defined them publicly.
__all__ = [
    "check_delete",
    "check_edit",
    "main",
    "native_record",
    "stopped",
    "storage",
    "subjects",
    "verify",
    "waits",
]

RUNTIME_PID = 1259319
RUNTIME_EXECUTABLE_SHA256 = (
    "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
)
HOST_PACKETS = 551
REPORT_COUNT = 19
COMPLETED_REPORTS = 18
HOST_SOCKETS = 25
GUEST_CONNECTIONS = 24
ORACLE_QUERY_COUNT = 16
NS_PER_SECOND = 1e9
REFERENCE_ID = 80
REFERENCE_REPORTS = {"before-final", "publish"}
AFTER_REPORTS = {"cleanup", "publish", "remove-publisher"}
PROBES = ["old", "intermediate", "final", "deleted"]
SCOPE = (
    "Normal native server application restart in the same emulator; no "
    "OS/power-loss restart, all-disconnect deadline, forced-write atomicity or "
    "historical-client claim. Host stage exit143 retained with independent "
    "confirmation."
)


def waits(report: Report, steps: list[Report]) -> None:
    """Check that each planned pause or quiet window lasted as long as planned."""
    for action, step in enumerate(steps):
        if step["op"] not in {"pause", "expect_quiet"}:
            continue
        event = "pause" if step["op"] == "pause" else "quiet"
        matches = [
            i
            for i, e in enumerate(report["events"])
            if e["action"] == action and e["event"] == event
        ]
        require(len(matches) == 1 and matches[0] > 0, "Missing live account wait event")
        index = matches[0]
        duration = step.get("seconds", step.get("timeout"))
        require(
            report["events"][index]["elapsed_ns"]
            - report["events"][index - 1]["elapsed_ns"]
            >= duration * NS_PER_SECOND,
            "Short live account wait",
        )


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """The corpus directory with what its files and the planners say to expect."""

    directory: Path
    manifest: Report
    runtimes: dict[str, Report]
    expected: dict[str, Plan]
    host: list[Report]
    guest: list[Report]
    tails: Report


def planned_reports() -> dict[str, Plan]:
    """Plan every report that the corpus holds, in recording order.

    Returns
    -------
    dict[str, tuple[list, dict]]
        The planned steps and expectation of each report, by directory name.
    """
    expected = {
        "preflight": cases.preflight(),
        "seed": cases.seed(),
        "edit": cases.edit(),
        "delete": cases.delete(),
    }
    expected.update({"before-login-" + label: cases.probe(label) for label in PROBES})
    expected.update({
        "before-final": cases.finalize(),
        "stopped": cases.stopped(),
        "after-inspect": cases.inspect(),
    })
    expected.update({"after-login-" + label: cases.probe(label) for label in PROBES})
    expected.update({
        "after-inspect-confirmation": cases.inspect(),
        "cleanup": cases.cleanup(),
        "publish": cases.publish_cleanup(),
        "remove-publisher": cases.remove_publisher(),
    })
    return expected


def open_corpus(directory: Path) -> Corpus:
    """Read the manifest, runtimes, packets and unread tail, and check them.

    Returns
    -------
    Corpus
        The corpus with its plans.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    runtimes = {
        phase: json.loads((directory / ("runtime-" + phase + ".json")).read_text())
        for phase in ["before", "after"]
    }
    require(
        all(
            r["emulator_pid"] == RUNTIME_PID
            and r["running_executable_sha256"] == RUNTIME_EXECUTABLE_SHA256
            for r in runtimes.values()
        )
        and runtimes["before"]["server_epoch"] != runtimes["after"]["server_epoch"],
        "Live runtime epochs differ",
    )
    expected = planned_reports()
    require(
        set(expected)
        == set(manifest["reports"])
        == {
            str(p.parent.relative_to(directory)) for p in directory.rglob("report.json")
        },
        "Live report inventory differs",
    )
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == HOST_PACKETS
        and "0 packets dropped by kernel"
        in (directory / "host-capture-statistics.txt").read_text(),
        "Live packet recorder count/drop differs",
    )
    tails = json.loads((directory / "delete-unread-tails.json").read_text())
    require(set(tails) == {"main"}, "Unexpected unread live socket")
    return Corpus(directory, manifest, runtimes, expected, host, guest, tails)


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
            for s in steps[: report["completed_actions"]]
            if s["op"] == "send" and s["connection"] == connection
        )
        require(recorded["sent_hex"] == sent, "Live recorded request differs from plan")


def replay_report(corpus: Corpus, key: str) -> tuple[Report, Report | None]:
    """Check one report against its plan, provenance, sent bytes and packets.

    Returns
    -------
    tuple[dict, dict | None]
        The verified report and its packet reconciliation (none for the
        stopped witness, which has none).
    """
    steps, expectation = corpus.expected[key]
    directory = corpus.directory
    case = directory / key
    plan = json.loads((case / "plan.json").read_text())
    phase = "after" if key.startswith("after-") or key in AFTER_REPORTS else "before"
    require(
        plan["steps"] == steps
        and plan["expectation"] == expectation
        and plan["environment"] == corpus.runtimes[phase],
        "Live as-run plan differs",
    )
    report = verify_capture(case)
    status = "failed" if key == "stopped" else "completed"
    require(
        report["status"] == corpus.manifest["reports"][key] == status
        and report["profile"] == "native-mac-oracle"
        and report["oracle_sha256"] == ORACLE_SHA256
        and report["driver_sha256"] == sha(directory / "sources/protocol_capture.py"),
        "Live capture provenance/status differs",
    )
    check_sent(report, steps, key)
    if key == "stopped":
        stopped(report, corpus.host, corpus.guest)
        return report, None
    unread = {"main": bytes.fromhex(corpus.tails["main"])} if key == "delete" else None
    observation = reconcile(report, corpus.host, corpus.guest, unread)
    waits(report, steps)
    return report, observation


def replay(corpus: Corpus) -> tuple[dict[str, Report], dict[str, Report], int]:
    """Check every report, and that the captures follow one another in time.

    Returns
    -------
    tuple[dict, dict, int]
        The reports and the packet observations by name, and the socket count.
    """
    reports, observations, sockets = {}, {}, 0
    for key in corpus.expected:
        report, observation = replay_report(corpus, key)
        if observation is not None:
            observations[key] = observation
        sockets += len(report["streams"])
        reports[key] = report
    require(
        all(
            dt.datetime.fromisoformat(reports[a]["recorded_at_utc"])
            <= dt.datetime.fromisoformat(reports[b]["started_at_utc"])
            for a, b in it.pairwise(corpus.expected)
        ),
        "Live epoch chronology differs",
    )
    return reports, observations, sockets


def check_counts(corpus: Corpus, reports: dict[str, Report], sockets: int) -> None:
    """Check the aggregate counts against the manifest."""
    manifest = corpus.manifest
    require(
        len(reports) == REPORT_COUNT
        and manifest["completed_reports"] == COMPLETED_REPORTS
        and manifest["expected_failed_reports"] == 1
        and sockets == manifest["host_socket_lifetimes"] == HOST_SOCKETS
        and manifest["established_guest_connections"] == GUEST_CONNECTIONS
        and manifest["stopped_guest_attempts"] == 1,
        "Live aggregate counts differ",
    )


def verify(directory: Path) -> Report:
    """Verify the retained live-account corpus.

    Returns
    -------
    dict[str, typing.Any]
        The counts of what was verified and the scope of the claim.
    """
    corpus = open_corpus(directory)
    reports, observations, sockets = replay(corpus)
    check_edit(reports["edit"])
    check_delete(
        reports["delete"], bytes.fromhex(corpus.tails["main"]), observations["delete"]
    )
    check_logins(reports)
    check_persistence(reports)
    baseline = check_baseline(reports)
    check_enumerations(reports, baseline)
    check_files(reports, baseline)
    storage(directory)
    check_restart_journal(directory, reports)
    check_oracle_queries(directory)
    check_counts(corpus, reports, sockets)
    return {
        "completed_reports": COMPLETED_REPORTS,
        "expected_stopped_report_failure": 1,
        "host_socket_lifetimes": sockets,
        "established_guest_connections": GUEST_CONNECTIONS,
        "matching_live_sessions": 2,
        "deleted_live_sessions": 2,
        "late_unread_removals": 2,
        "persisted_original_objects": 5,
        "oracle_queries": ORACLE_QUERY_COUNT,
        "scope": SCOPE,
    }


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a native live-account corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
