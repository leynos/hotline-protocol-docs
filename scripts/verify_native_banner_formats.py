#!/usr/bin/env python3
"""Verify native banner type selection, TEXT loading and absent-buffer recovery."""

import dataclasses as dc
import hashlib
import json
import typing as typ
from pathlib import Path

from native_banner_cases import GIF_B
from native_banner_formats import FORMATS
from native_banner_oracle import verify as verify_oracle
from native_packet_evidence import reconcile
from native_wire_names import FIELD_BANNER_TYPE
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from script_cli import run
from verify_native_banner_format_checks import (
    banner_ack,
    banners,
    check_format,
    requests,
    verify_native_files,
)
from verify_native_banner_recovery import (
    check_native_restore,
    check_post_reset_write,
    check_recovery,
)
from verify_native_banners import fields, unread
from verify_native_core import require

# verify_native_htxf imports requests from this module, and test_native_banner_formats
# imports check_format, check_recovery, verify and verify_native_files.

type Report = dict[str, typ.Any]

__all__ = [
    "check_format",
    "check_recovery",
    "main",
    "requests",
    "verify",
    "verify_native_files",
]

RECOVERY = "phase-checked-recovery"
EARLY_RECOVERY = "phase-checked-early-recovery"
CASES = {
    "phase-checked-recovery",
    "phase-checked-early-recovery",
    "before-delayed-recovery",
    "seed-formats",
    "seed-text",
    "seed-empty",
    "post-reset-session",
    "cleanup-no-banner",
    "missing-confirmation",
}
INITIAL_CASES = {
    "empty-followup-ack",
    "empty-open-window",
    "remote-empty-save",
    "remote-empty-return",
    "remote-empty-held-save",
}
POST_RESET_CASE = "empty-followup-ack"
POST_RESET_LIVENESS = 90
SCOPE = (
    "Native loader/type and raw-byte fixtures; no client rendering or arbitrary "
    "lifetime/ownership proof"
)
SETUP_SCOPE = (
    "Setup observation; completion does not imply its configuration expectation passed"
)


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """What a format corpus holds besides its transcripts.

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
    driver_hash : str
        The hash of the capture driver as it ran; empty until the inventory has
        been checked, because the driver is read after the inventory.
    """

    directory: Path
    manifest: Report
    host: list[Report]
    guest: list[Report]
    driver_hash: str = ""


def check_inventory(corpus: Corpus) -> None:
    """Check that the manifest and the transcripts name the expected cases."""
    expected = {"format-" + n for n in FORMATS} | CASES
    manifest = corpus.manifest
    require(
        set(manifest["cases"]) == expected and len(manifest["cases"]) == len(expected),
        "Format/recovery corpus inventory differs",
    )
    require(
        {p.name for p in (corpus.directory / "transcripts").iterdir()} == expected,
        "Unexpected final format transcript",
    )


def load_captures(corpus: Corpus) -> tuple[dict[str, Report], dict[str, Report]]:
    """Verify every final capture and reconcile it with both packet views.

    Returns
    -------
    tuple[dict[str, dict[str, typing.Any]], dict[str, dict[str, typing.Any]]]
        The reports and the packet reconciliations, by case.
    """
    reports = {}
    packets = {}
    for name in corpus.manifest["cases"]:
        report = verify_capture(corpus.directory / "transcripts" / name)
        require(
            report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_sha256"] == corpus.driver_hash,
            "Wrong native format oracle/capture source",
        )
        reports[name] = report
        packets[name] = reconcile(
            report, corpus.host, corpus.guest, unread(corpus.manifest, name)
        )
    return reports, packets


def check_recoveries(
    corpus: Corpus, reports: dict[str, Report]
) -> tuple[Report, Report]:
    """Check both recovery cases, then the delayed-recovery baseline.

    Returns
    -------
    tuple[dict[str, typing.Any], dict[str, typing.Any]]
        The summaries of the delayed and the early recovery.
    """
    summaries = []
    for name in (RECOVERY, EARLY_RECOVERY):
        plan_path = corpus.directory / "transcripts" / name / "plan.json"
        summaries.append(
            check_recovery(reports[name], json.loads(plan_path.read_text()))
        )
    baseline = reports["before-delayed-recovery"]
    require(
        baseline["status"] == "completed"
        and banner_ack(baseline)[1] == len(GIF_B)
        and len(banners(baseline, "main")) == 1
        and fields(banners(baseline, "main")[0])[FIELD_BANNER_TYPE] == b"GIFf",
        "Delayed-recovery baseline differs",
    )
    return summaries[0], summaries[1]


def check_controls(reports: dict[str, Report], packets: Report) -> None:
    """Check the no-banner controls and the reset of the empty-banner case."""
    require(
        reports["missing-confirmation"]["status"] == "completed"
        and not banners(reports["missing-confirmation"], "main"),
        "Initial absence control differs",
    )
    for connection in ["main", "observer"]:
        require(
            packets["format-empty"][connection]["guest_server_initiated_close"],
            "Empty banner observer/control reset not observed",
        )
        require(
            any(
                e["event"] == "eof" and e["connection"] == connection
                for e in reports["format-empty"]["events"]
            ),
            "Missing empty-trigger control EOF",
        )
    post = reports["post-reset-session"]
    require(
        post["status"] == "completed"
        and any(
            f["is_reply"] and f["id"] == POST_RESET_LIVENESS and f["error"] == 0
            for f in post["frames"]
        ),
        "Post-reset login/liveness failed",
    )
    require(
        reports["cleanup-no-banner"]["status"] == "completed"
        and not banners(reports["cleanup-no-banner"], "main"),
        "Final no-banner configuration differs",
    )


def check_initial_cases(corpus: Corpus) -> list[Report]:
    """Replay the exploratory hypotheses that preceded the final captures.

    Returns
    -------
    list[dict[str, typing.Any]]
        The case, status and error of each.
    """
    directory = corpus.directory
    differences = json.loads((directory / "boundary-differences.json").read_text())
    require(len(differences) == 1, "Post-reset boundary inventory differs")
    require(
        set(corpus.manifest["initial_cases"]) == INITIAL_CASES
        and {p.name for p in (directory / "initial").iterdir()} == INITIAL_CASES,
        "Exploratory format inventory differs",
    )
    initial = []
    for path in sorted((directory / "initial").iterdir()):
        report = verify_capture(path)
        require(
            report["driver_sha256"] == corpus.driver_hash,
            "Missing exploratory capture source",
        )
        expected_status = "failed" if path.name.startswith("empty-") else "completed"
        require(
            report["status"] == expected_status, "Initial hypothesis status differs"
        )
        if expected_status == "completed":
            notes = banners(report, "main")
            require(
                len(notes) == 1 and fields(notes[0])[FIELD_BANNER_TYPE] == b"GIFf",
                "Stale GUI configuration evidence differs",
            )
        pinned = unread(corpus.manifest, "initial/" + path.name)
        if path.name == POST_RESET_CASE:
            require(not pinned, "Unexpected post-reset unread output")
            check_post_reset_write(report, corpus.host, corpus.guest, differences[0])
        else:
            reconcile(report, corpus.host, corpus.guest, pinned)
        initial.append({
            "case": path.name,
            "status": report["status"],
            "error": report["error"],
        })
    require(len(initial) == len(INITIAL_CASES), "Initial hypothesis inventory differs")
    return initial


def check_setup_cases(corpus: Corpus) -> list[Report]:
    """Replay the setup captures, whose completion is not itself a finding.

    Returns
    -------
    list[dict[str, typing.Any]]
        The case, status, error and scope of each.
    """
    directory = corpus.directory
    setup = []
    require(
        set(corpus.manifest.get("setup_cases", []))
        == {p.name for p in (directory / "setup").iterdir()},
        "Setup inventory differs",
    )
    for path in sorted((directory / "setup").iterdir()):
        report = verify_capture(path)
        require(
            report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_sha256"] == corpus.driver_hash,
            "Setup capture provenance differs",
        )
        reconcile(
            report,
            corpus.host,
            corpus.guest,
            unread(corpus.manifest, "setup/" + path.name),
        )
        setup.append({
            "case": path.name,
            "status": report["status"],
            "error": report["error"],
            "scope": SETUP_SCOPE,
        })
    return setup


def open_corpus(directory: Path) -> Corpus:
    """Read the manifest and both packet captures of a corpus.

    Returns
    -------
    Corpus
        The corpus, without its driver hash.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    host = read_packets(directory / "host.pcap")
    guest = read_packets(directory / "guest.pcap")
    return Corpus(directory, manifest, host, guest)


def with_driver_hash(corpus: Corpus) -> Corpus:
    """Read the driver hash of a corpus, which follows its inventory check.

    Returns
    -------
    Corpus
        The corpus with its driver hash.
    """
    driver_hash = hashlib.sha256(
        (corpus.directory / "protocol_capture.py.as-run.txt").read_bytes()
    ).hexdigest()
    return dc.replace(corpus, driver_hash=driver_hash)


def check_native_restores(
    corpus: Corpus, reports: dict[str, Report], summaries: dict[str, Report]
) -> None:
    """Check the guest view of each recovery case, adding its delay to the summary."""
    for name, summary in summaries.items():
        check_native_restore(corpus.guest, reports[name], summary)


def verify(directory: Path) -> Report:
    """Verify every capture of a retained banner format corpus.

    Returns
    -------
    dict[str, typing.Any]
        The format, setup, oracle, exploratory and recovery observations.
    """
    corpus = open_corpus(directory)
    check_inventory(corpus)
    corpus = with_driver_hash(corpus)
    reports, packets = load_captures(corpus)
    native_files = verify_native_files(directory)
    oracle = verify_oracle(directory)
    observations = [check_format(name, reports["format-" + name]) for name in FORMATS]
    require(
        packets["format-empty"]["banner"]["guest_server_initiated_close"],
        "Empty banner native close not observed",
    )
    recovery, early_recovery = check_recoveries(corpus, reports)
    check_native_restores(
        corpus, reports, {RECOVERY: recovery, EARLY_RECOVERY: early_recovery}
    )
    check_controls(reports, packets)
    initial = check_initial_cases(corpus)
    return {
        "formats": observations,
        "setup": check_setup_cases(corpus),
        "oracle": oracle,
        "initial": initial,
        "native_files": native_files,
        "recovery": recovery,
        "early_recovery": early_recovery,
        "packet_reconciliation": packets,
        "scope": SCOPE,
    }


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a banner format corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
