#!/usr/bin/env python3
"""Verify owned duplicate, kick-protected deletion and self-deletion captures."""

import dataclasses as dc
import datetime as dt
import json
import typing as typ
from pathlib import Path

import native_account_identity_cases as cases
from native_packet_evidence import reconcile
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_ERROR_TEXT,
    FIELD_USER_ID,
    TYPE_PRESENCE_UPDATE,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from script_cli import run
from verify_native_account_identity_checks import (
    account,
    deletion,
    duplicate,
    expected_inventory,
)
from verify_native_account_identity_oracle import check_oracle_queries
from verify_native_account_updates import enumeration
from verify_native_auth import reply, selected
from verify_native_core import require
from verify_native_live_accounts import waits
from verify_native_mkdir import listing
from verify_native_shx import fields, sha

type Report = dict[str, typ.Any]

# The checks live in verify_native_account_identity_checks and the oracle checks
# in verify_native_account_identity_oracle; the names below stay importable from
# this module. deletion, duplicate and verify are imported by
# test_native_account_identity; account is kept because the original module
# defined it publicly.
__all__ = ["account", "deletion", "duplicate", "main", "verify"]

RUNTIME_EXECUTABLE_SHA256 = (
    "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
)
HOST_PACKETS = 394
BASELINE_ACCOUNTS = 2
ORIGINAL_FILES = 41
UNREAD_CASES = {"protected", "self"}
PREFLIGHT_OWNED_READS = range(20, 23)
SEED_FIRST_ID = 20
SEED_LOGIN_ID = 1
LISTING_ID = 11
LIVENESS_ID = 90
LOGIN_FRAMES = 4  # the login ACK, its privileges and agreement, and the liveness ACK
STAGES = [
    ("preflight", "seed"),
    ("seed", "duplicate-exact"),
    ("duplicate-exact", "duplicate-uppercase"),
    ("duplicate-uppercase", "duplicate-original-login"),
    ("duplicate-original-login", "duplicate-changed-login"),
    ("protected", "protected-login"),
    ("after-protected", "self"),
    ("self", "self-login"),
    ("after-self", "cleanup"),
    ("cleanup", "final"),
]
ENUMERATIONS = [
    ("duplicate-exact", list(cases.KEYS), 30),
    ("duplicate-uppercase", list(cases.KEYS), 30),
    ("after-protected", ["self", "duplicate"], 10),
    ("after-self", ["duplicate"], 10),
    ("cleanup", [], 20),
    ("final", [], 10),
]
SCOPE = (
    "Owned bit-23 protection and self-delete, exact/ASCII-case collisions and "
    "wire cleanup. No built-in-account deletion, native Trash fork, forced I/O, "
    "restart or universal name-folding claim."
)


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """The corpus directory with what its files and the planners say to expect."""

    directory: Path
    manifest: Report
    expected: dict[str, tuple[list[Report], Report]]
    host: list[Report]
    guest: list[Report]
    runtime: Report
    tails: Report


def open_corpus(directory: Path) -> Corpus:
    """Read the manifest, packets, runtime and unread tails, and check them.

    Returns
    -------
    Corpus
        The corpus with its plans.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    expected = cases.suites()
    require(
        set(expected)
        == set(manifest["reports"])
        == {p.parent.name for p in directory.glob("*/report.json")},
        "Identity report inventory differs",
    )
    host = read_packets(directory / "host.pcap")
    guest = read_packets(directory / "guest.pcap")
    runtime = json.loads((directory / "runtime.json").read_text())
    require(
        runtime["identity_observation"]["running_executable_sha256"]
        == RUNTIME_EXECUTABLE_SHA256
        and "ActiveState=active" in runtime["identity_observation"]["service_state"],
        "Identity runtime provenance differs",
    )
    require(
        len(host) == HOST_PACKETS
        and "0 packets dropped by kernel"
        in (directory / "host-capture-statistics.txt").read_text(),
        "Identity recorder count or drops differ",
    )
    tails = json.loads((directory / "unread-tails.json").read_text())
    require(set(tails) == UNREAD_CASES, "Unread identity cases differ")
    return Corpus(directory, manifest, expected, host, guest, runtime, tails)


def check_sent(report: Report, steps: list[Report], name: str) -> None:
    """Check that each connection sent exactly the bytes that the plan sent."""
    uid = ""
    if name in UNREAD_CASES:
        uid = fields(
            next(
                f for f in selected(report, "main") if f["type"] == TYPE_PRESENCE_UPDATE
            )
        )[FIELD_USER_ID].hex()
    for connection, recorded in report["streams"].items():
        sent = "".join(
            s["hex"].replace("{target_uid}", uid)
            for s in steps
            if s["op"] == "send" and s["connection"] == connection
        )
        require(sent == recorded["sent_hex"], "Identity wire request differs")


def replay_report(corpus: Corpus, name: str) -> tuple[Report, Report]:
    """Check one report against its plan, provenance, sent bytes and packets.

    Returns
    -------
    tuple[dict, dict]
        The verified report and its packet reconciliation.
    """
    steps, expectation = corpus.expected[name]
    directory = corpus.directory
    case = directory / name
    plan = json.loads((case / "plan.json").read_text())
    require(
        plan["steps"] == steps
        and plan["expectation"] == expectation
        and plan["environment"] == corpus.runtime,
        "Identity plan differs",
    )
    report = verify_capture(case)
    require(
        report["status"] == "completed"
        and report["profile"] == "native-mac-oracle"
        and report["oracle_sha256"] == ORACLE_SHA256
        and report["driver_sha256"]
        == corpus.manifest["as_run_sources"]["sources/protocol_capture.py.as-run.txt"],
        "Identity capture status or oracle differs",
    )
    waits(report, steps)
    check_sent(report, steps, name)
    unread = {k: bytes.fromhex(v) for k, v in corpus.tails.get(name, {}).items()}
    require(not unread or set(unread) == {"main"}, "Unexpected unread identity socket")
    return report, reconcile(report, corpus.host, corpus.guest, unread)


def check_stages(reports: dict[str, Report]) -> None:
    """Check that the stages were recorded one after another."""
    for first, second in STAGES:
        require(
            dt.datetime.fromisoformat(reports[first]["recorded_at_utc"])
            < dt.datetime.fromisoformat(reports[second]["started_at_utc"]),
            "Identity stage chronology differs",
        )


def check_original(reports: dict[str, Report]) -> tuple[list[str], dict[bytes, bytes]]:
    """Check the original account and file inventories and the free owned names.

    Returns
    -------
    tuple[list[str], dict[bytes, bytes]]
        The baseline enumeration and the original Files listing.
    """
    baseline = enumeration(reply(reports["preflight"], 10))
    original_files = listing(reply(reports["preflight"], LISTING_ID))
    require(
        len(baseline) == BASELINE_ACCOUNTS and len(original_files) == ORIGINAL_FILES,
        "Original inventory differs",
    )
    for identifier in PREFLIGHT_OWNED_READS:
        require(
            reply(reports["preflight"], identifier)["error"] == 1, "Owned name occupied"
        )
    return baseline, original_files


def check_login(report: Report, name: str) -> None:
    """Check one login contrast: the original login works and the others fail."""
    ok = name == "duplicate-original-login"
    require(
        reply(report, SEED_LOGIN_ID)["error"] == (0 if ok else 1),
        "Identity login contrast differs",
    )
    require(
        len(report["frames"]) == (LOGIN_FRAMES if ok else 1),
        "Identity login sequence differs",
    )
    if ok:
        require(
            fields(
                next(
                    f
                    for f in report["frames"]
                    if f["type"] == TYPE_PRIVILEGES_NOTIFICATION
                )
            )
            == {FIELD_ACCESS_BITMAP: bytes(8)}
            and reply(report, LIVENESS_ID)["error"] == 0,
            "Original duplicate-account login role or liveness differs",
        )
    else:
        require(
            fields(reply(report, SEED_LOGIN_ID))
            == {FIELD_ERROR_TEXT: b"Incorrect login."},
            "Identity login failure family differs",
        )


def check_accounts(reports: dict[str, Report]) -> None:
    """Check the seeded accounts, the duplicate refusals and the login contrasts."""
    for identifier, label in enumerate(cases.KEYS, SEED_FIRST_ID):
        account(reply(reports["seed"], identifier), label)
    for name, uppercase in [("duplicate-exact", False), ("duplicate-uppercase", True)]:
        duplicate(reports[name], uppercase)
    for name in [
        "duplicate-original-login",
        "duplicate-changed-login",
        "protected-login",
        "self-login",
    ]:
        check_login(reports[name], name)


def check_enumerations(
    reports: dict[str, Report], baseline: list[str], original_files: dict[bytes, bytes]
) -> None:
    """Check each stage's account enumeration and that the Files baseline held."""
    for name, labels, identifier in ENUMERATIONS:
        require(
            enumeration(reply(reports[name], identifier))
            == expected_inventory(baseline, labels),
            "Identity enumeration differs",
        )
    for name in ["after-protected", "after-self", "final"]:
        require(
            listing(reply(reports[name], LISTING_ID)) == original_files,
            "Original Files baseline differs",
        )


def verify(directory: Path) -> Report:
    """Verify the retained account-identity corpus.

    Returns
    -------
    dict[str, typing.Any]
        The counts of what was verified and the scope of the claim.
    """
    corpus = open_corpus(directory)
    reports, observations = {}, {}
    for name in corpus.expected:
        reports[name], observations[name] = replay_report(corpus, name)
    check_stages(reports)
    require(
        observations
        == json.loads((directory / "packet-observations.json").read_text()),
        "Retained packet observations differ",
    )
    baseline, original_files = check_original(reports)
    check_accounts(reports)
    check_enumerations(reports, baseline, original_files)
    for label in ["protected", "self"]:
        deletion(
            reports[label],
            label,
            observations[label],
            bytes.fromhex(corpus.tails[label]["main"]),
        )
    for name, expected_hash in corpus.manifest["as_run_sources"].items():
        require(
            sha(directory / name) == expected_hash, "Identity as-run source changed"
        )
    queries = check_oracle_queries(directory)
    return {
        "completed_reports": len(reports),
        "paired_connections": sum(map(len, observations.values())),
        "protected_delete_variants": 2,
        "duplicate_create_variants": 2,
        "unread_removal_tails": 2,
        "oracle_queries": len(queries),
        "scope": SCOPE,
    }


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a native account-identity corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
