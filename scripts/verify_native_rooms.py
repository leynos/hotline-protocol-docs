#!/usr/bin/env python3
"""Verify native room permissions, invitations, subjects and local event order."""

import datetime as dt
import json
from itertools import pairwise
from pathlib import Path

import native_room_cases as cases
from native_auth_cases import complement
from native_packet_evidence import reconcile
from native_plan import payload
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
)
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, decode_frame, verify_capture
from script_cli import run
from verify_native_account_updates import enumeration
from verify_native_auth import reply, roster, selected
from verify_native_core import require
from verify_native_live_accounts import waits
from verify_native_mkdir import listing
from verify_native_rooms_reports import (
    formatted,
    identities,
    members,
    missing,
    pushes,
)
from verify_native_rooms_semantic import semantic
from verify_native_rooms_stage import FAILED_REPORTS, Corpus, check_stage
from verify_native_rooms_tail import tail_frames, validate_tail
from verify_native_rooms_wire import (
    EMULATOR_PID,
    HOST_PACKETS,
    ORACLE_QUERIES,
    ORIGINAL_ACCOUNTS,
    ORIGINAL_FILES,
)
from verify_native_shx import fields, sha

# The test imports identities, semantic, validate_tail and verify. The other
# names below are kept importable because the original module defined them
# (pushes, members, missing, formatted and tail_frames) or imported them at
# module level, so that code which reached them through this module still does.
__all__ = [
    "ORACLE_SHA256",
    "cases",
    "complement",
    "decode_frame",
    "enumeration",
    "fields",
    "formatted",
    "identities",
    "listing",
    "members",
    "missing",
    "payload",
    "pushes",
    "read_packets",
    "reconcile",
    "reply",
    "require",
    "roster",
    "selected",
    "semantic",
    "sha",
    "tail_frames",
    "validate_tail",
    "verify",
    "verify_capture",
    "waits",
]

CHRONOLOGY = (
    "preflight",
    "seed",
    "basics-width-failure",
    "recovery-inspect",
    "basics",
    "topics",
    "lifecycle",
    "concurrent",
    "create_invites",
    "invites",
    "refusals-ack-timeout",
    "refusals",
    "formatting",
    "cleanup",
    "final",
)


def load_corpus(directory: Path) -> Corpus:
    """Read the manifest, the recordings and the tails of the room corpus.

    Parameters
    ----------
    directory : Path
        The corpus directory.

    Returns
    -------
    Corpus
        The files of the corpus, read in the order that the checks need them.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    expected = cases.suites()
    require(
        set(manifest["reports"])
        == set(expected) | set(FAILED_REPORTS)
        == {p.parent.name for p in directory.glob("*/report.json")},
        "Room report inventory differs",
    )
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == HOST_PACKETS
        and "0 packets dropped by kernel"
        in (directory / "host-capture-statistics.txt").read_text(),
        "Room recorder count/drops differ",
    )
    tails = json.loads((directory / "unread-tails.json").read_text())
    runtime = json.loads((directory / "runtime.json").read_text())
    return Corpus(directory, manifest, expected, runtime, tails, host, guest)


def check_chronology(reports: dict) -> None:
    """Check that each stage was recorded before the next one started.

    Parameters
    ----------
    reports : dict
        The verified report of each stage, by name.
    """
    for first, second in pairwise(CHRONOLOGY):
        require(
            dt.datetime.fromisoformat(reports[first]["recorded_at_utc"])
            < dt.datetime.fromisoformat(reports[second]["started_at_utc"]),
            "Room stage chronology differs",
        )


def check_baseline(reports: dict) -> None:
    """Check the original baseline and its restoration after the cleanup.

    Parameters
    ----------
    reports : dict
        The verified report of each stage, by name.
    """
    baseline = enumeration(reply(reports["preflight"], 10))
    files = listing(reply(reports["preflight"], 11))
    require(
        len(baseline) == ORIGINAL_ACCOUNTS and len(files) == ORIGINAL_FILES,
        "Room original baseline differs",
    )
    for i in range(20, 23):
        require(
            reply(reports["preflight"], i)["error"] == 1
            and reply(reports["final"], i)["error"] == 1,
            "Room owned name preflight/cleanup differs",
        )
    expected_accounts = [
        payload([
            (FIELD_NAME, b"Room30-" + label.encode()),
            (FIELD_LOGIN, complement(cases.key(label))),
            (FIELD_PASSWORD, b"x"),
            (FIELD_ACCESS_BITMAP, access),
        ]).hex()
        for label, access in cases.ROLES.items()
    ]
    require(
        enumeration(reply(reports["recovery-inspect"], 10))
        == sorted(baseline + expected_accounts),
        "Same-session recovery inventory differs",
    )
    require(
        enumeration(reply(reports["cleanup"], 20))
        == baseline
        == enumeration(reply(reports["final"], 10))
        and listing(reply(reports["cleanup"], 21))
        == files
        == listing(reply(reports["final"], 11)),
        "Room final baseline restoration differs",
    )


def check_sources_and_queries(corpus: Corpus) -> None:
    """Check the as-run sources, the oracle queries and the running epoch.

    Parameters
    ----------
    corpus : Corpus
        The files of the corpus.
    """
    for name, digest in corpus.manifest["as_run_sources"].items():
        require(sha(corpus.directory / name) == digest, "Room as-run source changed")
    queries = list((corpus.directory / "oracle-queries").glob("*.json"))
    require(len(queries) == ORACLE_QUERIES, "Room oracle query count differs")
    for path in queries:
        q = json.loads(path.read_text())
        require(
            q["program"]["sha256"] == ORACLE_SHA256
            and not q["result"].get("isError", False),
            "Room oracle query failed",
        )
    observation = corpus.runtime["room_observation"]
    require(
        observation["emulator_pid"] == EMULATOR_PID
        and "ActiveState=active" in observation["service_state"],
        "Room running epoch provenance differs",
    )


def verify(directory: Path) -> dict:
    """Verify a native room corpus and summarise what it establishes.

    Parameters
    ----------
    directory : Path
        The corpus directory.

    Returns
    -------
    dict
        The counts of the verified corpus and its stated scope.
    """
    corpus = load_corpus(directory)
    reports, observations = {}, {}
    for name in corpus.manifest["reports"]:
        reports[name], observations[name] = check_stage(corpus, name)
    check_chronology(reports)
    require(
        observations
        == json.loads((directory / "packet-observations.json").read_text()),
        "Room packet observations differ",
    )
    check_baseline(reports)
    check_sources_and_queries(corpus)
    return {
        "completed_reports": 13,
        "retained_failed_expectations": 2,
        "paired_connections": 45,
        "room_scenarios": 8,
        "oracle_queries": ORACLE_QUERIES,
        "host_packets": HOST_PACKETS,
        "scope": "Owned room permission, topic, lifecycle, invitation and formatting "
        "fixtures with explicit per-view unread tails. Local send/recipient "
        "ordering; no universal cross-socket delivery, restart or historical-client "
        "claim.",
    }


def show(directory: str) -> None:
    """Print the verified summary of the room corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a native room corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
