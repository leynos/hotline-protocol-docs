#!/usr/bin/env python3
"""Verify native account normalization, guest phases and configured login states."""

import hashlib
import json
import typing as typ
from pathlib import Path

from native_auth_cases import (
    cleanup,
    guest_create,
    lookup,
    reauthentication,
    seed,
    states,
)
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256
from script_cli import run
from verify_native_auth_accounts import verify_accounts
from verify_native_auth_checks import check_lookup, check_state
from verify_native_auth_corpus import (
    Corpus,
    check_capture,
    check_initial_cases,
    check_late_departure,
    check_oracle,
    check_outcome,
)
from verify_native_auth_frames import ADMIN, BYPASS, reply, roster, selected
from verify_native_core import require

type Report = dict[str, typ.Any]
type Cases = dict[str, tuple[list[Report], Report]]
type Captures = tuple[dict[str, Report], dict[str, Report], list[Report]]

# Evidence-held verifiers and many native_*_cases and verify_native_* scripts
# import ADMIN, reply, roster, selected and fields-based checks from this module,
# verify_native_agreements imports BYPASS, and test_native_auth imports cases,
# check_lookup, check_state, verify and verify_accounts.
__all__ = [
    "ADMIN",
    "BYPASS",
    "cases",
    "check_lookup",
    "check_state",
    "main",
    "reply",
    "roster",
    "selected",
    "verify",
    "verify_accounts",
]

CASE_COUNT = 33
INITIAL_CASE_COUNT = 2


def cases() -> Cases:
    """Plan every case of the corpus, in capture order.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The steps and the expectation of each case.
    """
    return (
        seed()
        | lookup(missing_guest=True)
        | guest_create()
        | lookup()
        | states()
        | reauthentication()
        | cleanup()
    )


def check_chronology(reports: dict[str, Report]) -> None:
    """Check that the guest account was created between the two lookup phases."""
    require(
        max(reports[n]["recorded_at_utc"] for n in lookup(missing_guest=True))
        < reports["create-temporary-guest"]["started_at_utc"]
        < min(reports[n]["started_at_utc"] for n in lookup()),
        "Guest phase chronology differs",
    )


def open_corpus(directory: Path, manifest: Report, agreement: bytes) -> Corpus:
    """Read both packet captures and the driver hash of a corpus.

    Returns
    -------
    Corpus
        The corpus.
    """
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    driver = hashlib.sha256(
        (directory / "protocol_capture.py.as-run.txt").read_bytes()
    ).hexdigest()
    return Corpus(directory, manifest, host, guest, driver, agreement)


def check_captures(corpus: Corpus, expected: Cases) -> Captures:
    """Check every transcript of the corpus.

    Returns
    -------
    tuple[dict, dict, list]
        The packet reconciliations, the reports and the state observations.
    """
    packets, reports, results = {}, {}, []
    for name, case in expected.items():
        report, packets[name] = check_capture(corpus, name, case)
        reports[name] = report
        result = check_outcome(name, report, case, corpus.agreement)
        if result is not None:
            results.append(result)
    return packets, reports, results


def verify(directory: Path) -> Report:
    """Verify every capture and record of a retained authentication corpus.

    Returns
    -------
    dict[str, typing.Any]
        The case count and the state and packet observations.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    expected = cases()
    require(
        set(manifest["cases"]) == set(expected) and len(expected) == CASE_COUNT,
        "Auth case inventory differs",
    )
    require(manifest["oracle_sha256"] == ORACLE_SHA256, "Auth oracle differs")
    corpus = open_corpus(directory, manifest, verify_accounts(directory))
    packets, reports, results = check_captures(corpus, expected)
    check_initial_cases(corpus, packets)
    check_late_departure(corpus, reports)
    require(
        packets == json.loads((directory / "packet-reconciliation.json").read_text()),
        "Auth packet observations differ",
    )
    check_chronology(reports)
    check_oracle(directory)
    return {
        "cases": len(reports),
        "initial_cases": INITIAL_CASE_COUNT,
        "state_observations": results,
        "packet_reconciliation": packets,
    }


def show(directory: str) -> None:
    """Print the number of cases that the corpus in ``directory`` verified."""
    result = verify(Path(directory))
    print(
        f"Verified {result['cases']} native authentication cases"
        " and two retained exploratory reports"
    )


def main() -> None:
    """Verify an authentication corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
