#!/usr/bin/env python3
"""Verify configured login-name bytes, version gates and refresh observations."""

import dataclasses as dc
import json
import typing as typ
from pathlib import Path

from native_login_extras_cases import (
    CONFIGURED_URL,
    NAMES,
    configured,
    downloads,
    lifetime,
)
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from script_cli import run
from verify_native_core import require
from verify_native_framing import check_quiet
from verify_native_login_extras_checks import (
    check_configured,
    check_downloads,
    check_lifetime,
    login_ack,
)
from verify_native_login_extras_failed import check_failed_lifetime
from verify_native_login_extras_prefs import check_configurations, preferences

type Report = dict[str, typ.Any]
type Packets = list[dict[str, typ.Any]]

# The checks live in verify_native_login_extras_checks, the preferences in
# verify_native_login_extras_prefs and the failed trial in
# verify_native_login_extras_failed; the names below stay importable from this
# module. check_configured, check_lifetime, login_ack, preferences and verify are
# imported by test_native_login_extras and preferences by verify_native_shx_extras;
# CONFIGURED_URL, NAMES, cases, check_downloads and check_failed_lifetime are
# kept because the original module defined them publicly.
__all__ = [
    "CONFIGURED_URL",
    "NAMES",
    "cases",
    "check_configured",
    "check_downloads",
    "check_failed_lifetime",
    "check_lifetime",
    "login_ack",
    "main",
    "preferences",
    "verify",
]

CASE_COUNT = 34
AGREEMENT_BYTES = 242
FAILED_TRIAL = "name-change-90s-waiting-expired"
GROUPS = [("setup", "setup_cases"), ("initial", "initial_cases")]
NS_PER_SECOND = 1e9


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """The corpus directory, its manifest and agreement, and the packet records."""

    directory: Path
    manifest: Report
    agreement: bytes
    packets: tuple[Packets, Packets]


def cases() -> dict[str, tuple[list[Report], Report]]:
    """Plan every login-extras case.

    Returns
    -------
    dict[str, tuple[list, dict]]
        The configured cases, the lifetime case and the download case.
    """
    expected = {}
    for name in NAMES:
        expected.update(configured(name))
    return expected | lifetime() | downloads()


def check_auxiliary(corpus: Corpus) -> None:
    """Replay the setup and initial captures against the packet records."""
    directory, manifest = corpus.directory, corpus.manifest
    for group, inventory in GROUPS:
        require(
            {p.name for p in (directory / group).iterdir()} == set(manifest[inventory]),
            "Login-extra auxiliary inventory differs",
        )
        for name in manifest[inventory]:
            root = directory / group / name
            verify_capture(root)
            report = json.loads((root / "report.json").read_text())
            if group == "setup":
                require(
                    report["status"] == "completed",
                    "Login-extra setup did not complete",
                )
            if group == "initial" and name == FAILED_TRIAL:
                check_failed_lifetime(report, *corpus.packets)
            else:
                tails = {
                    k: bytes.fromhex(v)
                    for k, v in manifest["other_unread_output"]
                    .get(group + "/" + name, {})
                    .items()
                }
                reconcile(report, *corpus.packets, tails)


def check_pauses(report: Report, steps: list[Report]) -> None:
    """Check that each planned pause lasted at least as long as planned."""
    for action, step in enumerate(steps):
        if step["op"] == "pause":
            pauses = [
                e
                for e in report["events"]
                if e["action"] == action and e["event"] == "pause"
            ]
            previous = [e for e in report["events"] if e["action"] < action]
            require(
                len(pauses) == 1
                and pauses[0]["elapsed_ns"] - previous[-1]["elapsed_ns"]
                >= step["seconds"] * NS_PER_SECOND,
                "Login-extra pause was shorter than planned",
            )


def check_case(corpus: Corpus, case: tuple[str, tuple[list[Report], Report]]) -> Report:
    """Check one recorded case against its plan, waits and packets.

    Returns
    -------
    dict[str, typing.Any]
        The case's outcome, its name and its packet reconciliation.
    """
    name, (steps, expected) = case
    root = corpus.directory / "captures" / name
    verify_capture(root)
    plan = json.loads((root / "plan.json").read_text())
    report = json.loads((root / "report.json").read_text())
    require(
        plan["steps"] == steps and plan["expectation"] == expected,
        "Retained login-extra plan differs",
    )
    require(report["status"] == "completed", "Login-extra case did not complete")
    check_quiet(report, plan)
    check_pauses(report, plan["steps"])
    match expected["kind"]:
        case "configured-login-extras":
            result = check_configured(report, expected, corpus.agreement)
        case "login-name-lifetime":
            result = check_lifetime(report, corpus.agreement)
        case _:
            result = check_downloads(report, corpus.agreement)
    tails = {
        k: bytes.fromhex(v)
        for k, v in corpus.manifest.get("unread_output", {}).get(name, {}).items()
    }
    result["case"] = name
    result["packets"] = reconcile(report, *corpus.packets, tails)
    return result


def original_agreement(directory: Path) -> bytes:
    """Read the original agreement with its line ends as the server sends them.

    Returns
    -------
    bytes
        The agreement, with each CR LF pair replaced by a CR.
    """
    return (directory / "original-agreement.data").read_bytes().replace(b"\r\n", b"\r")


def check_oracle_queries(directory: Path) -> None:
    """Check the identity and outcome of each retained oracle query."""
    for root in (directory / "oracle-queries").glob("*.json"):
        query = json.loads(root.read_text())
        require(
            query["program"]["sha256"] == ORACLE_SHA256
            and not query["result"]["isError"],
            "Login-extra oracle query identity/error differs",
        )


def verify(directory: Path) -> Report:
    """Verify the retained login-extras corpus.

    Returns
    -------
    dict[str, typing.Any]
        The number of cases and each case's result.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    require(manifest["oracle_sha256"] == ORACLE_SHA256, "Login-extra oracle differs")
    expected_cases = cases()
    require(
        set(manifest["cases"]) == set(expected_cases)
        and len(expected_cases) == CASE_COUNT,
        "Login-extra case inventory differs",
    )
    check_configurations(directory, manifest)
    agreement = original_agreement(directory)
    require(len(agreement) == AGREEMENT_BYTES, "Original agreement length differs")
    packets = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    corpus = Corpus(directory, manifest, agreement, packets)
    check_auxiliary(corpus)
    results = [check_case(corpus, case) for case in expected_cases.items()]
    check_oracle_queries(directory)
    return {"cases": len(results), "results": results}


def show(directory: str) -> None:
    """Print the summary of the verification of the corpus in ``directory``."""
    result = verify(Path(directory))
    print(f"Verified {result['cases']} configured login-extra and lifetime cases")


def main() -> None:
    """Verify a native login-extras corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
