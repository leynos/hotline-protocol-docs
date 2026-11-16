#!/usr/bin/env python3
"""Verify configured agreement content, readiness and observer transitions."""

import dataclasses as dc
import hashlib
import json
import typing as typ
from pathlib import Path

from native_agreement_cases import (
    FILES,
    NON_TEXT_FILES,
    ORIGINAL_AGREEMENT_SHA256,
    phase,
)
from native_packet_evidence import reconcile
from native_wire_names import (
    ACCESS_BITMAP_BYTES,
    ACCOUNT_ACCESS_OFFSET,
    ACCOUNT_RECORD_BYTES,
    FIELD_AGREEMENT_BYPASS,
    FIELD_DATA,
    TYPE_LOGIN_AGREEMENT,
)
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from script_cli import run
from verify_native_agreement_checks import AGREEMENT_PATH, check_overflow, native_file
from verify_native_auth import BYPASS, check_state
from verify_native_banners import fields
from verify_native_core import require
from verify_native_framing import check_quiet

type Report = dict[str, typ.Any]
type Packets = list[dict[str, typ.Any]]

# The overflow and file checks live in verify_native_agreement_checks; the names
# below stay importable from this module. check_overflow, native_file and verify
# are imported by test_native_agreements; PHASE_NAMES is kept because the
# original module defined it publicly.
__all__ = ["PHASE_NAMES", "check_overflow", "main", "native_file", "verify"]

PHASE_NAMES = {
    "original",
    "absent",
    "text",
    "empty",
    "directory",
    "text-limit",
    "text-over-limit",
    "nontext",
    "nontext-over-limit",
    "nontext-field-over-limit",
    "restored",
}
GROUPS = [("setup", "setup_cases"), ("initial", "initial_cases")]
RECOVERY_CASE = "absent-before-timer-recovery"
CLEANUP_REPLIES = [(1, 0), (10, 0), (11, 1)]
ORIGINAL_BYTES = 245
TEXT_LIMIT = 65535
NON_TEXT_LIMIT = 262140
BYPASS_ACCOUNT = "native-seed/catalog-11296.data"
RETAINED_ORIGINALS = {"original", "restored"}
BYPASS_FLAG = b"\0\1"


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """The corpus directory, its manifest and the host and guest packets."""

    directory: Path
    manifest: Report
    host: Packets
    guest: Packets


def check_auxiliary(corpus: Corpus) -> None:
    """Replay the setup and initial transcripts against the packet records."""
    directory, manifest = corpus.directory, corpus.manifest
    for group, inventory in GROUPS:
        require(
            {p.name for p in (directory / group).iterdir()} == set(manifest[inventory]),
            "Auxiliary transcript inventory differs",
        )
        for name in manifest[inventory]:
            root = directory / group / name
            verify_capture(root)
            report = json.loads((root / "report.json").read_text())
            if group == "setup":
                require(
                    report["status"] == "completed", "Setup/control did not complete"
                )
            if name != RECOVERY_CASE:
                tails = {
                    k: bytes.fromhex(v)
                    for k, v in manifest["other_unread_output"]
                    .get(group + "/" + name, {})
                    .items()
                }
                reconcile(report, corpus.host, corpus.guest, tails)


def check_cleanup(directory: Path) -> None:
    """Check the cleanup report and the stored bypass account's access bitmap."""
    cleanup = json.loads(
        (directory / "setup/remove-agreement-bypass-account/report.json").read_text()
    )
    require(
        [(f["id"], f["error"]) for f in cleanup["frames"] if f["is_reply"]]
        == CLEANUP_REPLIES,
        "Owned agreement account cleanup/readback differs",
    )
    account = (directory / BYPASS_ACCOUNT).read_bytes()
    end = ACCOUNT_ACCESS_OFFSET + ACCESS_BITMAP_BYTES
    require(
        len(account) == ACCOUNT_RECORD_BYTES
        and account[ACCOUNT_ACCESS_OFFSET:end] == BYPASS,
        "Native bypass account bitmap differs",
    )


def check_oracle_queries(directory: Path) -> None:
    """Check the identity and outcome of each retained oracle query."""
    for root in (directory / "oracle-queries").glob("*.json"):
        query = json.loads(root.read_text())
        require(
            query["program"]["sha256"] == ORACLE_SHA256
            and not query["result"]["isError"],
            "Agreement oracle query failed or identity differs",
        )


def retained_agreement(directory: Path, setup: Report) -> bytes:
    """Check the original agreement and its native file for a phase.

    Returns
    -------
    bytes
        The agreement as the server sends it, with CR LF replaced by CR.
    """
    raw = (directory / "original-agreement.data").read_bytes()
    require(len(raw) == ORIGINAL_BYTES, "Original agreement length differs")
    require(
        hashlib.sha256(raw).hexdigest() == ORIGINAL_AGREEMENT_SHA256,
        "Original agreement identity differs",
    )
    native_file(directory / setup["snapshot"], b"TEXT", raw)
    return raw.replace(b"\r\n", b"\r")


def agreement_for(directory: Path, name: str, setup: Report) -> bytes | None:
    """Check a phase's native agreement file and work out what logins receive.

    Returns
    -------
    bytes | None
        The agreement text a login receives, or none when it receives none.
    """
    if name in RETAINED_ORIGINALS:
        return retained_agreement(directory, setup)
    if name == "directory":
        extraction = json.loads(
            (directory / setup["snapshot"] / "extraction.json").read_text()
        )
        require(
            any(
                r["path"] == AGREEMENT_PATH and r["directory"]
                for r in extraction["records"]
            ),
            "Unreadable path lacks a positive native directory record",
        )
        return None
    if name == "absent":
        return None
    _, kind, raw = (FILES | NON_TEXT_FILES)[name]
    native_file(directory / setup["snapshot"], kind, raw)
    limit = TEXT_LIMIT if kind == b"TEXT" else NON_TEXT_LIMIT
    if 0 < len(raw) <= limit:
        return raw.replace(b"\r\n", b"\r") if kind == b"TEXT" else raw
    return None


def check_agreements(
    label: str, report: Report, expected: Report, agreement: bytes | None
) -> None:
    """Check that each login agreement is the bypass flag or the expected text."""
    for frame in report["frames"]:
        if frame["type"] == TYPE_LOGIN_AGREEMENT:
            bypass = expected["kind"] == "agreement-field-overflow" or (
                frame["connection"] == "subject" and expected["bypass"]
            )
            notice = (
                {FIELD_AGREEMENT_BYPASS: BYPASS_FLAG}
                if bypass
                else {}
                if agreement is None
                else {FIELD_DATA: agreement}
            )
            require(
                fields(frame) == notice,
                f"{label}: observer/subject agreement content differs",
            )


def check_label(
    corpus: Corpus,
    label: str,
    case: tuple[list[Report], Report],
    agreement: bytes | None,
) -> Report:
    """Check one observation against its plan, state and packets.

    Returns
    -------
    dict[str, typing.Any]
        The observation's result with its packet reconciliation.
    """
    steps, expected = case
    root = corpus.directory / "captures" / label
    verify_capture(root)
    plan = json.loads((root / "plan.json").read_text())
    report = json.loads((root / "report.json").read_text())
    require(
        plan["steps"] == steps and plan["expectation"] == expected,
        "Agreement observation plan differs",
    )
    require(report["status"] == "completed", "Agreement observation did not complete")
    check_quiet(report, plan)
    result = (
        check_overflow(report, expected)
        if expected["kind"] == "agreement-field-overflow"
        else check_state(label, report, expected, agreement)
    )
    check_agreements(label, report, expected, agreement)
    tails = {
        k: bytes.fromhex(v)
        for k, v in corpus.manifest.get("unread_output", {}).get(label, {}).items()
    }
    result["packets"] = reconcile(report, corpus.host, corpus.guest, tails)
    return result


def verify(directory: Path) -> Report:
    """Verify the retained agreement corpus.

    Returns
    -------
    dict[str, typing.Any]
        The counts of cases and phases, and each case's result.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    require(
        manifest["oracle_sha256"] == ORACLE_SHA256, "Agreement oracle identity differs"
    )
    require(set(manifest["phases"]) == PHASE_NAMES, "Agreement phase inventory differs")
    host = read_packets(directory / "host.pcap")
    guest = read_packets(directory / "guest.pcap")
    corpus = Corpus(directory, manifest, host, guest)
    check_auxiliary(corpus)
    check_cleanup(directory)
    check_oracle_queries(directory)
    results, labels = [], set()
    for name, setup in manifest["phases"].items():
        agreement = agreement_for(directory, name, setup)
        for label, case in phase(name).items():
            results.append(check_label(corpus, label, case, agreement))
            labels.add(label)
    require(set(manifest["cases"]) == labels, "Agreement case inventory differs")
    return {
        "cases": len(results),
        "phases": len(manifest["phases"]),
        "results": results,
    }


def show(directory: str) -> None:
    """Print the summary of the verification of the corpus in ``directory``."""
    result = verify(Path(directory))
    print(
        f"Verified {result['cases']} configured agreement cases across "
        f"{result['phases']} phases"
    )


def main() -> None:
    """Verify a native agreement corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
