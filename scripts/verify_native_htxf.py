#!/usr/bin/env python3
"""Verify native HTXF routing, size replacement and bounded reference use."""

import json
import typing as typ
from pathlib import Path

from native_htxf_cases import htxf
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from script_cli import run
from verify_native_core import require
from verify_native_htxf_checks import ack, check_case, observed

type Report = dict[str, typ.Any]

# The case checks live in verify_native_htxf_checks; the names below stay
# importable from this module. check_case, verify and verify_native_uploads are
# imported by test_native_htxf; ack and observed are kept because the original
# module defined them publicly.
__all__ = [
    "ack",
    "check_case",
    "main",
    "observed",
    "verify",
    "verify_native_uploads",
]

CASE_COUNT = 18  # seventeen planned cases and the preflight
UPLOAD_SELECTORS = [0, 2, 65535]  # the selectors of the three native uploads
UPLOAD_ROOT = "/Hotline19/Files/m-htxf-u"


def check_record(root: Path, record: Report, expected: dict[str, bytes]) -> None:
    """Check one stored upload: its identity, forks and extraction exit codes."""
    stat = (root / (record["key"] + ".stat.txt")).read_text()
    require(
        "File Path: " + record["path"] + "\n" in stat
        and "54455854  TEXT" in stat
        and "4d4f5448  MOTH" in stat,
        "Native upload identity differs",
    )
    require("Resource fork size:\t0\n" in stat, "Native resource fork size differs")
    require(
        record["attributes"]["data"]["exit_code"] == 0
        and (root / (record["key"] + ".data")).read_bytes() == expected[record["path"]],
        "Native upload data differs",
    )
    require(
        record["attributes"]["rsrc"]["exit_code"] == 1
        and "Attribute not found" in record["attributes"]["rsrc"]["stderr"],
        "Absent resource attribute was not retained",
    )


def verify_native_uploads(directory: Path) -> None:
    """Check the three uploads that the native server stored."""
    root = directory / "native-uploads"
    extraction = json.loads((root / "extraction.json").read_text())
    expected = {
        f"{UPLOAD_ROOT}{s}": b"header-routing-" + str(s).encode()
        for s in UPLOAD_SELECTORS
    }
    require(
        {r["path"] for r in extraction["records"]} == set(expected),
        "Native upload inventory differs",
    )
    for record in extraction["records"]:
        check_record(root, record, expected)


def check_manifest(manifest: Report) -> None:
    """Check the case inventory and the oracle identity of the manifest."""
    require(
        set(manifest["cases"]) == set(htxf()) | {"preflight"}
        and len(manifest["cases"]) == CASE_COUNT,
        "HTXF case inventory differs",
    )
    require(manifest["oracle_sha256"] == ORACLE_SHA256, "HTXF oracle identity differs")


def verify(directory: Path) -> Report:
    """Verify the retained HTXF corpus.

    Returns
    -------
    dict[str, typing.Any]
        The checked cases and the packet reconciliation of every case.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    check_manifest(manifest)
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    results, packets = [], {}
    for name in manifest["cases"]:
        report = verify_capture(directory / "transcripts" / name)
        packets[name] = reconcile(
            report,
            host,
            guest,
            {
                k: bytes.fromhex(v)
                for k, v in manifest["unread_output"].get(name, {}).items()
            },
        )
        results.append(check_case(name, report, packets[name]))
    require(
        packets == json.loads((directory / "packet-reconciliation.json").read_text()),
        "Retained packet reconciliation differs",
    )
    verify_native_uploads(directory)
    return {"cases": results, "packet_reconciliation": packets}


def show(directory: str) -> None:
    """Print the summary of the verification of the corpus in ``directory``."""
    result = verify(Path(directory))
    count = len(result["cases"])
    print(f"Verified {count} native HTXF observations and three native uploads")


def main() -> None:
    """Verify a native HTXF corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
