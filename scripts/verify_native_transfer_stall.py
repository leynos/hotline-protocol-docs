#!/usr/bin/env python3
"""Replay the failed C35 transfer and bounded H1/H2 packet findings offline."""

import hashlib
import json
import typing as typ
from pathlib import Path

import script_cli
from pcap_tcp import read_packets
from protocol_capture import verify_capture
from verify_native_core import require
from verify_native_stall_views import VIEWS, check_view, load, read_download

type Json = dict[str, typ.Any]

SOURCE_PLAN_SHA = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"
PREFIX_SHA = "b4c6dc15be0d82de42d3aa7102c1feca67397b978591ac8be2d2c846d6a62e7c"

STEPS = 29  # the A7 plan has this many steps
FAILED_ACTIONS = 21
PREFIX_BYTES = 98304
CONTROL_PORT = 15730
DATA_PORT = 15731
LOOPBACK = "127.0.0.1"
PROVENANCE_EXEMPT = {"manifest.json", "SHA256SUMS"}
UNKNOWN_DROPS = "0 packets dropped by kernel"


def sha(path: Path) -> str:
    """Hash a file.

    Returns
    -------
    str
        The SHA-256 digest in hexadecimal.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(corpus: Path) -> None:
    """Check the manifest, the checksum list and the provenance of a corpus."""
    manifest = load(corpus / "manifest.json")
    require(manifest["schema"] == "native-transfer-stall-01", "Manifest schema differs")
    expected = manifest["files"]
    actual = {
        str(p.relative_to(corpus))
        for p in corpus.rglob("*")
        if p.is_file() and p.name not in PROVENANCE_EXEMPT
    }
    require(actual == set(expected), "Corpus inventory differs")
    for name, digest in expected.items():
        require(sha(corpus / name) == digest, f"SHA differs: {name}")
    require(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{digest}  {name}" for name, digest in sorted(expected.items())],
        "SHA list differs",
    )
    provenance = load(corpus / "source-provenance.json")["sources"]
    for name, record in provenance.items():
        require(
            sha(corpus / name) == record["sha256"]
            and (corpus / name).stat().st_size == record["bytes"],
            f"Source provenance differs: {name}",
        )


def check_plan(corpus: Path) -> None:
    """Check that the as-run plan is the frozen A7 plan on the lab's ports."""
    source = load(corpus / "failure/a7-original-plan.json")
    plan = load(corpus / "failure/a7-as-run-plan.json")
    require(
        sha(corpus / "failure/a7-original-plan.json") == SOURCE_PLAN_SHA,
        "A7 source plan differs",
    )
    require(
        len(source["steps"]) == STEPS and source["steps"] == plan["steps"],
        "A7 steps differ",
    )
    for key in source.keys() - {"environment", "endpoints"}:
        require(source[key] == plan[key], f"A7 {key} changed")
    require(
        plan["endpoints"]
        == {
            "control": {"host": LOOPBACK, "port": CONTROL_PORT},
            "data": {"host": LOOPBACK, "port": DATA_PORT},
        },
        "A7 lab endpoints differ",
    )


def check_failure(corpus: Path, report: Json) -> bytes:
    """Check that the A7 failure was recorded as a failure, with a prefix body.

    Returns
    -------
    bytes
        The prefix that the download received.
    """
    require(
        report["status"] == "failed"
        and report["completed_actions"] == FAILED_ACTIONS
        and report["error"] == "TimeoutError: timed out",
        "Mandatory A7 failure was recast",
    )
    received = bytes.fromhex(report["streams"]["download"]["received_hex"])
    require(
        len(received) == PREFIX_BYTES
        and hashlib.sha256(received).hexdigest() == PREFIX_SHA,
        "Failed read prefix differs",
    )
    terminal = load(corpus / "failure/terminal.json")
    require(
        not terminal["processes"]["lab"]["exists"]
        and terminal["guard_seed_ban_probe_executed"] is False,
        "Lab retirement or option-two scope differs",
    )
    require(
        terminal["a7_failure"]["download_received_bytes"] == len(received),
        "Terminal failure length differs",
    )
    require(
        terminal["processes"]["primary"]["fd6"].endswith(
            "hotline22-recovery/working.dsk"
        ),
        "Primary FD changed",
    )
    return received


def check_recorders(corpus: Path) -> None:
    """Check that the primary saw nothing and that no recorder dropped packets."""
    require(
        not read_packets(corpus / "capture/host-primary.pcap"),
        "Primary capture has packets",
    )
    require(
        UNKNOWN_DROPS in (corpus / "capture/namespace-recorder.log").read_text(),
        "Namespace packet drops unknown",
    )
    require(
        UNKNOWN_DROPS in (corpus / "capture/host-recorder.log").read_text(),
        "Host packet drops unknown",
    )


def verify(corpus: Path) -> Json:
    """Replay the failed transfer and its packet findings.

    Returns
    -------
    dict[str, typing.Any]
        The verdict, the length received and the observations of each view.
    """
    corpus = corpus.resolve()
    inventory(corpus)
    check_plan(corpus)
    report = verify_capture(corpus / "failure")
    received = check_failure(corpus, report)
    check_recorders(corpus)
    download = read_download(corpus, report, received)
    return {
        "status": "verified_failed_baseline",
        "received_bytes": len(received),
        "option_two_executed": False,
        "views": {view.label: check_view(download, view) for view in VIEWS},
    }


def show(corpus: str) -> None:
    """Replay a corpus and print the result as JSON."""
    print(json.dumps(verify(Path(corpus)), indent=2))


def main() -> None:
    """Replay the failed transfer from the command line."""
    script_cli.run(show, __doc__)


if __name__ == "__main__":
    main()
