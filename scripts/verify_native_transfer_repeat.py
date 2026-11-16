#!/usr/bin/env python3
"""Replay the three disposable-lab A7 transfers from frozen packet captures."""

import json
import typing as typ
from pathlib import Path

import script_cli
from pcap_tcp import read_packets
from pinned_source import pinned_bytes
from protocol_capture import verify_capture
from verify_native_core import require
from verify_native_repeat_runs import (
    DRIVER_SHA,
    GUEST_PORT,
    LAB_ENDPOINT_OFFSET,
    LOOPBACK,
    PREFIX_BYTES,
    PROVENANCE_EXEMPT,
    UNKNOWN_DROPS,
    Run,
    View,
    check_assets,
    check_launch,
    check_outcome,
    check_plan,
    check_terminal,
    check_view,
    load,
    read_flow,
    sha,
)

type Json = dict[str, typ.Any]

# Each run and the front-end control port of its lab.
RUNS = {"c32": 15720, "c35": 15730, "c45": 15740}


def inventory(corpus: Path) -> None:
    """Check the manifest, the checksum list and the provenance of a corpus."""
    manifest = load(corpus / "manifest.json")
    require(manifest["schema"] == "native-transfer-repeat-01", "Corpus schema differs")
    files = manifest["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in PROVENANCE_EXEMPT
    }
    require(actual == set(files), "Corpus inventory differs")
    for name, digest in files.items():
        require(
            sha((corpus / name).read_bytes()) == digest, f"Corpus SHA differs: {name}"
        )
    lines = [f"{digest}  {name}" for name, digest in sorted(files.items())]
    require(
        (corpus / "SHA256SUMS").read_text().splitlines() == lines, "SHA list differs"
    )
    provenance = load(corpus / "source-provenance.json")
    require(provenance["schema"] == manifest["schema"], "Provenance schema differs")
    require(
        set(provenance["sources"]) == set(files) - {"source-provenance.json"},
        "Source set differs",
    )
    for name, record in provenance["sources"].items():
        data = (corpus / name).read_bytes()
        require(
            sha(data) == record["sha256"] and len(data) == record["bytes"],
            f"Source differs: {name}",
        )


def check_run(
    run: Run, comparison: Json, configs: Json
) -> tuple[bytes, dict[str, typ.Any]]:
    """Replay one run of the corpus.

    Returns
    -------
    tuple[bytes, dict[str, typing.Any]]
        The body that the run received, and its summary.
    """
    check_plan(run)
    report = verify_capture(run.root / "capture")
    received = check_outcome(run, report)
    flow = read_flow(run, report, received)
    views = {}
    for view in (
        View(
            "namespace",
            LOOPBACK,
            LOOPBACK,
            run.frontend + LAB_ENDPOINT_OFFSET,
            "lab-namespace.pcap",
        ),
        View("guest", "10.0.2.2", "10.0.2.15", GUEST_PORT, "lab-guest.pcap"),
    ):
        views[view.name] = check_view(
            flow, view, comparison[run.name]["views"][view.name]
        )
    require(
        not read_packets(run.root / "boot/primary-host.pcap"),
        f"{run.name} host primary contact",
    )
    for log in ("host-recorder.log", "ns-recorder.log"):
        require(
            UNKNOWN_DROPS in (run.root / "boot" / log).read_text(),
            f"{run.name} recorder drops unknown",
        )
    check_assets(run, configs[run.name])
    check_launch(run)
    check_terminal(run)
    summary = {
        "status": "completed" if run.complete else "failed",
        "bytes": run.expected_bytes,
        "views": views,
    }
    return received, summary


def verify(corpus: Path) -> dict[str, typ.Any]:
    """Replay the three runs of a corpus.

    Returns
    -------
    dict[str, typing.Any]
        The status, length and view sizes of each run.
    """
    corpus = corpus.resolve()
    inventory(corpus)
    comparison = load(corpus / "analysis/packet-comparison.json")["runs"]
    configs = load(corpus / "analysis/config-comparison.json")
    require(set(comparison) == set(configs) == set(RUNS), "Comparison run set differs")
    require(
        sha(pinned_bytes("protocol_capture.py")) == DRIVER_SHA,
        "Capture driver revision differs",
    )
    summary = {}
    bodies = {}
    for name, frontend in RUNS.items():
        run = Run(name, corpus / "runs" / name, frontend)
        bodies[name], summary[name] = check_run(run, comparison, configs)
    require(
        bodies["c35"] == bodies["c45"] == bodies["c32"][:PREFIX_BYTES],
        "Repeated prefixes differ",
    )
    return summary


def show(corpus: str) -> None:
    """Replay a corpus and print the summary as JSON."""
    print(json.dumps(verify(Path(corpus)), indent=2))


def main() -> None:
    """Replay a transfer corpus from the command line."""
    script_cli.run(show, __doc__)


if __name__ == "__main__":
    main()
