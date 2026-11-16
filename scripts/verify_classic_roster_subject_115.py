"""Replay B62's finite Classic roster-115 experiment from portable evidence."""

import json
import typing as typ
from pathlib import Path

from pcap_tcp import read_packets
from script_cli import run
from verify_classic_roster_subject_115_capture import capture_check, selection_check
from verify_classic_roster_subject_115_cleanup import cleanup_check
from verify_classic_roster_subject_115_common import (
    AGREEMENT_SHA,
    CAPTURE_GATE_SHA,
    FILP_SHA,
    FORWARDED_ROSTER_SHA,
    HEADER,
    PARSER_SHA,
    PROXY_SHA,
    RAW_ACK_SHA,
    RAW_ROSTER_SHA,
    ROUTES,
    load,
    need,
    sha,
)
from verify_classic_roster_subject_115_source import a7_check, inventory, source_check
from verify_classic_roster_subject_115_ui import ui_check
from verify_classic_roster_subject_115_wire import split_frames
from verify_classic_roster_subject_115_wire_audit import wire_check

APPROVED_SOURCE_LINES = 620  # the verifier budget that the manifest approves
ORIGINAL_SOURCE_LINES = 470  # the original verifier size that the budget builds on
SELECTED_PCAP_COUNT = 4  # the selected PCAP views in the corpus

# The test suite and the Makefile recipe depend on these names, so they stay here.
# scripts/tests/test_classic_roster_subject_115.py imports ``verify``;
# the Makefile runs ``python3 scripts/verify_classic_roster_subject_115.py <corpus>``.
__all__ = [
    "AGREEMENT_SHA",
    "CAPTURE_GATE_SHA",
    "FILP_SHA",
    "FORWARDED_ROSTER_SHA",
    "HEADER",
    "PARSER_SHA",
    "PROXY_SHA",
    "RAW_ACK_SHA",
    "RAW_ROSTER_SHA",
    "ROUTES",
    "a7_check",
    "capture_check",
    "cleanup_check",
    "inventory",
    "load",
    "main",
    "need",
    "selection_check",
    "sha",
    "show",
    "source_check",
    "split_frames",
    "ui_check",
    "verify",
    "wire_check",
]


def verify(base: Path) -> dict[str, typ.Any]:
    """Verify the retained roster-115 corpus and summarise each check group.

    Returns
    -------
    dict[str, typing.Any]
        The inventory count and the summary of each check group.
    """
    base = base.resolve()
    count = inventory(base)
    manifest = load(base / "manifest.json")
    need(manifest["schema_version"] == 1, "manifest schema")
    need(
        manifest["verifier_budget"]["approved_source_lines"] == APPROVED_SOURCE_LINES
        and manifest["verifier_budget"]["original_source_lines"]
        == ORIGINAL_SOURCE_LINES,
        "approved verifier budget",
    )
    source_check(base, manifest)
    packets = {
        "pcaps/" + p.name: read_packets(p) for p in (base / "pcaps").glob("*.pcap")
    }
    need(len(packets) == SELECTED_PCAP_COUNT, "four selected PCAPs")
    selection_check(base, manifest, packets)
    return {
        "inventory_files": count,
        "a7": a7_check(base),
        "capture": capture_check(base, manifest),
        "wire": wire_check(base, manifest, packets),
        "ui": ui_check(base, packets),
        "cleanup": cleanup_check(base),
    }


def show(corpus: str) -> None:
    """Verify a roster-115 corpus directory and print its summary as JSON."""
    print(json.dumps(verify(Path(corpus)), indent=2))


def main() -> None:
    """Verify the retained roster-115 corpus named on the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
