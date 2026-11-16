#!/usr/bin/env python3
"""Replay the frozen Hotline 1.9 field-212/325 native case offline."""

import json
import sys
from pathlib import Path

from script_cli import run
from verify_native_path_fields_capture import paired
from verify_native_path_fields_constants import (
    BASE,
    CASES,
    CONTROL,
    DATA,
    DEADLINE,
    EXE,
    FORKS,
    HELPER_APPROVAL,
    INODE,
    NS,
    PID,
    PLAN,
    PORTS,
    PREFIX,
    ROM,
    SOURCE_APPROVAL,
    START,
)
from verify_native_path_fields_core import need, pins, read, sha
from verify_native_path_fields_corpus import inventory, trusted_sources
from verify_native_path_fields_frozen import frozen
from verify_native_path_fields_identity import identity
from verify_native_path_fields_outcomes import outcomes
from verify_native_path_fields_sources import source_identity
from verify_native_path_fields_stopped import stopped

# The names below stay importable from this module, which is the verifier's public
# interface. The checks live in the verify_native_path_fields_* helper modules. The
# tests in test_verify_native_path_fields import CORPUS, PREFIX, sha and verify, and
# the evidence recipes name this module on the command line.
__all__ = [
    "BASE",
    "CASES",
    "CONTROL",
    "CORPUS",
    "DATA",
    "DEADLINE",
    "EXE",
    "FORKS",
    "HELPER_APPROVAL",
    "INODE",
    "NS",
    "PID",
    "PLAN",
    "PORTS",
    "PREFIX",
    "ROM",
    "SOURCE_APPROVAL",
    "START",
    "frozen",
    "identity",
    "inventory",
    "main",
    "need",
    "outcomes",
    "paired",
    "pins",
    "read",
    "sha",
    "source_identity",
    "stopped",
    "trusted_sources",
    "verify",
]

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-14/native-path-fields-01"
)


def verify(corpus: Path = CORPUS) -> dict:
    """Replay the frozen case from its corpus and return the outcome.

    Returns
    -------
    dict
        The status, the case status and the stream lengths of each flow.
    """
    manifest = inventory(corpus)
    raw = corpus / "raw/epoch"
    trusted_sources(corpus)
    with frozen(raw) as modules:
        plan = source_identity(corpus, modules)
        identity(corpus, plan)
        report = read(raw / "coordinator/report.json")
        outcomes(corpus, plan, report, modules)
        flows = paired(corpus, report, modules)
    stopped(corpus)
    need(
        manifest["retirement"]["forced_term_after_app_quit"] is True,
        "Retirement provenance differs",
    )
    return {"status": "PASS", "case_status": "completed", "flows": flows}


def cli(*, corpus: str = str(CORPUS)) -> None:
    """Replay the frozen case and print its outcome as JSON."""
    sys.stdout.write(json.dumps(verify(Path(corpus)), indent=2) + "\n")


def main() -> None:
    """Replay the frozen Hotline 1.9 native case from the command line."""
    run(cli, __doc__)


if __name__ == "__main__":
    main()
