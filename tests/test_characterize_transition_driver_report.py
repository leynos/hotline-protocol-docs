"""Characterize the report of the same-session 304 transition capture driver.

Every expectation was observed on ``verify_native_settings_transition`` at its
pinned commit (``scripts/pinned-sources.json``) and must hold on the refactored
driver; ``tests/test_pin_equivalence.py`` runs these tests against both. A recorder
that connects to nothing runs the plan, and the gates that read frames are replaced
by ones that pass. The report, its checksums and the stage gates are compared field
by field. Since decision D31 a report also holds ``driver_identity`` beside
``driver_sha256``, and this is the only difference that the tests allow.
"""

import hashlib
import json
import typing as typ
from unittest import mock

import native_settings_transition_cases as cases
import pytest
import verify_native_settings_transition as driver
from driver_report_support import (
    CAPTURE_FILES,
    QuietRecorder,
    driver_problems,
    listing,
    oracle_digest,
    prepared,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

    from driver_report_support import Report

REPORT_KEYS = [
    "schema_version",
    "profile",
    "status",
    "native_conformance",
    "identity_scope",
    "operator",
    "oracle_sha256",
    "plan_sha256",
    "driver_sha256",
    "recorded_at_utc",
    "started_at_utc",
    "gap_ids",
    "completed_actions",
    "error",
    "events",
    "frames",
    "streams",
]
SCOPE = "Local binary hash verified; remote process identity is operator-reported"
SUBJECT_UID = b"\0\x21"
MAIN_UID = b"\0\x20"
STAGE = {"label": "stage"}


class TransitionDriverReportTests:
    """The report of a completed transition run."""

    @pytest.fixture
    def run(self, tmp_path: Path) -> tuple[Report, Path]:
        """Run the plan with a recorder that executes nothing and gates that pass.

        Returns
        -------
        tuple[dict[str, typing.Any], pathlib.Path]
            The report and the output directory.
        """
        (tmp_path / "plan.json").write_text(json.dumps(prepared(cases)))
        (tmp_path / "binary").write_bytes(b"offline")
        output = tmp_path / "out"
        with (
            mock.patch.object(driver, "Recorder", QuietRecorder),
            mock.patch.object(driver, "digest", oracle_digest(cases.ORACLE_SHA256)),
            mock.patch.object(
                driver, "current_uids", return_value=(SUBJECT_UID, MAIN_UID)
            ),
            mock.patch.object(driver, "check_update"),
            mock.patch.object(driver, "check_stage", return_value=STAGE),
        ):
            report = driver.run_gated(
                tmp_path / "plan.json", tmp_path / "binary", output
            )
        return report, output

    def test_the_keys_are_these_in_this_order(self, run: tuple[Report, Path]) -> None:
        """No field is added, dropped or moved; the identity record follows the hash."""
        report = run[0]
        keys = [key for key in report if key != "driver_identity"]
        assert keys == REPORT_KEYS, keys
        if "driver_identity" in report:
            keys = list(report)
            assert keys[keys.index("driver_sha256") + 1] == "driver_identity", keys

    def test_a_complete_run_is_recorded_as_such(self, run: tuple[Report, Path]) -> None:
        """Status, counts, scope and the fixed fields."""
        report = run[0]
        assert report["status"] == "completed", report["error"]
        assert report["completed_actions"] == len(prepared(cases)["steps"]), report
        assert report["identity_scope"] == SCOPE, report
        assert report["native_conformance"] is False, report
        assert not report["error"], report

    def test_the_driver_is_identified(self, run: tuple[Report, Path]) -> None:
        """One file before decision D31; the module set and its record after."""
        assert not driver_problems(run[0], driver), run[0]["driver_sha256"]

    def test_the_files_and_the_stage_gates_are_written(
        self, run: tuple[Report, Path]
    ) -> None:
        """The capture directory, its checksums and the stages that passed."""
        report, output = run
        assert listing(output) == CAPTURE_FILES, listing(output)
        written = json.loads((output / "report.json").read_text())
        assert written == json.loads(json.dumps(report)), "expected the same report"
        gates = json.loads((output / "stage-gates.json").read_text())
        windows = len(prepared(cases)["expectation"]["windows"])
        expected = {"passed": [STAGE] * windows, "status": "completed", "error": ""}
        assert gates == expected, gates
        lines = (output / "checksums.sha256").read_text().splitlines()
        assert lines == [
            f"{hashlib.sha256((output / name).read_bytes()).hexdigest()}  {name}"
            for name in ("plan.json", "report.json")
        ], lines
