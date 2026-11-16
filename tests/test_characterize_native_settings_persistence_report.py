"""Characterize the report of the settings persistence runner.

Every expectation was observed on ``native_settings_persistence`` at its pinned
commit (``scripts/pinned-sources.json``) and must hold on the refactored runner;
``tests/test_pin_equivalence.py`` runs these tests against both. A recorder that
connects to nothing runs a short plan, so no socket is opened and no capture is
made. The report, its checksums and the held-sockets record are compared field by
field. Since decision D31 a report also holds ``driver_identity`` beside
``driver_sha256``, and this is the only difference that the tests allow.
"""

import hashlib
import json
import typing as typ
from pathlib import Path
from unittest import mock

import capture_identity
import native_settings_persistence as runner
import native_settings_persistence_cases as cases
import pytest
from protocol_capture import Recorder, digest

type Report = dict[str, typ.Any]
type Plan = dict[str, typ.Any]

RUNTIME = {"emulator_pid": 123, "source_a7_sha256": cases.A7_SHA}
MODULES = getattr(
    runner,
    "CAPTURE_MODULES",
    ("native_settings_persistence.py", "native_settings_persistence_cases.py"),
)
ACTIONS = 4  # two connections, then two end-of-file reads
REPORT_KEYS = [
    "schema_version",
    "profile",
    "status",
    "native_conformance",
    "persistence_proven",
    "full_file_baseline",
    "oracle_sha256",
    "plan_sha256",
    "driver_sha256",
    "readiness_report_sha256",
    "capture_receipt_sha256",
    "started_at_utc",
    "recorded_at_utc",
    "completed_actions",
    "error",
    "gates",
    "events",
    "frames",
    "streams",
]
FILES = ["checksums.sha256", "hold-ready.json", "plan.json", "report.json"]


class OfflineRecorder(Recorder):
    """A recorder that connects and waits for end of file without a socket."""

    def execute(self, action: int, step: Report) -> None:
        """Run one offline step.

        Raises
        ------
        AssertionError
            If the step is not a connect or an end-of-file read.
        """
        name = step["connection"]
        match step["op"]:
            case "connect":
                self.sockets[name] = mock.Mock()
                self.event(action, name, "connect")
            case "read_eof":
                self.event(action, name, "eof")
            case _:
                message = "Unexpected offline action"
                raise AssertionError(message)


def write_inputs(tmp_path: Path, plan: Plan) -> tuple[bytes, Path, Path, Path]:
    """Write what a phase is run from: the plans, the readiness capture and the receipt.

    Both records of the scripts are written, the hashes of two files that the runner
    checked before decision D31 and the record of its module set after it.

    Parameters
    ----------
    tmp_path : pathlib.Path
        The directory that receives them.
    plan : dict[str, typing.Any]
        The phase's plan.

    Returns
    -------
    tuple[bytes, pathlib.Path, pathlib.Path, pathlib.Path]
        The plan file's bytes, the plan directory, the readiness directory and the
        capture-ready receipt.
    """
    plans = tmp_path / "plans"
    plans.mkdir()
    raw = (json.dumps(plan) + "\n").encode()
    (plans / "phase1.json").write_bytes(raw)
    (plans / "source-hashes.json").write_text(json.dumps({"phase1": digest(raw)}))
    scripts = Path(runner.__file__).parent
    legacy = {
        name: digest((scripts / name).read_bytes())
        for name in (
            "native_settings_persistence_cases.py",
            "native_settings_persistence.py",
        )
    }
    (plans / "source-code-sha256.json").write_text(json.dumps(legacy))
    files = capture_identity.identity(MODULES)["files"]
    (plans / "source-code-identity.json").write_text(json.dumps({"files": files}))
    ready = tmp_path / "readiness"
    ready.mkdir()
    (ready / "plan.json").write_text(json.dumps(plan))
    (ready / "report.json").write_text("{}")
    receipt = tmp_path / "capture-ready.json"
    receipt.write_text('{"emulator_pid": 123}')
    return raw, plans, ready, receipt


@pytest.fixture
def phase(tmp_path: Path) -> tuple[Report, Path, Path]:
    """Run a short phase with a recorder that opens no socket.

    Returns
    -------
    tuple[dict[str, typing.Any], pathlib.Path, pathlib.Path]
        The report, the output directory and the directory of the plans.
    """
    binary = tmp_path / "oracle.bin"
    binary.write_bytes(b"offline oracle identity fixture")
    oracle = digest(binary.read_bytes())
    plan = cases.plans(RUNTIME, 15760)["phase1"]
    plan["oracle_sha256"] = oracle
    plan["steps"] = [s for s in plan["steps"] if s["op"] == "connect"] + plan["steps"][
        -2:
    ]
    plan["expectation"]["observation_actions"] = 2
    _raw, plans, ready, receipt = write_inputs(tmp_path, plan)
    output = tmp_path / "phase"
    with (
        mock.patch.object(runner.os, "geteuid", return_value=0),
        mock.patch.object(runner, "ORACLE_SHA256", oracle),
        mock.patch.object(runner, "verify_plan", return_value=1),
        mock.patch.object(
            runner, "verify_capture", return_value={"oracle_sha256": oracle}
        ),
        mock.patch.object(runner, "gate_readiness"),
        mock.patch.object(runner, "capture_gate"),
        mock.patch.object(runner, "phase_gate", return_value=None),
        mock.patch.object(runner, "Recorder", OfflineRecorder),
    ):
        report = runner.run_gated(plans / "phase1.json", ready, receipt, binary, output)
    return report, output, tmp_path


class PersistenceReportTests:
    """The report of a completed phase."""

    def test_the_keys_are_these_in_this_order(
        self, phase: tuple[Report, Path, Path]
    ) -> None:
        """No field is added, dropped or moved; the identity record follows the hash."""
        report = phase[0]
        keys = [key for key in report if key != "driver_identity"]
        assert keys == REPORT_KEYS, keys
        if "driver_identity" in report:
            keys = list(report)
            assert keys[keys.index("driver_sha256") + 1] == "driver_identity", keys

    def test_the_fixed_fields_are_as_recorded(
        self, phase: tuple[Report, Path, Path]
    ) -> None:
        """Status, scope, counts and the digests of the inputs."""
        report, _output, root = phase
        assert report["status"] == "completed", report["error"]
        assert report["completed_actions"] == ACTIONS, report
        assert report["native_conformance"] is False, report
        assert report["persistence_proven"] is False, report
        assert report["full_file_baseline"] == "not_exercised", report
        assert not report["error"], report
        receipt = (root / "capture-ready.json").read_bytes()
        assert report["capture_receipt_sha256"] == digest(receipt), report
        ready = (root / "readiness/report.json").read_bytes()
        assert report["readiness_report_sha256"] == digest(ready), report

    def test_the_driver_is_identified(self, phase: tuple[Report, Path, Path]) -> None:
        """One file before decision D31; the module set and its record after."""
        report = phase[0]
        scripts = Path(runner.__file__).parent
        if "driver_identity" not in report:
            held = (scripts / "native_settings_persistence.py").read_bytes()
            assert report["driver_sha256"] == hashlib.sha256(held).hexdigest(), report
            return
        record = report["driver_identity"]
        assert report["driver_sha256"] == record["digest"], report
        names = [Path(item["path"]).name for item in record["files"]]
        assert names[0] == "native_settings_persistence.py", names
        for item in record["files"]:
            held = (scripts / Path(item["path"]).name).read_bytes()
            assert item["sha256"] == hashlib.sha256(held).hexdigest(), item

    def test_the_files_and_the_hold_record_are_written(
        self, phase: tuple[Report, Path, Path]
    ) -> None:
        """The capture directory, its checksums and the held sockets."""
        report, output, _root = phase
        assert sorted(p.name for p in output.iterdir()) == FILES, "expected files"
        written = json.loads((output / "report.json").read_text())
        assert written == json.loads(json.dumps(report)), "expected the same report"
        held = json.loads((output / "hold-ready.json").read_text())
        assert sorted(held) == ["phase", "sockets", "utc"], held
        assert held["phase"] == 1, held
        assert held["sockets"] == ["main", "subject"], held
        lines = (output / "checksums.sha256").read_text().splitlines()
        assert lines == [
            f"{hashlib.sha256((output / name).read_bytes()).hexdigest()}  {name}"
            for name in ("plan.json", "report.json")
        ], lines
