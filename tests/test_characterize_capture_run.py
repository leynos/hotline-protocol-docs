"""Characterize what ``run_plan`` of ``protocol_capture`` records and refuses first.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``). The plan used here only pauses, so no socket
is opened and nothing is captured from a peer. The report's keys and the
files written are pinned, and so is the order of the three refusals that
precede the run: the plan, the oracle binary and the output directory.
"""

import hashlib
import json
import runpy
import sys
import typing as typ
from pathlib import Path

import protocol_capture as pc
import pytest

CHARACTERIZES = "protocol_capture.py"
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / CHARACTERIZES
BINARY = b"binary"
SCOPE = "Local binary hash verified; remote process identity is operator-reported"

type Plan = dict[str, typ.Any]

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


def pause_plan() -> Plan:
    """Build a plan that pauses for no time.

    Returns
    -------
    dict[str, typing.Any]
        The plan, whose oracle hash is that of ``BINARY``.
    """
    return {
        "schema_version": 1,
        "profile": "synthetic-tool-test",
        "operator": "operator",
        "oracle_sha256": hashlib.sha256(BINARY).hexdigest(),
        "gap_ids": ["GAP-001"],
        "endpoints": {"control": {"host": "127.0.0.1", "port": 15500}},
        "steps": [{"op": "pause", "seconds": 0}],
    }


class Run:
    """A plan file and a binary in a temporary directory."""

    def __init__(self, root: Path) -> None:
        """Write the plan and the binary.

        Parameters
        ----------
        root : pathlib.Path
            An empty directory.
        """
        self.root = root
        self.plan_path = root / "plan.json"
        self.binary = root / "binary"
        self.output = root / "out"
        self.source = (json.dumps(pause_plan()) + "\n").encode()
        self.plan_path.write_bytes(self.source)
        self.binary.write_bytes(BINARY)

    def run(self) -> dict[str, typ.Any]:
        """Record the plan.

        Returns
        -------
        dict[str, typing.Any]
            The report.
        """
        return pc.run_plan(self.plan_path, self.binary, self.output)


@pytest.fixture
def run(tmp_path: Path) -> Run:
    """Create a plan, a binary and no output yet.

    Returns
    -------
    Run
        The setup.
    """
    return Run(tmp_path)


class TestReport:
    """The report of a completed run."""

    def test_the_keys_are_these_in_this_order(self, run: Run) -> None:
        """No field is added, dropped or moved by a change to the driver."""
        assert list(run.run()) == REPORT_KEYS, "expected the recorded keys"

    def test_the_fixed_fields_are_as_recorded(self, run: Run) -> None:
        """Profile, status, scope and counts for a completed pause."""
        report = run.run()
        assert report["schema_version"] == 1, report
        assert report["profile"] == "synthetic-tool-test", report
        assert report["status"] == "completed", report
        assert report["native_conformance"] is False, report
        assert report["identity_scope"] == SCOPE, report
        assert report["operator"] == "operator", report
        assert report["gap_ids"] == ["GAP-001"], report
        assert report["completed_actions"] == 1, report
        assert not report["error"], report
        assert report["frames"] == [], report
        assert report["streams"] == {}, report

    def test_the_plan_and_oracle_hashes_are_those_of_the_inputs(self, run: Run) -> None:
        """The plan hash covers the bytes of the plan file as read."""
        report = run.run()
        assert report["plan_sha256"] == pc.digest(run.source), report
        assert report["oracle_sha256"] == pc.digest(BINARY), report

    def test_the_driver_hash_is_that_of_the_module_file(self, run: Run) -> None:
        """Before decision D31 the driver is one file, ``protocol_capture.py``."""
        report = run.run()
        assert report["driver_sha256"] == pc.digest(SCRIPT.read_bytes()), report

    def test_the_pause_is_one_event_without_a_connection(self, run: Run) -> None:
        """An event has these fields; its time is not compared."""
        event = run.run()["events"][0]
        assert sorted(event) == [
            "action",
            "connection",
            "elapsed_ns",
            "event",
            "hex",
        ], event
        assert (event["action"], event["connection"], event["event"]) == (
            0,
            "",
            "pause",
        ), event
        assert not event["hex"], event
        assert isinstance(event["elapsed_ns"], int), event

    def test_the_times_are_utc_timestamps(self, run: Run) -> None:
        """Both timestamps carry an explicit zero offset."""
        report = run.run()
        assert report["recorded_at_utc"].endswith("+00:00"), report
        assert report["started_at_utc"].endswith("+00:00"), report


class TestFiles:
    """The directory a run leaves."""

    def test_three_files_are_written(self, run: Run) -> None:
        """The plan, the report and the checksum list; nothing else."""
        run.run()
        names = sorted(path.name for path in run.output.iterdir())
        assert names == ["checksums.sha256", "plan.json", "report.json"], names

    def test_the_plan_is_kept_byte_for_byte(self, run: Run) -> None:
        """The plan file is copied, not re-serialised."""
        run.run()
        assert (run.output / "plan.json").read_bytes() == run.source, (
            "expected (run.output / 'plan.json').read_bytes() == run.sou"
        )

    def test_the_report_file_is_the_report_as_indented_json(self, run: Run) -> None:
        """Two-space indentation and a final newline."""
        report = run.run()
        text = (run.output / "report.json").read_text()
        assert text == json.dumps(report, indent=2) + "\n", (
            "expected text == json.dumps(report, indent=2) + 'n'"
        )

    def test_the_checksums_list_the_plan_then_the_report(self, run: Run) -> None:
        """Two lines of the form ``<sha256>  <name>``."""
        run.run()
        expected = "".join(
            f"{pc.digest((run.output / name).read_bytes())}  {name}\n"
            for name in ("plan.json", "report.json")
        )
        assert (run.output / "checksums.sha256").read_text() == expected, (
            "expected (run.output / 'checksums.sha256').read_text() == e"
        )

    def test_the_directory_verifies(self, run: Run) -> None:
        """What ``run_plan`` writes, ``verify_capture`` accepts."""
        run.run()
        assert pc.verify_capture(run.output)["status"] == "completed", (
            "expected pc.verify_capture(run.output)['status'] == 'comple"
        )


class TestRefusals:
    """The order of the checks before the run."""

    def test_an_absent_plan_is_a_file_not_found_error(self, run: Run) -> None:
        """The plan is read first."""
        run.plan_path.unlink()
        run.binary.unlink()
        with pytest.raises(FileNotFoundError):
            run.run()

    def test_a_plan_that_is_not_json_is_refused_before_the_binary_is_read(
        self, run: Run
    ) -> None:
        """Parsing comes before validation, and the binary comes after both."""
        run.plan_path.write_bytes(b"{")
        run.binary.unlink()
        with pytest.raises(json.JSONDecodeError):
            run.run()

    def test_an_invalid_plan_is_refused_before_the_binary_is_read(
        self, run: Run
    ) -> None:
        """Validation comes before the oracle hash."""
        plan = pause_plan() | {"schema_version": 2}
        run.plan_path.write_text(json.dumps(plan))
        run.binary.unlink()
        with pytest.raises(ValueError, match=r"^Unsupported capture schema$"):
            run.run()

    def test_an_absent_binary_is_a_file_not_found_error(self, run: Run) -> None:
        """A valid plan then reads the binary."""
        run.binary.unlink()
        with pytest.raises(FileNotFoundError):
            run.run()

    def test_a_wrong_binary_is_refused_before_the_output_exists(self, run: Run) -> None:
        """The oracle hash is checked before the directory is made."""
        run.binary.write_bytes(b"other")
        run.output.mkdir()
        with pytest.raises(ValueError, match=r"^Oracle binary hash mismatch$"):
            run.run()

    def test_an_existing_output_is_refused_last(self, run: Run) -> None:
        """A directory that exists is never reused."""
        run.output.mkdir()
        with pytest.raises(FileExistsError):
            run.run()
        assert not list(run.output.iterdir()), "expected no files"


class TestCommandLine:
    """The ``capture`` command."""

    def test_capture_prints_the_profile_status_and_action_count(
        self,
        run: Run,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The summary line is the one the recipes read."""
        argv = [
            "protocol_capture.py",
            "capture",
            str(run.plan_path),
            "--oracle-binary",
            str(run.binary),
            "--output",
            str(run.output),
        ]
        monkeypatch.setattr(sys, "argv", argv)
        runpy.run_path(str(SCRIPT), run_name="__main__")
        assert (
            capsys.readouterr().out == "synthetic-tool-test: completed; 1 actions\n"
        ), "expected capsys.readouterr().out == 'synthetic-tool-test: c"
        assert (run.output / "report.json").is_file(), (
            "expected (run.output / 'report.json').is_file()"
        )
