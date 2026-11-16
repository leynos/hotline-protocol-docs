"""Characterize ``native_settings_cases`` before it is refactored.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``) and must hold on the refactored module;
``tests/test_pin_equivalence.py`` runs these tests against both. The case table
and every step builder are pinned by fingerprints of their exact output, so a
change in a single byte of a plan fails a test. The command line is covered for
the plans it writes, its message, and the order in which it reads, creates and
refuses.
"""

import hashlib
import json
import sys
import typing as typ

import native_settings_cases as cases
import pytest

if typ.TYPE_CHECKING:
    from pathlib import Path

CHARACTERIZES = "native_settings_cases.py"
CASE_COUNT = 10
STEPS_PER_CASE = 33
CASE_ORDER = [
    "absent",
    "empty",
    "zero-two",
    "one-byte-refuse",
    "two-byte-auto",
    "three-byte-default",
    "four-byte-both",
    "five-byte-prefix",
    "duplicate-refuse-auto",
    "duplicate-auto-refuse",
]
CASES_FINGERPRINT = "a231fffae3b3ed2d026fca959c1625a14d3f497e2610e2b3f52b01ce72f2d2e4"
PLANS_FINGERPRINT = "5830589b0a3d831391d045c6dc6fe274b60b2b86960f1eb043ece01ec21503d1"
PM_FINGERPRINT = "db2a3944b44b3d8be44a431572dd6a1ad51eb749d6e3331b87dd52cb7728272c"
LOGIN_FINGERPRINT = "eb7002324c937760f246339ce2c53c67654fe5ff882ed71d111b0953b79c233d"
MAIN_BARRIER = "a2564ff9d98d21eeea842691f33c64962868e88220d20fc846bac2493c68a5a4"
SUBJECT_BARRIER = "45c4d7dd405bb6e10d8300bb32889ee8e34b96b83c9f4a24e3a72f59e804bd82"
OUTPUT_FINGERPRINT = "bcfb3d43d40fdb8db492ea30253959641a4b8d948b5c1157ababd93968cd854b"
ABSENT_PLAN_SHA256 = "94ff2558d4c94083cf6362881f34cee6011bb4a954d85280d60442b9881ca869"
USAGE_STATUS = 2
CONTROL_ENDPOINT = {"control": {"host": "127.0.0.1", "port": 15500}}
GAP_IDS = ["GAP-015", "GAP-016", "GAP-017", "GAP-084"]


def fingerprint(value: object) -> str:
    """Hash the JSON text of a value, keys in their existing order.

    Returns
    -------
    str
        The lower-case hexadecimal SHA-256.
    """
    return hashlib.sha256(json.dumps(value).encode()).hexdigest()


class PlanBuilderTests:
    """The case table and the steps built from it, pinned by fingerprint."""

    def test_the_case_table_is_unchanged(self) -> None:
        """Ten cases in order, each with its values and expected flags."""
        assert list(cases.CASES) == CASE_ORDER, "expected the case order"
        table = {
            name: [None if values is None else [v.hex() for v in values], flags]
            for name, (values, flags) in cases.CASES.items()
        }
        assert fingerprint(table) == CASES_FINGERPRINT, "expected the same values"

    def test_every_case_plan_is_unchanged(self) -> None:
        """The steps and the expectation of all ten cases, byte for byte."""
        built = cases.cases()
        assert list(built) == list(cases.CASES), "expected the table order"
        assert {
            name: len(steps) for name, (steps, _) in built.items()
        } == dict.fromkeys(cases.CASES, STEPS_PER_CASE), "expected the same step count"
        plans = {name: [steps, detail] for name, (steps, detail) in built.items()}
        assert fingerprint(plans) == PLANS_FINGERPRINT, "expected the same plans"

    def test_an_expectation_names_the_case_flags_and_text(self) -> None:
        """A duplicate case has no single expected flag value."""
        _steps, detail = cases.cases()["duplicate-auto-refuse"]
        assert detail["case"] == "duplicate-auto-refuse", "expected the case name"
        assert detail["expected_flags"] is None, "expected no single flag value"
        assert detail["duplicate"] is True, "expected the duplicate flag"
        assert detail["pm_text"] == b"settings25-pm-10".hex(), "expected the text"
        assert detail["oracle_sha256"].startswith("ad7040db"), "expected the oracle"

    def test_a_private_message_carries_the_saved_subject_variable(self) -> None:
        """The two-byte subject UID is a placeholder in the sent hex."""
        step = cases.pm_request(70, b"hello")
        assert "{subject_uid}" in step["hex"], "expected the saved variable"
        assert fingerprint(step) == PM_FINGERPRINT, "expected the exact step"

    def test_the_subject_login_is_unchanged(self) -> None:
        """Three handshake steps, the login and three reads, on the subject."""
        steps = cases.subject_login()
        assert len(steps) == 7, "expected seven steps"
        assert {step["connection"] for step in steps} == {"subject"}, "connection"
        assert fingerprint(steps) == LOGIN_FINGERPRINT, "expected the exact steps"

    @pytest.mark.parametrize(
        ("connection", "identifier", "expected"),
        [("main", 41, MAIN_BARRIER), ("subject", 72, SUBJECT_BARRIER)],
    )
    def test_a_barrier_is_a_500_request_and_its_reply(
        self, connection: str, identifier: int, expected: str
    ) -> None:
        """One send and one matched read on the named connection."""
        steps = cases.barrier(connection, identifier)
        assert [step["op"] for step in steps] == ["send", "read_frame"], "ops"
        assert fingerprint(steps) == expected, "expected the exact steps"


class CommandLineTests:
    """``main`` reads a runtime record and writes one plan per case."""

    @staticmethod
    def argv(monkeypatch: pytest.MonkeyPatch, *arguments: str) -> None:
        """Set the command line of a run."""
        monkeypatch.setattr(sys, "argv", [CHARACTERIZES, *arguments])

    @pytest.fixture
    def record(self, tmp_path: Path) -> Path:
        """Write a runtime record.

        Returns
        -------
        pathlib.Path
            The record's path.
        """
        path = tmp_path / "runtime.json"
        path.write_text(json.dumps({"emulator_pid": 123}))
        return path

    def test_ten_plans_are_written_with_exact_bytes_and_one_message(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
        record: Path,
    ) -> None:
        """One file per case, indented JSON, then the count on standard output."""
        output = tmp_path / "plans"
        self.argv(monkeypatch, "--runtime-record", str(record), "--output", str(output))
        cases.main()
        assert capsys.readouterr().out == "Prepared 10 native settings cases\n", "text"
        written = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(output.iterdir())
        }
        assert fingerprint(written) == OUTPUT_FINGERPRINT, "expected the same files"
        assert written["absent.json"] == ABSENT_PLAN_SHA256, "expected the first plan"
        assert len(written) == CASE_COUNT, "expected one file per case"

    def test_the_runtime_record_is_embedded_in_each_plan(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, record: Path
    ) -> None:
        """The plan's environment is the record, and its endpoint is fixed."""
        output = tmp_path / "plans"
        self.argv(monkeypatch, "--runtime-record", str(record), "--output", str(output))
        cases.main()
        plan = json.loads((output / "empty.json").read_text())
        assert plan["environment"] == {"emulator_pid": 123}, "expected the record"
        assert plan["endpoints"] == CONTROL_ENDPOINT, "expected the fixed endpoint"
        assert plan["gap_ids"] == GAP_IDS, "expected the four gaps"
        assert plan["expectation"]["case"] == "empty", "expected the case name"

    @pytest.mark.parametrize("arguments", [["stray"], ["--runtime-record", "x"], []])
    def test_a_command_line_that_cannot_be_used_exits_with_status_two(
        self, monkeypatch: pytest.MonkeyPatch, arguments: list[str]
    ) -> None:
        """A stray argument, or a missing required option."""
        self.argv(monkeypatch, *arguments)
        with pytest.raises(SystemExit) as caught:
            cases.main()
        assert caught.value.code == USAGE_STATUS, "expected the usage status"

    def test_a_missing_runtime_record_leaves_no_output_directory(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The record is read before the directory is made."""
        output = tmp_path / "plans"
        record = tmp_path / "absent.json"
        self.argv(monkeypatch, "--runtime-record", str(record), "--output", str(output))
        with pytest.raises(FileNotFoundError) as caught:
            cases.main()
        assert caught.value.filename == str(record), "expected the record"
        assert not output.exists(), "expected no output directory"

    def test_a_record_that_is_not_json_leaves_no_output_directory(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The record is parsed before the directory is made."""
        record = tmp_path / "runtime.json"
        record.write_text("not json")
        output = tmp_path / "plans"
        self.argv(monkeypatch, "--runtime-record", str(record), "--output", str(output))
        with pytest.raises(json.JSONDecodeError):
            cases.main()
        assert not output.exists(), "expected no output directory"

    def test_an_existing_output_is_refused_after_the_record_is_read(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, record: Path
    ) -> None:
        """The directory is created exclusively, so an existing one is an error."""
        output = tmp_path / "plans"
        output.mkdir()
        self.argv(monkeypatch, "--runtime-record", str(record), "--output", str(output))
        with pytest.raises(FileExistsError):
            cases.main()
        assert not list(output.iterdir()), "expected the directory untouched"

    def test_a_missing_record_is_reported_before_an_existing_output(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Both faults at once end with the missing record."""
        output = tmp_path / "plans"
        output.mkdir()
        record = tmp_path / "absent.json"
        self.argv(monkeypatch, "--runtime-record", str(record), "--output", str(output))
        with pytest.raises(FileNotFoundError):
            cases.main()
