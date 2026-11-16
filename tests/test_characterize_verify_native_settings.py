"""Characterize ``verify_native_settings`` before it is refactored.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``) and must hold on the refactored module;
``tests/test_pin_equivalence.py`` runs these tests against both. The result for
the retained cases is pinned by a fingerprint, as is the text of the command
line. The order in which a faulted report is refused is held in
``test_native_settings_check_order.py``.
"""

import hashlib
import json
import sys
from pathlib import Path

import pytest
import verify_native_settings as verifier

CHARACTERIZES = "verify_native_settings.py"
ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "evidence/gap-remediation/2026-11-13/native-settings-01/raw/cases"
RESULT_FINGERPRINT = "30dc65f8631988a30412ad787bea83df0e173e7b45309c40b0fae6d547184377"
OUTPUT_FINGERPRINT = "f208e018eecc4b389910c538ed7b0eb2ee5640762ab646c590d440c97a99ddfc"
OUTPUT_CHARACTERS = 1410
SCOPE = "304 field 113 only; duplicate selections measured per case"
USAGE_STATUS = 2
FIRST_CASE = {
    "case": "absent",
    "observed_flags": 0,
    "subject_uid_hex": "0016",
    "feedback_option": 0,
}


class VerifyTests:
    """``verify`` replays every retained case and infers its flags."""

    def test_the_retained_cases_give_the_recorded_result(self) -> None:
        """Ten results in plan order, and the scope sentence."""
        result = verifier.verify(CASES)
        assert result["scope"] == SCOPE, "expected the scope sentence"
        assert result["cases"][0] == FIRST_CASE, "expected the first case"
        digest = hashlib.sha256(json.dumps(result).encode()).hexdigest()
        assert digest == RESULT_FINGERPRINT, "expected the same result"

    def test_a_directory_whose_cases_differ_is_refused_first(
        self, tmp_path: Path
    ) -> None:
        """The inventory is compared before any case is read."""
        (tmp_path / "extra").mkdir()
        with pytest.raises(ValueError, match=r"^Settings corpus inventory differs$"):
            verifier.verify(tmp_path)

    def test_a_missing_directory_is_a_file_error(self, tmp_path: Path) -> None:
        """The directory is listed before anything else is checked."""
        with pytest.raises(FileNotFoundError):
            verifier.verify(tmp_path / "absent")

    def test_fields_map_each_identifier_to_its_bytes(self) -> None:
        """The hex of each field is decoded; a repeated identifier keeps the last."""
        frame = {
            "fields": [
                {"id": 1, "hex": "0a"},
                {"id": 2, "hex": ""},
                {"id": 1, "hex": "0b0c"},
            ]
        }
        assert verifier.fields(frame) == {1: b"\x0b\x0c", 2: b""}, "expected bytes"


class CommandLineTests:
    """``main`` takes the directory of cases and prints the result."""

    @staticmethod
    def argv(monkeypatch: pytest.MonkeyPatch, *arguments: str) -> None:
        """Set the command line of a run."""
        monkeypatch.setattr(sys, "argv", [CHARACTERIZES, *arguments])

    def test_the_result_is_printed_as_indented_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """One document, two-space indentation, a final newline."""
        self.argv(monkeypatch, str(CASES))
        verifier.main()
        printed = capsys.readouterr().out
        assert printed == json.dumps(verifier.verify(CASES), indent=2) + "\n", "text"
        assert len(printed) == OUTPUT_CHARACTERS, "expected the same length"
        digest = hashlib.sha256(printed.encode()).hexdigest()
        assert digest == OUTPUT_FINGERPRINT, "expected the same text"

    @pytest.mark.parametrize("arguments", [[], ["a", "b"]])
    def test_a_command_line_that_cannot_be_used_exits_with_status_two(
        self, monkeypatch: pytest.MonkeyPatch, arguments: list[str]
    ) -> None:
        """No directory, or a stray argument."""
        self.argv(monkeypatch, *arguments)
        with pytest.raises(SystemExit) as caught:
            verifier.main()
        assert caught.value.code == USAGE_STATUS, "expected the usage status"

    def test_a_missing_directory_is_a_file_error_not_a_usage_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The path is not checked until the verifier lists it."""
        self.argv(monkeypatch, str(tmp_path / "absent"))
        with pytest.raises(FileNotFoundError):
            verifier.main()
