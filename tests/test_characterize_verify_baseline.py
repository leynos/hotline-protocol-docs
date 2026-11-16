"""Characterize ``verify-baseline-evidence.py`` before it is refactored.

Every expectation below was observed on the script at its pinned commit
(``scripts/pinned-sources.json``), and the same tests must give the same
outcomes on the refactored script; ``tests/test_pin_equivalence.py`` runs them
against both. Each check of the verifier has a synthetic corpus that breaks that
check alone, and the pairs of breakages pin which error is raised first. This
module covers the manifest and the saved queries; the inventory and the ledger
are in ``test_characterize_verify_baseline_ledger.py``.
"""

import runpy
import typing as typ

import pinned_source
import pytest
from baseline_corpus_support import CODE, CORPUS, HELPERS, Corpus, expect, refused
from script_loading import ROOT, load_script

if typ.TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType

CHARACTERIZES = "verify-baseline-evidence.py"
RETAINED_OUTPUT = [
    "Verified 154 MCP queries and 83 ledger entries",
    "Complete data inventory: 4553 items",
]
ZEROS = "0" * 64


@pytest.fixture(scope="module")
def verifier() -> ModuleType:
    """Load the verifier under test.

    Returns
    -------
    types.ModuleType
        The executed script.
    """
    return load_script(ROOT / "scripts" / CHARACTERIZES, "verify_baseline_under_test")


def saved(tmp_path: Path, name: str) -> Path:
    """Name a saved query record of the synthetic corpus.

    Returns
    -------
    pathlib.Path
        The path that the verifier puts in its message.
    """
    return tmp_path / CORPUS / "queries" / f"{name}.json"


class SoundCorpusTests:
    """A consistent corpus passes and is summarised on standard output."""

    def test_a_sound_corpus_prints_its_three_summary_lines(
        self,
        verifier: ModuleType,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Queries, ledger entries, data items and the status counts are printed."""
        verifier.verify(Corpus(tmp_path).write())
        assert capsys.readouterr().out.splitlines() == [
            "Verified 4 MCP queries and 3 ledger entries",
            "Complete data inventory: 3 items",
            "{'Doc defect': 2, 'Confirmed': 1}",
        ], "expected the three summary lines"

    def test_the_retained_corpus_passes_with_its_recorded_counts(
        self,
        verifier: ModuleType,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The retained records and ledger are accepted, read-only."""
        pins = pinned_source.Pins()
        for name in HELPERS:
            target = tmp_path / "scripts" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(pins.read(name))
        (tmp_path / "evidence").symlink_to(ROOT / "evidence")
        (tmp_path / "docs").symlink_to(ROOT / "docs")
        verifier.verify(tmp_path)
        lines = capsys.readouterr().out.splitlines()
        assert lines[:2] == RETAINED_OUTPUT, "expected the retained counts"
        assert lines[2].startswith("{"), "expected the status counts last"


class CommandLineTests:
    """Run as a program, the script verifies the tree that holds it."""

    @staticmethod
    def place_script(root: Path) -> Path:
        """Put the script under test at ``scripts/`` of a synthetic root.

        Returns
        -------
        pathlib.Path
            The script's path in the synthetic root.
        """
        target = root / "scripts" / CHARACTERIZES
        target.write_bytes((ROOT / "scripts" / CHARACTERIZES).read_bytes())
        return target

    def test_the_program_verifies_the_root_above_its_directory(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The root is the parent of the script's directory."""
        script = self.place_script(Corpus(tmp_path).write())
        runpy.run_path(str(script), run_name="__main__")
        assert capsys.readouterr().out.splitlines()[0] == (
            "Verified 4 MCP queries and 3 ledger entries"
        ), "expected the summary of the synthetic corpus"

    def test_the_program_lets_a_refusal_propagate(self, tmp_path: Path) -> None:
        """A refused corpus ends the program with the verifier's exception."""
        corpus = Corpus(tmp_path)
        corpus.manifest["capture_count"] = 5
        script = self.place_script(corpus.write())
        with pytest.raises(ValueError, match="Capture inventory differs"):
            runpy.run_path(str(script), run_name="__main__")

    def test_importing_the_script_does_not_run_it(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Loading the module prints nothing and exposes ``verify``."""
        module = load_script(ROOT / "scripts" / CHARACTERIZES, "verify_baseline_fresh")
        assert callable(module.verify), "expected verify to be public"
        assert not capsys.readouterr().out, "expected no output on import"


class ManifestChecksTests:
    """The manifest's helper scripts and input snapshots are checked first."""

    def test_a_changed_helper_script_is_named_by_its_manifest_path(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A recorded hash that the helper does not carry is refused."""
        corpus = Corpus(tmp_path)
        corpus.manifest["helper_scripts"][1]["sha256"] = ZEROS
        expect(verifier, corpus, f"Helper script changed: scripts/{HELPERS[1]}")

    def test_a_changed_input_snapshot_is_named_by_its_saved_path(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """An input whose bytes no longer match its hash is refused."""
        corpus = Corpus(tmp_path)
        corpus.manifest["inputs"][0]["sha256"] = ZEROS
        message = f"Input snapshot changed: {tmp_path / CORPUS / 'inputs/a.txt'}"
        expect(verifier, corpus, message)

    def test_the_helper_check_comes_before_the_input_check(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """When both fail, the helper is reported."""
        corpus = Corpus(tmp_path)
        corpus.manifest["helper_scripts"][0]["sha256"] = ZEROS
        corpus.manifest["inputs"][0]["sha256"] = ZEROS
        expect(verifier, corpus, "Helper script changed", starts=True)

    def test_the_input_check_comes_before_the_plans_are_read(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A changed input is reported although a query is also wrong."""
        corpus = Corpus(tmp_path)
        corpus.manifest["inputs"][0]["sha256"] = ZEROS
        corpus.records["A-1"]["program"]["sha256"] = "00"
        expect(verifier, corpus, "Input snapshot changed", starts=True)

    def test_the_program_key_is_read_before_the_helper_list(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A manifest with neither key raises the missing program first."""
        corpus = Corpus(tmp_path)
        del corpus.manifest["program"]
        del corpus.manifest["helper_scripts"]
        error = refused(verifier, corpus)
        assert isinstance(error, KeyError), "expected a KeyError"
        assert error.args == ("program",), "expected the program key to be missing"

    def test_a_missing_helper_list_is_a_key_error(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """With the program present, the helper list is read next."""
        corpus = Corpus(tmp_path)
        del corpus.manifest["helper_scripts"]
        error = refused(verifier, corpus)
        assert isinstance(error, KeyError), "expected a KeyError"
        assert error.args == ("helper_scripts",), "expected the helper key"

    def test_a_missing_manifest_is_a_file_not_found_error(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """An empty root has no manifest to read."""
        with pytest.raises(FileNotFoundError):
            verifier.verify(tmp_path)


class QueryChecksTests:
    """Each saved query is checked against its plan, oracle and result."""

    def test_a_duplicate_identifier_in_one_plan_is_refused(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """The second use of an identifier raises."""
        corpus = Corpus(tmp_path)
        corpus.plans["01-first.json"].append(corpus.plans["01-first.json"][0])
        expect(verifier, corpus, "Duplicate query ID: A-1")

    def test_a_duplicate_identifier_across_plans_is_refused(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """Plans are read in file-name order and share one identifier set."""
        corpus = Corpus(tmp_path)
        corpus.plans["02-second.json"].append(corpus.plans["01-first.json"][1])
        expect(verifier, corpus, "Duplicate query ID: B-1")

    def test_a_missing_record_is_a_file_not_found_error(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A planned query with no saved record cannot be read."""
        corpus = Corpus(tmp_path)
        corpus.plans["02-second.json"].append({"id": "Z-9", "tool": "get_z"})
        error = refused(verifier, corpus)
        assert isinstance(error, FileNotFoundError), f"unexpected {error!r}"

    def test_a_record_for_another_query_is_a_plan_mismatch(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """The saved query must equal the planned one."""
        corpus = Corpus(tmp_path)
        corpus.records["C-1"]["query"]["arguments"] = {"changed": True}
        expect(verifier, corpus, f"Query plan mismatch: {saved(tmp_path, 'C-1')}")

    def test_the_plan_check_comes_before_the_oracle_check(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A record that fails both is reported as a plan mismatch."""
        corpus = Corpus(tmp_path)
        corpus.records["A-1"]["query"]["arguments"] = {"changed": True}
        corpus.records["A-1"]["program"]["sha256"] = "00"
        expect(verifier, corpus, "Query plan mismatch", starts=True)

    def test_a_record_from_another_program_is_a_wrong_oracle(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """The record's program hash must equal the manifest's."""
        corpus = Corpus(tmp_path)
        corpus.records["B-2"]["program"]["sha256"] = "00"
        expect(verifier, corpus, f"Wrong oracle: {saved(tmp_path, 'B-2')}")

    def test_the_oracle_check_comes_before_the_error_flag(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A record that fails both is reported as a wrong oracle."""
        corpus = Corpus(tmp_path)
        corpus.records["A-1"]["program"]["sha256"] = "00"
        corpus.records["A-1"]["result"]["isError"] = True
        expect(verifier, corpus, "Wrong oracle", starts=True)

    def test_an_error_result_is_a_failed_query(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A result flagged as an error is refused."""
        corpus = Corpus(tmp_path)
        corpus.records["C-1"]["result"]["isError"] = True
        expect(verifier, corpus, f"Failed MCP query: {saved(tmp_path, 'C-1')}")

    def test_the_error_flag_comes_before_the_truncation_check(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """An error with no structured content is reported as an error."""
        corpus = Corpus(tmp_path)
        corpus.records["C-1"]["result"]["isError"] = True
        corpus.records["C-1"]["result"]["structuredContent"] = None
        expect(verifier, corpus, "Failed MCP query", starts=True)

    def test_absent_structured_content_is_a_missing_result(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A result without structured content is refused."""
        corpus = Corpus(tmp_path)
        corpus.records["C-1"]["result"]["structuredContent"] = None
        message = f"Missing or truncated result: {saved(tmp_path, 'C-1')}"
        expect(verifier, corpus, message)

    def test_a_truncated_result_is_refused(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A result marked truncated is refused."""
        corpus = Corpus(tmp_path)
        corpus.data("C-1")["truncated"] = True
        expect(verifier, corpus, "Missing or truncated result", starts=True)

    def test_a_changed_decompiler_export_is_refused(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """The saved ``.c`` file must equal the code in the record."""
        corpus = Corpus(tmp_path)
        corpus.code["A-1"] = CODE + "// edited\n"
        message = f"Decompiler export changed: {saved(tmp_path, 'A-1')}"
        expect(verifier, corpus, message)

    def test_a_missing_decompiler_export_is_a_file_not_found_error(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A record with code but no ``.c`` file cannot be compared."""
        corpus = Corpus(tmp_path)
        del corpus.code["A-1"]
        error = refused(verifier, corpus)
        assert isinstance(error, FileNotFoundError), f"unexpected {error!r}"

    def test_the_export_check_comes_before_the_incomplete_result_check(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A record with changed code and more pages is reported for the code."""
        corpus = Corpus(tmp_path)
        corpus.code["A-1"] = "other\n"
        corpus.data("A-1")["has_more"] = True
        expect(verifier, corpus, "Decompiler export changed", starts=True)

    def test_a_result_with_more_pages_is_incomplete(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """Only a data-item listing may have pages."""
        corpus = Corpus(tmp_path)
        corpus.data("C-1")["has_more"] = True
        message = f"Incomplete query result: {saved(tmp_path, 'C-1')}"
        expect(verifier, corpus, message)

    def test_a_data_item_page_may_declare_more_pages(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A listing's ``has_more`` is ignored; its offsets are checked instead."""
        corpus = Corpus(tmp_path)
        corpus.data("B-1")["has_more"] = True
        verifier.verify(corpus.write())
