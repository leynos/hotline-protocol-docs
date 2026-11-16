"""Characterize the failure paths and command line of ``capture-ghidra-evidence.py``.

The replay and the requests are in ``test_characterize_capture_ghidra.py``. Here
the fake bridge refuses, or the plan and output directory are wrong, and the
tests pin which error the script raises first and what it has written by then.
Expectations were observed on the script at its pinned commit and must hold on
the refactored script. The usage text of the command line is not pinned: only
its exit code is, because the command line later moves from ``argparse`` to
Cyclopts.
"""

import json
import runpy
import sys
import typing as typ

import pytest
from capture_ghidra_support import (
    IDENTITY,
    Harness,
    identity,
    make_harness,
    run,
    sequence,
    write_plan,
)
from ghidra_bridge_fake import BASELINE_SHA, ok
from script_loading import ROOT

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

CHARACTERIZES = "capture-ghidra-evidence.py"
SCRIPT = ROOT / "scripts" / CHARACTERIZES
DESCRIPTION = (
    "Capture read-only MCP queries with target identity and replayable arguments."
)


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> Harness:
    """Provide the loader for the script under test.

    Returns
    -------
    collections.abc.Callable
        A function from the replies to the loaded module and its bridge.
    """
    return make_harness(monkeypatch, SCRIPT)


class IdentityFailureTests:
    """The program identity is checked before and after the queries."""

    @pytest.fixture
    def query(self) -> dict[str, str]:
        """Return a plain query.

        Returns
        -------
        dict[str, str]
            The query.
        """
        return {"id": "Q-1", "tool": "get_function"}

    def test_an_error_reply_to_the_identity_request_is_a_runtime_error(
        self, harness: Harness, tmp_path: Path, query: dict[str, str]
    ) -> None:
        """The error carries the string form of the reply's content."""
        bad = {"isError": True, "structuredContent": None, "content": ["no program"]}
        module, bridge = harness([bad])
        with pytest.raises(RuntimeError) as caught:
            run(module, write_plan(tmp_path, [query]), tmp_path / "out")
        assert str(caught.value) == "['no program']", "expected the content text"
        assert bridge.calls() == [("get_program_info", {})], "expected one call"

    def test_an_identity_without_structured_content_is_refused(
        self, harness: Harness, tmp_path: Path, query: dict[str, str]
    ) -> None:
        """The identity must be structured."""
        module, _bridge = harness([ok(None)])
        with pytest.raises(
            RuntimeError, match=r"^Expected structured program identity$"
        ):
            run(module, write_plan(tmp_path, [query]), tmp_path / "out")

    def test_the_error_flag_is_checked_before_the_content(
        self, harness: Harness, tmp_path: Path, query: dict[str, str]
    ) -> None:
        """An error reply that also has structured content is an error."""
        bad = {"isError": True, "structuredContent": dict(IDENTITY), "content": ["x"]}
        module, _bridge = harness([bad])
        with pytest.raises(RuntimeError, match=r"^\['x'\]$"):
            run(module, write_plan(tmp_path, [query]), tmp_path / "out")

    def test_another_program_is_refused_before_any_query(
        self, harness: Harness, tmp_path: Path, query: dict[str, str]
    ) -> None:
        """The loaded program must have the baseline's SHA-256."""
        other = {**IDENTITY, "sha256": "0" * 64}
        module, bridge = harness([ok(other)])
        message = r"^Loaded program is not the Hotline Server baseline$"
        with pytest.raises(RuntimeError, match=message):
            run(module, write_plan(tmp_path, [query]), tmp_path / "out")
        assert bridge.calls() == [("get_program_info", {})], "expected no query"

    def test_the_baseline_hash_is_the_documented_one(self) -> None:
        """The retained identity carries the hash that the script demands."""
        assert IDENTITY["sha256"] == BASELINE_SHA, "expected the baseline hash"

    def test_an_identity_without_a_hash_is_a_key_error(
        self, harness: Harness, tmp_path: Path, query: dict[str, str]
    ) -> None:
        """The hash is read by key."""
        module, _bridge = harness([ok({"name": "x"})])
        with pytest.raises(KeyError, match="sha256"):
            run(module, write_plan(tmp_path, [query]), tmp_path / "out")

    def test_a_changed_identity_after_the_run_is_refused_after_writing(
        self, harness: Harness, tmp_path: Path, query: dict[str, str]
    ) -> None:
        """The records stay on disk when the closing check fails."""
        changed = ok({**IDENTITY, "function_count": 1})
        module, _bridge = harness([identity(), ok({"name": "n"}), changed])
        output = tmp_path / "out"
        with pytest.raises(RuntimeError, match=r"^Program identity changed during"):
            run(module, write_plan(tmp_path, [query]), output)
        assert (output / "Q-1.json").exists(), "expected the record kept"

    def test_an_error_reply_to_the_closing_identity_request_is_refused(
        self, harness: Harness, tmp_path: Path, query: dict[str, str]
    ) -> None:
        """An error flag at the end is the same failure as a changed identity."""
        bad = {"isError": True, "structuredContent": dict(IDENTITY), "content": []}
        module, _bridge = harness([identity(), ok({"name": "n"}), bad])
        message = r"^Program identity changed during capture$"
        with pytest.raises(RuntimeError, match=message):
            run(module, write_plan(tmp_path, [query]), tmp_path / "out")


class PlanAndOutputFailureTests:
    """Failures of the plan file, the output directory and the plan's entries."""

    def test_a_missing_plan_fails_before_the_output_is_created(
        self, harness: Harness, tmp_path: Path
    ) -> None:
        """The plan is read first, so nothing else happens."""
        module, bridge = harness([])
        output = tmp_path / "out"
        with pytest.raises(FileNotFoundError):
            run(module, tmp_path / "absent.json", output)
        assert not output.exists(), "expected no output directory"
        assert bridge.events == [], "expected no bridge activity"

    def test_a_plan_that_is_not_json_fails_before_the_output_is_created(
        self, harness: Harness, tmp_path: Path
    ) -> None:
        """A syntax error is a ``ValueError`` from the JSON reader."""
        module, bridge = harness([])
        plan = tmp_path / "plan.json"
        plan.write_text("[", encoding="utf-8")
        with pytest.raises(json.JSONDecodeError):
            run(module, plan, tmp_path / "out")
        assert not (tmp_path / "out").exists(), "expected no output directory"
        assert bridge.events == [], "expected no bridge activity"

    def test_the_output_directory_exists_after_an_identity_failure(
        self, harness: Harness, tmp_path: Path
    ) -> None:
        """The directory is made before the bridge starts."""
        module, _bridge = harness([ok(None)])
        output = tmp_path / "out"
        with pytest.raises(RuntimeError):
            run(module, write_plan(tmp_path, []), output)
        assert output.is_dir(), "expected the directory"

    def test_an_existing_record_is_never_overwritten(
        self, harness: Harness, tmp_path: Path
    ) -> None:
        """The existing file is named in the error and is left as it was."""
        query = {"id": "Q-1", "tool": "get_function"}
        module, bridge = harness(sequence(query))
        output = tmp_path / "out"
        output.mkdir()
        (output / "Q-1.json").write_text("kept", encoding="utf-8")
        with pytest.raises(FileExistsError) as caught:
            run(module, write_plan(tmp_path, [query]), output)
        assert caught.value.args == (output / "Q-1.json",), "expected the path"
        assert (output / "Q-1.json").read_text() == "kept", "expected it untouched"
        assert bridge.calls() == [("get_program_info", {})], "expected no query sent"

    def test_the_tool_check_comes_before_the_existing_record_check(
        self, harness: Harness, tmp_path: Path
    ) -> None:
        """A mutation is refused although its record also exists."""
        query = {"id": "Q-1", "tool": "set_comment"}
        module, _bridge = harness(sequence(query))
        output = tmp_path / "out"
        output.mkdir()
        (output / "Q-1.json").write_text("kept", encoding="utf-8")
        with pytest.raises(ValueError, match="Mutation is not permitted"):
            run(module, write_plan(tmp_path, [query]), output)

    def test_a_query_without_a_tool_is_a_key_error_on_tool(
        self, harness: Harness, tmp_path: Path
    ) -> None:
        """The tool is read first."""
        module, _bridge = harness([identity()])
        with pytest.raises(KeyError, match="tool"):
            run(module, write_plan(tmp_path, [{"id": "Q-1"}]), tmp_path / "out")

    def test_a_query_without_an_id_is_a_key_error_on_id(
        self, harness: Harness, tmp_path: Path
    ) -> None:
        """The identifier is read after the tool check passes."""
        module, bridge = harness([identity()])
        with pytest.raises(KeyError, match="id"):
            run(module, write_plan(tmp_path, [{"tool": "get_x"}]), tmp_path / "out")
        assert bridge.calls() == [("get_program_info", {})], "expected no query sent"

    def test_a_disallowed_tool_without_an_id_is_refused_for_the_tool(
        self, harness: Harness, tmp_path: Path
    ) -> None:
        """The tool check comes before the identifier is read."""
        module, _bridge = harness([identity()])
        with pytest.raises(ValueError, match="Mutation is not permitted: nope"):
            run(module, write_plan(tmp_path, [{"tool": "nope"}]), tmp_path / "out")


class CommandLineTests:
    """The script run as a program."""

    @staticmethod
    def program(
        monkeypatch: pytest.MonkeyPatch, *arguments: str
    ) -> cabc.Callable[[], None]:
        """Prepare a run of the script as ``__main__`` with these arguments.

        Returns
        -------
        collections.abc.Callable[[], None]
            A function that runs it.
        """
        monkeypatch.setattr(sys, "argv", [CHARACTERIZES, *arguments])

        def start() -> None:
            """Run the script as the main program."""
            runpy.run_path(str(SCRIPT), run_name="__main__")

        return start

    def test_two_positional_arguments_capture_the_plan_into_the_directory(
        self,
        harness: Harness,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The plan path and the output directory are the two arguments."""
        query = {"id": "Q-1", "tool": "get_function"}
        _module, bridge = harness(sequence(query))
        plan = write_plan(tmp_path, [query])
        output = tmp_path / "out"
        self.program(monkeypatch, str(plan), str(output))()
        assert (output / "Q-1.json").exists(), "expected the record"
        assert capsys.readouterr().out == "Q-1 OK\n", "expected the progress line"
        assert bridge.calls()[1] == ("get_function", {}), "expected the query"

    @pytest.mark.parametrize("arguments", [[], ["only-one"], ["a", "b", "c"]])
    def test_a_wrong_number_of_arguments_exits_with_status_two(
        self,
        harness: Harness,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        arguments: list[str],
    ) -> None:
        """The usage error is a status of 2 and a message on standard error."""
        harness([])
        start = self.program(monkeypatch, *arguments)
        with pytest.raises(SystemExit) as caught:
            start()
        assert caught.value.code == 2, "expected the usage status"
        captured = capsys.readouterr()
        assert not captured.out, "expected nothing on standard output"
        assert "error" in captured.err, "expected a message on standard error"

    def test_help_exits_cleanly_and_prints_the_description(
        self,
        harness: Harness,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """``--help`` prints the module description and exits with status 0."""
        harness([])
        start = self.program(monkeypatch, "--help")
        with pytest.raises(SystemExit) as caught:
            start()
        assert caught.value.code == 0, "expected success"
        assert DESCRIPTION in " ".join(capsys.readouterr().out.split()), "description"
