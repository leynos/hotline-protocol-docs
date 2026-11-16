"""Characterize ``capture-ghidra-evidence.py`` before it is refactored.

The script drives a Ghidra MCP bridge. These tests replace the ``mcp`` library
with a fake that replays the retained query records of
``evidence/hotline-server-1.9``, so no Ghidra and no bridge runs. Every
expectation was observed on the script at its pinned commit
(``scripts/pinned-sources.json``) and must hold on the refactored script. This
module covers the replay of the retained plans, the requests and the handling of
results; ``test_characterize_capture_ghidra_failures.py`` covers the failure
paths and the command line.
"""

import datetime as dt
import json
import typing as typ

import pytest
from capture_ghidra_support import (
    IDENTITY,
    SERVER,
    Harness,
    identity,
    make_harness,
    run,
    sequence,
    write_plan,
)
from ghidra_bridge_fake import RETAINED, ok, retained_record
from script_loading import ROOT

if typ.TYPE_CHECKING:
    from pathlib import Path

CHARACTERIZES = "capture-ghidra-evidence.py"
SCRIPT = ROOT / "scripts" / CHARACTERIZES
PLANS = sorted(path.name for path in (RETAINED / "plans").glob("*.json"))


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> Harness:
    """Provide the loader for the script under test.

    Returns
    -------
    collections.abc.Callable
        A function from the replies to the loaded module and its bridge.
    """
    return make_harness(monkeypatch, SCRIPT)


def check_written(query_id: str, output: Path, bounds: tuple[dt.datetime, ...]) -> None:
    """Compare what the script wrote for one query with its retained record.

    Parameters
    ----------
    query_id : str
        The query's identifier.
    output : pathlib.Path
        The directory that the script wrote.
    bounds : tuple[datetime.datetime, ...]
        The times before and after the run, between which the stamp must lie.
    """
    text = (output / f"{query_id}.json").read_text()
    written = json.loads(text)
    stamp = dt.datetime.fromisoformat(written.pop("captured_at_utc"))
    assert bounds[0] <= stamp <= bounds[1], "expected a timestamp from this run"
    assert stamp.utcoffset() == dt.timedelta(0), "expected a UTC offset"
    retained = retained_record(query_id)
    retained.pop("captured_at_utc")
    assert written == retained, f"expected the retained record of {query_id}"
    export = RETAINED / "queries" / f"{query_id}.c"
    target = output / f"{query_id}.c"
    assert target.exists() == export.exists(), "expected an export where code exists"
    if export.exists():
        assert target.read_bytes() == export.read_bytes(), "expected the code"


class ReplayTests:
    """Each retained plan is replayed against its retained results."""

    @pytest.mark.parametrize("plan_name", PLANS)
    def test_a_replayed_plan_rewrites_the_retained_records(
        self,
        harness: Harness,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        plan_name: str,
    ) -> None:
        """Records, exports and the progress lines equal the retained ones."""
        plan = json.loads((RETAINED / "plans" / plan_name).read_text())
        results = [retained_record(query["id"])["result"] for query in plan]
        module, bridge = harness([identity(), *results, identity()])
        output = tmp_path / "captured" / "nested"
        before = dt.datetime.now(dt.UTC)
        run(module, RETAINED / "plans" / plan_name, output)
        bounds = (before, dt.datetime.now(dt.UTC))
        for query in plan:
            check_written(query["id"], output, bounds)
        assert capsys.readouterr().out.splitlines() == [
            f"{query['id']} OK" for query in plan
        ], "expected one progress line per query"
        requested = [(query["tool"], query.get("arguments", {})) for query in plan]
        assert bridge.calls() == [
            ("get_program_info", {}),
            *requested,
            ("get_program_info", {}),
        ], "expected the identity, the plan in order, then the identity again"

    def test_a_written_record_is_indented_json_with_a_trailing_newline(
        self, harness: Harness, tmp_path: Path
    ) -> None:
        """A record file is ``json.dumps`` with indent 2 and a final newline."""
        query = {"id": "Q-1", "tool": "get_function"}
        module, _bridge = harness(sequence(query))
        run(module, write_plan(tmp_path, [query]), tmp_path / "out")
        text = (tmp_path / "out" / "Q-1.json").read_text()
        assert text == json.dumps(json.loads(text), indent=2) + "\n", "expected layout"


class RequestTests:
    """How the script starts the bridge and what it asks for."""

    def test_the_session_is_opened_and_closed_around_the_calls(
        self, harness: Harness, tmp_path: Path
    ) -> None:
        """The bridge command, the streams, ``initialize`` and the exits."""
        query = {"id": "Q-1", "tool": "get_function", "arguments": {"a": 1}}
        module, bridge = harness(sequence(query))
        run(module, write_plan(tmp_path, [query]), tmp_path / "out")
        expected = [
            ("stdio", str(ROOT / "ghidra-mcp")),
            ("session", "read-stream", "write-stream"),
            ("initialize",),
            ("call", "get_program_info", {}),
            ("call", "get_function", {"a": 1}),
            ("call", "get_program_info", {}),
            ("session-exit",),
            ("stdio-exit",),
        ]
        assert bridge.events == expected, "expected the full conversation"

    def test_a_query_without_arguments_sends_an_empty_dictionary(
        self, harness: Harness, tmp_path: Path
    ) -> None:
        """The arguments default to ``{}``."""
        query = {"id": "Q-1", "tool": "list_functions"}
        module, bridge = harness(sequence(query))
        run(module, write_plan(tmp_path, [query]), tmp_path / "out")
        assert bridge.calls()[1] == ("list_functions", {}), "expected empty arguments"

    @pytest.mark.parametrize(
        "tool",
        [
            "get_x",
            "list_x",
            "search_x",
            "decompile_x",
            "disassemble_x",
            "read_x",
        ],
    )
    def test_a_read_only_tool_prefix_is_allowed(
        self, harness: Harness, tmp_path: Path, tool: str
    ) -> None:
        """Each of the six prefixes passes."""
        query = {"id": "Q-1", "tool": tool}
        module, bridge = harness(sequence(query))
        run(module, write_plan(tmp_path, [query]), tmp_path / "out")
        assert bridge.calls()[1][0] == tool, "expected the call to be made"

    @pytest.mark.parametrize(
        "tool",
        [
            "rename_function",
            "set_comment",
            "write_memory",
            "create_x",
            "get",
            "GET_x",
            "",
        ],
    )
    def test_any_other_tool_is_refused_before_it_is_called(
        self, harness: Harness, tmp_path: Path, tool: str
    ) -> None:
        """A tool outside the prefixes raises, and is never sent."""
        query = {"id": "Q-1", "tool": tool}
        module, bridge = harness(sequence(query))
        with pytest.raises(ValueError, match=r"^Mutation is not permitted: ") as caught:
            run(module, write_plan(tmp_path, [query]), tmp_path / "out")
        assert str(caught.value) == f"Mutation is not permitted: {tool}", "message"
        assert bridge.calls() == [("get_program_info", {})], "expected no query sent"

    def test_earlier_queries_stay_written_when_a_later_one_is_refused(
        self, harness: Harness, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Records are written as the plan proceeds, with no rollback."""
        good = {"id": "G-1", "tool": "get_function"}
        bad = {"id": "B-1", "tool": "set_comment"}
        module, _bridge = harness(sequence(good, bad))
        output = tmp_path / "out"
        with pytest.raises(ValueError, match="Mutation"):
            run(module, write_plan(tmp_path, [good, bad]), output)
        names = sorted(path.name for path in output.iterdir())
        assert names == ["G-1.json"], "expected only the first record"
        assert capsys.readouterr().out == "G-1 OK\n", "expected the first progress"


class ResultHandlingTests:
    """What is written for each kind of result."""

    def test_an_error_result_is_recorded_and_reported_as_an_error(
        self, harness: Harness, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The query is written with its error and the run continues."""
        failing = {"id": "E-1", "tool": "get_function"}
        after = {"id": "N-1", "tool": "get_function"}
        replies = [
            identity(),
            {"isError": True, "structuredContent": None, "content": ["boom"]},
            ok({"name": "n"}),
            identity(),
        ]
        module, _bridge = harness(replies)
        output = tmp_path / "out"
        run(module, write_plan(tmp_path, [failing, after]), output)
        written = json.loads((output / "E-1.json").read_text())
        assert written["result"]["isError"] is True, "expected the error recorded"
        assert capsys.readouterr().out == "E-1 ERROR\nN-1 OK\n", "expected both lines"

    def test_code_in_structured_content_is_saved_beside_the_record(
        self, harness: Harness, tmp_path: Path
    ) -> None:
        """A ``code`` key writes ``<id>.c`` with that text."""
        query = {"id": "C-1", "tool": "decompile_function"}
        replies = [identity(), ok({"code": "int f(void);\n"}), identity()]
        module, _bridge = harness(replies)
        output = tmp_path / "out"
        run(module, write_plan(tmp_path, [query]), output)
        assert (output / "C-1.c").read_text() == "int f(void);\n", "expected the code"

    def test_an_empty_code_string_still_writes_an_empty_export(
        self, harness: Harness, tmp_path: Path
    ) -> None:
        """The key, not the text, decides."""
        query = {"id": "C-1", "tool": "decompile_function"}
        module, _bridge = harness([identity(), ok({"code": ""}), identity()])
        output = tmp_path / "out"
        run(module, write_plan(tmp_path, [query]), output)
        assert not (output / "C-1.c").read_text(), "expected an empty export"

    @pytest.mark.parametrize("data", [None, {}, {"name": "f"}])
    def test_no_export_is_written_without_code(
        self, harness: Harness, tmp_path: Path, data: dict[str, str] | None
    ) -> None:
        """Absent, empty and code-less data write the record alone."""
        query = {"id": "C-1", "tool": "get_function"}
        module, _bridge = harness([identity(), ok(data), identity()])
        output = tmp_path / "out"
        run(module, write_plan(tmp_path, [query]), output)
        assert [path.name for path in output.iterdir()] == ["C-1.json"], "records"

    def test_the_record_carries_the_query_identity_and_server(
        self, harness: Harness, tmp_path: Path
    ) -> None:
        """Key order and content of one written record."""
        query = {"id": "Q-1", "tool": "get_function", "arguments": {"a": 1}}
        module, _bridge = harness(sequence(query))
        output = tmp_path / "out"
        run(module, write_plan(tmp_path, [query]), output)
        written = json.loads((output / "Q-1.json").read_text())
        assert list(written) == [
            "captured_at_utc",
            "query",
            "program",
            "mcp_server",
            "result",
        ], "expected the five keys in order"
        assert written["query"] == query, "expected the query as planned"
        assert written["program"] == IDENTITY, "expected the identity"
        assert written["mcp_server"] == SERVER, "expected the server description"

    def test_an_empty_plan_checks_the_identity_twice_and_writes_nothing(
        self, harness: Harness, tmp_path: Path
    ) -> None:
        """The output directory is created and stays empty."""
        module, bridge = harness([identity(), identity()])
        output = tmp_path / "out"
        run(module, write_plan(tmp_path, []), output)
        assert not list(output.iterdir()), "expected no files"
        assert bridge.calls() == [("get_program_info", {})] * 2, "expected two checks"
