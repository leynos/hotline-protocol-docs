"""Tests for the INV-SCRIPT golden tooling and the committed goldens.

The first half exercises the capture and compare logic on synthetic trees. The
second half asserts the shape of ``tests/goldens/``. Neither half runs the
inherited legacy suite, which takes about ten minutes; ``make goldens-check``
does that.
"""

import json
import re
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # the tests run the runner helper
import sys
import tempfile
import typing as typ
from pathlib import Path

import capture_goldens as cg
import golden_model as gm
import golden_planners as gp
import golden_recipes as gr
import golden_tests as gt
import pytest

if typ.TYPE_CHECKING:
    from tree_helpers import TreeBuilder

REPO = Path(__file__).resolve().parents[1]
HEX = re.compile(r"[0-9a-f]{64}")
MAKEFILE = """\
evidence-verify:
\t@echo ok one
\t@echo "took 1.25s in $$PWD"
evidence-verify-known-red:
\t@echo bad; exit 3
test-legacy:
\tpython3 -m unittest discover -s scripts -p 'test_*.py'
"""
TESTS = """\
import unittest


class Sample(unittest.TestCase):
    def test_pass(self):
        pass

    def test_fail(self):
        self.assertEqual(1, 2)

    def test_error(self):
        raise ValueError("boom")

    @unittest.skip("not today")
    def test_skip(self):
        pass

    def test_subtests(self):
        for number in (1, 2):
            with self.subTest(number=number):
                self.assertEqual(number, 1)
"""


def normaliser(root: Path, scratch: Path) -> gm.Normaliser:
    """Build a normaliser for a synthetic tree.

    Returns
    -------
    golden_model.Normaliser
        One that knows no script digests.
    """
    return gm.Normaliser(root, scratch, {})


@pytest.fixture
def tree(tmp_path: Path, make_tree: TreeBuilder) -> Path:
    """Create a synthetic repository with a Makefile and one test module.

    Returns
    -------
    pathlib.Path
        Its root.
    """
    root = tmp_path / "repo"
    make_tree(root, {"Makefile": MAKEFILE, "scripts/test_sample.py": TESTS})
    return root


def test_canonical_json_layout() -> None:
    """Goldens are indented, keep non-ASCII text and end with a newline."""
    text = gm.canonical_json({"b": "é", "a": [1]})
    assert text.endswith("}\n"), text
    assert text.startswith('{\n  "b": "é",\n'), text
    assert json.loads(text) == {"a": [1], "b": "é"}, text


def test_text_normalisation_removes_only_unstable_parts(tmp_path: Path) -> None:
    """The checkout path, mktemp names and durations go; everything else stays."""
    root, scratch = tmp_path / "checkout", tmp_path / "scratch"
    norm = normaliser(root, scratch)
    raw = (
        f"{root}/evidence/x.json Ran 3 tests in 0.123s {scratch}/a "
        f"{Path(tempfile.gettempdir()) / 'tmp.AbC123xyz9' / 'hotline-protocol-docs'} "
        "digest " + "ab" * 32 + " addr 10.0.2.2 token 48545846\n"
    )
    text = norm.text(raw.encode())
    assert text.startswith("<ROOT>/evidence/x.json Ran 3 tests in <T>s <SCRATCH>/a "), (
        "text.startswith('<ROOT>/evidence/x.json Ran 3 tests in <T>s <SCRATCH>/a ')"
    )
    assert "digest " + "ab" * 32 + " addr 10.0.2.2 token 48545846" in text, (
        "'digest ' + 'ab' * 32 + ' addr 10.0.2.2 token 48545846' in text"
    )
    assert str(root) not in text, "str(root) not in text"
    assert str(scratch) not in text, "str(scratch) not in text"


def test_plan_normalisation_names_script_digests(tmp_path: Path) -> None:
    """A digest of a script becomes its name; other digests are untouched."""
    own, other = "a1" * 32, "b2" * 32
    norm = gm.Normaliser(tmp_path, tmp_path, {own: "planner.py"})
    content, names = norm.plan(f'{{"x": "{own}", "y": "{other}"}}'.encode())
    assert names == ["planner.py"], names
    assert content == f'{{"x": "{{scripts/planner.py}}", "y": "{other}"}}'.encode(), (
        content
    )


def test_script_digests_map_digest_to_name(
    make_tree: TreeBuilder, tmp_path: Path
) -> None:
    """Each ``scripts/*.py`` file is known by the digest of its bytes."""
    make_tree(tmp_path, {"scripts/a.py": "print(1)\n", "scripts/b.txt": "x"})
    digest = gm.sha256_hex(b"print(1)\n")
    assert gm.script_digests(tmp_path) == {digest: "a.py"}, gm.script_digests(tmp_path)


def test_select_filters_by_substring() -> None:
    """No filter selects all keys; a filter selects keys that contain it."""
    keys = ["verify_native_board.py x", "native_board_cases.py", "test_other"]
    assert gm.select(keys, []) == keys, gm.select(keys, [])
    assert gm.select(keys, ["board"]) == keys[:2], gm.select(keys, ["board"])
    assert gm.select(keys, ["board", "other"]) == keys, gm.select(
        keys, ["board", "other"]
    )


def test_differences_report_changed_missing_and_unexpected() -> None:
    """Each kind of drift is reported once, and a filter narrows the report."""
    golden = {"a": {"exit": 0}, "b": {"exit": 0}, "c": {"exit": 0}}
    fresh = {"a": {"exit": 1}, "c": {"exit": 0}, "d": {"exit": 0}}
    lines = gm.differences(golden, fresh, [])
    assert lines == [
        "changed: a: exit: 0 -> 1",
        "missing: b",
        "unexpected: d",
    ], lines
    assert gm.differences(golden, fresh, ["a"]) == ["changed: a: exit: 0 -> 1"], (
        gm.differences(golden, fresh, ["a"])
    )


def test_recipe_lines_come_from_make(tree: Path) -> None:
    """The recipe list is read from the Makefile, not held in the tool."""
    lines = gr.recipe_lines(tree, "evidence-verify", None)
    assert lines == ["echo ok one", 'echo "took 1.25s in $PWD"'], lines
    with pytest.raises(RuntimeError, match=r"no recipe"):
        gr.recipe_lines(tree, "absent-target", None)


def test_capture_recipes_records_exit_code_and_normalised_output(tree: Path) -> None:
    """A recipe's verdict and output digest ignore the checkout path and timing."""
    run = gr.RecipeRun(tree, None, normaliser(tree, tree.parent))
    records = gr.capture_recipes(run, [])
    assert [r["exit_code"] for r in records.values()] == [0, 0, 3], [
        r["exit_code"] for r in records.values()
    ]
    timed = records['evidence-verify: echo "took 1.25s in $PWD"']
    assert timed["last_line"] == "took <T>s in <ROOT>", timed["last_line"]
    expected = gm.sha256_hex(b"took <T>s in <ROOT>\n")
    assert timed["output_sha256"] == expected, timed["output_sha256"]
    narrowed = gr.capture_recipes(run, ["known-red"])
    assert list(narrowed) == ["evidence-verify-known-red: echo bad; exit 3"], list(
        narrowed
    )


def test_unittest_runner_records_each_outcome(tree: Path) -> None:
    """Pass, fail, error, skip and a failing subtest each get one outcome."""
    out = tree / "out.json"
    subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv, no shell
        [sys.executable, str(gt.RUNNER), str(out), "scripts", "test_*.py"],
        cwd=tree,
        check=True,
        capture_output=True,
    )
    result = json.loads(out.read_text(encoding="utf-8"))
    outcomes = {key.split(".")[-1]: value["outcome"] for key, value in result.items()}
    expected = {
        "test_pass": "ok",
        "test_fail": "fail",
        "test_error": "error",
        "test_skip": "skipped",
        "test_subtests": "fail",
    }
    assert outcomes == expected, outcomes
    detail = result["test_sample.Sample.test_error"]["detail"]
    assert detail == "ValueError: boom", detail


def test_discovery_arguments_come_from_the_makefile(tree: Path) -> None:
    """The start directory and pattern are read from the test-legacy recipe."""
    assert gt.discovery(tree, None) == ("scripts", "test_*.py"), gt.discovery(
        tree, None
    )


def test_capture_tests_honours_a_filter(tree: Path) -> None:
    """Only tests whose id contains the filter run."""
    run = gr.RecipeRun(tree, None, normaliser(tree, tree.parent))
    records = gt.capture_tests(run, ["test_pass"])
    assert list(records) == ["test_sample.Sample.test_pass"], list(records)


def write_planner(root: Path, body: str) -> gp.PlannerRun:
    """Create a one-file planner and a run that can execute it.

    Returns
    -------
    golden_planners.PlannerRun
        A run rooted at ``root``.
    """
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "plan.py").write_text(body, encoding="utf-8")
    scratch = root.parent / "scratch"
    scratch.mkdir()
    digests = gm.script_digests(root)
    return gp.PlannerRun(root, scratch, gm.Normaliser(root, scratch, digests))


def test_planner_record_holds_digest_and_size_of_each_file(tmp_path: Path) -> None:
    """Emitted files are recorded by digest and size, in sorted name order."""
    body = (
        "import pathlib,sys,hashlib\n"
        "out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True)\n"
        "(out/'plan.json').write_text('{}\\n')\n"
        "me=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()\n"
        "(out/'hashes.json').write_text(me)\n"
    )
    run = write_planner(tmp_path / "repo", body)
    record = gp._execute(run, ["scripts/plan.py", "{out}"], "plan")
    assert record["status"] == "emitted", record["status"]
    files = record["files"]
    assert files["plan.json"]["sha256"] == gm.sha256_hex(b"{}\n"), files["plan.json"][
        "sha256"
    ]
    assert files["plan.json"]["size"] == 3, files["plan.json"]["size"]
    assert files["hashes.json"]["embeds_script_digests"] == ["plan.py"], files[
        "hashes.json"
    ]["embeds_script_digests"]
    assert files["hashes.json"]["sha256"] == gm.sha256_hex(b"{scripts/plan.py}"), files[
        "hashes.json"
    ]["sha256"]


def test_planner_failure_is_recorded_not_hidden(tmp_path: Path) -> None:
    """A planner that exits non-zero is a failed record, never an emitted one."""
    run = write_planner(tmp_path / "repo", "raise SystemExit(4)\n")
    record = gp._execute(run, ["scripts/plan.py", "{out}"], "plan")
    assert record["status"] == "failed", record["status"]
    assert record["exit_code"] == 4, record["exit_code"]


def test_coverage_refuses_a_planner_with_no_offline_route(
    make_tree: TreeBuilder, tmp_path: Path
) -> None:
    """A new ``*_cases.py`` file must be assigned a way to emit plans."""
    make_tree(
        tmp_path,
        {
            "scripts/prepare_native_cases.py": "import native_a_cases\n",
            "scripts/native_a_cases.py": "",
            "scripts/native_b_cases.py": "",
        },
    )
    with pytest.raises(RuntimeError, match=r"native_b_cases\.py"):
        gp.coverage(tmp_path)


def test_compare_reports_differences_and_exits_non_zero(
    tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Capture then compare is clean; an altered recipe is counted."""
    root = ["--root", str(tree), "--oracle", "verifiers"]
    captured = cg.main(["capture", *root])
    clean = cg.main(["compare", *root])
    clean_output = capsys.readouterr().out
    assert (captured, clean) == (0, 0), clean_output
    assert clean_output.endswith("0 differences\n"), clean_output
    makefile = tree / "Makefile"
    makefile.write_text(makefile.read_text().replace("exit 3", "exit 4"))
    cg.main(["capture", *root])
    makefile.write_text(makefile.read_text().replace("exit 4", "exit 5"))
    capsys.readouterr()
    drifted = cg.main(["compare", *root])
    output = capsys.readouterr().out
    assert drifted == 1, output
    missing = "missing: evidence-verify-known-red: echo bad; exit 4"
    assert missing in output, output
    assert output.endswith("2 differences\n"), output
    narrowed = cg.main(["compare", *root, "--filter", "ok one"])
    assert narrowed == 0, capsys.readouterr().out


def test_missing_withheld_file_stops_the_run(tree: Path) -> None:
    """The verifiers and tests refuse to run without the withheld files."""
    data = b"withheld bytes"
    entry = {"path": "evidence/w.bin", "sha256": gm.sha256_hex(data)}
    manifest = tree / "evidence" / "withheld.json"
    manifest.parent.mkdir()
    manifest.write_text(json.dumps({"files": [entry]}), encoding="utf-8")
    argv = ["compare", "--root", str(tree), "--oracle", "verifiers"]
    assert cg.main(argv) == 2, "a run without the withheld file must exit 2"
    (tree / "evidence" / "w.bin").write_bytes(data)
    cg.require_withheld(tree, ["verifiers"])
    cg.require_withheld(tree, ["planners"])


def test_unknown_oracle_is_a_usage_error(tree: Path) -> None:
    """A misspelt oracle name exits 2 instead of silently doing nothing."""
    argv = ["compare", "--root", str(tree), "--oracle", "verifier"]
    assert cg.main(argv) == 2, "an unknown oracle must exit 2"
