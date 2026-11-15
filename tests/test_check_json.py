"""Tests for the JSON layout gate (obligation INV-JSON)."""

import hashlib
import json
import typing as typ

import check_json
import pytest
from hypothesis import given
from hypothesis import strategies as st
from tool_support import EXIT_FINDINGS, EXIT_MISSING, EXIT_OK

if typ.TYPE_CHECKING:
    from pathlib import Path

    from tree_helpers import TreeBuilder

FIXED = '{\n  "a": 1\n}\n'
GOOD = '{\n  "b": 1,\n  "a": [\n    1,\n    2\n  ]\n}\n'

FAULTS: list[tuple[str, str | bytes, str]] = [
    ("syntax.json", '{"a": }\n', "syntax"),
    ("dup.json", '{\n  "a": 1,\n  "a": 2\n}\n', "duplicate key"),
    ("tab.json", '{\n\t"a": 1\n}\n', "layout"),
    ("nonl.json", '{\n  "a": 1\n}', "layout"),
    ("escaped.json", '{\n  "a": "\\u00e9"\n}\n', "layout"),
    ("trailing.json", '{\n  "a": 1 \n}\n', "layout"),
    ("badbytes.json", b'{"a": "\xff"}\n', "UTF-8"),
]


def sha256(text: str) -> str:
    """Return the SHA-256 of ``text`` encoded as UTF-8.

    Returns
    -------
    str
        The hexadecimal digest.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_good_file_passes_with_key_order_preserved(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A canonical file with unsorted keys is accepted and counted."""
    make_tree(tmp_path, {"good.json": GOOD, "sub/utf.json": '{\n  "é": "ß"\n}\n'})
    report = check_json.check(tmp_path)
    assert not report.failures, "expected not report.failures"
    assert report.checked == 2, "expected report.checked == 2"


@pytest.mark.parametrize("fault", FAULTS)
def test_each_layout_fault_is_rejected_by_name(
    tmp_path: Path,
    make_tree: TreeBuilder,
    fault: tuple[str, str | bytes, str],
) -> None:
    """Every enumerated fault fails, and the message names the file."""
    name, content, word = fault
    make_tree(tmp_path, {name: content, "good.json": GOOD})
    report = check_json.check(tmp_path)
    assert len(report.failures) == 1, "expected len(report.failures) == 1"
    assert name in report.failures[0], "expected name in report.failures[0]"
    assert word in report.failures[0], "expected word in report.failures[0]"


def test_write_rewrites_outside_evidence_only(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """``write`` fixes authored files and leaves evidence bytes alone."""
    ugly = '{"a":1}'
    make_tree(tmp_path, {"authored.json": ugly, "evidence/e.json": ugly})
    report = check_json.check(tmp_path, write=True)
    assert (tmp_path / "authored.json").read_text() == FIXED, (
        "authored file not rewritten"
    )
    assert (tmp_path / "evidence/e.json").read_text() == ugly, (
        "expected (tmp_path / 'evidence/e.json').read_text() == ugly"
    )
    assert len(report.failures) == 1, "expected len(report.failures) == 1"
    assert "evidence/e.json" in report.failures[0], (
        "expected 'evidence/e.json' in report.failures[0]"
    )


def test_write_never_rewrites_a_duplicate_key(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Rewriting would silently drop a value, so the file is left failing."""
    dup = '{"a": 1, "a": 2}'
    make_tree(tmp_path, {"dup.json": dup})
    report = check_json.check(tmp_path, write=True)
    assert (tmp_path / "dup.json").read_text() == dup, (
        "expected (tmp_path / 'dup.json').read_text() == dup"
    )
    assert "duplicate key" in report.failures[0], (
        "expected 'duplicate key' in report.failures[0]"
    )


def test_exempt_evidence_file_passes_while_its_hash_matches(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A listed evidence file is exempt only at its recorded hash."""
    ugly = '{"a":1}'
    make_tree(
        tmp_path,
        {
            "evidence/e.json": ugly,
            "exceptions.txt": f"# reason\n{sha256(ugly)}  evidence/e.json\n",
        },
    )
    exceptions = tmp_path / "exceptions.txt"
    assert not check_json.check(tmp_path, exceptions=exceptions).failures, (
        "expected not check_json.check(tmp_path, exceptions=exceptions).fai..."
    )
    (tmp_path / "evidence/e.json").write_text('{"a":2}')
    report = check_json.check(tmp_path, exceptions=exceptions)
    assert len(report.failures) == 1, "expected len(report.failures) == 1"
    assert "evidence/e.json" in report.failures[0], (
        "expected 'evidence/e.json' in report.failures[0]"
    )
    assert "no longer matches" in report.failures[0], (
        "expected 'no longer matches' in report.failures[0]"
    )


@pytest.mark.parametrize(
    ("entry", "word"),
    [
        ("authored.json", "outside evidence"),
        ("evidence/gone.json", "does not exist"),
    ],
)
def test_bad_exception_entries_are_failures(
    tmp_path: Path, make_tree: TreeBuilder, entry: str, word: str
) -> None:
    """Exceptions may only name existing files under ``evidence/``."""
    make_tree(
        tmp_path,
        {"authored.json": GOOD, "exceptions.txt": f"{sha256(GOOD)}  {entry}\n"},
    )
    report = check_json.check(tmp_path, exceptions=tmp_path / "exceptions.txt")
    assert any(entry in f and word in f for f in report.failures), (
        "expected any((entry in f and word in f for f in report.failures))"
    )


def test_malformed_exception_line_is_a_failure(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A line that is not ``<sha256>  <path>`` is reported, not ignored."""
    make_tree(tmp_path, {"exceptions.txt": "nonsense\n"})
    report = check_json.check(tmp_path, exceptions=tmp_path / "exceptions.txt")
    assert any("nonsense" in f for f in report.failures), (
        "expected any(('nonsense' in f for f in report.failures))"
    )


def test_missing_exceptions_file_is_a_missing_input(tmp_path: Path) -> None:
    """A named exceptions file that is absent is exit code 2."""
    code = check_json.main([
        "--root",
        str(tmp_path),
        "--exceptions",
        str(tmp_path / "none.txt"),
    ])
    assert code == EXIT_MISSING, "expected code == EXIT_MISSING"


def test_main_exit_codes_and_summary(
    tmp_path: Path,
    make_tree: TreeBuilder,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The CLI prints the count line and exits 0 or 1."""
    make_tree(tmp_path, {"good.json": GOOD})
    assert check_json.main(["--root", str(tmp_path)]) == EXIT_OK, (
        "expected check_json.main(['--root', str(tmp_path)]) == EXIT_OK"
    )
    assert "1 files, 0 failures" in capsys.readouterr().out, (
        "expected '1 files, 0 failures' in capsys.readouterr().out"
    )
    make_tree(tmp_path, {"bad.json": "{"})
    assert check_json.main(["--root", str(tmp_path)]) == EXIT_FINDINGS, (
        "expected check_json.main(['--root', str(tmp_path)]) == EXIT_FINDINGS"
    )
    assert "2 files, 1 failures" in capsys.readouterr().out, (
        "expected '2 files, 1 failures' in capsys.readouterr().out"
    )
    assert check_json.main(["--root", str(tmp_path / "absent")]) == EXIT_MISSING, (
        "expected check_json.main(['--root', str(tmp_path / 'absent')]) == ..."
    )


json_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(),
    lambda children: (
        st.lists(children, max_size=4)
        | st.dictionaries(st.text(), children, max_size=4)
    ),
    max_leaves=12,
)


@given(json_values)
def test_canonical_is_idempotent_and_accepted_by_the_gate(value: object) -> None:
    """Canonical rendering is a fixed point and preserves the parsed value."""
    once = check_json.canonical(json.dumps(value))
    assert check_json.canonical(once) == once, (
        "expected check_json.canonical(once) == once"
    )
    assert json.loads(once) == value, "expected json.loads(once) == value"
    assert once.endswith("\n"), "expected once.endswith('n')"
