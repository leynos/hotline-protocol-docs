"""A Python traceback is reduced to its exception line before it is hashed.

The verifier golden hashes the normalised output of a recipe line. A failing
verifier prints a traceback whose file names, line numbers, source lines and
frame count change whenever the script is restructured, though the verdict does
not. The normaliser therefore keeps the final exception line of each traceback
and a marker that a traceback was present, and nothing else of it.
"""

import typing as typ

import golden_model as gm
import pytest

if typ.TYPE_CHECKING:
    from pathlib import Path

MARKER = "<traceback>"


def reduce(raw: str, tmp_path: Path) -> str:
    """Normalise captured output the way the verifier oracle does.

    Returns
    -------
    str
        The normalised text.
    """
    return gm.Normaliser(tmp_path / "root", tmp_path / "scratch", {}).text(raw.encode())


def traceback_of(frames: list[tuple[str, int, str]], last: str) -> str:
    """Build the text of a traceback from frames and an exception line.

    Returns
    -------
    str
        A traceback in the layout that CPython prints.
    """
    lines = ["Traceback (most recent call last):"]
    for name, number, source in frames:
        lines.extend([f'  File "{name}", line {number}, in run', f"    {source}"])
    return "\n".join([*lines, last, ""])


FRAMES_A = [("scripts/a.py", 10, "main()"), ("scripts/a.py", 20, "check(x)")]
FRAMES_B = [("scripts/b.py", 7, "go()")]


def test_restructured_traceback_compares_equal(tmp_path: Path) -> None:
    """Other files, lines, sources and frame counts leave the text unchanged."""
    last = "ValueError: capture gate source identity"
    one = reduce(traceback_of(FRAMES_A, last), tmp_path)
    two = reduce(traceback_of(FRAMES_B, last), tmp_path)
    assert one == two, f"{one!r} != {two!r}"
    assert one == f"{MARKER}\n{last}\n", one


@pytest.mark.parametrize(
    "other",
    ["ValueError: another message", "KeyError: 'capture gate source identity'"],
)
def test_different_exception_differs(other: str, tmp_path: Path) -> None:
    """A different type or message gives different text."""
    base = reduce(
        traceback_of(FRAMES_A, "ValueError: capture gate source identity"), tmp_path
    )
    changed = reduce(traceback_of(FRAMES_A, other), tmp_path)
    assert base != changed, f"{base!r} == {changed!r}"


def test_output_without_traceback_is_unchanged(tmp_path: Path) -> None:
    """Plain output, even one that mentions a traceback, is not touched."""
    raw = 'ok\n  File "x.py", line 3\nTraceback is a word here\nValueError: no\n'
    assert reduce(raw, tmp_path) == raw, "plain output changed"


def test_surrounding_output_is_kept(tmp_path: Path) -> None:
    """Lines before and after a traceback stay exactly as they were."""
    body = traceback_of(FRAMES_A, "OSError: gone")
    text = reduce(f"before\n  indented before\n{body}after\n", tmp_path)
    assert text == f"before\n  indented before\n{MARKER}\nOSError: gone\nafter\n", text


def test_each_chained_traceback_is_reduced(tmp_path: Path) -> None:
    """Chained exceptions give one marker each, with the connector kept."""
    link = "\nDuring handling of the above exception, another exception occurred:\n\n"
    raw = traceback_of(FRAMES_A, "KeyError: 'k'") + link
    raw += traceback_of(FRAMES_B, "ValueError: v")
    text = reduce(raw, tmp_path)
    assert text.count(MARKER) == 2, text
    assert text.endswith(f"{MARKER}\nValueError: v\n"), text
    assert "During handling" in text, text


def test_traceback_at_the_end_without_a_newline(tmp_path: Path) -> None:
    """The last line need not end with a newline."""
    raw = traceback_of(FRAMES_A, "RuntimeError: x").rstrip("\n")
    assert reduce(raw, tmp_path) == f"{MARKER}\nRuntimeError: x", "tail changed"
