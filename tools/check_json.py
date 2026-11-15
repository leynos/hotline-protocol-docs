"""Check that every tracked JSON file is parseable and in canonical layout.

The canonical layout is ``json.dumps(value, indent=2, ensure_ascii=False)``
followed by one newline, with key order preserved. A duplicate key is a
failure, because parsing would silently drop one of the values. Files under
``evidence/`` are never rewritten; a listed few may be exempt at a recorded
SHA-256.

Run ``python3 tools/check_json.py --root .`` (add ``--write`` to rewrite the
authored files outside ``evidence/``). Exit codes: 0 success, 1 findings,
2 missing inputs.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

import cyclopts
from repo_files import repo_files
from tool_support import MissingInputError, Report, ToolError, invoke

EVIDENCE = "evidence/"
INDENT = 2
EXCEPTION_LINE = re.compile(r"([0-9a-f]{64}) {2}(\S.*)")

app = cyclopts.App(result_action="return_value")


class DuplicateKeyError(ToolError):
    """A JSON object repeats a key."""


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build an object from ``pairs``, refusing a repeated key.

    Parameters
    ----------
    pairs : list[tuple[str, object]]
        The key and value pairs of one JSON object, in document order.

    Returns
    -------
    dict[str, object]
        The object, with its keys in document order.

    Raises
    ------
    DuplicateKeyError
        If a key occurs twice.
    """
    seen: dict[str, object] = {}
    for key, value in pairs:
        if key in seen:
            message = f"duplicate key {key!r}"
            raise DuplicateKeyError(message)
        seen[key] = value
    return seen


def canonical(text: str) -> str:
    """Return the canonical rendering of the JSON document ``text``.

    Parameters
    ----------
    text : str
        A JSON document in any layout.

    Returns
    -------
    str
        The value re-rendered with two-space indentation, literal non-ASCII
        characters, preserved key order and one trailing newline.

    Invalid JSON raises ``json.JSONDecodeError`` and a repeated key raises
    :class:`DuplicateKeyError`.
    """
    value = json.loads(text, object_pairs_hook=_reject_duplicates)
    return json.dumps(value, indent=INDENT, ensure_ascii=False) + "\n"


def _read_exceptions(path: Path, report: Report) -> dict[str, str]:
    """Parse an exceptions file, reporting malformed lines.

    Parameters
    ----------
    path : pathlib.Path
        The exceptions file.
    report : Report
        Receives one failure per malformed line.

    Returns
    -------
    dict[str, str]
        The recorded SHA-256 for each exempt path.

    Raises
    ------
    MissingInputError
        If the file does not exist.
    """
    if not path.is_file():
        message = f"exceptions file {path} is absent"
        raise MissingInputError(message)
    entries: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = EXCEPTION_LINE.fullmatch(line)
        if match is None:
            report.failures.append(f"{path.name}: malformed exception line {line!r}")
        else:
            entries[match[2]] = match[1]
    return entries


def _check_exceptions(root: Path, entries: dict[str, str], report: Report) -> None:
    """Report exceptions that are misplaced, stale or no longer match."""
    for name, expected in entries.items():
        target = root / name
        if not name.startswith(EVIDENCE):
            report.failures.append(f"{name}: exception is outside evidence/")
        elif not target.is_file():
            report.failures.append(
                f"{name}: exception names a file that does not exist"
            )
        elif hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            report.failures.append(
                f"{name}: SHA-256 no longer matches its exception entry"
            )


def _check_file(root: Path, name: str, *, write: bool) -> str | None:
    """Check one file, rewriting it when ``write`` allows.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    name : str
        The file's POSIX path relative to ``root``.
    write : bool
        Whether a non-canonical authored file is rewritten.

    Returns
    -------
    str | None
        A failure message, or ``None`` when the file conforms.
    """
    target = root / name
    try:
        text = target.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        return f"{name}: not valid UTF-8"
    try:
        expected = canonical(text)
    except DuplicateKeyError as exc:
        return f"{name}: {exc}"
    except json.JSONDecodeError as exc:
        return f"{name}: syntax error: {exc}"
    if text == expected:
        return None
    if write and not name.startswith(EVIDENCE):
        target.write_bytes(expected.encode("utf-8"))
        return None
    return f"{name}: layout is not canonical (indent, order, escapes or newline)"


def check(root: Path, *, write: bool = False, exceptions: Path | None = None) -> Report:
    """Check every tracked JSON file below ``root``.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    write : bool
        Rewrite non-canonical files outside ``evidence/`` instead of failing.
    exceptions : pathlib.Path | None
        An optional file of ``<sha256>  <path>`` lines naming evidence files
        that are exempt while their hash is unchanged.

    Returns
    -------
    Report
        The number of files examined and one message per failure.

    A missing ``root`` or exceptions file raises ``MissingInputError``.
    """
    report = Report()
    entries = _read_exceptions(exceptions, report) if exceptions else {}
    _check_exceptions(root, entries, report)
    for path in repo_files(root, ".json"):
        name = path.as_posix()
        report.checked += 1
        if name in entries:
            continue
        failure = _check_file(root, name, write=write)
        if failure:
            report.failures.append(failure)
    return report


@app.default
def run(
    root: Path = Path(),
    *,
    write: bool = False,
    exceptions: Path | None = None,
) -> int:
    """Check the layout of every tracked JSON file.

    Parameters
    ----------
    root
        The repository root.
    write
        Rewrite non-canonical authored files (never those under evidence/).
    exceptions
        A file of ``<sha256>  <path>`` lines for exempt evidence files.

    Returns
    -------
    int
        0 when every file conforms, otherwise 1.
    """
    report = check(root, write=write, exceptions=exceptions)
    for failure in report.failures:
        sys.stdout.write(f"{failure}\n")
    sys.stdout.write(f"{report.checked} files, {len(report.failures)} failures\n")
    return report.exit_code


def main(argv: list[str] | None = None) -> int:
    """Run the command line and return the process exit code.

    Parameters
    ----------
    argv : list[str] | None
        Command-line tokens, or ``None`` to read ``sys.argv``.

    Returns
    -------
    int
        The exit code: 0, 1 or 2.
    """
    return invoke(app, argv)


if __name__ == "__main__":
    sys.exit(main())
