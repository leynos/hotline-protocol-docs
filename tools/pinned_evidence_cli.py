"""Verify or rebuild ``scripts/pinned-evidence.json`` from the command line.

Run ``python3 tools/pinned_evidence_cli.py check --root .`` to verify that every
evidence ``.py`` file is pinned and differs from its capture commit by docstrings
at most. ``generate`` rebuilds the record from the history of a repository whose
evidence files are still as imported. Exit codes: 0 success, 1 findings, 2
missing inputs. See :mod:`pinned_evidence`.
"""

import json
import sys
from pathlib import Path

import cyclopts
from pinned_evidence import (
    RECORD_RELATIVE,
    PinRecord,
    PinRecordError,
    check,
    load_record,
    read_live,
    run_git,
    tracked_evidence_python,
)
from tool_support import EXIT_FINDINGS, EXIT_OK, invoke

SCHEMA_VERSION = 1
INDENT = 2

app = cyclopts.App(result_action="return_value")


def generate(root: Path) -> dict[str, str]:
    """Find the commit that added each tracked evidence ``.py`` file.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.

    Returns
    -------
    dict[str, str]
        The adding commit of each file, whose bytes there equal the file's
        bytes in the working tree.

    Raises
    ------
    PinRecordError
        If a file has no adding commit or was edited since.
    """
    log = run_git(
        root,
        "log",
        "--reverse",
        "--diff-filter=A",
        "--name-only",
        "--format=%x00%H",
        "--",
        ":(glob)evidence/**/*.py",
    )
    added: dict[str, str] = {}
    for chunk in log.stdout.decode().split("\0")[1:]:
        commit, *names = chunk.split("\n")
        for name in filter(None, names):
            added.setdefault(name, commit)
    pins: dict[str, str] = {}
    for path in tracked_evidence_python(root):
        if path not in added:
            message = f"no commit added {path}"
            raise PinRecordError(message)
        pins[path] = added[path]
    record = PinRecord(root, pins)
    for path, commit in pins.items():
        if record.read(path) != read_live(root / path):
            message = f"{path} was edited after commit {commit}"
            raise PinRecordError(message)
    return pins


@app.command(name="check")
def run_check(root: Path = Path()) -> int:
    """Verify that every evidence ``.py`` file is pinned and changed only by docstrings.

    Parameters
    ----------
    root
        The repository root.

    Returns
    -------
    int
        0 when every pin holds, otherwise 1.
    """
    failures = check(root)
    sys.stdout.write("".join(f"{line}\n" for line in failures))
    count = len(load_record(root).pins)
    sys.stdout.write(f"{count} pinned evidence files, {len(failures)} failures\n")
    return EXIT_FINDINGS if failures else EXIT_OK


@app.command(name="generate")
def run_generate(root: Path = Path()) -> int:
    """Write ``scripts/pinned-evidence.json`` from the history.

    Parameters
    ----------
    root
        The repository root, whose evidence files are still as imported.

    Returns
    -------
    int
        0 after the record is written.
    """
    pins = generate(root)
    document = {
        "schema_version": SCHEMA_VERSION,
        "files": [{"path": path, "commit": commit} for path, commit in pins.items()],
    }
    text = json.dumps(document, indent=INDENT, ensure_ascii=False) + "\n"
    (root / RECORD_RELATIVE).write_text(text, encoding="utf-8")
    sys.stdout.write(f"{len(pins)} evidence files pinned\n")
    return EXIT_OK


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
