"""Prove that every pinned script is free to change (decision D29).

A script that a verifier compares with a recorded hash cannot change without
turning that verifier red. Once the comparison reads the script at its pinned
commit instead, a behaviour-neutral edit must leave every golden untouched.
This tool makes that edit, a comment appended to each script named in
``scripts/pinned-sources.json``, compares the goldens, and restores the bytes
whatever happens.

Run ``python3 tools/pin_experiment.py run --root . --mothra ../mothra``. Exit
codes: 0 for ``0 differences``, 1 for differences, 2 for missing inputs.
"""

import contextlib
import json
import sys
import typing as typ
from pathlib import Path

import capture_goldens
import cyclopts
from tool_support import MissingInputError, invoke

if typ.TYPE_CHECKING:
    import collections.abc as cabc

RECORD = "scripts/pinned-sources.json"
COMMENT = b"# behaviour-neutral edit appended by tools/pin_experiment.py\n"

app = cyclopts.App(result_action="return_value")


@contextlib.contextmanager
def perturbed(root: Path, names: cabc.Sequence[str]) -> cabc.Iterator[None]:
    """Append a comment to each script below ``scripts/`` and restore it after.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    names : collections.abc.Sequence[str]
        File names under ``scripts/``.

    Yields
    ------
    None
        While every named script carries the comment.
    """
    paths = [root / "scripts" / name for name in names]
    saved = {path: path.read_bytes() for path in paths}
    try:
        for path, original in saved.items():
            separator = b"" if original.endswith(b"\n") else b"\n"
            path.write_bytes(original + separator + COMMENT)
        yield
    finally:
        for path, original in saved.items():
            path.write_bytes(original)


def pinned_names(root: Path) -> list[str]:
    """Read the names of the pinned scripts from the record.

    Returns
    -------
    list[str]
        File names under ``scripts/``.

    Raises
    ------
    MissingInputError
        If the record is absent.
    """
    path = root / RECORD
    if not path.is_file():
        message = f"{path} does not exist"
        raise MissingInputError(message)
    sources = json.loads(path.read_text(encoding="utf-8"))["sources"]
    return [Path(entry["path"]).name for entry in sources]


@app.command(name="run")
def run_experiment(root: Path = Path(), *, mothra: Path | None = None) -> int:
    """Compare every golden while each pinned script has an extra comment.

    Parameters
    ----------
    root
        The repository root.
    mothra
        The mothra checkout (default: ``MOTHRA_ROOT``).

    Returns
    -------
    int
        0 for ``0 differences``, otherwise 1.
    """
    names = pinned_names(root)
    sys.stdout.write(f"appending a comment to {len(names)} pinned scripts\n")
    with perturbed(root, names):
        return capture_goldens.run_compare(root, mothra=mothra)


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
