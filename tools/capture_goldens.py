"""Capture and compare the INV-SCRIPT goldens of the inherited scripts.

``capture`` records what the scripts under ``scripts/`` do today, in three
oracles, below ``tests/goldens/``:

* ``verifiers``: the exit code and a digest of the normalised output of every
  recipe line of the Makefile targets ``evidence-verify`` and
  ``evidence-verify-known-red``;
* ``planners``: the bytes of every plan that each ``*_cases.py`` planner emits
  offline;
* ``tests``: the name and outcome of every inherited ``unittest``.

``compare`` re-runs the oracles and prints ``N differences``; it exits 1 when
N is above zero. ``--filter TEXT`` (repeatable) limits a run to the records
whose key contains TEXT, so one script family can be compared alone. A key is
a recipe line, a planner file and case, or a test id.

Run ``python3 tools/capture_goldens.py compare --mothra ../mothra``. Exit
codes: 0 success, 1 differences, 2 missing inputs.
"""

import dataclasses as dc
import json
import os
import sys
import tempfile
import typing as typ
from pathlib import Path

import cyclopts
import golden_model as gm
import golden_planners as gp
import golden_recipes as gr
import golden_tests as gt
from tool_support import EXIT_FINDINGS, EXIT_OK, MissingInputError, invoke

if typ.TYPE_CHECKING:
    import collections.abc as cabc

ORACLES = ("verifiers", "planners", "tests")
app = cyclopts.App(result_action="return_value")


@dc.dataclass(frozen=True, slots=True)
class Request:
    """What a capture or compare run covers.

    Attributes
    ----------
    root : pathlib.Path
        The repository root.
    mothra : pathlib.Path | None
        The mothra checkout that two verifiers read.
    oracles : tuple[str, ...]
        The oracles to run, from ``ORACLES``.
    filters : tuple[str, ...]
        Record-key substrings; empty selects every record.
    """

    root: Path
    mothra: Path | None
    oracles: tuple[str, ...] = ORACLES
    filters: tuple[str, ...] = ()


def capture_oracle(request: Request, oracle: str) -> dict[str, typ.Any]:
    """Run one oracle and build its golden document.

    Returns
    -------
    dict[str, typing.Any]
        The document, with its records under ``records``.
    """
    root = request.root.resolve()
    with tempfile.TemporaryDirectory(prefix="goldens-") as name:
        scratch = Path(name)
        norm = gm.Normaliser(root, scratch, gm.script_digests(root))
        recipes = gr.RecipeRun(root, request.mothra, norm)
        document: dict[str, typ.Any] = {"schema_version": gm.SCHEMA_VERSION}
        match oracle:
            case "verifiers":
                document["targets"] = list(gr.TARGETS)
                document["records"] = gr.capture_recipes(recipes, request.filters)
            case "planners":
                run = gp.PlannerRun(root, scratch, norm)
                document["coverage"] = gp.coverage(root)
                document["records"] = gp.capture_planners(run, request.filters)
            case _:
                document["records"] = gt.capture_tests(recipes, request.filters)
    return document


def count_differences(request: Request, oracle: str) -> list[str]:
    """Compare one oracle's fresh run with its committed golden.

    Returns
    -------
    list[str]
        The differences, each prefixed with the oracle's name.
    """
    golden = gm.read_golden(request.root, f"{oracle}.json")
    fresh = capture_oracle(request, oracle)
    lines = gm.differences(golden["records"], fresh["records"], request.filters)
    unfiltered = oracle == "planners" and not request.filters
    if unfiltered and golden["coverage"] != fresh["coverage"]:
        lines.append("changed: planner coverage")
    return [f"{oracle}: {line}" for line in lines]


def require_withheld(root: Path, oracles: cabc.Sequence[str]) -> None:
    """Refuse to run the verifiers or tests without the withheld files.

    Eight evidence files are withheld from Git. Several verifiers and tests
    read them, so a run without them records failures that the goldens do not
    hold. The planners never read them.

    Raises
    ------
    MissingInputError
        If a withheld file is absent or differs from the manifest.
    """
    manifest = root / "evidence" / "withheld.json"
    if not manifest.is_file() or not {"verifiers", "tests"} & set(oracles):
        return
    entries = json.loads(manifest.read_text(encoding="utf-8"))["files"]
    bad = [
        entry["path"]
        for entry in entries
        if not (root / entry["path"]).is_file()
        or gm.sha256_hex((root / entry["path"]).read_bytes()) != entry["sha256"]
    ]
    if bad:
        message = f"withheld files absent or changed, copy them first: {bad}"
        raise MissingInputError(message)


def _mothra(given: Path | None) -> Path | None:
    """Resolve the mothra checkout from the option or ``MOTHRA_ROOT``.

    Returns
    -------
    pathlib.Path | None
        The checkout, or ``None`` when neither is set.

    Raises
    ------
    MissingInputError
        If a checkout is named but is not a directory.
    """
    chosen = given or (
        Path(os.environ["MOTHRA_ROOT"]) if "MOTHRA_ROOT" in os.environ else None
    )
    if chosen is not None and not chosen.is_dir():
        message = f"mothra checkout {chosen} is not a directory"
        raise MissingInputError(message)
    return chosen


def _oracles(only: cabc.Sequence[str]) -> tuple[str, ...]:
    """Validate an oracle selection.

    Returns
    -------
    tuple[str, ...]
        The chosen oracles, or all three when none is named.

    Raises
    ------
    MissingInputError
        If a name is not one of the three oracles.
    """
    unknown = [name for name in only if name not in ORACLES]
    if unknown:
        message = f"unknown oracle {unknown}; choose from {', '.join(ORACLES)}"
        raise MissingInputError(message)
    return tuple(only) or ORACLES


@app.command(name="capture")
def run_capture(
    root: Path = Path(),
    *,
    mothra: Path | None = None,
    oracle: list[str] | None = None,
) -> int:
    """Record the goldens below ``tests/goldens/``.

    Parameters
    ----------
    root
        The repository root.
    mothra
        The mothra checkout (default: ``MOTHRA_ROOT``).
    oracle
        Oracles to record: verifiers, planners or tests (default: all).

    Returns
    -------
    int
        0 once the goldens are written.
    """
    request = Request(root, _mothra(mothra), _oracles(oracle or []))
    require_withheld(root, request.oracles)
    for name in request.oracles:
        document = capture_oracle(request, name)
        path = gm.write_golden(root, f"{name}.json", document)
        sys.stdout.write(f"{name}: {len(document['records'])} records -> {path}\n")
    return EXIT_OK


@app.command(name="compare")
def run_compare(
    root: Path = Path(),
    *,
    mothra: Path | None = None,
    oracle: list[str] | None = None,
    filter: list[str] | None = None,  # ruff: ignore[builtin-argument-shadowing]  # the option's name
) -> int:
    """Re-run the oracles and report every difference from the goldens.

    Parameters
    ----------
    root
        The repository root.
    mothra
        The mothra checkout (default: ``MOTHRA_ROOT``).
    oracle
        Oracles to compare: verifiers, planners or tests (default: all).
    filter
        Compare only records whose key contains this text (repeatable).

    Returns
    -------
    int
        0 for ``0 differences``, otherwise 1.
    """
    request = Request(
        root, _mothra(mothra), _oracles(oracle or []), tuple(filter or [])
    )
    require_withheld(root, request.oracles)
    lines: list[str] = []
    for name in request.oracles:
        lines.extend(count_differences(request, name))
    sys.stdout.write("".join(f"{line}\n" for line in lines))
    sys.stdout.write(f"{len(lines)} differences\n")
    return EXIT_FINDINGS if lines else EXIT_OK


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
