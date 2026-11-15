"""Refresh the gap-register audit against the current documents.

An audit revision is a directory ``protocol-gap-analysis/<date>/revision-N``
holding ``manifest.json`` (the inputs, their hashes and the run metadata),
``sections.json`` (every heading of every input), a fresh snapshot of every
input under ``inputs/`` and ``SHA256SUMS``. ``gap-register.json`` must match
the revision exactly; mothra's renderer ``validate`` is the independent oracle.

``refresh`` maps each old section to its new section (see :mod:`audit_model`),
rewrites the register's source and coverage locations, writes the new revision
and the register, and refuses, writing nothing, when a gap's protected fields
would change, the gap count is wrong, a revision directory already exists, or
a heading change has no section-map entry.

Run ``python3 tools/refresh_audit.py refresh --help`` or
``python3 tools/refresh_audit.py compare OLD NEW``. Exit codes: 0 success,
1 findings or refusal, 2 missing inputs.
"""

import dataclasses as dc
import datetime as dt
import sys
import typing as typ
from pathlib import Path

import audit_model as am
import cyclopts
from audit_io import read_json, record_local_corpus
from audit_workspace import EXPECTED_GAPS, Workspace
from section_map import RefreshRefusedError
from tool_support import EXIT_FINDINGS, EXIT_OK, MissingInputError, invoke

app = cyclopts.App(result_action="return_value")


@dc.dataclass(slots=True)
class RefreshArgs:
    """The command line of ``refresh``.

    Attributes
    ----------
    revision : int
        The new revision number.
    root : pathlib.Path
        The register checkout.
    evidence_root : pathlib.Path | None
        Where earlier revisions are read from (default: the register's pointers).
    out_root : pathlib.Path | None
        Where the new revision is written (default: ``evidence`` in the checkout).
    section_map : pathlib.Path | None
        Reviewed correspondences for moved or restructured documents.
    baseline : pathlib.Path | None
        A register whose protected fields the current one must match.
    expected_gaps : int
        The required number of gaps.
    today : datetime.date | None
        The audit date; defaults to today (UTC).
    reason : str | None
        Why the revision is cut; given, the revision is listed in the evidence
        tree's ``local-corpora.json``.
    """

    revision: int
    root: Path = Path()
    evidence_root: Path | None = None
    out_root: Path | None = None
    section_map: Path | None = None
    baseline: Path | None = None
    expected_gaps: int = EXPECTED_GAPS
    today: dt.date | None = None
    reason: str | None = None


def _summary(old: am.Register, new: am.Register) -> tuple[str, int]:
    """Summarize a comparison of two registers.

    Parameters
    ----------
    old : dict[str, typing.Any]
        The reference register.
    new : dict[str, typing.Any]
        The register under test.

    Returns
    -------
    tuple[str, int]
        The ``N gaps, K protected fields changed`` line and the exit code.
    """
    changes = am.compare_registers(old, new)
    for change in changes:
        sys.stdout.write(f"{change}\n")
    line = f"{len(new['gaps'])} gaps, {len(changes)} protected fields changed"
    return line, EXIT_FINDINGS if changes else EXIT_OK


@app.command(name="refresh")
def refresh_command(
    args: typ.Annotated[RefreshArgs, cyclopts.Parameter(name="*")],
) -> int:
    """Write a new audit revision and update the register to match it.

    Parameters
    ----------
    args
        The command-line options.

    Returns
    -------
    int
        0 on success, 1 when the refresh is refused.

    Raises
    ------
    MissingInputError
        If the register checkout is absent.
    """
    workspace = Workspace(
        args.root,
        evidence_root=args.evidence_root,
        out_root=args.out_root,
        expected_gaps=args.expected_gaps,
        baseline=args.baseline,
    )
    if not args.root.is_dir():
        message = f"register checkout {args.root} is absent"
        raise MissingInputError(message)
    today = args.today or dt.datetime.now(dt.UTC).date()
    try:
        written = workspace.refresh(
            args.revision, today=today, section_map=args.section_map
        )
    except RefreshRefusedError as exc:
        sys.stdout.write(f"refused: {exc}\n")
        return EXIT_FINDINGS
    if args.reason is not None:
        record_local_corpus(written.directory, args.reason)
    sys.stdout.write(f"wrote {written.directory}\n")
    return EXIT_OK


@app.command(name="compare")
def compare_command(old: Path, new: Path, *, expected_gaps: int = EXPECTED_GAPS) -> int:
    """Compare the protected fields of two register files.

    Parameters
    ----------
    old
        The reference register.
    new
        The register under test.
    expected_gaps
        The required number of gaps in the register under test.

    Returns
    -------
    int
        0 when nothing protected changed and the count is right, otherwise 1.
    """
    line, code = _summary(read_json(old), read_json(new))
    count = len(read_json(new)["gaps"])
    if count != expected_gaps:
        sys.stdout.write(f"expected {expected_gaps} gaps, found {count}\n")
        code = EXIT_FINDINGS
    sys.stdout.write(f"{line}\n")
    return code


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
