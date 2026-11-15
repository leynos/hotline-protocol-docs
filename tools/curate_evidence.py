"""Select, copy and check the curated evidence import (decision D22).

``select`` decides which corpora of a source checkout are relevant and writes
``evidence/curation.json``; ``copy`` copies the included corpora byte for byte
without the withheld files; ``check`` proves the result faithful (obligation
INV-IMPORT).

Run ``python3 tools/curate_evidence.py select|copy|check``. Exit codes:
0 success, 1 findings, 2 missing inputs.
"""

import dataclasses as dc
import sys
from pathlib import Path

import cyclopts
from curate_check import CheckRequest, check
from curate_copy import CopyRequest, copy_evidence
from curate_select import SelectRequest, select, selection_text
from evidence_corpus import EXCLUDED, INCLUDED
from evidence_files import parse_citing
from tool_support import invoke

app = cyclopts.App(result_action="return_value")


@cyclopts.Parameter(name="*")
@dc.dataclass(frozen=True, slots=True)
class SelectArguments:
    """The options of ``select``.

    Attributes
    ----------
    source_root : pathlib.Path
        A tree that contains ``evidence/``.
    output : pathlib.Path
        Where to write ``curation.json``.
    citing : list[str]
        ``KIND=PATH`` for each citing file or directory; repeat the option.
    withheld : pathlib.Path | None
        The withheld manifest.
    source_commit : str
        The commit to record; defaults to the checkout's ``HEAD``.
    """

    source_root: Path
    output: Path
    citing: list[str]
    withheld: Path | None = None
    source_commit: str = ""


@app.command(name="select")
def run_select(arguments: SelectArguments) -> int:
    """Decide which corpora are relevant and write ``curation.json``.

    Parameters
    ----------
    arguments
        The options.

    Returns
    -------
    int
        0 after the file is written.
    """
    request = SelectRequest(
        arguments.source_root,
        tuple(parse_citing(spec) for spec in arguments.citing),
        arguments.withheld,
        arguments.source_commit,
    )
    selection = select(request)
    arguments.output.write_text(selection_text(selection), encoding="utf-8")
    kept = [c for c in selection.corpora if c.disposition == INCLUDED]
    dropped = [c for c in selection.corpora if c.disposition == EXCLUDED]
    sys.stdout.write(
        f"{len(kept)} included ({sum(c.files for c in kept)} files, "
        f"{sum(c.bytes for c in kept)} bytes), {len(dropped)} excluded "
        f"({sum(c.files for c in dropped)} files)\n"
    )
    return 0


@app.command(name="copy")
def run_copy(
    source_root: Path,
    root: Path = Path(),
    *,
    withheld: Path | None = None,
    curation: Path | None = None,
) -> int:
    """Copy the included corpora from the source, skipping withheld files.

    Parameters
    ----------
    source_root
        The tree to copy from.
    root
        The repository to copy into.
    withheld
        The withheld manifest.
    curation
        The curation file (default ``evidence/curation.json`` in ``root``).

    Returns
    -------
    int
        0 after the copy.
    """
    result = copy_evidence(CopyRequest(source_root, root, withheld, curation))
    sys.stdout.write(
        f"{result.copied} copied, {result.identical} identical, "
        f"{result.withheld} withheld skipped\n"
    )
    return 0


@cyclopts.Parameter(name="*")
@dc.dataclass(frozen=True, slots=True)
class CheckArguments:
    """The options of ``check``.

    Attributes
    ----------
    root : pathlib.Path
        The repository that holds the imported ``evidence/``.
    curation : pathlib.Path | None
        The curation file.
    withheld : pathlib.Path | None
        The withheld manifest.
    citing : list[str]
        ``KIND=PATH`` whose citations must resolve; repeat the option.
    source_root : pathlib.Path | None
        The source checkout, for the content comparison.
    source_commit : str
        The commit to compare against.
    local_file : list[str]
        Paths that may exist here without existing in the source.
    """

    root: Path = Path()
    curation: Path | None = None
    withheld: Path | None = None
    citing: list[str] = dc.field(default_factory=list)
    source_root: Path | None = None
    source_commit: str = ""
    local_file: list[str] = dc.field(default_factory=list)


@app.command(name="check")
def run_check(arguments: CheckArguments | None = None) -> int:
    """Check the imported evidence against its curation record and the source.

    Parameters
    ----------
    arguments
        The options.

    Returns
    -------
    int
        0 when the import is faithful, otherwise 1.
    """
    arguments = arguments or CheckArguments()
    result = check(
        CheckRequest(
            root=arguments.root,
            curation=arguments.curation,
            withheld=arguments.withheld,
            citing=tuple(parse_citing(spec) for spec in arguments.citing),
            source_root=arguments.source_root,
            source_commit=arguments.source_commit,
            local_files=tuple(arguments.local_file),
        )
    )
    lines = [*result.failures, *result.notes]
    sys.stdout.write("".join(f"{line}\n" for line in lines))
    if arguments.source_root is not None:
        sys.stdout.write(
            f"{result.compared} files compared, {result.differences} differences\n"
        )
    return result.exit_code


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
