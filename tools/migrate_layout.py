"""Relocate the documents into their sets (one-off; deleted in EP-M11).

``plan`` is a dry run. ``apply`` moves the files with ``git mv``, rewrites every
reference that the move would break, and then checks obligation INV-MOVE on the
result, leaving the tree as it is, for inspection, when the check fails.
``section-map`` writes the correspondence that ``refresh_audit.py refresh
--section-map`` needs for a pure relocation.

Run ``python3 tools/migrate_layout.py plan --help``. Exit codes: 0 success,
1 refusal or findings, 2 missing inputs.
"""

import collections as col
import dataclasses as dc
import json
import sys
import typing as typ
from pathlib import Path, PurePosixPath

import audit_model as am
import cyclopts
from layout_mentions import mentions
from layout_scan import GENERATED, REGISTER, Computation, compute, read_exact
from layout_verify import verify_document
from repo_files import git
from tool_support import EXIT_FINDINGS, EXIT_OK, MissingInputError, ToolError, invoke

if typ.TYPE_CHECKING:
    from layout_rewrite import Moves

DEFAULT_MOVES = Path(__file__).with_name("layout_moves.json")
ACTIONABLE = ("code or configuration", "glob over")

app = cyclopts.App(result_action="return_value")


@dc.dataclass(slots=True)
class Options:
    """The command line shared by every subcommand.

    Attributes
    ----------
    root : pathlib.Path
        The repository root.
    moves : pathlib.Path
        The move map.
    include : list[str]
        Old paths of flagged moves to carry out as well.
    all_flagged : bool
        Carry out every flagged move.
    register_paths : bool
        Also rewrite the register's structured ``path`` values. The audit
        refresh follows those itself and needs the old paths, so leave this off
        when a refresh follows.
    verbose : bool
        List every Markdown mention that stays, not just the code and
        configuration ones.
    """

    root: Path
    moves: Path = DEFAULT_MOVES
    include: list[str] = dc.field(default_factory=list)
    all_flagged: bool = False
    register_paths: bool = False
    verbose: bool = False


def load_moves(
    path: Path, include: list[str], *, everything: bool
) -> dict[PurePosixPath, PurePosixPath]:
    """Read the move map and add the flagged moves that were asked for.

    Parameters
    ----------
    path : pathlib.Path
        The JSON map: ``moves`` and ``flagged``, each old path to new path.
    include : list[str]
        Old paths of flagged moves to carry out.
    everything : bool
        Carry out every flagged move.

    Returns
    -------
    dict[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.

    Raises
    ------
    MissingInputError
        If the map is absent or names no such flagged move.
    """
    if not path.is_file():
        message = f"move map {path} is absent"
        raise MissingInputError(message)
    raw = json.loads(path.read_text(encoding="utf-8"))
    flagged: dict[str, str] = raw.get("flagged", {})
    unknown = [name for name in include if name not in flagged]
    if unknown:
        message = f"no flagged move named {', '.join(unknown)}"
        raise MissingInputError(message)
    chosen = flagged if everything else {n: flagged[n] for n in include}
    pairs = {**raw["moves"], **chosen}
    return {PurePosixPath(old): PurePosixPath(new) for old, new in pairs.items()}


def check_preconditions(root: Path, moves: Moves) -> None:
    """Refuse unless every source exists and every destination is free.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.

    Raises
    ------
    MissingInputError
        If a source is absent.
    ToolError
        If a destination exists or two moves share one.
    """
    missing = sorted(str(old) for old in moves if not (root / old).is_file())
    if missing:
        message = f"sources are absent: {', '.join(missing)}"
        raise MissingInputError(message)
    taken = sorted(str(new) for new in moves.values() if (root / new).exists())
    twice = [str(n) for n, c in col.Counter(moves.values()).items() if c > 1]
    if taken or twice:
        message = f"destinations exist: {taken}; destinations repeated: {twice}"
        raise ToolError(message)


def report_lines(root: Path, moves: Moves, args: Options) -> list[str]:
    """Describe what a relocation would rewrite and what it would leave.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.
    args : Options
        The command line.

    Returns
    -------
    list[str]
        The summary, one line each.
    """
    done = compute(root, moves, register_paths=args.register_paths)
    counts, listed = mentions(root, moves)
    total = sum(done.classes.values())
    lines = [
        f"{len(moves)} moves; {len(done.texts)} files edited",
        f"{GENERATED} is regenerated by the renderer, not edited",
        f"links rewritten: {total} (reference definitions: {done.references})",
        *(f"  {name}: {count}" for name, count in sorted(done.classes.items())),
        f"links needing no rewrite: {done.unchanged}",
        f"register values rewritten: {done.register}",
        f"directory links holding moved files, left as written: {len(done.held)}",
        *(f"  {item}" for item in done.held),
        "names of moved files that stay as written, by class:",
        *(f"  {name}: {count}" for name, count in sorted(counts.items())),
        "references needing a decision (path:line):",
    ]
    lines += [
        f"  {where}"
        for kind, where in listed
        if args.verbose or kind.startswith(ACTIONABLE)
    ]
    return lines


@app.command(name="plan")
def plan_command(args: typ.Annotated[Options, cyclopts.Parameter(name="*")]) -> int:
    """Report what the relocation would do, changing nothing.

    Parameters
    ----------
    args
        The command-line options.

    Returns
    -------
    int
        0 when the relocation can proceed.
    """
    moves = load_moves(args.moves, args.include, everything=args.all_flagged)
    check_preconditions(args.root, moves)
    sys.stdout.write("\n".join(report_lines(args.root, moves, args)) + "\n")
    return EXIT_OK


def _head(root: Path, path: PurePosixPath) -> str:
    """Read a file as it stood at ``HEAD``.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    path : pathlib.PurePosixPath
        The path at ``HEAD``.

    Returns
    -------
    str
        The content.

    Raises
    ------
    ToolError
        If Git cannot show the file.
    """
    result = git("-C", str(root), "show", f"HEAD:{path}").run_sync()
    if result.exit_code != 0:
        message = f"git show HEAD:{path} failed: {result.stderr}"
        raise ToolError(message)
    return result.stdout or ""


def verify(root: Path, moves: Moves, done: Computation) -> list[str]:
    """Check INV-MOVE over every document and the register after the move.

    Parameters
    ----------
    root : pathlib.Path
        The repository root, after the move.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.
    done : Computation
        The edits that were made.

    Returns
    -------
    list[str]
        One message per violation; empty when the move is faithful.
    """
    problems = [f"{old}: still present" for old in moves if (root / old).exists()]
    for path in sorted({*moves, *done.texts} - {GENERATED}):
        if path.suffix == ".md":
            before = _head(root, path)
            after = read_exact(root / moves.get(path, path))
            problems += verify_document(before, after, path, moves)
    if REGISTER in done.texts or REGISTER in moves:
        old = json.loads(_head(root, REGISTER))
        new_register = json.loads(read_exact(root / moves.get(REGISTER, REGISTER)))
        problems += am.compare_registers(old, new_register)
    return problems


@app.command(name="apply")
def apply_command(args: typ.Annotated[Options, cyclopts.Parameter(name="*")]) -> int:
    """Move the files, rewrite the references and verify INV-MOVE.

    Parameters
    ----------
    args
        The command-line options.

    Returns
    -------
    int
        0 when INV-MOVE holds; 1, with the tree left as it is, when it does not.

    Raises
    ------
    ToolError
        If the checkout has uncommitted changes or a move fails.
    """
    root = args.root
    moves = load_moves(args.moves, args.include, everything=args.all_flagged)
    check_preconditions(root, moves)
    status = git(
        "-C", str(root), "status", "--porcelain", "--untracked-files=no"
    ).run_sync()
    if (status.stdout or "").strip():
        message = "the checkout has uncommitted changes to tracked files"
        raise ToolError(message)
    done = compute(root, moves, register_paths=args.register_paths)
    for old, new in moves.items():
        (root / new).parent.mkdir(parents=True, exist_ok=True)
        moved = git("-C", str(root), "mv", str(old), str(new)).run_sync()
        if moved.exit_code != 0:
            message = f"git mv {old} {new} failed: {moved.stderr}"
            raise ToolError(message)
    for path, text in done.texts.items():
        (root / moves.get(path, path)).write_bytes(text.encode("utf-8"))
    problems = verify(root, moves, done)
    sys.stdout.write(
        f"moved {len(moves)} files; rewrote {sum(done.classes.values())} links\n"
    )
    for problem in problems:
        sys.stdout.write(f"INV-MOVE violated: {problem}\n")
    return EXIT_FINDINGS if problems else EXIT_OK


@app.command(name="section-map")
def section_map_command(
    args: typ.Annotated[Options, cyclopts.Parameter(name="*")], *, out: Path
) -> int:
    """Write the section map for a pure relocation.

    Every section of a moved document corresponds to the same section at its
    new path, so the map holds only the old-to-new file names.

    Parameters
    ----------
    args
        The command-line options.
    out
        Where to write the map.

    Returns
    -------
    int
        0 on success.
    """
    moves = load_moves(args.moves, args.include, everything=args.all_flagged)
    files = {
        str(old): str(new) for old, new in sorted(moves.items()) if old.suffix == ".md"
    }
    out.write_text(json.dumps({"files": files}, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(f"wrote {out} with {len(files)} files\n")
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
