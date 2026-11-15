"""Find the references to moved files that a relocation leaves as written.

Links are rewritten (see :mod:`layout_scan`). Everything else that names a
moved file stays: names in prose and code spans, anything under ``evidence/``,
the register's prose, code and configuration. This module counts each, sorts it
into a class, and lists the lines that a person has to decide about, including
globs that stop matching once the documents have moved.
"""

import collections as col
import json
import re
import typing as typ
from pathlib import PurePosixPath

import markdown_model as mm
from layout_rewrite import Moves, link_spans
from layout_scan import EVIDENCE, GENERATED, REGISTER, read_exact
from repo_files import repo_files

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

MAP = PurePosixPath("tools/layout_moves.json")
GLOB = re.compile(r"[\w./$()-]*\*[\w./*-]*\.(?:md|json)")
STRUCTURED = "register: structured path values (the audit refresh follows them)"
PROSE = "register: names inside strings"
type Mention = tuple[str, str]


def name_pattern(moves: Moves) -> re.Pattern[str]:
    """Build the pattern that finds the name of any moved file.

    Parameters
    ----------
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.

    Returns
    -------
    re.Pattern[str]
        Matches a file name not embedded in a longer word or name.
    """
    names = sorted({old.name for old in moves}, key=len, reverse=True)
    return re.compile(r"(?<![\w.-])(" + "|".join(map(re.escape, names)) + r")(?![\w-])")


def _markdown_names(
    text: str, pattern: re.Pattern[str]
) -> cabc.Iterator[tuple[int, str]]:
    """Yield each name in Markdown that is not part of a link target.

    Parameters
    ----------
    text : str
        The document.
    pattern : re.Pattern[str]
        Finds the names of moved files.

    Yields
    ------
    tuple[int, str]
        The line number and the class: ``fenced code``, ``code span`` or
        ``prose``.
    """
    targets = col.defaultdict(list)
    for span in link_spans(text):
        targets[span.line].append((span.start, span.end))
    visible = {number for number, _ in mm.unfenced_lines(text)}
    for number, line in enumerate(text.splitlines(), 1):
        code = [found.span() for found in mm.CODE_SPAN.finditer(line)]
        for found in pattern.finditer(line):
            column = found.start()
            if any(a <= column < b for a, b in targets[number]):
                continue
            if number not in visible:
                yield number, "fenced code"
            elif any(a <= column < b for a, b in code):
                yield number, "code span"
            else:
                yield number, "prose"


def _register_names(
    value: object, pattern: re.Pattern[str], moves: Moves
) -> cabc.Iterator[str]:
    """Yield the class of each moved name in the register that stays.

    Parameters
    ----------
    value : object
        A parsed JSON value.
    pattern : re.Pattern[str]
        Finds the names of moved files.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.

    Yields
    ------
    str
        :data:`STRUCTURED` for a ``path`` value, :data:`PROSE` for a name
        outside any link target.
    """
    match value:
        case str():
            inside = [(s.start, s.end) for s in link_spans(value)]
            yield from (
                PROSE
                for found in pattern.finditer(value)
                if not any(a <= found.start() < b for a, b in inside)
            )
        case list():
            for item in value:
                yield from _register_names(item, pattern, moves)
        case dict():
            for key, item in value.items():
                if key == "path" and PurePosixPath(str(item)) in moves:
                    yield STRUCTURED
                else:
                    yield from _register_names(item, pattern, moves)
        case _:
            return


def _glob_matches(line: str, moves: Moves) -> list[str]:
    """Find the globs on a line that select a moved document.

    Parameters
    ----------
    line : str
        A line of code or configuration.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.

    Returns
    -------
    list[str]
        Each glob that matches at least one old path, ``*`` not crossing ``/``.
    """
    found: list[str] = []
    for glob in GLOB.findall(line):
        pattern = re.compile(re.escape(glob.split("(")[-1]).replace(r"\*", "[^/]*"))
        if any(pattern.fullmatch(str(old)) for old in moves):
            found.append(glob)
    return found


def _other_file(
    path: PurePosixPath, text: str, pattern: re.Pattern[str], moves: Moves
) -> cabc.Iterator[Mention]:
    """Yield the classified mentions in a file that is not Markdown.

    Parameters
    ----------
    path : pathlib.PurePosixPath
        The file.
    text : str
        Its content.
    pattern : re.Pattern[str]
        Finds the names of moved files.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.

    Yields
    ------
    tuple[str, str]
        The class and a ``path:line: name`` locator.
    """
    kind = f"code or configuration: {path.parts[0]}"
    for number, line in enumerate(text.splitlines(), 1):
        for glob in _glob_matches(line, moves):
            yield "glob over moved documents", f"{path}:{number}: {glob}"
        for found in pattern.finditer(line):
            yield kind, f"{path}:{number}: {found[1]}"


def mentions(root: Path, moves: Moves) -> tuple[col.Counter[str], list[Mention]]:
    """Find every occurrence of a moved file's name that is not a link.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.

    Returns
    -------
    tuple[collections.Counter[str], list[tuple[str, str]]]
        Counts by class, and the class with a ``path:line`` locator of every
        occurrence outside ``evidence/`` and the register.
    """
    pattern = name_pattern(moves)
    counts: col.Counter[str] = col.Counter()
    listed: list[Mention] = []
    for relative in repo_files(root, ""):
        path = PurePosixPath(relative.as_posix())
        if path in {GENERATED, MAP} or path.parts[0] == ".git":
            continue
        text = read_exact(root / relative)
        if path.parts[0] == EVIDENCE:
            counts["evidence (hashed, untouched)"] += len(pattern.findall(text))
        elif path == REGISTER:
            counts.update(_register_names(json.loads(text), pattern, moves))
        elif path.suffix == ".md":
            for number, kind in _markdown_names(text, pattern):
                counts[kind] += 1
                listed.append((kind, f"{path}:{number}"))
        else:
            for kind, where in _other_file(path, text, pattern, moves):
                counts[kind] += 1
                listed.append((kind, where))
    return counts, listed
