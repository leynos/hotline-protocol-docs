"""Work out what a relocation would rewrite, and what it would leave alone.

:func:`compute` is the single source of truth for the edits: ``plan`` reports
it and ``apply`` writes it. :func:`mentions` finds every other occurrence of a
moved file's name, which stays as written, and sorts it into a class so that
the report can say why. Nothing here writes to the file system.
"""

import collections as col
import dataclasses as dc
import json
from pathlib import Path, PurePosixPath

import markdown_model as mm
from check_json import canonical
from layout_register import rewrite_register
from layout_rewrite import Moves, is_local, link_spans, rewrite_link, rewrite_text
from repo_files import repo_files

EVIDENCE = "evidence"
REGISTER = PurePosixPath("gap-register.json")
GENERATED = PurePosixPath("gap-analysis.md")
LITERAL_FILES = (PurePosixPath("typos.local.toml"),)
SIZE_LIMIT = 4_000_000
NAMED_TOP = ("evidence", "scripts", "tools", "docs")


@dc.dataclass(slots=True)
class Computation:
    """The edits a relocation makes to the files that stay in the tree.

    Attributes
    ----------
    texts : dict[pathlib.PurePosixPath, str]
        New content, keyed by the file's old path, for each file that changes.
    classes : collections.Counter[str]
        How many links were rewritten, by ``source -> target`` class.
    unchanged : int
        How many links needed no rewrite.
    references : int
        How many of the rewritten links are reference definitions.
    held : list[str]
        ``path:line`` of each link to a directory that holds moved files, which
        is left as written.
    register : int
        How many register values were rewritten.
    """

    texts: dict[PurePosixPath, str] = dc.field(default_factory=dict)
    classes: col.Counter[str] = dc.field(default_factory=col.Counter)
    unchanged: int = 0
    references: int = 0
    held: list[str] = dc.field(default_factory=list)
    register: int = 0


def link_class(
    source: PurePosixPath, target: PurePosixPath | None, moves: Moves
) -> str:
    """Name the class of a rewritten link.

    Parameters
    ----------
    source : pathlib.PurePosixPath
        The linking document's old path.
    target : pathlib.PurePosixPath | None
        What the link resolved to before the move, or ``None`` outside the root.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.

    Returns
    -------
    str
        For example ``moved -> moved document`` or ``unmoved -> evidence/``.
    """
    origin = "moved" if source in moves else "unmoved"
    if target is None:
        return f"{origin} -> outside the repository"
    if target in moves:
        return f"{origin} -> moved document"
    top = target.parts[0] if target.parts else "."
    return f"{origin} -> {top + '/' if top in NAMED_TOP else 'other file or directory'}"


def _old_target(source: PurePosixPath, link: str) -> PurePosixPath | None:
    """Resolve a link as it stood before the move.

    Parameters
    ----------
    source : pathlib.PurePosixPath
        The linking document's old path.
    link : str
        The target as written.

    Returns
    -------
    pathlib.PurePosixPath | None
        The target, or ``None`` when it leaves the repository.
    """
    escapes, parts = mm.lexical_target(source, link.partition("#")[0])
    return None if escapes else PurePosixPath(*parts)


def _document(path: PurePosixPath, text: str, moves: Moves, out: Computation) -> None:
    """Rewrite one document and record the counts.

    Parameters
    ----------
    path : pathlib.PurePosixPath
        The document's old path.
    text : str
        Its content.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.
    out : Computation
        Receives the new text and the counts.
    """
    for span in link_spans(text):
        if not is_local(span.target.partition("#")[0]):
            continue
        target = _old_target(path, span.target)
        if rewrite_link(span.target, path, moves) == span.target:
            out.unchanged += 1
        else:
            out.classes[link_class(path, target, moves)] += 1
            out.references += span.reference
        if target is not None and any(
            old != target and old.is_relative_to(target) for old in moves
        ):
            out.held.append(f"{path}:{span.line}: {span.target}")
    new = rewrite_text(text, path, moves)[0]
    if new != text:
        out.texts[path] = new


def _configuration(root: Path, moves: Moves, out: Computation) -> None:
    """Follow exact quoted paths in the configuration files that name them.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.
    out : Computation
        Receives the new text.
    """
    for path in LITERAL_FILES:
        if not (root / path).is_file():
            continue
        text = read_exact(root / path)
        new = text
        for old, target in moves.items():
            new = new.replace(f'"{old}"', f'"{target}"')
        if new != text:
            out.texts[path] = new


def _register(root: Path, moves: Moves, out: Computation, *, paths: bool) -> None:
    """Follow the moves through the gap register.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.
    out : Computation
        Receives the new text and the count.
    paths : bool
        Also rewrite the structured ``path`` values.
    """
    if not (root / REGISTER).is_file():
        return
    text = read_exact(root / REGISTER)
    register, out.register = rewrite_register(
        json.loads(text), GENERATED, moves, paths=paths
    )
    new = canonical(json.dumps(register))
    if new != text:
        out.texts[REGISTER] = new


def compute(root: Path, moves: Moves, *, register_paths: bool = False) -> Computation:
    """Work out every edit that follows from ``moves``.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.
    register_paths : bool
        Also rewrite the register's structured ``path`` values.

    Returns
    -------
    Computation
        The edits and the counts.
    """
    out = Computation()
    for relative in repo_files(root, ".md"):
        path = PurePosixPath(relative.as_posix())
        if path.parts[0] != EVIDENCE and path != GENERATED:
            _document(path, read_exact(root / relative), moves, out)
    _configuration(root, moves, out)
    _register(root, moves, out, paths=register_paths)
    return out


def read_exact(path: Path) -> str:
    """Read a file's text without translating its line endings.

    Parameters
    ----------
    path : pathlib.Path
        The file.

    Returns
    -------
    str
        The content, or an empty string for binary data and huge files.
    """
    if path.stat().st_size > SIZE_LIMIT:
        return ""
    try:
        return path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        return ""


__all__ = ["Computation", "compute", "read_exact"]
