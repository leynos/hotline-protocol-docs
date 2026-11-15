"""Check obligation INV-MOVE on a relocated document.

The check does not call the rewriter. It compares the text before and after:
the heading sequence is identical, every line outside a link target is
identical, and every link now reaches the moved counterpart of its old target.
"""

import typing as typ

import markdown_model as mm
from layout_rewrite import Moves, Span, is_local, link_spans, mapped, resolve

if typ.TYPE_CHECKING:
    from pathlib import PurePosixPath


def masked(text: str) -> list[str]:
    """Replace each link target by a placeholder, line by line.

    Parameters
    ----------
    text : str
        The Markdown source.

    Returns
    -------
    list[str]
        The lines with their line endings, targets masked.
    """
    lines = text.splitlines(keepends=True)
    for span in reversed(link_spans(text)):
        line = lines[span.line - 1]
        lines[span.line - 1] = f"{line[: span.start]}\0{line[span.end :]}"
    return lines


def same_destination(old: Span, new: Span, source: PurePosixPath, moves: Moves) -> bool:
    """Say whether a rewritten link reaches the moved counterpart of its target.

    Parameters
    ----------
    old : layout_rewrite.Span
        The link before the move.
    new : layout_rewrite.Span
        The same link after it.
    source : pathlib.PurePosixPath
        The linking document's old path.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.

    Returns
    -------
    bool
        ``True`` when the fragment is kept and the paths agree.
    """
    path, _, fragment = old.target.partition("#")
    new_path, _, new_fragment = new.target.partition("#")
    if fragment != new_fragment:
        return False
    if not is_local(path):
        return old.target == new.target
    here = moves.get(source, source)
    return is_local(new_path) and resolve(here, new_path) == mapped(source, path, moves)


def verify_document(
    old: str, new: str, source: PurePosixPath, moves: Moves
) -> list[str]:
    """Compare a document before and after its relocation.

    Parameters
    ----------
    old : str
        The text before.
    new : str
        The text after.
    source : pathlib.PurePosixPath
        The document's old path.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.

    Returns
    -------
    list[str]
        One message per violation; empty when INV-MOVE holds.
    """
    problems: list[str] = []
    headings = [s["heading"] for s in mm.section_inventory(old)]
    if headings != [s["heading"] for s in mm.section_inventory(new)]:
        problems.append(f"{source}: the heading sequence changed")
    before, after = masked(old), masked(new)
    if len(before) != len(after):
        return [*problems, f"{source}: the line count changed"]
    problems.extend(
        f"{source}:{number}: a line changed beyond its link targets"
        for number, (a, b) in enumerate(zip(before, after, strict=True), 1)
        if a != b
    )
    old_links, new_links = link_spans(old), link_spans(new)
    if len(old_links) != len(new_links):
        return [*problems, f"{source}: the number of links changed"]
    problems.extend(
        f"{source}:{o.line}: {o.target} became {n.target}, which reaches elsewhere"
        for o, n in zip(old_links, new_links, strict=True)
        if not same_destination(o, n, source, moves)
    )
    return problems
