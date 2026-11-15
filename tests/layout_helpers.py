"""Generators and fixtures for the relocation tests (obligation INV-MOVE)."""

import collections as col
import dataclasses as dc
import json
import posixpath
import typing as typ
from pathlib import PurePosixPath

import layout_rewrite as lrw
from hypothesis import strategies as st

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Rewriter = cabc.Callable[
    [str, PurePosixPath, cabc.Mapping[PurePosixPath, PurePosixPath]], str
]

DIRECTORIES = ("a", "b", "c")
NAMES = ("x.md", "y.md", "z.md")
LIMIT = 3


@dc.dataclass(frozen=True, slots=True)
class Case:
    """One link, the document that holds it and the moves around it.

    Attributes
    ----------
    source : pathlib.PurePosixPath
        The linking document, before the move.
    link : str
        The link as written, fragment included.
    target : pathlib.PurePosixPath
        The file or directory the link names, before the move.
    moves : dict[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.
    """

    source: PurePosixPath
    link: str
    target: PurePosixPath
    moves: dict[PurePosixPath, PurePosixPath]


paths = st.builds(
    lambda dirs, name: PurePosixPath(*dirs, name),
    st.lists(st.sampled_from(DIRECTORIES), max_size=LIMIT),
    st.sampled_from(NAMES),
)


@st.composite
def cases(draw: st.DrawFn) -> Case:
    """Draw a link in a tree where some files move, deeper or shallower.

    Parameters
    ----------
    draw : hypothesis.strategies.DrawFn
        The Hypothesis draw function.

    Returns
    -------
    Case
        The link and its surroundings.
    """
    universe = draw(st.lists(paths, min_size=2, max_size=6, unique=True))
    moved = draw(st.lists(st.sampled_from(universe), unique=True))
    fresh = paths.filter(lambda p: p not in universe)
    news = draw(st.lists(fresh, min_size=len(moved), max_size=len(moved), unique=True))
    source = draw(st.sampled_from(universe))
    target = draw(st.sampled_from(universe))
    as_directory = draw(st.booleans()) and bool(target.parent.parts)
    if as_directory:
        target = target.parent
    path = posixpath.relpath(target.as_posix(), source.parent.as_posix() or ".")
    if draw(st.booleans()) and not path.startswith(".."):
        path = f"./{path}"
    if draw(st.booleans()):
        path = f"{draw(st.sampled_from(DIRECTORIES))}/../{path}"
    path = f"{path}/" if as_directory else path
    fragment = draw(st.sampled_from(["", "#top", "#a-b"]))
    return Case(source, path + fragment, target, dict(zip(moved, news, strict=True)))


def oracle(case: Case, rewritten: str) -> bool:
    """Say whether a rewritten link still reaches the mapped old target.

    This resolves with :mod:`posixpath`, independently of the tool.

    Parameters
    ----------
    case : Case
        The case that was rewritten.
    rewritten : str
        The rewriter's output.

    Returns
    -------
    bool
        ``True`` when the new link, from the new location, reaches the old
        target's counterpart and keeps the fragment.
    """
    old_dir = case.source.parent.as_posix()
    old = posixpath.normpath(posixpath.join(old_dir, case.link.partition("#")[0]))
    want = case.moves.get(PurePosixPath(old), PurePosixPath(old)).as_posix()
    here = case.moves.get(case.source, case.source).parent.as_posix()
    new = posixpath.normpath(posixpath.join(here, rewritten.partition("#")[0]))
    return new == want and rewritten.partition("#")[2] == case.link.partition("#")[2]


def classify(case: Case) -> col.Counter[str]:
    """Count the properties that make a case worth running.

    Parameters
    ----------
    case : Case
        The case.

    Returns
    -------
    collections.Counter[str]
        One count for each property the case has.
    """
    found: col.Counter[str] = col.Counter()
    new_source = case.moves.get(case.source, case.source)
    depth = len(new_source.parts) - len(case.source.parts)
    found["deeper" if depth > 0 else "shallower" if depth < 0 else "same depth"] += 1
    found["source moved"] += case.source in case.moves
    found["target moved"] += case.target in case.moves
    found["to directory"] += case.link.partition("#")[0].endswith("/")
    return found


def lines_without_links(text: str) -> list[str]:
    """Return the lines that hold no link.

    Parameters
    ----------
    text : str
        The Markdown source.

    Returns
    -------
    list[str]
        Those lines, line endings kept.
    """
    linked = {span.line for span in lrw.link_spans(text)}
    lines = text.splitlines(keepends=True)
    return [line for n, line in enumerate(lines, 1) if n not in linked]


TREE = {
    "AGENTS.md": "# Agents\n\nSee [a](a.md) and `a.md`.\n",
    "a.md": (
        "# A\n\nText [b](b.md#section) and [e](evidence/x.txt) here.\n\n"
        "```\n[b](b.md)\n```\n\nPlain a.md name.\n"
    ),
    "b.md": (
        '# B\n\n## Section\n\n[r][ref] and [d](evidence/) and [t](a.md "A")\n\n'
        '[ref]: a.md#a "Title"\n'
    ),
    "docs/glossary.md": "# Glossary\n\n[a](../a.md) and [b](../b.md).\n",
    "evidence/x.txt": "mentions a.md\n",
    "evidence/n.md": "# Note\n\n[a](../a.md)\n",
    "gap-analysis.md": "# Generated\n\n[a](a.md)\n",
    "gap-register.json": json.dumps(
        {
            "schema_version": 1,
            "gaps": [
                {
                    "id": "GAP-001",
                    "status": "Open",
                    "question": "Is a.md right?",
                    "sources": [{"path": "a.md"}],
                    "resolution": {"evidence": ["[A](a.md#a) and [E](evidence/x.txt)"]},
                }
            ],
            "review_coverage": [{"path": "b.md"}],
        },
        indent=2,
    )
    + "\n",
}
MOVES = {"a.md": "docs/one/a.md", "b.md": "docs/two/deeper/b.md"}
