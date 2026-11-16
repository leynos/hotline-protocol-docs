"""The command-line values that the planner entries read, and the types they share."""

import collections.abc as cabc
import dataclasses as dc
import typing as typ

if typ.TYPE_CHECKING:
    from pathlib import Path

type Case = tuple[list[typ.Any], dict[str, typ.Any]]
type Cases = dict[str, Case]
type Entry = cabc.Callable[[], Cases]


@dc.dataclass(frozen=True, slots=True)
class Inputs:
    """The options that some planner entries read, already converted to their types.

    Attributes
    ----------
    account_inventory : Path | None
        The retained account inventory for ``account-batch-cleanup``.
    original_agreement : Path | None
        The retained original agreement for ``agreement-restore-stage``.
    article_parent : int
        The parent article identifier for the ``news-thread-`` suites.
    case_name : str | None
        The retained category name for ``article-delete-resume``.
    completed_nodes : int
        The number of nodes already completed for ``article-delete-resume``.
    category_exists : bool
        Whether the category already exists for ``article-delete-resume``.
    first_child : int
        The first child number for ``news-boundary-append``.
    last_child : int
        The last child number for ``news-boundary-append``.
    """

    account_inventory: Path | None
    original_agreement: Path | None
    article_parent: int
    case_name: str | None
    completed_nodes: int
    category_exists: bool
    first_child: int
    last_child: int
