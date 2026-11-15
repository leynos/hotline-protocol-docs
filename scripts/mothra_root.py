"""Locate the sibling checkout of the general mothra capture toolset.

The evidence that the scripts verify lives in this repository. Only the
general tooling and the untracked runtime state stay in mothra, so scripts
that still need them resolve the checkout here.
"""

import os
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]


def mothra_root(repository: Path = REPOSITORY) -> Path:
    """Return the mothra checkout for ``repository``.

    ``MOTHRA_ROOT`` wins when it is set and not empty. Otherwise the first
    existing of ``<repository>/../mothra`` and ``<repository>/../../mothra``
    is used (the second is where it sits relative to a linked worktree), and
    when neither exists the conventional ``<repository>/../mothra``, so that
    messages name the expected place.
    """
    configured = os.environ.get("MOTHRA_ROOT")
    if configured:
        return Path(configured)
    nearest = repository.parent / "mothra"
    for candidate in (nearest, repository.parent.parent / "mothra"):
        if candidate.exists():
            return candidate
    return nearest
