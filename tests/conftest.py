"""Shared pytest configuration for the repository tooling tests.

The tools in ``tools/`` are standalone command-line modules, not an installed
package, so their directory is placed on the import path here. Tests can then
import each tool as a top-level module, for example ``import check_links``.
"""

import os
import sys
import typing as typ
from pathlib import Path

import pytest

if typ.TYPE_CHECKING:
    import collections.abc as cabc

    from tree_helpers import TreeBuilder

TOOLS = Path(__file__).resolve().parents[1] / "tools"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

# Modules that pin a migrated script to the behaviour observed on its pristine
# version: which error is raised first, and how each fault in a corpus ends.
CONTINUITY_SUFFIXES = ("_order.py", "_faults.py")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark every test in a continuity module, so the commit gate can skip it.

    Parameters
    ----------
    items : list[pytest.Item]
        The collected tests, changed in place.
    """
    for item in items:
        if item.path.name.endswith(CONTINUITY_SUFFIXES):
            item.add_marker(pytest.mark.continuity)


@pytest.fixture
def make_tree() -> TreeBuilder:
    """Return a helper that writes a mapping of relative paths to content.

    Returns
    -------
    TreeBuilder
        A function that creates each file, and its parent directories, below
        the given root. Text is written as UTF-8 without newline translation.
    """

    def build(root: Path, files: cabc.Mapping[str, str | bytes]) -> None:
        """Write ``files`` below ``root``."""
        for name, content in files.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            data = content.encode("utf-8") if isinstance(content, str) else content
            target.write_bytes(data)

    return build


@pytest.fixture
def mothra() -> Path:
    """Locate the sibling mothra checkout that holds the retained evidence.

    The lookup order is the ``MOTHRA_ROOT`` environment variable, then
    ``../mothra`` and ``../../mothra`` relative to the repository root.

    Returns
    -------
    pathlib.Path
        The checkout's root directory.
    """
    repo = Path(__file__).resolve().parents[1]
    candidates = (
        [Path(os.environ["MOTHRA_ROOT"])] if "MOTHRA_ROOT" in os.environ else []
    )
    candidates += [repo.parent / "mothra", repo.parent.parent / "mothra"]
    found = next((c for c in candidates if (c / "evidence").is_dir()), None)
    if found is None:
        searched = ", ".join(str(c) for c in candidates)
        pytest.fail(
            "the mothra checkout is required for this test; set MOTHRA_ROOT or "
            f"place it at ../mothra or ../../mothra (searched: {searched})"
        )
    return found
