"""Shared pytest configuration for the repository tooling tests.

The tools in ``tools/`` are standalone command-line modules, not an installed
package, so their directory is placed on the import path here. Tests can then
import each tool as a top-level module, for example ``import check_links``.
"""

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
