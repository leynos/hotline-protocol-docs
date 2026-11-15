"""Shared pytest configuration for the repository tooling tests.

The tools in ``tools/`` are standalone command-line modules, not an installed
package, so their directory is placed on the import path here. Tests can then
import each tool as a top-level module, for example ``import check_links``.
"""

import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
