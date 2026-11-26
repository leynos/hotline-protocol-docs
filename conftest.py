"""Show every test the retained evidence ``.py`` files as they were captured.

``make`` already does this through ``tools/pinview/sitecustomize.py``; this module
does it for a run that starts pytest directly. See ``tools/evidence_pin_view.py``.
"""

import sys
from pathlib import Path

TOOLS = str(Path(__file__).resolve().parent / "tools")

if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

import evidence_pin_view  # ruff: ignore[module-import-not-at-top-of-file]  # needs TOOLS on the path first

evidence_pin_view.install()
