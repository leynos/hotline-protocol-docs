"""Load the evidence pin view into every interpreter that the Makefile starts.

Python imports this module at start-up when its directory is on ``PYTHONPATH``.
See :mod:`evidence_pin_view`.
"""

import sys
from pathlib import Path

_TOOLS = str(Path(__file__).resolve().parents[1])
sys.path.insert(0, _TOOLS)
try:
    import evidence_pin_view

    evidence_pin_view.install()
finally:
    sys.path.remove(_TOOLS)
