"""Type aliases shared by the tool tests."""

import collections.abc as cabc
from pathlib import Path

type TreeBuilder = cabc.Callable[[Path, cabc.Mapping[str, str | bytes]], None]
