"""Record and replay the endings of named cases, for characterization tests.

A characterization test lists named cases, each a function that calls the code
under test and returns what the caller would see. The ending of each case on the
scripts before they were brought to the standard is stored in a table of
``name``, a tab and the ending, beside the test in ``tests/data``. The test
replays every case and compares. The table is written by :func:`record`, which
is run only on the earlier scripts.
"""

import re
import typing as typ
from pathlib import Path

from mutation_support import ending

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Cases = dict[str, cabc.Callable[[], object]]

# A message that names a temporary directory would differ from run to run.
TEMPORARY = re.compile(r"(?:/[^/\s']+)*/tmp[0-9a-z_]{8}")


def scripts_directory() -> Path:
    """Find the ``scripts`` directory that is first on the import path.

    Returns
    -------
    pathlib.Path
        The directory of ``script_cli``, so that a run against the earlier
        scripts finds them wherever they are.
    """
    import script_cli  # imported where the path is first known

    return Path(script_cli.__file__).resolve().parent


def settle(case: cabc.Callable[[], object]) -> str:
    """Run a case and describe how it ended, without temporary directory names.

    Returns
    -------
    str
        The ending of :func:`mutation_support.ending`, with each temporary
        directory shown as ``<tmp>``.
    """
    return TEMPORARY.sub("<tmp>", ending(lambda _state: case(), None))


def read_endings(table: Path) -> dict[str, str]:
    """Read the recorded ending of each case.

    Returns
    -------
    dict[str, str]
        The ending of each case, by name.
    """
    lines = table.read_text(encoding="utf-8").splitlines()
    return {name: end for name, _, end in (line.partition("\t") for line in lines)}


def replay(cases: Cases, table: Path, name: str) -> tuple[str, str]:
    """Run one case and fetch its recorded ending.

    Returns
    -------
    tuple[str, str]
        What the case ended with now, and what the table records for it.
    """
    return settle(cases[name]), read_endings(table)[name]


def record(cases: Cases) -> str:
    """Run every case and write the table text.

    Returns
    -------
    str
        One line per case, sorted by name.
    """
    return "".join(f"{name}\t{settle(cases[name])}\n" for name in sorted(cases))
