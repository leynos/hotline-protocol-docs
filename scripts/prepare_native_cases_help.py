"""Print the help of the planner dispatcher in the layout that tools read.

``tools/golden_planners.py`` finds the dispatcher's suites in the first ``{a,b,c}``
of the usage line of ``--help``, as ``argparse`` laid it out. The command line is
run through Cyclopts, which lays suites out differently, so ``--help`` alone is
rendered here by an ``argparse`` parser that holds the same arguments.
"""

import argparse
import typing as typ
from pathlib import Path

from prepare_native_cases_table import SUITES


def show_help(description: str | None) -> typ.NoReturn:
    """Print the help of the dispatcher, as it was printed before, and exit.

    Parameters
    ----------
    description : str | None
        The module description, shown under the usage line.

    Raises
    ------
    SystemExit
        With status 0, as ``argparse`` ends after printing help.
    """
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("suite", choices=list(SUITES))
    parser.add_argument("--runtime-record", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--original-agreement", type=Path)
    parser.add_argument("--article-parent", type=int, default=0)
    parser.add_argument("--case-name")
    parser.add_argument("--completed-nodes", type=int, default=0)
    parser.add_argument("--category-exists", action="store_true")
    parser.add_argument("--account-inventory", type=Path)
    parser.add_argument("--first-child", type=int, default=1)
    parser.add_argument("--last-child", type=int, default=10)
    parser.parse_args(["--help"])
    raise SystemExit(0)  # parse_args exits on --help; this keeps the return type honest
