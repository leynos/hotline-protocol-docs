#!/usr/bin/env python3
"""Validate the documentation gap register and render its Markdown report."""

import json
from pathlib import Path

from gap_analysis_links import (
    MOTHRA_PREFIX,
    Section,
    check_links,
    mothra_checkout,
    section_inventory,
)
from gap_analysis_report import render
from gap_analysis_text import bullet, gap_links, paragraph
from gap_analysis_validate import validate
from script_cli import run

# Names re-exported from the gap_analysis_* helper modules. Callers that load a
# renderer by path with importlib (tests/test_refresh_golden.py, which loads the
# mothra copy) and the documents that cite this script rely on these names.
__all__ = [
    "MOTHRA_PREFIX",
    "Section",
    "bullet",
    "check_links",
    "gap_links",
    "main",
    "mothra_checkout",
    "paragraph",
    "render",
    "section_inventory",
    "validate",
]


def main(*, check: bool = False) -> None:
    """Validate the gap register, then write or check the generated report.

    Parameters
    ----------
    check : bool
        Check without writing

    Raises
    ------
    ValueError
        If the register fails a check, or if ``check`` is set and the report is
        stale.
    """
    root = Path(__file__).resolve().parent.parent
    directory = root
    register = json.loads((directory / "gap-register.json").read_text())
    manifest = validate(root, directory, register)
    generated = render(register, manifest)
    target = directory / "gap-analysis.md"
    checked_links = check_links(target, generated)
    for item in manifest["inputs"]:
        path = directory / item["path"]
        checked_links += check_links(path, path.read_text())
    if check:
        if target.read_text() != generated:
            message = "Generated gap analysis is stale; run without --check"
            raise ValueError(message)
    else:
        target.write_text(generated)
    print(
        f"Validated {len(register['gaps'])} gaps and "
        f"{len(register['review_coverage'])} reviewed sections; "
        f"checked {checked_links} local link references"
    )


if __name__ == "__main__":
    run(main, __doc__)
