"""Pin the gap-analysis renderer: its output, its check line and its checks' order.

``render-protocol-gap-analysis.py`` regenerates ``gap-analysis.md`` from
``gap-register.json`` and validates the register against the audit revision. It
was restructured, so these tests hold what must not change. The generated report
equals the committed one, byte for byte; ``--check`` prints the same line; and
``data/gap_analysis_faults.tsv`` lists faults put into the register, singly and
in pairs, with the ending that each produced on the script as it stood before it
was brought to the standard (commit 8a3f8cd): the check that runs first decides
the ending.
"""

import contextlib
import io
import json
import re
import sys
import typing as typ
from pathlib import Path
from unittest import mock

import pytest
from characterize_support import scripts_directory
from mutation_support import ending, fault_state, read_table
from script_loading import ROOT, load_script

if typ.TYPE_CHECKING:
    import types

TABLE = Path(__file__).with_name("data") / "gap_analysis_faults.tsv"
SCRIPT = "render-protocol-gap-analysis.py"
SUBJECT = "gap-register"
LINE = re.compile(
    r"^Validated (\d+) gaps and (\d+) reviewed sections; "
    r"checked (\d+) local link references$"
)
ROWS = read_table(TABLE) if TABLE.exists() else []


def outcome(ending_text: str) -> str:
    """Reduce an ending to what stays true as the register is revised.

    A fault that the checks do not catch ends ``ok`` followed by a digest of
    the result, and that digest covers the live register, which changes with
    every audit revision. Only the fact that the checks passed is pinned; a
    fault that is caught ends with its message, which is compared in full.

    Parameters
    ----------
    ending_text : str
        The recorded or observed ending.

    Returns
    -------
    str
        ``ok`` for a passing ending, otherwise the ending unchanged.
    """
    return "ok" if ending_text.startswith("ok ") else ending_text


def renderer() -> types.ModuleType:
    """Load the renderer, whose file name has a hyphen.

    Returns
    -------
    types.ModuleType
        The script as a module.
    """
    return load_script(scripts_directory() / SCRIPT, "render_gap_analysis")


def load_register() -> dict[str, typ.Any]:
    """Read the committed register.

    Returns
    -------
    dict[str, typing.Any]
        The parsed ``gap-register.json``.
    """
    return json.loads((ROOT / "gap-register.json").read_text())


def check(register: dict[str, typ.Any]) -> object:
    """Validate a register and render the report from it.

    Returns
    -------
    object
        The length and head of the report; the checks raise before that when
        the register is unsound.
    """
    module = renderer()
    manifest = module.validate(ROOT, ROOT, register)
    text = module.render(register, manifest)
    return {"length": len(text), "head": text[:60]}


class GapAnalysisTests:
    """Keep the renderer's output and the order of its checks."""

    def test_the_report_equals_the_committed_one(self) -> None:
        """Rendering the committed register reproduces ``gap-analysis.md``."""
        module = renderer()
        register = load_register()
        manifest = module.validate(ROOT, ROOT, register)
        committed = (ROOT / "gap-analysis.md").read_text()
        assert module.render(register, manifest) == committed, "report differs"

    def test_check_prints_the_validation_line(self) -> None:
        """``--check`` prints one line of three counts and leaves the file alone."""
        module = renderer()
        before = (ROOT / "gap-analysis.md").read_bytes()
        out = io.StringIO()
        with (
            mock.patch.object(sys, "argv", [SCRIPT, "--check"]),
            contextlib.redirect_stdout(out),
        ):
            module.main()
        match = LINE.match(out.getvalue().strip())
        assert match is not None, out.getvalue()
        register = load_register()
        gaps, sections, links = (int(x) for x in match.groups())
        assert gaps == len(register["gaps"]), "gap count differs"
        assert sections == len(register["review_coverage"]), "section count differs"
        assert links > 0, "no link was checked"
        assert (ROOT / "gap-analysis.md").read_bytes() == before, "file changed"

    @pytest.mark.parametrize(
        ("subject", "faults", "expected"),
        ROWS,
        ids=[f"{i}-{row[0]}" for i, row in enumerate(ROWS)],
    )
    def test_the_recorded_faults_end_as_they_did(
        self, subject: str, faults: list[tuple[str, str]], expected: str
    ) -> None:
        """Each recorded fault, alone or paired, ends with the recorded message."""
        assert subject == SUBJECT, "only the register is recorded"
        state = fault_state(load_register(), faults)
        assert outcome(ending(check, state)) == outcome(expected), "ending differs"
