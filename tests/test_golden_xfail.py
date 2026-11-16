"""A strict expected failure is recorded as the ``error`` its unittest had.

The known-red verdict (decision D18) is a ``unittest`` error in the golden. Its
pytest form is a strict ``xfail`` that names the exception, so ``make test`` is
green while the verdict holds and red when it changes. The golden plugin must
therefore record an expected failure as ``error`` with the reason as detail,
and every other ending of such a test as the ``fail`` that it is.
"""

import typing as typ

import golden_model as gm
import golden_recipes as gr
import golden_tests as gt

if typ.TYPE_CHECKING:
    from pathlib import Path

    from tree_helpers import TreeBuilder

MODULE = """\
import pytest

REASON = "ValueError: gate"


class KnownTests:
    @pytest.mark.xfail(raises=ValueError, strict=True, reason=REASON)
    def test_expected(self):
        raise ValueError("gate")

    @pytest.mark.xfail(raises=ValueError, strict=True, reason=REASON)
    def test_unexpected_pass(self):
        pass

    @pytest.mark.xfail(raises=ValueError, strict=True, reason=REASON)
    def test_other_exception(self):
        raise KeyError("gate")
"""


def test_expected_failure_is_the_recorded_error(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Only the expected exception is an ``error``; a pass or another is a ``fail``."""
    root = tmp_path / "repo"
    config = '[tool.pytest.ini_options]\npython_classes = ["*Tests"]\n'
    make_tree(root, {"scripts/tests/test_known.py": MODULE, "pyproject.toml": config})
    run = gr.RecipeRun(root, None, gm.Normaliser(root, tmp_path, {}))
    found = gt.capture_pytests(run, [])
    key = "test_known.KnownTests."
    assert found[key + "test_expected"] == {
        "outcome": "error",
        "detail": "ValueError: gate",
    }, found
    assert found[key + "test_unexpected_pass"]["outcome"] == "fail", found
    assert found[key + "test_other_exception"]["outcome"] == "fail", found
