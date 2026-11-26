"""The test oracle: the name and outcome of every inherited ``unittest``.

The discovery arguments come from ``make -n test-legacy``. The tests run in a
helper process under the same ``python3`` as the Makefile, which writes each
test's outcome as JSON. A test that has moved to ``scripts/tests`` as a pytest
class keeps its module, class and method names, so it keeps its key and its
golden record; ``golden_pytest_plugin`` writes those outcomes the same way.
"""

import json
import os
import shlex
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # the oracle runs the tests
import typing as typ
from pathlib import Path

import golden_model as gm
import golden_recipes as gr

if typ.TYPE_CHECKING:
    import collections.abc as cabc

TARGET = "test-legacy"
RUNNER = Path(__file__).with_name("golden_unittest_runner.py")
PYTEST_DIR = "scripts/tests"


def discovery(root: Path, mothra: Path | None) -> tuple[str, str]:
    """Read the start directory and pattern from the ``test-legacy`` recipe.

    Returns
    -------
    tuple[str, str]
        The ``-s`` and ``-p`` values of the recipe's ``unittest discover``.

    Raises
    ------
    RuntimeError
        If the recipe is not a single ``unittest discover`` command.
    """
    lines = gr.recipe_lines(root, TARGET, mothra)
    words = shlex.split(lines[0]) if len(lines) == 1 else []
    if words[:4] != ["python3", "-m", "unittest", "discover"]:
        message = f"{TARGET} is not one unittest discover command: {lines}"
        raise RuntimeError(message)
    options = dict(zip(words[4::2], words[5::2], strict=False))
    return options["-s"], options["-p"]


def capture_tests(
    run: gr.RecipeRun, filters: cabc.Sequence[str]
) -> dict[str, gm.Record]:
    """Run the selected legacy tests and record each outcome.

    Returns
    -------
    dict[str, dict[str, str]]
        Test id to ``{"outcome", "detail"}``; details are normalised.

    Raises
    ------
    RuntimeError
        If the helper process fails to write its result.
    """
    start, pattern = discovery(run.root, run.mothra)
    result = run.normaliser.scratch / "tests.json"
    done = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv, no shell
        [gm.PYTHON3, str(RUNNER), str(result), start, pattern, *filters],
        cwd=run.root,
        env={**os.environ, **run.recipe_environment()},
        capture_output=True,
        check=False,
    )
    if not result.exists():
        message = f"the test helper wrote no result: {done.stderr.decode()[-400:]}"
        raise RuntimeError(message)
    outcomes = json.loads(result.read_text(encoding="utf-8"))
    outcomes.update(capture_pytests(run, filters))
    for record in outcomes.values():
        record["detail"] = run.normaliser.text(record["detail"].encode())
    return outcomes


def capture_pytests(
    run: gr.RecipeRun, filters: cabc.Sequence[str]
) -> dict[str, gm.Record]:
    """Run the converted tests in ``scripts/tests`` and record each outcome.

    Returns
    -------
    dict[str, dict[str, str]]
        Test key to outcome; empty when no test ran.
    """
    out = run.normaliser.scratch / "pytests.json"
    tools = Path(__file__).parent
    env = {**os.environ, **run.recipe_environment(), "GOLDEN_PYTEST_OUT": str(out)}
    env["PYTHONPATH"] = os.pathsep.join([str(tools), env.get("PYTHONPATH", "")])
    options = ["-q", "-p", "no:cacheprovider", "-p", "golden_pytest_plugin"]
    subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv, no shell
        [gm.PYTHON3, "-m", "pytest", PYTEST_DIR, *options],
        cwd=run.root,
        env=env,
        capture_output=True,
        check=False,
    )
    found = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
    return {key: found[key] for key in gm.select(found, filters)}
