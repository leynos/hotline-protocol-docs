"""Tests for the helpers shared by the command-line tools."""

import cyclopts
import pytest
import tool_support


def _app() -> cyclopts.App:
    """Build a one-command application that returns its argument.

    Returns
    -------
    cyclopts.App
        The application under test.
    """
    app = cyclopts.App(result_action="return_value")

    @app.default
    def run(code: int = 0) -> int:
        """Return the given exit code.

        Parameters
        ----------
        code : int
            The exit code to return.

        Returns
        -------
        int
            The same code.
        """
        return code

    return app


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        pytest.param(["--code", "1"], 1, id="command result"),
        pytest.param([], 0, id="default"),
        pytest.param(["--help"], 0, id="help prints and succeeds"),
        pytest.param(["--version"], 0, id="version prints and succeeds"),
    ],
)
def test_invoke_maps_outcomes_to_exit_codes(argv: list[str], expected: int) -> None:
    """A command's result, or a meta-option that returns nothing, is an exit code."""
    code = tool_support.invoke(_app(), argv)
    assert code == expected, f"expected exit code {expected} for {argv}, got {code}"
