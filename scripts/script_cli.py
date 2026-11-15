"""Run a script's command line through Cyclopts, loading it only when it is used.

The inherited scripts are both command-line programs and libraries. Evidence
kept under ``evidence/`` imports the libraries by module name from whichever
interpreter its recipe names, so a library module must import without any
third-party package. Cyclopts is therefore imported here, inside :func:`run`,
and only a script that is started as a program reaches it.
"""

import sys
import typing as typ

if typ.TYPE_CHECKING:
    import collections.abc as cabc

EXIT_USAGE = 2  # argparse's code for a command line that cannot be used


class UsageError(Exception):
    """A command line that parsed but names something that cannot be used."""


def run(
    command: cabc.Callable[..., object],
    description: str | None = None,
    argv: cabc.Sequence[str] | None = None,
) -> None:
    """Run ``command`` with its arguments taken from the command line.

    The parameters of ``command`` become the arguments: a positional one is a
    positional argument and a keyword-only one is the option of the same name.
    A command line that cannot be parsed, or a :class:`UsageError` raised by
    ``command``, prints a message to standard error and exits with status 2, as
    ``argparse`` did. Any other exception propagates unchanged.

    Parameters
    ----------
    command : collections.abc.Callable[..., object]
        The function to run.
    description : str | None
        The help text, usually the module's docstring.
    argv : collections.abc.Sequence[str] | None
        The tokens to parse; ``None`` reads ``sys.argv``.

    Raises
    ------
    SystemExit
        With status 2 when the command line cannot be used.
    """
    import cyclopts  # see the module docstring

    app = cyclopts.App(help=description)
    app.default(command)
    try:
        app(
            None if argv is None else list(argv), exit_on_error=False, print_error=False
        )
    except (cyclopts.CycloptsError, UsageError) as error:
        sys.stderr.write(f"{sys.argv[0]}: error: {error}\n")
        raise SystemExit(EXIT_USAGE) from error
