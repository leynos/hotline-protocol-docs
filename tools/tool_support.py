"""Shared result types and command-line plumbing for the repository tools.

Every tool in this directory reports through :class:`Report`, exits with one
of the codes defined here, and runs its Cyclopts application through
:func:`invoke` so that usage errors and missing inputs share one exit code.
"""

import dataclasses as dc
import sys
import typing as typ

if typ.TYPE_CHECKING:
    import collections.abc as cabc

    import cyclopts

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_MISSING = 2


class ToolError(Exception):
    """Base class for failures that a tool reports instead of tracebacks."""


class MissingInputError(ToolError):
    """A required file, directory or option value is absent."""


@dc.dataclass(slots=True)
class Report:
    """The outcome of one tool run.

    Attributes
    ----------
    checked : int
        How many files or documents were examined.
    links : int
        How many links were examined (zero for tools that do not check links).
    failures : list[str]
        One human-readable message per finding, each naming its subject.
    """

    checked: int = 0
    links: int = 0
    failures: list[str] = dc.field(default_factory=list)

    @property
    def exit_code(self) -> int:
        """The process exit code that this report earns."""
        return EXIT_FINDINGS if self.failures else EXIT_OK


def invoke(app: cyclopts.App, argv: cabc.Sequence[str] | None) -> int:
    """Run a Cyclopts application and map its outcome to an exit code.

    Parameters
    ----------
    app : cyclopts.App
        The application, configured with ``result_action="return_value"``.
    argv : collections.abc.Sequence[str] | None
        Command-line tokens, or ``None`` to read ``sys.argv``.

    Returns
    -------
    int
        The command's integer result, ``EXIT_OK`` when a meta-option such as
        ``--help`` handled the invocation, or ``EXIT_MISSING`` for usage errors
        and missing inputs.
    """
    # Imported here so that the plain tool modules, and the evidence pin view that
    # loads in every verifier, import under an interpreter without Cyclopts.
    import cyclopts

    try:
        result = app(None if argv is None else list(argv), exit_on_error=False)
    except cyclopts.CycloptsError as exc:
        sys.stderr.write(f"{exc}\n")
        return EXIT_MISSING
    except MissingInputError as exc:
        sys.stderr.write(f"missing input: {exc}\n")
        return EXIT_MISSING
    except ToolError as exc:
        sys.stderr.write(f"refused: {exc}\n")
        return EXIT_FINDINGS
    # Meta-options such as --help print their output and return nothing.
    return EXIT_OK if result is None else int(result)
