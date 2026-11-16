"""Verify the pinned scripts, or stage their pinned bytes in a scratch tree.

Run ``python3 scripts/pinned_source_cli.py check`` to verify every pin in
``scripts/pinned-sources.json``, or ``python3 scripts/pinned_source_cli.py stage
DIRECTORY`` to overwrite each pinned script in ``DIRECTORY`` with its pinned
bytes (the Makefile does this for the verifiers held under ``evidence/``). Exit
codes: 0 success, 1 a pin failed, 2 a command line that cannot be used.
"""

import sys
from pathlib import Path

import script_cli
from pinned_source import RECORD, ROOT, PinnedSourceError, Pins

EXIT_FAILED = 1


def command(
    action: str,
    destination: str | None = None,
    *,
    record: str = str(RECORD),
    repo: str = str(ROOT),
) -> None:
    """Verify the pins, or stage the pinned bytes of each script.

    Parameters
    ----------
    action
        ``check`` or ``stage``.
    destination
        For ``stage``, the directory to write into.
    record
        The pin record.
    repo
        A directory inside the repository that holds the history.

    Raises
    ------
    script_cli.UsageError
        If the action is unknown or ``stage`` has no destination.
    """
    pins = Pins(Path(record), Path(repo))
    if action == "check":
        names = pins.check()
        sys.stdout.write(f"{len(names)} pinned scripts verified\n")
    elif action == "stage" and destination is not None:
        names = pins.stage(Path(destination))
        sys.stdout.write(f"{len(names)} pinned scripts staged in {destination}\n")
    else:
        message = "use `check`, or `stage DIRECTORY`"
        raise script_cli.UsageError(message)


def main(argv: list[str] | None = None) -> int:
    """Run the command line and return the process exit code.

    Parameters
    ----------
    argv : list[str] | None
        Command-line tokens, or ``None`` to read ``sys.argv``.

    Returns
    -------
    int
        0 on success, 1 when a pin fails and 2 for a command line that cannot
        be used.
    """
    try:
        script_cli.run(command, __doc__, argv)
    except PinnedSourceError as error:
        sys.stderr.write(f"pinned_source: {error}\n")
        return EXIT_FAILED
    except SystemExit as stop:  # Cyclopts exits when a command line finishes or fails
        return stop.code if isinstance(stop.code, int) else EXIT_FAILED
    return 0


if __name__ == "__main__":
    sys.exit(main())
