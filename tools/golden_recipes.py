"""The verifier oracle: run each Makefile recipe line and record its verdict.

The recipe lines come from ``make -n``, so the goldens never hold a second copy
of the list. Each line runs under ``sh -c`` from the repository root, exactly
as ``make`` would run it, and is recorded by exit code and a digest of its
normalised output.
"""

import dataclasses as dc
import os
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # the oracle runs the recipes
import typing as typ

import golden_model as gm

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

TARGETS = ("evidence-verify", "evidence-verify-known-red")
SUMMARY_WIDTH = 160


@dc.dataclass(frozen=True, slots=True)
class RecipeRun:
    """Where and how the recipes run.

    Attributes
    ----------
    root : pathlib.Path
        The repository root, used as the working directory.
    mothra : pathlib.Path | None
        The mothra checkout, handed to ``make`` and the scripts.
    normaliser : golden_model.Normaliser
        Removes the unstable parts of the output.
    """

    root: Path
    mothra: Path | None
    normaliser: gm.Normaliser

    def environment(self) -> dict[str, str]:
        """Build the environment that ``make`` would give a recipe.

        Returns
        -------
        dict[str, str]
            The current environment, plus ``MOTHRA_ROOT`` when known.
        """
        env = dict(os.environ)
        if self.mothra is not None:
            env["MOTHRA_ROOT"] = str(self.mothra.resolve())
        return env

    def recipe_environment(self) -> dict[str, str]:
        """Build the environment of a recipe, as ``make`` gives it for the verifiers.

        The Makefile loads the evidence pin view into every interpreter that these
        recipes start (``tools/pinview``), so that an evidence ``.py`` file may gain
        docstrings while its recorded hashes stay true.

        Returns
        -------
        dict[str, str]
            The environment, with the pin view first on ``PYTHONPATH``.
        """
        env = self.environment()
        pinview = str(self.root / "tools" / "pinview")
        env["PYTHONPATH"] = os.pathsep.join(
            filter(None, [pinview, env.get("PYTHONPATH")])
        )
        return env


def recipe_lines(root: Path, target: str, mothra: Path | None) -> list[str]:
    """List the recipe lines of a Makefile target without running them.

    Returns
    -------
    list[str]
        One shell command per line of ``make -n TARGET``.

    Raises
    ------
    RuntimeError
        If ``make`` fails or the target has no recipe.
    """
    command = ["make", "-n", "--no-print-directory", target]
    if mothra is not None:
        command.append(f"MOTHRA={mothra}")
    done = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv, no shell
        command, cwd=root, capture_output=True, text=True, check=False
    )
    lines = [line for line in done.stdout.splitlines() if line.strip()]
    if done.returncode != 0 or not lines:
        message = f"make -n {target} gave no recipe: {done.stderr.strip()}"
        raise RuntimeError(message)
    return lines


def run_line(run: RecipeRun, command: str) -> gm.Record:
    """Run one recipe line and describe its outcome.

    Returns
    -------
    dict[str, typing.Any]
        The exit code, the digest and size of the normalised output, and its
        last non-empty line for a human reader.
    """
    done = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # the recipe is the Makefile's own
        ["/bin/sh", "-c", command],
        cwd=run.root,
        env=run.recipe_environment(),
        capture_output=True,
        check=False,
    )
    text = run.normaliser.text(done.stdout + done.stderr)
    tail = [line for line in text.splitlines() if line.strip()][-1:]
    return {
        "exit_code": done.returncode,
        "output_sha256": gm.sha256_hex(text.encode("utf-8")),
        "output_bytes": len(text.encode("utf-8")),
        "last_line": tail[0][:SUMMARY_WIDTH] if tail else "",
    }


def capture_recipes(
    run: RecipeRun, filters: cabc.Sequence[str]
) -> dict[str, gm.Record]:
    """Run every selected recipe line of both verifier targets.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        Records keyed by ``TARGET: COMMAND``.
    """
    records: dict[str, gm.Record] = {}
    for target in TARGETS:
        lines = recipe_lines(run.root, target, run.mothra)
        for key in gm.select([f"{target}: {line}" for line in lines], filters):
            line = key.removeprefix(f"{target}: ")
            records[key] = {"target": target, **run_line(run, line)}
    return records
