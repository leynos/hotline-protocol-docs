"""Run the tests that reach a pinned script against its pinned and current bytes.

Decision D29 replaces the hash of a live script with a reference to the file at
a pinned commit. The owner's condition is test coverage that spans the pinned
version and the refactored one. :func:`differences` checks that for one script:
it lays out two copies of ``scripts/``, one as it is and one with the script
replaced by its pinned bytes, runs every test file that can reach the script
through imports in each, and lists each test whose outcome differs. An empty
list means the two versions are indistinguishable to the existing tests. A
script that no test reaches cannot be shown equivalent, so that is an error unless
the caller names a command line that runs it as a program (exit code and output).
"""

import ast
import dataclasses as dc
import itertools
import os
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # runs pytest on a copy
import sys
import tempfile
import typing as typ
from pathlib import Path

if typ.TYPE_CHECKING:
    import collections.abc as cabc

OUTCOME = re.compile(r"^(PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS) (\S+)", re.MULTILINE)
PYTEST_INI = "[pytest]\npythonpath = scripts\npython_classes = Test* *Tests\n"
RUN_SECONDS = 1800


class NoCoverageError(Exception):
    """No test reaches the script, so no equivalence can be shown."""


def _imports(path: Path, stems: set[str]) -> set[str]:
    """List the sibling modules that a file imports.

    Returns
    -------
    set[str]
        Module names that are also files of ``scripts/``.
    """
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        match node:
            case ast.Import():
                found.update(alias.name.split(".")[0] for alias in node.names)
            case ast.ImportFrom(level=0):
                found.add((node.module or "").split(".")[0])
    return found & stems


def reaching_tests(scripts: Path, name: str) -> list[str]:
    """List the test files whose imports lead to a script.

    Parameters
    ----------
    scripts : pathlib.Path
        The ``scripts/`` directory.
    name : str
        The script's file name.

    Returns
    -------
    list[str]
        Paths such as ``scripts/tests/test_x.py``, sorted.
    """
    files = [*scripts.glob("*.py"), *scripts.glob("tests/*.py")]
    stems = {path.stem for path in files}
    imports = {path: _imports(path, stems) for path in files}
    reach = {Path(name).stem}
    grew = True
    while grew:
        grew = False
        for path, found in imports.items():
            if path.stem not in reach and found & reach:
                reach.add(path.stem)
                grew = True
    return sorted(
        f"scripts/{path.relative_to(scripts).as_posix()}"
        for path in files
        if path.stem in reach and path.name.startswith("test_")
    )


def lay_out(
    base: Path,
    scripts: Path,
    swap: tuple[str, bytes] | None,
    links: cabc.Mapping[str, Path],
) -> Path:
    """Copy ``scripts/`` into a checkout-shaped tree, optionally swapping a file.

    Parameters
    ----------
    base : pathlib.Path
        An empty directory; the tree is ``base/hotline-protocol-docs``.
    scripts : pathlib.Path
        The directory to copy.
    swap : tuple[str, bytes] | None
        A script name and the bytes to put in its place.
    links : collections.abc.Mapping[str, pathlib.Path]
        Names to link beside the copy, relative to ``base`` or to the tree
        (``evidence``), for tests that read retained corpora.

    Returns
    -------
    pathlib.Path
        The tree's root.
    """
    root = base / "hotline-protocol-docs"
    shutil.copytree(
        scripts, root / "scripts", ignore=shutil.ignore_patterns("__pycache__")
    )
    if swap is not None:
        (root / "scripts" / swap[0]).write_bytes(swap[1])
    for name, target in links.items():
        place = base / name if name == "mothra" else root / name
        place.symlink_to(target)
    (root / "pytest.ini").write_text(PYTEST_INI, encoding="utf-8")
    return root


def outcomes(root: Path, tests: cabc.Sequence[str]) -> dict[str, str]:
    """Run test files in a tree and map each test to its outcome.

    Returns
    -------
    dict[str, str]
        Node identifier to ``PASSED``, ``FAILED``, ``ERROR``, ``SKIPPED``,
        ``XFAIL`` or ``XPASS``.

    Raises
    ------
    NoCoverageError
        If pytest reports no test at all.
    """
    command = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider"]
    command += ["-c", "pytest.ini", "--rootdir", ".", "-q", "-rA", "--tb=no"]
    done = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv
        [*command, *tests],
        cwd=root,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        check=False,
        timeout=RUN_SECONDS,
    )
    found = {match[2]: match[1] for match in OUTCOME.finditer(done.stdout)}
    if not found:
        message = f"pytest collected nothing in {root}: {done.stdout[-400:]}"
        raise NoCoverageError(message)
    return found


def run_program(root: Path, name: str, arguments: cabc.Sequence[str]) -> list[str]:
    """Run a script as a program in a tree and describe the result.

    Returns
    -------
    list[str]
        The exit code and the output lines, with the tree's path masked.
    """
    done = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv
        [sys.executable, f"scripts/{name}", *arguments],
        cwd=root,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        check=False,
        timeout=RUN_SECONDS,
    )
    text = (done.stdout + done.stderr).replace(str(root), "<ROOT>")
    return [f"exit code {done.returncode}", *text.splitlines()]


@dc.dataclass(frozen=True, slots=True)
class Setting:
    """How the two copies are run.

    Attributes
    ----------
    links : collections.abc.Mapping[str, pathlib.Path]
        Links for the copies; see :func:`lay_out`.
    program : collections.abc.Sequence[str] | None
        The arguments with which to run the script as a program, for a script
        that no test imports; that run is then compared instead of the tests.
    """

    links: cabc.Mapping[str, Path] = dc.field(default_factory=dict)
    program: cabc.Sequence[str] | None = None


def differences(
    scripts: Path, name: str, pinned: bytes, setting: Setting | None = None
) -> list[str]:
    """Compare the tests, or a program run, under both versions of a script.

    Parameters
    ----------
    scripts : pathlib.Path
        The ``scripts/`` directory, holding the current version.
    name : str
        The script's file name.
    pinned : bytes
        The script's bytes at its pinned commit.
    setting : Setting | None
        Links and the optional program run; none by default.

    Returns
    -------
    list[str]
        One line per test whose outcome differs, or per differing line of the
        program run; empty when the versions are indistinguishable.

    Raises
    ------
    NoCoverageError
        If no test reaches the script and no program run is named.
    """
    setting = setting or Setting()
    tests = reaching_tests(scripts, name)
    if not tests and setting.program is None:
        message = f"no test reaches {name}; add characterisation tests first"
        raise NoCoverageError(message)
    with tempfile.TemporaryDirectory(prefix="pin-equivalence-") as scratch:
        base = Path(scratch)
        now = lay_out(base / "current", scripts, None, setting.links)
        then = lay_out(base / "pinned", scripts, (name, pinned), setting.links)
        if setting.program is not None:
            after = run_program(now, name, setting.program)
            before = run_program(then, name, setting.program)
            return [
                f"program run: pinned {old!r}, current {new!r}"
                for old, new in itertools.zip_longest(before, after)
                if old != new
            ]
        current, earlier = outcomes(now, tests), outcomes(then, tests)
    return [
        f"{key}: pinned {earlier.get(key, 'absent')}, "
        f"current {current.get(key, 'absent')}"
        for key in sorted(current.keys() | earlier.keys())
        if current.get(key) != earlier.get(key)
    ]
