#!/usr/bin/env python3
"""Build the identified historical shx terminal source using local dependencies."""

import hashlib
import json
import os
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # the build runs fixed argv lists only, as before
import tarfile
import typing as typ
from pathlib import Path

from script_cli import run

ROOT = Path(__file__).resolve().parent.parent
INPUTS = ROOT / "evidence/gap-remediation/2026-11-13/shx-build-01"
REVISION = "adb1bf8c8cb12f7eb2fa2c01673295a6312f262b"
FLAGS = [
    "--enable-tty",
    "--enable-hfs",
    "--enable-htxf-fork",
    "--disable-gtk",
    "--disable-hope",
    "--disable-cipher",
    "--disable-compress",
    "--disable-ipv6",
]


def fail(message: str) -> typ.NoReturn:
    """Raise the ValueError that refuses a build.

    Parameters
    ----------
    message : str
        The reason the build was refused.

    Raises
    ------
    ValueError
        Always, with ``message``.
    """
    raise ValueError(message)


def digest(path: Path) -> str:
    """Return the SHA-256 hexadecimal digest of the bytes of a file.

    Parameters
    ----------
    path : pathlib.Path
        The file to hash.

    Returns
    -------
    str
        The lowercase hexadecimal digest.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _RunOptions(typ.TypedDict, total=False):
    """The keyword arguments that the build passes to ``subprocess.run``."""

    cwd: Path
    env: dict[str, str]
    stdin: typ.IO[bytes]
    stdout: typ.IO[str]
    stderr: int


def run_tool(
    command: list[str], *, check: bool, **options: typ.Unpack[_RunOptions]
) -> None:
    """Run one build command, to completion, with the given options.

    Parameters
    ----------
    command : list[str]
        The fixed argument vector of the command.
    check : bool
        Whether a failing command raises ``subprocess.CalledProcessError``.
    **options : _RunOptions
        The remaining keyword arguments of ``subprocess.run``.
    """
    subprocess.run(command, check=check, **options)  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv lists built in this module, never shell text


def capture_tool(command: list[str]) -> str:
    """Run one command and return its standard output as text.

    Parameters
    ----------
    command : list[str]
        The fixed argument vector of the command.

    Returns
    -------
    str
        The text the command wrote to standard output.
    """
    return subprocess.check_output(command, text=True)  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv lists built in this module, never shell text


def patch_file() -> Path:
    """Return the patch that makes the historical source build on this host.

    Returns
    -------
    pathlib.Path
        The patch under the repository root.
    """
    return ROOT / "patches/shx-modern-c.patch"


def locations(deps_root: str | None, output: str | None) -> tuple[Path, Path]:
    """Resolve the dependency and output directories and keep them in the repository.

    Parameters
    ----------
    deps_root : str | None
        The directory of the extracted Readline and ncurses files, or ``None``
        for ``tools/shx-deps`` under the repository root.
    output : str | None
        The directory to create, or ``None`` for ``tools/shx-peer`` under the
        repository root.

    Returns
    -------
    tuple[pathlib.Path, pathlib.Path]
        The resolved dependency and output directories, both inside the
        repository root; a location outside it is refused with ``ValueError``.
    """
    dependencies = (
        ROOT / "tools/shx-deps" if deps_root is None else Path(deps_root)
    ).resolve()
    target = (ROOT / "tools/shx-peer" if output is None else Path(output)).resolve()
    if not target.is_relative_to(ROOT) or not dependencies.is_relative_to(ROOT):
        fail("Build output and dependencies must be inside mothra")
    return dependencies, target


def frozen_inputs() -> dict[str, typ.Any]:
    """Read the record of the frozen build inputs and check it against the files.

    Returns
    -------
    dict[str, typing.Any]
        The parsed ``inputs.json`` record; a changed revision or input file is
        refused with ``ValueError``.
    """
    inputs = json.loads((INPUTS / "inputs.json").read_text())
    if inputs["source_commit"] != REVISION:
        fail("Historical source revision differs")
    for name, expected in inputs["inputs"].items():
        if digest(INPUTS / "inputs" / name) != expected:
            fail(f"Changed frozen build input: {name}")
    return inputs


def require_readline(dependencies: Path) -> None:
    """Check that the Readline header was extracted into the dependency directory.

    Parameters
    ----------
    dependencies : pathlib.Path
        The dependency directory; a missing header is refused with ``ValueError``.
    """
    if not (dependencies / "usr/include/readline/readline.h").is_file():
        fail("Extract the documented Readline/ncurses RPMs into --deps-root first")


def unpack(output: Path) -> Path:
    """Extract the frozen source archive and its configure helper scripts.

    Parameters
    ----------
    output : pathlib.Path
        The build output directory, which already exists.

    Returns
    -------
    pathlib.Path
        The directory holding the extracted source.
    """
    source = output / "source"
    source.mkdir()
    with tarfile.open(INPUTS / "inputs/source.tar.gz", "r:gz") as archive:
        archive.extractall(source, filter="data")
    for name in ["config.guess", "config.sub"]:
        shutil.copy2(INPUTS / "inputs" / name, source / name)
    return source


def apply_patch(source: Path, output: Path) -> None:
    """Apply the portability patch to the extracted source.

    Parameters
    ----------
    source : pathlib.Path
        The extracted source directory.
    output : pathlib.Path
        The build output directory, which receives ``patch.log``.
    """
    with patch_file().open("rb") as data, (output / "patch.log").open("w") as log:
        run_tool(
            ["patch", "-p1", "--batch"],
            cwd=source,
            stdin=data,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
        )


def environment(dependencies: Path) -> dict[str, str]:
    """Return the process environment in which the source is configured and built.

    Parameters
    ----------
    dependencies : pathlib.Path
        The dependency directory whose include and library paths are used.

    Returns
    -------
    dict[str, str]
        The current environment with the compiler and linker variables set.
    """
    include = "-I" + str(dependencies / "usr/include")
    return dict(
        os.environ,
        CC="gcc",
        CFLAGS="-O0 -g -std=gnu89 -fcommon " + include,
        CPPFLAGS=include,
        LDFLAGS="-L"
        + str(dependencies / "usr/lib64")
        + " -Wl,-rpath,"
        + str(dependencies / "usr/lib64"),
    )


def configure_and_build(
    source: Path, output: Path, env: dict[str, str]
) -> list[list[str]]:
    """Configure the source, then build its ``hx`` target, logging each step.

    Parameters
    ----------
    source : pathlib.Path
        The extracted source directory, where the commands run.
    output : pathlib.Path
        The build output directory, which receives the step logs.
    env : dict[str, str]
        The environment of both commands.

    Returns
    -------
    list[list[str]]
        The two command vectors, in the order they ran.
    """
    commands = [
        [
            "bash",
            "configure",
            "--cache-file=/dev/null",
            "--prefix=" + str(output / "install"),
            *FLAGS,
        ],
        ["make", "-j2", "hx"],
    ]
    for command, name in zip(commands, ["configure", "build"], strict=True):
        with (output / (name + ".log")).open("w") as log:
            run_tool(
                command,
                cwd=source,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
            )
    return commands


def libraries(dependencies: Path) -> dict[str, str]:
    """Return the digests of the shared libraries in the dependency directory.

    Parameters
    ----------
    dependencies : pathlib.Path
        The dependency directory.

    Returns
    -------
    dict[str, str]
        The path of each shared library, relative to the dependency directory,
        and its digest.
    """
    return {
        str(path.relative_to(dependencies)): digest(path)
        for path in sorted((dependencies / "usr/lib64").glob("*.so.*"))
        if path.is_file() and not path.is_symlink()
    }


def build(*, deps_root: str | None = None, output: str | None = None) -> None:
    """Build the shx peer from the frozen source and print its binary and digest.

    Parameters
    ----------
    deps_root : str | None
        The directory of the extracted Readline and ncurses files, default
        ``tools/shx-deps`` under the repository root.
    output : str | None
        The directory to create for the build, default ``tools/shx-peer`` under
        the repository root.
    """
    dependencies, target = locations(deps_root, output)
    inputs = frozen_inputs()
    require_readline(dependencies)
    target.mkdir(parents=True, exist_ok=False)
    source = unpack(target)
    apply_patch(source, target)
    env = environment(dependencies)
    commands = configure_and_build(source, target, env)
    libraries_found = libraries(dependencies)
    binary = source / "hx"
    manifest = {
        "source_commit": REVISION,
        "source_archive_sha256": inputs["inputs"]["source.tar.gz"],
        "binary_sha256": digest(binary),
        "binary": str(binary.relative_to(ROOT)),
        "patch_sha256": digest(patch_file()),
        "config_h_sha256": digest(source / "config.h"),
        "configuration_flags": FLAGS,
        "compiler": capture_tool(["gcc", "--version"]).splitlines()[0],
        "environment": {
            key: env[key] for key in ["CC", "CFLAGS", "CPPFLAGS", "LDFLAGS"]
        },
        "commands": commands,
        "libraries": libraries_found,
        "ldd": capture_tool(["ldd", str(binary)]),
        "identity": (
            "Modern Linux build of shx0.1.48 historical source; four cast-lvalue "
            "syntax substitutions and modern host detection, no claim of original "
            "distributed binary identity."
        ),
    }
    (target / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(binary)
    print(manifest["binary_sha256"])


def main() -> None:
    """Build the identified historical shx terminal source using local dependencies."""
    run(build, __doc__)


if __name__ == "__main__":
    main()
