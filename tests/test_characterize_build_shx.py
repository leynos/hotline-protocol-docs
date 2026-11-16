"""Characterize the shx build script against a fake build tree and fake tools.

``build-shx.py`` builds and runs an external program, so it is never run here.
The cases give it a small tree in a temporary directory (frozen inputs, a patch,
dependency headers) and stand-ins for ``patch``, ``configure``, ``make``, ``gcc``
and ``ldd``, and record what it refuses, what it would run and what it writes.
The endings were recorded on the script as it stood before it was brought to the
standard (commit 8a3f8cd) in ``data/characterize_build_shx.tsv``.
"""

import contextlib
import dataclasses as dc
import gzip
import hashlib
import io
import json
import sys
import tarfile
import tempfile
import typing as typ
from pathlib import Path
from unittest import mock

import pytest
from characterize_support import Cases, record, replay, scripts_directory
from script_loading import load_script

TABLE = Path(__file__).with_name("data") / "characterize_build_shx.tsv"
SCRIPT = "build-shx.py"
REVISION = "adb1bf8c8cb12f7eb2fa2c01673295a6312f262b"
FROZEN = {
    "source.tar.gz": b"",
    "config.guess": b"guess\n",
    "config.sub": b"sub\n",
}


def build_module() -> typ.Any:  # ruff: ignore[any-type]  # the script is loaded by path, so it has no static type
    """Load the build script, whose file name has a hyphen.

    Returns
    -------
    typing.Any
        The script as a module.
    """
    return load_script(scripts_directory() / SCRIPT, "build_shx")


def tarball(path: Path) -> bytes:
    """Write a small source archive and return its bytes.

    Returns
    -------
    bytes
        The archive.
    """
    # A fixed archive time keeps the digest of the archive the same from run to run.
    with (
        gzip.GzipFile(path, "wb", mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w") as archive,
    ):
        data = b"int main(void) { return 0; }\n"
        info = tarfile.TarInfo("main.c")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return path.read_bytes()


class Fake:
    """Stand-ins for the programs that the build script runs."""

    def __init__(self) -> None:
        """Start with no calls."""
        self.calls: list[dict[str, object]] = []

    def run(self, command: list[str], **options: object) -> None:
        """Record a command, and make the files that a real run would leave."""
        cwd = Path(str(options["cwd"]))
        env = typ.cast("dict[str, str]", options.get("env") or {})
        self.calls.append({
            "command": command,
            "cwd": cwd.name,
            "env": {
                k: env[k] for k in ("CC", "CFLAGS", "CPPFLAGS", "LDFLAGS") if k in env
            },
            "check": options.get("check"),
            "has_stdin": "stdin" in options,
        })
        if command[0] == "bash":
            (cwd / "config.h").write_text("#define X 1\n")
        if command[0] == "make":
            (cwd / "hx").write_bytes(b"binary")

    def output(self, command: list[str], **_options: object) -> str:
        """Answer the two questions that the script asks of the host.

        Returns
        -------
        str
            The compiler banner, or the library listing.
        """
        self.calls.append({"output": command[:1]})
        return (
            "gcc (fake) 1.0\nsecond line\n" if command[0] == "gcc" else "ldd output\n"
        )


def tree(base: Path, module: typ.Any, *, frozen: dict[str, bytes]) -> Path:  # ruff: ignore[any-type]  # the script is loaded by path, so it has no static type
    """Lay out a repository, its frozen inputs and the dependency headers.

    Returns
    -------
    pathlib.Path
        The dependency root.
    """
    root = base / "repo"
    inputs = root / "evidence/gap-remediation/2026-11-13/shx-build-01"
    (inputs / "inputs").mkdir(parents=True)
    (root / "patches").mkdir()
    (root / "patches/shx-modern-c.patch").write_text("patch\n")
    names = dict(frozen)
    names["source.tar.gz"] = tarball(inputs / "inputs/source.tar.gz")
    for name, data in names.items():
        if name != "source.tar.gz":
            (inputs / "inputs" / name).write_bytes(data)
    (inputs / "inputs.json").write_text(
        json.dumps({
            "source_commit": REVISION,
            "inputs": {n: hashlib.sha256(d).hexdigest() for n, d in names.items()},
        })
    )
    module.ROOT = root
    module.INPUTS = inputs
    return root


@dc.dataclass(frozen=True, slots=True)
class Scenario:
    """The faults of one case; the default is a build that nothing refuses."""

    revision: str = REVISION
    change: str = ""
    header: bool = True
    exists: bool = False
    outside: bool = False


def run_main(module: typ.Any) -> None:  # ruff: ignore[any-type]  # the script is loaded by path, so it has no static type
    """Run the script's ``main``, accepting the successful exit of a Cyclopts command.

    Raises
    ------
    SystemExit
        When the script exits with a failure status.
    """
    try:
        module.main()
    except SystemExit as stop:
        if stop.code not in {None, 0}:
            raise


def furnish(module: typ.Any, base: Path, scenario: Scenario) -> tuple[Path, Path]:  # ruff: ignore[any-type]  # the script is loaded by path, so it has no static type
    """Lay out the tree for one case and name the dependency and output roots.

    Returns
    -------
    tuple[pathlib.Path, pathlib.Path]
        The dependency root and the output directory to pass to the script.
    """
    root = tree(base, module, frozen=FROZEN)
    record_file = module.INPUTS / "inputs.json"
    if scenario.revision != REVISION:
        data = json.loads(record_file.read_text())
        data["source_commit"] = scenario.revision
        record_file.write_text(json.dumps(data))
    if scenario.change:
        (module.INPUTS / "inputs" / scenario.change).write_bytes(b"changed")
    deps = root / "tools/shx-deps"
    if scenario.header:
        (deps / "usr/include/readline").mkdir(parents=True)
        (deps / "usr/include/readline/readline.h").write_text("")
        (deps / "usr/lib64").mkdir(parents=True)
        (deps / "usr/lib64/libx.so.1").write_bytes(b"lib")
        (deps / "usr/lib64/libx.so").symlink_to("libx.so.1")
    else:
        deps.mkdir(parents=True)
    output = base / "elsewhere" if scenario.outside else root / "tools/shx-peer"
    if scenario.exists:
        output.mkdir(parents=True)
    return deps, output


def build(scenario: Scenario | None = None) -> object:
    """Run the script's ``main`` on a fake tree and describe what it did.

    Returns
    -------
    object
        What it printed, what it ran and the manifest it wrote.
    """
    scenario = scenario or Scenario()
    module = build_module()
    fake = Fake()
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary).resolve()
        deps, output = furnish(module, base, scenario)
        argv = ["build-shx.py", "--deps-root", str(deps), "--output", str(output)]
        out = io.StringIO()
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(module.subprocess, "run", fake.run),
            mock.patch.object(module.subprocess, "check_output", fake.output),
            contextlib.redirect_stdout(out),
        ):
            run_main(module)
        manifest = json.loads((output / "manifest.json").read_text())
        text = json.dumps(
            {"stdout": out.getvalue(), "calls": fake.calls, "manifest": manifest},
            indent=1,
            sort_keys=True,
        )
        return text.replace(str(base), "<base>")


CASES: Cases = {
    "outside-the-repository": lambda: build(Scenario(outside=True)),
    "other-revision": lambda: build(Scenario(revision="0" * 40)),
    "other-revision-and-outside": lambda: build(
        Scenario(revision="0" * 40, outside=True)
    ),
    "changed-input": lambda: build(Scenario(change="config.sub")),
    "changed-input-and-no-header": lambda: build(
        Scenario(change="config.sub", header=False)
    ),
    "other-revision-and-changed-input": lambda: build(
        Scenario(revision="0" * 40, change="config.sub")
    ),
    "no-header": lambda: build(Scenario(header=False)),
    "output-exists": lambda: build(Scenario(exists=True)),
    "no-header-and-output-exists": lambda: build(Scenario(header=False, exists=True)),
    "success": build,
}


class BuildShxCharacterizationTests:
    """Keep the build script as it was recorded."""

    @pytest.mark.parametrize("name", sorted(CASES))
    def test_each_case_ends_as_it_did(self, name: str) -> None:
        """Each case ends with the exception or result recorded earlier."""
        now, recorded = replay(CASES, TABLE, name)
        assert now == recorded, "ending differs"


def table() -> str:
    """Say how every case ends, for the table; run it only on the earlier scripts.

    Returns
    -------
    str
        The table text.
    """
    return record(CASES)
