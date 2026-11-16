"""The planner oracle: the bytes of every plan the ``*_cases.py`` files emit.

Each planner is run offline, from the repository root, against retained
runtime records. Nothing here starts an emulator, Ghidra, a capture or a build.
A planner that cannot emit offline is recorded as skipped, with the reason.
"""

import ast
import dataclasses as dc
import json
import re
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # the oracle runs the planners
import typing as typ

import golden_model as gm
from golden_inputs import (
    CASE,
    DISPATCHER,
    DRIVER,
    IN_PROCESS,
    OUT,
    SKIPPED,
    SUITE_EXTRAS,
    SYNTHETIC_RUNTIME,
    Direct,
    direct_specs,
)

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

CHOICES = re.compile(r"\{([^{}\s]+)\}")


@dc.dataclass(frozen=True, slots=True)
class PlannerRun:
    """Where the planners run and how their output is normalised.

    Attributes
    ----------
    root : pathlib.Path
        The repository root, used as the working directory.
    scratch : pathlib.Path
        An empty directory that receives every run's output.
    normaliser : golden_model.Normaliser
        Normalises the planners' stdout and embedded script digests.
    """

    root: Path
    scratch: Path
    normaliser: gm.Normaliser


def _slug(key: str) -> str:
    """Turn ``key`` into a name that is safe for a directory.

    Returns
    -------
    str
        ``key`` with each run of other characters replaced by one hyphen.
    """
    return re.sub(r"[^A-Za-z0-9]+", "-", key).strip("-")


def _execute(run: PlannerRun, argv: cabc.Sequence[str], slug: str) -> gm.Record:
    """Run one planner command and record the files that appeared.

    Returns
    -------
    dict[str, typing.Any]
        The exit code, the digest of stdout, and one entry per emitted file.
    """
    out = run.scratch / slug / "out"
    out.parent.mkdir(parents=True, exist_ok=True)
    command = [gm.PYTHON3, *(a.replace(OUT, str(out)) for a in argv)]
    done = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # argv is built from the table
        command, cwd=run.root, capture_output=True, check=False
    )
    files = {}
    paths = [out] if out.is_file() else sorted(out.rglob("*")) if out.is_dir() else []
    for path in (p for p in paths if p.is_file()):
        raw = path.read_bytes()
        content, named = run.normaliser.plan(raw)
        name = "(the output file)" if path == out else str(path.relative_to(out))
        files[name] = {
            "sha256": gm.sha256_hex(content),
            "size": len(gm.settle(raw)),
            "embeds_script_digests": named,
        }
    return {
        "status": "emitted" if files and done.returncode == 0 else "failed",
        "exit_code": done.returncode,
        "stdout_sha256": gm.sha256_hex(run.normaliser.text(done.stdout).encode()),
        "files": files,
    }


def choices_of(run: PlannerRun, file: str) -> list[str]:
    """Read a planner's positional choices from its ``--help``.

    Returns
    -------
    list[str]
        The names in the first ``{a,b,c}`` of the usage line.
    """
    done = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # argv is built from the table
        [gm.PYTHON3, f"scripts/{file}", "--help"],
        cwd=run.root,
        capture_output=True,
        text=True,
        check=False,
    )
    found = CHOICES.search(done.stdout)
    return found.group(1).split(",") if found else []


def _runtime_for(run: PlannerRun, key: str, spec: Direct) -> str:
    """Name the runtime record a spec runs on, patching a copy if it has an overlay.

    Returns
    -------
    str
        The retained record, or the path of a patched copy in the scratch tree.
    """
    if not spec.overlay:
        return spec.runtime
    patched = run.scratch / f"{_slug(key)}-runtime.json"
    record = json.loads((run.root / spec.runtime).read_text(encoding="utf-8"))
    patched.write_text(json.dumps({**record, **dict(spec.overlay)}), encoding="utf-8")
    return str(patched)


def build_jobs(run: PlannerRun) -> dict[str, list[str]]:
    """List every planner command that the oracle runs.

    Returns
    -------
    dict[str, list[str]]
        Arguments after the interpreter, keyed by planner file and case.
    """
    runtime = run.scratch / "runtime.json"
    runtime.write_text(json.dumps(SYNTHETIC_RUNTIME), encoding="utf-8")
    jobs: dict[str, list[str]] = {}
    for spec in direct_specs():
        cases = choices_of(run, spec.file) if spec.cases else [""]
        for case in cases:
            key = " ".join(p for p in (spec.file, case, spec.label) if p)
            args = spec.args(_runtime_for(run, key, spec))
            args = [a.replace(CASE, case) for a in args if a != CASE or case]
            jobs[key] = [f"scripts/{spec.file}", *args]
    for suite in choices_of(run, DISPATCHER):
        extra = SUITE_EXTRAS.get(suite, ())
        jobs[f"{DISPATCHER} {suite}"] = [
            *(f"scripts/{DISPATCHER}", suite, "--runtime-record", str(runtime)),
            *("--output", OUT, *extra),
        ]
    for file, (record, port) in IN_PROCESS.items():
        jobs[file] = ["-c", DRIVER, file, record, port, OUT]
    return jobs


def capture_planners(
    run: PlannerRun, filters: cabc.Sequence[str]
) -> dict[str, gm.Record]:
    """Run every selected planner and record its plans.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        Records keyed by planner file and, where it has several, the case.
    """
    jobs = build_jobs(run)
    records: dict[str, gm.Record] = {}
    for key in gm.select(sorted(jobs), filters):
        if key in SKIPPED:
            records[key] = {"status": "skipped", "reason": SKIPPED[key]}
        else:
            records[key] = _execute(run, jobs[key], _slug(key))
    return records


def _imported_modules(source: Path) -> set[str]:
    """List the modules that a script imports, with or without ``from``.

    Returns
    -------
    set[str]
        Dotted module names.
    """
    tree = ast.parse(source.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        match node:
            case ast.ImportFrom(module=str() as module):
                names.add(module)
            case ast.Import(names=aliases):
                names.update(alias.name for alias in aliases)
    return names


def coverage(root: Path) -> dict[str, str]:
    """Say how each ``scripts/*_cases.py`` planner is exercised.

    Returns
    -------
    dict[str, str]
        File name to role: ``direct`` (own command line), ``in-process``
        (``write_plans`` called directly), ``dispatcher`` or ``via
        prepare_native_cases.py`` (a library its suites call).

    Raises
    ------
    RuntimeError
        If a planner file fits none of those roles.
    """
    imported = _imported_modules(root / "scripts" / DISPATCHER)
    direct = {spec.file for spec in direct_specs()}
    roles = {}
    for path in sorted((root / "scripts").glob("*_cases.py")):
        if path.name == DISPATCHER:
            roles[path.name] = "dispatcher"
        elif path.name in direct:
            roles[path.name] = "direct"
        elif path.name in IN_PROCESS:
            roles[path.name] = "in-process"
        elif path.stem in imported:
            roles[path.name] = f"via {DISPATCHER}"
        else:
            message = f"{path.name} has no way to emit plans offline"
            raise RuntimeError(message)
    return roles
