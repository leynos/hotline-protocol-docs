#!/usr/bin/env python3
"""Exercise an unchanged historical shx login callback on the host, in isolation."""

import hashlib
import json
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # the fixed argv runs the host compiler and the built harness with no shell
import typing as typ
from pathlib import Path

CASE_COUNT = 7  # the callback cases that the harness must complete and pass


def _fail(error: type[Exception], message: str) -> typ.NoReturn:
    """Raise ``error`` with ``message``, for a failed check that stops the run."""
    raise error(message)


def _run_text(argv: list[str], *, check: bool) -> subprocess.CompletedProcess[str]:
    """Run ``argv`` with no shell and capture its output as text.

    Returns
    -------
    subprocess.CompletedProcess[str]
        The finished process, with its standard streams captured.
    """
    return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv, no shell
        argv, check=check, capture_output=True, text=True
    )


def _frozen_inputs(root: Path) -> tuple[dict[str, typ.Any], dict[str, str]]:
    """Check every frozen input and keep the three sources that the callback uses.

    Returns
    -------
    tuple[dict[str, typing.Any], dict[str, str]]
        The evidence manifest, and the text of the three retained sources.
    """
    evidence = root / "evidence/gap-remediation/2026-11-12/batch-12"
    manifest = json.loads((evidence / "manifest.json").read_text())
    sources: dict[str, str] = {}
    for entry in manifest["inputs"]:
        content = (evidence / entry["snapshot"]).read_bytes()
        if hashlib.sha256(content).hexdigest() != entry["sha256"]:
            _fail(ValueError, f"Changed frozen source: {entry['path']}")
        if entry["path"] in {"hotline.h", "hxd.h", "hx_commands.c"}:
            sources[entry["path"]] = content.decode()
    return manifest, sources


def _generate(root: Path, sources: dict[str, str]) -> dict[str, str]:
    """Insert the unchanged macros and callback into the harness.

    Returns
    -------
    dict[str, str]
        The generated harness, and the callback and macro text that it holds.
    """
    source = sources["hx_commands.c"]
    start = source.index("static void\nrcv_task_login (")
    callback = source[start : source.index("\nvoid\nhx_connect (", start)]
    header = sources["hxd.h"]
    start = header.index("#define dh_start(")
    macros = header[start : header.index("static inline struct htlc_conn", start)]
    harness = (root / "scripts/shx-login-harness.c").read_text()
    generated = harness.replace("/* INSERT_UNCHANGED_MACROS */", macros).replace(
        "/* INSERT_UNCHANGED_CALLBACK */", callback
    )
    return {"generated": generated, "callback": callback, "macros": macros}


def _write_fragment(root: Path, sources: dict[str, str], generated: str) -> Path:
    """Write the header and the generated source into the fragment directory.

    Returns
    -------
    pathlib.Path
        The fragment directory.
    """
    output = root / "state/shx-login-fragment"
    output.mkdir(parents=True, exist_ok=True)
    (output / "hotline.h").write_text(sources["hotline.h"])
    (output / "login-fragment.c").write_text(generated)
    return output


def _compile_and_run(
    output: Path, manifest: dict[str, typ.Any], pieces: dict[str, str]
) -> dict[str, typ.Any]:
    """Compile the fragment, run its matrix and retain the result record.

    Returns
    -------
    dict[str, typing.Any]
        The record that is written as ``result.json``.
    """
    source_path = output / "login-fragment.c"
    compiler = shutil.which("cc")
    if compiler is None:
        _fail(RuntimeError, "A host C compiler named cc is required")
    command = [
        compiler,
        "-std=gnu11",
        "-Wall",
        "-Wextra",
        str(source_path),
        "-o",
        str(output / "login-fragment"),
    ]
    compiled = _run_text(command, check=False)
    if compiled.returncode:
        _fail(RuntimeError, f"Host callback compile failed:\n{compiled.stderr}")
    result = _run_text([str(output / "login-fragment")], check=True)
    cases = [json.loads(line) for line in result.stdout.splitlines()]
    if len(cases) != CASE_COUNT or not all(case["passed"] for case in cases):
        _fail(ValueError, "Incomplete or failing callback matrix")
    record = {
        "source_commit": manifest["source_git_head"],
        "scope": "Host-built isolated basic-login callback; "
        "not a full client/server run",
        "compiler": subprocess.check_output(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv, no shell
            [compiler, "--version"], text=True
        ),
        "command": command,
        "preprocessor_profile": "No CONFIG_HOPE, CONFIG_CIPHER or CONFIG_COMPRESS",
        "generated_sha256": hashlib.sha256(pieces["generated"].encode()).hexdigest(),
        "callback_sha256": hashlib.sha256(pieces["callback"].encode()).hexdigest(),
        "macros_sha256": hashlib.sha256(pieces["macros"].encode()).hexdigest(),
        "compiler_output": compiled.stdout + compiled.stderr,
        "cases": cases,
    }
    (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


def main() -> None:
    """Exercise the unchanged callback in isolation and retain its record."""
    root = Path(__file__).resolve().parent.parent
    manifest, sources = _frozen_inputs(root)
    pieces = _generate(root, sources)
    output = _write_fragment(root, sources, pieces["generated"])
    record = _compile_and_run(output, manifest, pieces)
    print(
        f"Verified {len(record['cases'])} isolated shx callback cases "
        f"at {record['source_commit']}"
    )


if __name__ == "__main__":
    main()
