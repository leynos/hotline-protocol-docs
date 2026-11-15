#!/usr/bin/env python3
"""Exercise an unchanged historical shx login callback on the host, in isolation."""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    evidence = root / "evidence/gap-remediation/2026-11-12/batch-12"
    manifest = json.loads((evidence / "manifest.json").read_text())
    sources = {}
    for entry in manifest["inputs"]:
        content = (evidence / entry["snapshot"]).read_bytes()
        if hashlib.sha256(content).hexdigest() != entry["sha256"]:
            raise ValueError(f"Changed frozen source: {entry['path']}")
        if entry["path"] in {"hotline.h", "hxd.h", "hx_commands.c"}:
            sources[entry["path"]] = content.decode()
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
    output = root / "state/shx-login-fragment"
    output.mkdir(parents=True, exist_ok=True)
    (output / "hotline.h").write_text(sources["hotline.h"])
    source_path = output / "login-fragment.c"
    source_path.write_text(generated)
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("A host C compiler named cc is required")
    command = [
        compiler,
        "-std=gnu11",
        "-Wall",
        "-Wextra",
        str(source_path),
        "-o",
        str(output / "login-fragment"),
    ]
    compiled = subprocess.run(command, check=False, capture_output=True, text=True)
    if compiled.returncode:
        raise RuntimeError(f"Host callback compile failed:\n{compiled.stderr}")
    result = subprocess.run(
        [str(output / "login-fragment")], check=True, capture_output=True, text=True
    )
    cases = [json.loads(line) for line in result.stdout.splitlines()]
    if len(cases) != 7 or not all(case["passed"] for case in cases):
        raise ValueError("Incomplete or failing callback matrix")
    record = {
        "source_commit": manifest["source_git_head"],
        "scope": "Host-built isolated basic-login callback; not a full client/server run",
        "compiler": subprocess.check_output([compiler, "--version"], text=True),
        "command": command,
        "preprocessor_profile": "No CONFIG_HOPE, CONFIG_CIPHER or CONFIG_COMPRESS",
        "generated_sha256": hashlib.sha256(generated.encode()).hexdigest(),
        "callback_sha256": hashlib.sha256(callback.encode()).hexdigest(),
        "macros_sha256": hashlib.sha256(macros.encode()).hexdigest(),
        "compiler_output": compiled.stdout + compiled.stderr,
        "cases": cases,
    }
    (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    print(
        f"Verified {len(cases)} isolated shx callback cases at {record['source_commit']}"
    )


if __name__ == "__main__":
    main()
