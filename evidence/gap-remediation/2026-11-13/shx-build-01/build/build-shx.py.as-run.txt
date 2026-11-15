#!/usr/bin/env python3
"""Build the identified historical shx terminal source using local dependencies."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

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


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deps-root", type=Path, default=ROOT / "tools/shx-deps")
    parser.add_argument("--output", type=Path, default=ROOT / "tools/shx-peer")
    args = parser.parse_args()
    dependencies, output = args.deps_root.resolve(), args.output.resolve()
    if not output.is_relative_to(ROOT) or not dependencies.is_relative_to(ROOT):
        raise ValueError("Build output and dependencies must be inside mothra")
    inputs = json.loads((INPUTS / "inputs.json").read_text())
    if inputs["source_commit"] != REVISION:
        raise ValueError("Historical source revision differs")
    for name, expected in inputs["inputs"].items():
        if digest(INPUTS / "inputs" / name) != expected:
            raise ValueError(f"Changed frozen build input: {name}")
    if not (dependencies / "usr/include/readline/readline.h").is_file():
        raise ValueError(
            "Extract the documented Readline/ncurses RPMs into --deps-root first"
        )
    output.mkdir(parents=True, exist_ok=False)
    source = output / "source"
    source.mkdir()
    with tarfile.open(INPUTS / "inputs/source.tar.gz", "r:gz") as archive:
        archive.extractall(source, filter="data")
    for name in ["config.guess", "config.sub"]:
        shutil.copy2(INPUTS / "inputs" / name, source / name)
    patch = ROOT / "patches/shx-modern-c.patch"
    with patch.open("rb") as data, (output / "patch.log").open("w") as log:
        subprocess.run(
            ["patch", "-p1", "--batch"],
            cwd=source,
            stdin=data,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
        )
    include = "-I" + str(dependencies / "usr/include")
    env = dict(
        os.environ,
        CC="gcc",
        CFLAGS="-O0 -g -std=gnu89 -fcommon " + include,
        CPPFLAGS=include,
        LDFLAGS="-L"
        + str(dependencies / "usr/lib64")
        + " -Wl,-rpath,"
        + str(dependencies / "usr/lib64"),
    )
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
            subprocess.run(
                command,
                cwd=source,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
            )
    binary = source / "hx"
    libraries = {
        str(path.relative_to(dependencies)): digest(path)
        for path in sorted((dependencies / "usr/lib64").glob("*.so.*"))
        if path.is_file() and not path.is_symlink()
    }
    manifest = {
        "source_commit": REVISION,
        "source_archive_sha256": inputs["inputs"]["source.tar.gz"],
        "binary_sha256": digest(binary),
        "binary": str(binary.relative_to(ROOT)),
        "patch_sha256": digest(patch),
        "config_h_sha256": digest(source / "config.h"),
        "configuration_flags": FLAGS,
        "compiler": subprocess.check_output(
            ["gcc", "--version"], text=True
        ).splitlines()[0],
        "environment": {
            key: env[key] for key in ["CC", "CFLAGS", "CPPFLAGS", "LDFLAGS"]
        },
        "commands": commands,
        "libraries": libraries,
        "ldd": subprocess.check_output(["ldd", str(binary)], text=True),
        "identity": "Modern Linux build of shx0.1.48 historical source; four cast-lvalue syntax substitutions and modern host detection, no claim of original distributed binary identity.",
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(binary)
    print(manifest["binary_sha256"])


if __name__ == "__main__":
    main()
