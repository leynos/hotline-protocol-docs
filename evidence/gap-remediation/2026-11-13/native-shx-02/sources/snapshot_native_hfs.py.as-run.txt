#!/usr/bin/env python3
"""Retain bounded, read-only HFS catalogue/fork observations using SleuthKit."""

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def snapshot(
    image: Path, tools: Path, start: int, end: int, roots: list[str], output: Path
) -> dict:
    """Record positive direct lookups; failed probes never prove path absence."""
    if not 2 <= start <= end or end - start >= 4096 or not roots:
        raise ValueError(
            "Require roots and an ordered range of at most4096 catalogue IDs"
        )
    if not image.is_file():
        raise ValueError("Image must exist")
    executables = {name: tools / name for name in ["istat", "icat"]}
    identities = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in executables.items()
    }
    output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, LD_LIBRARY_PATH=str(tools.resolve().parent / "lib64"))
    records, probes = [], []
    for catalog in range(start, end + 1):
        result = subprocess.run(
            [str(executables["istat"]), "-f", "hfs", str(image), str(catalog)],
            env=env,
            check=False,
            capture_output=True,
            timeout=15,
        )
        probes.append(
            {
                "catalog": catalog,
                "exit_code": result.returncode,
                "stderr": result.stderr.decode(errors="replace"),
            }
        )
        if result.returncode:
            continue
        stat = result.stdout.decode(errors="replace")
        name = next(
            (
                line.removeprefix("File Path: ")
                for line in stat.splitlines()
                if line.startswith("File Path: ")
            ),
            "",
        )
        if not any(
            name == root or name.startswith(root.rstrip("/") + "/") for root in roots
        ):
            continue
        key = f"catalog-{catalog}"
        (output / (key + ".stat.txt")).write_bytes(result.stdout)
        directory = "Type:\tFolder" in stat
        record = {
            "path": name,
            "key": key,
            "catalog": catalog,
            "directory": directory,
            "attributes": {},
        }
        if not directory:
            for suffix, attribute in [("data", "4352-0"), ("rsrc", "4353-1")]:
                fork = subprocess.run(
                    [
                        str(executables["icat"]),
                        "-f",
                        "hfs",
                        str(image),
                        f"{catalog}-{attribute}",
                    ],
                    env=env,
                    check=False,
                    capture_output=True,
                    timeout=15,
                )
                (output / (key + "." + suffix)).write_bytes(fork.stdout)
                if fork.stderr:
                    (output / (key + "." + suffix + ".stderr")).write_bytes(fork.stderr)
                record["attributes"][suffix] = {
                    "attribute": attribute,
                    "exit_code": fork.returncode,
                    "bytes": len(fork.stdout),
                    "stderr": fork.stderr.decode(errors="replace"),
                }
        records.append(record)
    report = {
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "image": str(image),
        "tool_sha256": identities,
        "catalog_range": [start, end],
        "roots": roots,
        "method": "Read-only direct catalogue observations. Positive paths verified by istat before fork reads. Not an exhaustive directory listing, path-absence proof, protocol certification or restart-durability result.",
        "probes": probes,
        "records": records,
    }
    (output / "extraction.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--tsk-bin", type=Path, required=True)
    parser.add_argument("--catalog-range", nargs=2, type=int, required=True)
    parser.add_argument("--root", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = snapshot(
        args.image,
        args.tsk_bin,
        args.catalog_range[0],
        args.catalog_range[1],
        args.root,
        args.output,
    )
    print(
        f"Retained {len(report['records'])} positive catalogue records; inspect every probe/fork status"
    )


if __name__ == "__main__":
    main()
