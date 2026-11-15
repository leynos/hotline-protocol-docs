#!/usr/bin/env python3
"""Package committed protocol documents and evidence as adjacent checkouts."""

import gzip
import hashlib
import json
import subprocess
from pathlib import Path


def revision(repository: Path) -> str:
    subprocess.run(
        ["git", "diff", "--exit-code", "HEAD", "--"],
        cwd=repository,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repository, text=True
    ).strip()


def archive(repository: Path, commit: str) -> bytes:
    data = subprocess.check_output(
        ["git", "archive", "--format=tar", f"--prefix={repository.name}/", commit],
        cwd=repository,
    )
    return gzip.compress(data, mtime=0)


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    documents = root.parent / "hotline-protocol-docs"
    repositories = (root, documents)
    commits = {path.name: revision(path) for path in repositories}
    identifier = "-".join(commits[path.name][:12] for path in repositories)
    output = root / "state/protocol-exports" / identifier
    archives = {path.name: archive(path, commits[path.name]) for path in repositories}
    output.mkdir(parents=True, exist_ok=False)
    records = []
    for name, data in archives.items():
        filename = f"{name}.tar.gz"
        (output / filename).write_bytes(data)
        records.append(
            {
                "repository": name,
                "commit": commits[name],
                "archive": filename,
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    (output / "manifest.json").write_text(
        json.dumps({"schema_version": 1, "repositories": records}, indent=2) + "\n"
    )
    (output / "README.txt").write_text(
        "Verify SHA256SUMS from this directory, then extract both archives into\n"
        "the same empty parent directory. They create mothra/ and\n"
        "hotline-protocol-docs/ with sibling-relative evidence links intact.\n\n"
        "Archives contain committed files only: no downloaded Ghidra/JDK,\n"
        "runtime state, caches, ignored files or Git history.\n"
        "manifest.json records the exact source commits. The archives are\n"
        "documentation/evidence exports, not standalone Ghidra installations.\n\n"
        "From the extracted mothra directory, Python 3.13+ can run:\n"
        "  python3 scripts/extract-synhxd-evidence.py\n"
        "  python3 scripts/verify-baseline-evidence.py\n"
        "  python3 scripts/render-protocol-gap-analysis.py --check\n"
        "Most evidence/**/SHA256SUMS use that directory; mxd-login-extras-01\n"
        "and native-diagnostic-near-01 use their own corpus directories.\n"
        "Full make check additionally needs the tools described in README.md.\n"
    )
    (output / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in sorted(output.iterdir())
            if path.is_file()
        )
    )
    print(output)


if __name__ == "__main__":
    main()
