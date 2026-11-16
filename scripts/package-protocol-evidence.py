#!/usr/bin/env python3
"""Package committed protocol documents and evidence as adjacent checkouts."""

import gzip
import hashlib
import json
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # runs git with fixed argv lists and no shell
from pathlib import Path


def git_argv(*arguments: str) -> list[str]:
    """Return the argument vector that runs Git with ``arguments``.

    Parameters
    ----------
    *arguments : str
        The Git arguments, after the program name.

    Returns
    -------
    list[str]
        The argument vector, with Git resolved from ``PATH`` as before.
    """
    return ["git", *arguments]


def revision(repository: Path) -> str:
    """Return the HEAD commit of a checkout whose worktree matches it.

    Parameters
    ----------
    repository : Path
        The repository to inspect.

    Returns
    -------
    str
        The full commit identifier.
    """
    subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv, no shell
        git_argv("diff", "--exit-code", "HEAD", "--"),
        cwd=repository,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return subprocess.check_output(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv, no shell
        git_argv("rev-parse", "HEAD"), cwd=repository, text=True
    ).strip()


def archive(repository: Path, commit: str) -> bytes:
    """Return a gzipped tar archive of one commit, without timestamps.

    Parameters
    ----------
    repository : Path
        The repository to archive.
    commit : str
        The commit to archive.

    Returns
    -------
    bytes
        The gzip-compressed archive.
    """
    data = subprocess.check_output(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv; the commit comes from rev-parse, no shell
        git_argv("archive", "--format=tar", f"--prefix={repository.name}/", commit),
        cwd=repository,
    )
    return gzip.compress(data, mtime=0)


def main() -> None:
    """Write the archives, manifest, README and checksums for both checkouts."""
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
        records.append({
            "repository": name,
            "commit": commits[name],
            "archive": filename,
            "sha256": hashlib.sha256(data).hexdigest(),
        })
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
