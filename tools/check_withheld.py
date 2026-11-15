"""Check the manifest of withheld files and scan history for them.

``evidence/withheld.json`` lists files that are never published. ``check``
confirms that none is tracked, that each is covered by ``.gitignore``, that a
local copy (when present) matches its recorded size and SHA-256, and that each
BSDIFF40 patch is tracked, hashes as recorded and, when its base is present,
rebuilds the recorded result. ``--scan-history`` additionally examines every
blob of a repository. ``write-manifest`` builds the manifest from real files.

Run ``python3 tools/check_withheld.py check --root .``. Exit codes: 0 success,
1 findings, 2 missing inputs.
"""

import dataclasses as dc
import operator
import sys
import typing as typ
from pathlib import Path

import bsdiff4
import cyclopts
from git_lossless import git_names, git_text
from tool_support import MissingInputError, invoke
from withheld_history import scan_history
from withheld_model import (
    MANIFEST_RELATIVE,
    PATCH_SUFFIX,
    Entry,
    Manifest,
    NotedReport,
    Patch,
    load_manifest,
    render_manifest,
    sha256_bytes,
    sha256_of,
)

app = cyclopts.App(result_action="return_value")


@dc.dataclass(frozen=True, slots=True)
class ManifestRequest:
    """What ``write-manifest`` is asked to record.

    Attributes
    ----------
    root : pathlib.Path
        The repository that receives the manifest and any patches.
    source_root : pathlib.Path
        The tree that holds the real withheld files.
    reason : str
        Why the files are withheld.
    specs : tuple[tuple[str, str], ...]
        ``(fork, path)`` pairs.
    patch_bases : dict[str, str]
        For an entry stored as a patch, the path of its base file.
    """

    root: Path
    source_root: Path
    reason: str
    specs: tuple[tuple[str, str], ...]
    patch_bases: dict[str, str] = dc.field(default_factory=dict)


@dc.dataclass(frozen=True, slots=True)
class Context:
    """What one run of the entry checks shares.

    Attributes
    ----------
    root : pathlib.Path
        The repository root.
    manifest : Manifest
        The manifest under check.
    tracked : frozenset[str]
        The manifest's paths that Git tracks.
    report : NotedReport
        Receives failures and notes.
    """

    root: Path
    manifest: Manifest
    tracked: frozenset[str]
    report: NotedReport


def write_manifest(request: ManifestRequest) -> Manifest:
    """Build the manifest, and any patches, from the real files.

    Parameters
    ----------
    request : ManifestRequest
        The files to record.

    Returns
    -------
    Manifest
        The manifest that was written.

    Raises
    ------
    MissingInputError
        If a listed source file is absent.
    """
    entries: list[Entry] = []
    for fork, path in sorted(request.specs, key=operator.itemgetter(1)):
        source = request.source_root / path
        if not source.is_file():
            message = f"withheld source file {source} is absent"
            raise MissingInputError(message)
        data = source.read_bytes()
        patch = None
        if path in request.patch_bases:
            base = (request.source_root / request.patch_bases[path]).read_bytes()
            patch = _write_patch(request.root, path, (base, data))
        entries.append(Entry(path, len(data), sha256_of(source), fork, patch))
    manifest = Manifest(reason=request.reason, files=tuple(entries))
    target = request.root / MANIFEST_RELATIVE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_manifest(manifest), encoding="utf-8")
    return manifest


def _write_patch(root: Path, path: str, pair: tuple[bytes, bytes]) -> Patch:
    """Store the patch that rebuilds ``pair[1]`` from ``pair[0]``.

    Returns
    -------
    Patch
        The patch description.
    """
    base, data = pair
    stored = root / (path + PATCH_SUFFIX)
    stored.parent.mkdir(parents=True, exist_ok=True)
    stored.write_bytes(bsdiff4.diff(base, data))
    return Patch(
        path=path + PATCH_SUFFIX,
        base_sha256=sha256_bytes(base),
        patch_sha256=sha256_of(stored),
        result_sha256=sha256_bytes(data),
    )


def _check_copy(ctx: Context, entry: Entry) -> None:
    """Verify a local copy of a withheld file, if there is one."""
    target = ctx.root / entry.path
    if not target.is_file():
        ctx.report.notes.append(f"{entry.path}: withheld (absent)")
    elif target.stat().st_size != entry.size:
        ctx.report.failures.append(
            f"{entry.path}: size {target.stat().st_size} differs from {entry.size}"
        )
    elif sha256_of(target) != entry.sha256:
        ctx.report.failures.append(f"{entry.path}: sha256 differs from the manifest")
    else:
        ctx.report.notes.append(f"{entry.path}: verified")


def _check_patch_file(ctx: Context, entry: Entry, patch: Patch) -> bool:
    """Check that a patch file exists, is tracked and is the recorded one.

    Returns
    -------
    bool
        ``True`` when the patch may be applied.
    """
    stored = ctx.root / patch.path
    failures = ctx.report.failures
    if not stored.is_file():
        failures.append(f"{patch.path}: patch file missing")
    elif patch.path not in ctx.tracked:
        failures.append(f"{patch.path}: patch file untracked")
    elif sha256_of(stored) != patch.patch_sha256:
        failures.append(f"{patch.path}: patch sha256 differs from the manifest")
    else:
        if patch.result_sha256 != entry.sha256:
            failures.append(f"{entry.path}: patch result_sha256 is not the entry's")
        return True
    return False


def _check_patch(ctx: Context, entry: Entry) -> None:
    """Check an entry's patch, and apply it when its base is present."""
    patch = entry.patch
    if patch is None or not _check_patch_file(ctx, entry, patch):
        return
    bases = [e for e in ctx.manifest.files if e.sha256 == patch.base_sha256]
    base = ctx.root / bases[0].path if bases else None
    if base is None:
        ctx.report.failures.append(f"{entry.path}: patch base matches no entry")
    elif not base.is_file():
        ctx.report.notes.append(f"{entry.path}: patch not exercised: base absent")
    elif sha256_of(base) != patch.base_sha256:
        # The base's own entry already reports the mismatch.
        ctx.report.notes.append(f"{entry.path}: patch not exercised: base differs")
    else:
        rebuilt = bsdiff4.patch(base.read_bytes(), (ctx.root / patch.path).read_bytes())
        if sha256_bytes(rebuilt) == patch.result_sha256:
            ctx.report.notes.append(f"{entry.path}: patch verified")
        else:
            ctx.report.failures.append(f"{entry.path}: patch result sha256 differs")


def _scan(history: Path, manifest: Manifest, report: NotedReport) -> None:
    """Scan a repository's blobs and record the findings."""
    scan = scan_history(history, manifest)
    report.failures.extend(f"history: blob {line}" for line in scan.found)
    report.notes.append(
        f"{scan.blobs} blobs scanned, {len(scan.found)} withheld objects"
    )


def check(root: Path, history: Path | None = None) -> NotedReport:
    """Check the manifest below ``root``.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    history : pathlib.Path | None
        A repository whose every object is scanned for withheld content.

    Returns
    -------
    NotedReport
        The failures and the informational lines.
    """
    manifest = load_manifest(root / MANIFEST_RELATIVE)
    report = NotedReport(checked=len(manifest.files))
    paths = [e.path for e in manifest.files]
    paths += [e.patch.path for e in manifest.files if e.patch]
    tracked: frozenset[str] = frozenset()
    ignored: frozenset[str] = frozenset()
    if paths:
        tracked = frozenset(git_names(root, "ls-files", "-z", "--", *paths))
        found = git_text(root, "check-ignore", "--no-index", "--", *paths, ok=(0, 1))
        ignored = frozenset(found.splitlines())
    ctx = Context(root, manifest, tracked, report)
    for entry in manifest.files:
        if entry.path in tracked:
            report.failures.append(f"{entry.path}: tracked by Git, so it is published")
        if entry.path not in ignored:
            report.failures.append(f"{entry.path}: not ignored by .gitignore")
        _check_copy(ctx, entry)
        _check_patch(ctx, entry)
    if history is not None:
        _scan(history, manifest, report)
    return report


@app.command(name="check")
def run_check(
    root: Path = Path(),
    *,
    scan_history: bool = False,
    repository: Path | None = None,
) -> int:
    """Check the withheld manifest, optionally scanning every blob of history.

    Parameters
    ----------
    root
        The repository root that holds ``evidence/withheld.json``.
    scan_history
        Also scan every blob of ``repository`` for withheld content.
    repository
        The repository to scan; defaults to ``root``.

    Returns
    -------
    int
        0 when everything holds, otherwise 1.
    """
    history = (repository or root) if scan_history else None
    report = check(root, history)
    for line in report.failures:
        sys.stdout.write(f"{line}\n")
    for line in report.notes:
        sys.stdout.write(f"{line}\n")
    sys.stdout.write(f"{report.checked} entries, {len(report.failures)} failures\n")
    return report.exit_code


@cyclopts.Parameter(name="*")
@dc.dataclass(frozen=True, slots=True)
class WriteArguments:
    """The options of ``write-manifest``.

    Attributes
    ----------
    root : pathlib.Path
        The repository that receives the manifest and the patches.
    source_root : pathlib.Path
        The tree that holds the real files.
    reason : str
        Why the files are withheld.
    entry : list[str]
        ``FORK=PATH`` for each withheld file; repeat the option.
    patch_base : list[str]
        ``PATH=BASE`` for each file stored as a patch against another.
    """

    source_root: Path
    reason: str
    entry: list[str]
    root: Path = Path()
    patch_base: list[str] = dc.field(default_factory=list)


@app.command(name="write-manifest")
def run_write(arguments: WriteArguments) -> int:
    """Record withheld files, reading the real ones, and write their patches.

    Parameters
    ----------
    arguments
        The options.

    Returns
    -------
    int
        0 after the manifest is written.
    """
    specs = tuple(tuple(item.split("=", 1)) for item in arguments.entry)
    bases = dict(item.split("=", 1) for item in arguments.patch_base)
    request = ManifestRequest(
        root=arguments.root,
        source_root=arguments.source_root,
        reason=arguments.reason,
        specs=typ.cast("tuple[tuple[str, str], ...]", specs),
        patch_bases=bases,
    )
    manifest = write_manifest(request)
    sys.stdout.write(f"{len(manifest.files)} entries written\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the command line and return the process exit code.

    Parameters
    ----------
    argv : list[str] | None
        Command-line tokens, or ``None`` to read ``sys.argv``.

    Returns
    -------
    int
        The exit code: 0, 1 or 2.
    """
    return invoke(app, argv)


if __name__ == "__main__":
    sys.exit(main())
