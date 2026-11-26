"""Verify every ``SHA256SUMS`` file under ``evidence/``.

Each line is ``<sha256>  <path>`` (or ``<sha256> *<path>``); a leading
backslash marks a name whose backslash, newline and carriage return are written
as backslash escapes. A path
is resolved from the repository root and otherwise from the sums file's own
directory. Each entry ends in one outcome: ``ok``, ``mismatch`` (failure),
``withheld`` (absent, as ``evidence/withheld.json`` allows), ``not imported``
(inside a corpus that ``evidence/curation.json`` excludes), ``external``
(outside ``evidence/``, so not verified) or ``missing`` (failure). A Git LFS
pointer where content belongs is a failure that names ``git lfs pull``.

Run ``python3 tools/check_sums.py check --root .``; ``lfs`` checks the
storage rule instead. Exit codes: 0 success, 1 findings, 2 missing inputs.
"""

import dataclasses as dc
import hashlib
import posixpath
import sys
from pathlib import Path

import cyclopts
from evidence_corpus import corpus_of, load_excluded
from lfs_rule import POINTER_PREFIX, check_lfs
from pinned_evidence import RECORD_RELATIVE, PinRecord, load_record
from sums_parse import SumsEntry, parse_sums
from tool_support import MissingInputError, invoke
from withheld_model import MANIFEST_RELATIVE, NotedReport, load_manifest

SUMS_NAME = "SHA256SUMS"
CURATION_RELATIVE = "evidence/curation.json"
EVIDENCE_PREFIX = "evidence/"
ROOT, DIR, MIXED = "root", "dir", "mixed"

app = cyclopts.App(result_action="return_value")


@dc.dataclass(frozen=True, slots=True)
class SumsRequest:
    """What a sums run examines.

    Attributes
    ----------
    root : pathlib.Path
        The repository root (or a source checkout in source mode).
    withheld : pathlib.Path | None
        The withheld manifest; defaults to ``evidence/withheld.json``.
    curation : pathlib.Path | None
        The curation file; defaults to ``evidence/curation.json``.
    """

    root: Path
    withheld: Path | None = None
    curation: Path | None = None


@dc.dataclass(slots=True)
class SumsReport(NotedReport):
    """The outcome of a sums run.

    Attributes
    ----------
    files : int
        How many sums files were read.
    ok : int
        Entries whose content matched.
    withheld : int
        Entries for withheld files that are absent.
    not_imported : int
        Entries in a corpus that curation excludes.
    external : int
        Entries that resolve outside ``evidence/``.
    externals : list[str]
        Those entries, for ``--verbose``.
    conventions : dict[str, str]
        For each sums file, the path convention its entries use.
    """

    files: int = 0
    ok: int = 0
    withheld: int = 0
    not_imported: int = 0
    external: int = 0
    externals: list[str] = dc.field(default_factory=list)
    conventions: dict[str, str] = dc.field(default_factory=dict)

    def summary(self) -> str:
        """Render the closing line.

        Returns
        -------
        str
            ``N sums files, M entries: A ok, W withheld, X not imported, ...``.
        """
        return (
            f"{self.files} sums files, {self.checked} entries: {self.ok} ok, "
            f"{self.withheld} withheld, {self.not_imported} not imported, "
            f"{self.external} external, {len(self.failures)} failures"
        )


@dc.dataclass(slots=True)
class Run:
    """The state shared while every sums file is read.

    Attributes
    ----------
    root : pathlib.Path
        The repository root.
    withheld : frozenset[str]
        Withheld paths.
    excluded : frozenset[str]
        Corpora that curation excludes.
    report : SumsReport
        Receives every outcome.
    hashes : dict[pathlib.Path, str]
        Content hashes already computed, so a file listed twice is read once.
    """

    root: Path
    withheld: frozenset[str]
    excluded: frozenset[str]
    report: SumsReport
    hashes: dict[Path, str] = dc.field(default_factory=dict)
    pins: PinRecord | None = None

    def hash_of(self, path: Path) -> str | None:
        """Hash a file, or return ``None`` for a Git LFS pointer.

        A pinned evidence ``.py`` file is hashed as it is at its capture commit,
        because the recorded hashes name those bytes (``scripts/pinned-evidence.json``).

        Returns
        -------
        str | None
            The hexadecimal SHA-256 of the content.
        """
        if path not in self.hashes:
            name = path.relative_to(self.root).as_posix()
            if self.pins is not None and name in self.pins.pins:
                self.hashes[path] = hashlib.sha256(self.pins.read(name)).hexdigest()
                return self.hashes[path]
            with path.open("rb") as handle:
                if handle.read(len(POINTER_PREFIX)) == POINTER_PREFIX:
                    return None
                handle.seek(0)
                self.hashes[path] = hashlib.file_digest(handle, "sha256").hexdigest()
        return self.hashes[path]


def _existing(run: Run, directory: str, name: str) -> tuple[str, str] | None:
    """Find the file an entry names inside ``evidence/``.

    Returns
    -------
    tuple[str, str] | None
        The repository-relative path and the convention that found it.
    """
    candidates = ((ROOT, name), (DIR, posixpath.join(directory, name)))
    for convention, raw in candidates:
        rel = posixpath.normpath(raw)
        if rel.startswith(EVIDENCE_PREFIX) and (run.root / rel).is_file():
            return rel, convention
    return None


def _outcome(run: Run, directory: str, entry: SumsEntry, *, dir_style: bool) -> str:
    """Classify an entry whose file was not found inside ``evidence/``.

    Returns
    -------
    str
        ``withheld``, ``not imported``, ``external`` or ``missing``.
    """
    name = entry.name
    if name.startswith("/"):
        return "external"
    in_root = posixpath.normpath(name)
    in_dir = posixpath.normpath(posixpath.join(directory, name))
    for rel in (in_root, in_dir):
        if rel in run.withheld:
            return "withheld"
        if corpus_of(rel) in run.excluded:
            return "not imported"
    outside = not in_root.startswith(EVIDENCE_PREFIX)
    if outside and (run.root / in_root).is_file():
        return "external"
    return "missing" if "/" not in name or not outside or dir_style else "external"


def _verify(run: Run, label: str, entry: SumsEntry, rel: str) -> None:
    """Compare an entry with the content of the file it names."""
    actual = run.hash_of(run.root / rel)
    where = f"{label}:{entry.line}: {entry.name}"
    if actual is None:
        run.report.failures.append(
            f"{where}: Git LFS pointer, not content; run git lfs pull"
        )
    elif actual == entry.digest:
        run.report.ok += 1
    else:
        run.report.failures.append(f"{where}: mismatch, content hashes to {actual}")


def _settle(run: Run, label: str, entry: SumsEntry, outcome: str) -> None:
    """Record an entry that has no file to verify."""
    where = f"{label}:{entry.line}: {entry.name}"
    report = run.report
    match outcome:
        case "withheld":
            report.withheld += 1
        case "not imported":
            report.not_imported += 1
        case "external":
            report.external += 1
            report.externals.append(where)
        case _:
            report.failures.append(f"{where}: missing")


def _read_file(run: Run, sums: Path) -> None:
    """Verify one sums file."""
    label = sums.relative_to(run.root).as_posix()
    directory = posixpath.dirname(label)
    entries, malformed = parse_sums(sums.read_bytes())
    run.report.failures += [f"{label}:{n}: malformed line" for n in malformed]
    run.report.checked += len(entries)
    found = {e.line: _existing(run, directory, e.name) for e in entries}
    used = {hit[1] for hit in found.values() if hit}
    convention = MIXED if len(used) > 1 else next(iter(used), "none")
    run.report.conventions[label] = convention
    if convention == MIXED:
        run.report.notes.append(
            f"{label}: mixes root-relative and directory-relative paths"
        )
    for entry in entries:
        hit = found[entry.line]
        if hit:
            _verify(run, label, entry, hit[0])
        else:
            outcome = _outcome(run, directory, entry, dir_style=convention == DIR)
            _settle(run, label, entry, outcome)


def check(request: SumsRequest) -> SumsReport:
    """Verify every sums file below ``request.root``.

    Parameters
    ----------
    request : SumsRequest
        What to examine.

    Returns
    -------
    SumsReport
        The tally and the failures.

    Raises
    ------
    MissingInputError
        If there is no ``evidence/`` directory, or an explicitly named
        manifest or curation file is absent.
    """
    root = request.root
    if not (root / "evidence").is_dir():
        message = f"no evidence directory below {root}"
        raise MissingInputError(message)
    withheld_path = request.withheld or root / MANIFEST_RELATIVE
    curation_path = request.curation or root / CURATION_RELATIVE
    withheld = frozenset()
    if request.withheld or withheld_path.is_file():
        withheld = load_manifest(withheld_path).paths
    excluded = frozenset()
    if request.curation or curation_path.is_file():
        excluded = load_excluded(curation_path)
    pins = load_record(root) if (root / RECORD_RELATIVE).is_file() else None
    run = Run(root, withheld, excluded, SumsReport(), pins=pins)
    for sums in sorted((root / "evidence").rglob(SUMS_NAME)):
        run.report.files += 1
        _read_file(run, sums)
    return run.report


@app.command(name="check")
def run_check(
    root: Path = Path(),
    *,
    withheld: Path | None = None,
    curation: Path | None = None,
    verbose: bool = False,
) -> int:
    """Verify every ``SHA256SUMS`` file under ``evidence/``.

    Parameters
    ----------
    root
        The repository root, or a source checkout.
    withheld
        The withheld manifest (default ``evidence/withheld.json`` if present).
    curation
        The curation file (default ``evidence/curation.json`` if present).
    verbose
        List external entries, notes and each sums file's convention.

    Returns
    -------
    int
        0 when every entry holds, otherwise 1.
    """
    report = check(SumsRequest(root, withheld, curation))
    sys.stdout.write("".join(f"{line}\n" for line in report.failures))
    if verbose:
        sys.stdout.write("".join(f"external: {item}\n" for item in report.externals))
        sys.stdout.write("".join(f"note: {note}\n" for note in report.notes))
        sys.stdout.write(
            "".join(f"convention {c}: {f}\n" for f, c in report.conventions.items())
        )
    sys.stdout.write(f"{report.summary()}\n")
    return report.exit_code


@app.command(name="lfs")
def run_lfs(root: Path = Path()) -> int:
    """Check that exactly the large and binary evidence is stored through LFS.

    Parameters
    ----------
    root
        The repository root.

    Returns
    -------
    int
        0 when the rule holds, otherwise 1.
    """
    report = check_lfs(root)
    sys.stdout.write("".join(f"{line}\n" for line in [*report.failures, *report.notes]))
    return report.exit_code


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
