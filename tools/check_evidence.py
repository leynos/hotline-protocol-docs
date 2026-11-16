"""Check what the documents cite, and generate the per-set evidence indexes.

``check`` is read-only. It reports, with ``file:line``:

* ledger identifiers (``V001``, ``M001``) that ``claims.json`` does not define,
  gap identifiers that the register does not define, and script paths that do
  not exist (INV-EVID);
* sentences that state a gap status the register contradicts, unless a dated
  status note for the gap follows in the same section (INV-STATUS);
* a gap that is not Resolved and is missing from, or repeated in, the first
  table of the remaining-work ledger, and a Resolved gap that appears in it;
* a cited corpus that no family of the recreation guide covers, and a script
  the guide names that does not exist (INV-RECREATE);
* a generated index that is not current (regenerating it gives other bytes).

``--known FILE`` names accepted current findings (a JSON list of objects with
``rule``, ``path``, ``key`` and ``reason``); an entry that matches no finding is
itself reported. ``index --write`` regenerates ``docs/<set>/evidence.md`` for
every set; without ``--write`` it reports the indexes that are stale. Exit
codes: 0 success, 1 findings, 2 missing inputs.
"""

import dataclasses as dc
import sys
from pathlib import Path

import cyclopts
from evidence_cites import Finding
from evidence_families import ledger_rows
from evidence_files import list_files
from evidence_index import COMMAND, render_indexes, set_of
from evidence_known import apply_known
from evidence_repo import GUIDE, LEDGER, Repo, load_repo, read_required
from evidence_rules import (
    family_findings,
    guide_findings,
    identifier_findings,
    ledger_table_findings,
    script_findings,
)
from evidence_status import scan_status
from tool_support import invoke

FLOOR_RULE = "floor"

app = cyclopts.App(result_action="return_value")


@cyclopts.Parameter(name="*")
@dc.dataclass(frozen=True, slots=True)
class Options:
    """What a check run reads and requires.

    Attributes
    ----------
    known : pathlib.Path | None
        A JSON list of accepted findings, each with ``rule``, ``path``, ``key``
        and ``reason``.
    listing : pathlib.Path | None
        A file that receives every sentence naming a Resolved gap, for review.
    min_ledger : int
        Fail if fewer ledger citations than this are seen.
    min_links : int
        Fail if fewer evidence links than this are seen.
    """

    known: Path | None = None
    listing: Path | None = None
    min_ledger: int = 0
    min_links: int = 0


@dc.dataclass(slots=True)
class Result:
    """The outcome of a check run.

    Attributes
    ----------
    findings : list[Finding]
        Every finding that is not accepted.
    accepted : list[Finding]
        Findings that ``--known`` accepts.
    counts : dict[str, int]
        What the run saw.
    corpora : dict[str, int]
        Corpora indexed, by set.
    resolved : list[tuple[str, int, str]]
        Every sentence that names a Resolved gap, for human review.
    phrases : dict[str, int]
        How often each status phrasing matched.
    """

    findings: list[Finding] = dc.field(default_factory=list)
    accepted: list[Finding] = dc.field(default_factory=list)
    counts: dict[str, int] = dc.field(default_factory=dict)
    corpora: dict[str, int] = dc.field(default_factory=dict)
    resolved: list[tuple[str, int, str]] = dc.field(default_factory=list)
    phrases: dict[str, int] = dc.field(default_factory=dict)


def index_findings(repo: Repo, rendered: dict[str, str]) -> list[Finding]:
    """Compare each rendered index with the file on disk.

    Parameters
    ----------
    repo : Repo
        The repository inputs.
    rendered : dict[str, str]
        The expected content by path.

    Returns
    -------
    list[Finding]
        One finding per index that is absent or differs.
    """
    found: list[Finding] = []
    for path, text in sorted(rendered.items()):
        target = repo.root / path
        current = target.read_text(encoding="utf-8") if target.is_file() else None
        if current != text:
            state = "is absent" if current is None else "is stale"
            message = f"the generated index {state}; run `{COMMAND}`"
            found.append(Finding(path, 1, "index", message, path))
    return found


def _document_findings(repo: Repo, result: Result) -> None:
    """Apply the per-document rules.

    Parameters
    ----------
    repo : Repo
        The repository inputs.
    result : Result
        The result to extend.
    """
    for path, doc in sorted(repo.cites.items()):
        result.findings += identifier_findings(doc, repo.known)
        result.findings += script_findings(doc, repo.root)
        if not set_of(path):
            continue
        scan = scan_status(path, repo.texts[path], repo.known.gaps)
        result.findings += scan.findings
        result.resolved += [
            (path, line, text) for line, text in scan.resolved_sentences
        ]
        for name, count in scan.phrases.items():
            result.phrases[name] = result.phrases.get(name, 0) + count


def _structure_findings(repo: Repo, result: Result) -> dict[str, str]:
    """Apply the ledger, family, guide and index rules.

    Parameters
    ----------
    repo : Repo
        The repository inputs.
    result : Result
        The result to extend.

    Returns
    -------
    dict[str, str]
        The rendered indexes by path.
    """
    ledger = ledger_rows(read_required(repo.root, LEDGER))
    result.findings += ledger_table_findings(LEDGER, ledger, repo.known.gaps)
    uncovered, _ = family_findings(repo.citing.values(), repo.families)
    retained = {name.rsplit("/", 1)[-1] for name in list_files(repo.root)}
    guide = guide_findings(GUIDE, repo.guide, repo.root, retained)
    result.findings += [*uncovered, *guide]
    rendered = render_indexes(repo.index_inputs())
    result.findings += index_findings(repo, rendered)
    return rendered


def _count(repo: Repo, result: Result, rendered: dict[str, str]) -> None:
    """Record what the run saw.

    Parameters
    ----------
    repo : Repo
        The repository inputs.
    result : Result
        The result to fill in.
    rendered : dict[str, str]
        The rendered indexes, whose sets are counted.
    """
    docs = repo.cites.values()
    result.counts = {
        "documents": len(repo.cites),
        "ledger citations": sum(len(d.ledger) for d in docs),
        "gap citations": sum(len(d.gaps) for d in docs),
        "evidence links": sum(d.evidence_links for d in docs),
        "script citations": sum(len(d.scripts) for d in docs),
        "sentences naming a Resolved gap": len(result.resolved),
    }
    per_set: dict[str, set[str]] = {}
    for path, doc in repo.citing.items():
        name = set_of(path) or ""
        per_set.setdefault(name, set()).update(o.value for o in doc.corpora)
    for path in rendered:
        name = path.split("/")[1]
        result.corpora[name] = len(per_set.get(name, set()))


def _floors(options: Options, result: Result) -> None:
    """Fail a run that saw too little to mean anything.

    Parameters
    ----------
    options : Options
        The run's floors.
    result : Result
        The result to extend.
    """
    for label, floor in (
        ("ledger citations", options.min_ledger),
        ("evidence links", options.min_links),
    ):
        seen = result.counts[label]
        if seen < floor:
            message = f"only {seen} {label} were seen; at least {floor} required"
            result.findings.append(Finding("(run)", 0, FLOOR_RULE, message, label))


def run_check(root: Path, options: Options | None = None) -> Result:
    """Run every rule against a repository.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    options : Options | None
        The known file and the non-vacuity floors.

    Returns
    -------
    Result
        The findings and the counts.
    """
    options = options or Options()
    repo = load_repo(root)
    result = Result()
    _document_findings(repo, result)
    rendered = _structure_findings(repo, result)
    _count(repo, result, rendered)
    _floors(options, result)
    if options.known is not None:
        result.findings, result.accepted = apply_known(
            root, options.known, result.findings
        )
    result.findings.sort()
    return result


def write_indexes(root: Path) -> list[str]:
    """Regenerate every evidence index.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.

    Returns
    -------
    list[str]
        The paths whose content changed.
    """
    rendered = render_indexes(load_repo(root).index_inputs())
    changed: list[str] = []
    for path, text in sorted(rendered.items()):
        target = root / path
        if not target.is_file() or target.read_text(encoding="utf-8") != text:
            target.write_text(text, encoding="utf-8", newline="\n")
            changed.append(path)
    return changed


@app.command(name="check")
def check_command(root: Path = Path(), *, options: Options | None = None) -> int:
    """Check the documents' citations, statuses, ledger, families and indexes.

    Parameters
    ----------
    root
        The repository root.
    options
        The known file, the review listing and the non-vacuity floors.

    Returns
    -------
    int
        0 when nothing is found, otherwise 1.
    """
    options = options or Options()
    result = run_check(root, options)
    sys.stdout.write("".join(f"{f.render()}\n" for f in result.findings))
    if options.listing is not None:
        lines = (f"{p}:{n}: {s}\n" for p, n, s in sorted(result.resolved))
        options.listing.write_text("".join(lines), encoding="utf-8")
    for label, count in result.counts.items():
        sys.stdout.write(f"{label}: {count}\n")
    for name, count in sorted(result.corpora.items()):
        sys.stdout.write(f"corpora indexed in {name}: {count}\n")
    sys.stdout.write(
        f"{len(result.accepted)} accepted by --known, {len(result.findings)} findings\n"
    )
    return 1 if result.findings else 0


@app.command(name="index")
def index_command(root: Path = Path(), *, write: bool = False) -> int:
    """Generate ``docs/<set>/evidence.md`` for each set, or report stale ones.

    Parameters
    ----------
    root
        The repository root.
    write
        Write the indexes; without it, report the ones that are not current.

    Returns
    -------
    int
        0 when the indexes are current (or were written), otherwise 1.
    """
    if write:
        sys.stdout.write("".join(f"wrote {p}\n" for p in write_indexes(root)))
        return 0
    repo = load_repo(root)
    stale = index_findings(repo, render_indexes(repo.index_inputs()))
    sys.stdout.write("".join(f"{f.render()}\n" for f in stale))
    return 1 if stale else 0


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
