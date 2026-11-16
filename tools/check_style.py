"""Check the house style of the Markdown documents.

``check`` reports, with ``file:line: rule: message`` and a count per rule:

* ``table-caption``: a table without a caption ``_Table N: ..._`` beneath it, or
  with the wrong number;
* ``figure``: a Mermaid block without a ``For screen readers:`` paragraph before
  it or a caption ``_Figure N: ..._`` after it;
* ``code-fence``: a fenced block without a language label;
* ``heading-case``: a heading word capitalized outside sentence case, judged
  conservatively against ``style-terms.txt`` (words the rule cannot judge go to
  the listing, not to the findings);
* ``person``: first or second person in prose (outside
  ``README.md``);
* ``glossary``: the glossary obligation of ``glossary-terms.txt`` (INV-GLOSSARY).

The documents outside the checked scope are the generated ``gap-analysis.md``,
the upstream style guide, the hash-pinned validity ledger, the execution plans
and the working records; a generated ``docs/<set>/evidence.md`` is checked for
captions only. ``--known FILE`` accepts current findings, as for
``check_evidence.py``. ``--listing FILE`` receives the undecided heading words
and the documents that link to neither their overview nor the glossary.
Exit codes: 0 success, 1 findings, 2 missing inputs.
"""

import dataclasses as dc
import sys
from pathlib import Path

import cyclopts
import style_glossary as sg
import style_layout as sl
import style_prose as sp
from evidence_cites import Finding
from evidence_known import apply_known
from repo_files import repo_files
from tool_support import MissingInputError, invoke

FLOOR_RULE = "floor"
TERMS_FILE = "style-terms.txt"
GLOSSARY_TERMS_FILE = "glossary-terms.txt"
UNCHECKED = frozenset({
    "gap-analysis.md",
    "docs/documentation-style-guide.md",
    "docs/baseline-validity-ledger.md",
})
UNCHECKED_PREFIXES = ("evidence/", "docs/execplans/")
RECORDS = ("docs/provenance/records/", "docs/provenance/protocol-handoff.md")
SET_DEPTH = 3
FIRST_PERSON_ALLOWED = "README.md"

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
        A file that receives the undecided heading words and the unlinked
        neighbours.
    min_tables : int
        Fail if fewer tables than this are seen.
    min_figures : int
        Fail if fewer Mermaid blocks than this are seen.
    min_glossary : int
        Fail if the glossary holds fewer entries than this.
    """

    known: Path | None = None
    listing: Path | None = None
    min_tables: int = 0
    min_figures: int = 0
    min_glossary: int = 0


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
    undecided : list[sp.Undecided]
        Heading words the case rule cannot judge.
    unlinked : list[str]
        Documents that link to neither their overview nor the glossary.
    """

    findings: list[Finding] = dc.field(default_factory=list)
    accepted: list[Finding] = dc.field(default_factory=list)
    counts: dict[str, int] = dc.field(default_factory=dict)
    undecided: list[sp.Undecided] = dc.field(default_factory=list)
    unlinked: list[str] = dc.field(default_factory=list)


def _read_list(root: Path, name: str) -> str:
    """Read a maintained list that the run requires.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    name : str
        The file name.

    Returns
    -------
    str
        The file's text.

    Raises
    ------
    MissingInputError
        If the file is absent.
    """
    path = root / name
    if not path.is_file():
        message = f"{name} is absent"
        raise MissingInputError(message)
    return path.read_text(encoding="utf-8")


def _terms(text: str) -> set[str]:
    """Read ``style-terms.txt``.

    Parameters
    ----------
    text : str
        The file's text; blank lines and ``#`` comments are ignored.

    Returns
    -------
    set[str]
        The listed terms.
    """
    lines = (line.strip() for line in text.splitlines())
    return {line for line in lines if line and not line.startswith("#")}


def _classify(path: str) -> str:
    """Place a document in the checked scope.

    Parameters
    ----------
    path : str
        A repository-relative POSIX path.

    Returns
    -------
    str
        ``skip``, ``record`` (kept as written, read only for label series),
        ``index`` (a generated evidence index, checked for captions only) or
        ``full``.
    """
    if path in UNCHECKED or path.startswith(UNCHECKED_PREFIXES):
        return "skip"
    if path.startswith(RECORDS):
        return "record"
    parts = path.split("/")
    generated = len(parts) == SET_DEPTH and parts[2] == "evidence.md"
    return "index" if generated and parts[0] == "docs" else "full"


def _load(root: Path) -> dict[str, tuple[str, str]]:
    """Read every tracked Markdown document that a rule reads.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.

    Returns
    -------
    dict[str, tuple[str, str]]
        Each document's scope class and text, by path.
    """
    loaded: dict[str, tuple[str, str]] = {}
    for file in repo_files(root, ".md"):
        path = file.as_posix()
        kind = _classify(path)
        if kind != "skip":
            loaded[path] = (kind, (root / file).read_text(encoding="utf-8"))
    return loaded


def _document_findings(
    docs: dict[str, tuple[str, str]], terms: set[str], result: Result
) -> None:
    """Apply the per-document rules.

    Parameters
    ----------
    docs : dict[str, tuple[str, str]]
        The documents, by path.
    terms : set[str]
        The listed proper nouns.
    result : Result
        The result to extend.
    """
    full = {p: t for p, (k, t) in docs.items() if k == "full"}
    lower: set[str] = set().union(*(sp.lowercase_words(t) for t in full.values()))
    tables = figures = 0
    for path, (kind, text) in sorted(docs.items()):
        if kind == "record":
            continue
        layout = sl.layout_findings(path, text, tables_only=kind == "index")
        result.findings += layout.findings
        tables += layout.tables
        figures += layout.figures
        if kind != "full":
            continue
        wrong, undecided = sp.heading_findings(path, text, (terms, lower))
        result.findings += wrong
        result.undecided += undecided
        if path != FIRST_PERSON_ALLOWED:
            result.findings += sp.person_findings(path, text)
    result.counts["documents"] = len(full)
    result.counts["tables"] = tables
    result.counts["mermaid blocks"] = figures


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
        ("tables", options.min_tables),
        ("mermaid blocks", options.min_figures),
        ("glossary entries", options.min_glossary),
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
        The findings, the counts and the listings.
    """
    options = options or Options()
    terms = _terms(_read_list(root, TERMS_FILE))
    glossary_terms = sg.parse_terms(_read_list(root, GLOSSARY_TERMS_FILE))
    docs = _load(root)
    result = Result()
    _document_findings(docs, terms, result)
    texts = {p: t for p, (_, t) in docs.items()}
    labelled = {p: t for p, (k, t) in docs.items() if k != "index"}
    found, entries = sg.glossary_findings(texts, labelled, glossary_terms)
    result.findings += found
    result.counts["glossary entries"] = entries
    result.counts["required terms"] = len(glossary_terms.required)
    result.unlinked = sg.unlinked_neighbours(texts)
    _floors(options, result)
    if options.known is not None:
        result.findings, result.accepted = apply_known(
            root, options.known, result.findings
        )
    result.findings.sort()
    return result


def _report(result: Result, options: Options) -> str:
    """Render the findings, the per-rule counts and the totals.

    Parameters
    ----------
    result : Result
        The outcome.
    options : Options
        The run's options, for the listing.

    Returns
    -------
    str
        The text for standard output.
    """
    lines = [f"{finding.render()}\n" for finding in result.findings]
    for rule in sorted({f.rule for f in [*result.findings, *result.accepted]}):
        shown = sum(f.rule == rule for f in result.findings)
        accepted = sum(f.rule == rule for f in result.accepted)
        lines.append(f"{rule}: {shown} findings, {accepted} accepted\n")
    lines += [f"{label}: {count}\n" for label, count in result.counts.items()]
    lines.append(f"undecided heading words: {len(result.undecided)}\n")
    lines.append(
        f"documents linking to neither overview nor glossary: {len(result.unlinked)}\n"
    )
    lines.append(
        f"{len(result.accepted)} accepted by --known, {len(result.findings)} findings\n"
    )
    if options.listing is not None:
        entries = [f"undecided: {u.render()}\n" for u in result.undecided]
        entries += [f"unlinked: {path}\n" for path in result.unlinked]
        options.listing.write_text("".join(entries), encoding="utf-8")
    return "".join(lines)


@app.command(name="check")
def check_command(root: Path = Path(), *, options: Options | None = None) -> int:
    """Check captions, figures, fences, heading case, person and the glossary.

    Parameters
    ----------
    root
        The repository root.
    options
        The known file, the listing and the non-vacuity floors.

    Returns
    -------
    int
        0 when nothing is found, otherwise 1.
    """
    options = options or Options()
    result = run_check(root, options)
    sys.stdout.write(_report(result, options))
    return 1 if result.findings else 0


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
