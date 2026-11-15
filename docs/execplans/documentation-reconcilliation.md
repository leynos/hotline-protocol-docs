# Reconcile, correlate and orient the Hotline Protocol documentation

This ExecPlan (execution plan) is a living document. The sections `Constraints`,
`Tolerances`, `Risks`, `Progress`, `Surprises & discoveries`, `Decision log`,
`Outcomes & retrospective`, `Conformance basis`, and `Verification plan` must
be kept up to date as work proceeds.

Status: DRAFT

## Purpose / big picture

The repository holds 103 Markdown documents about the Hotline 1.9 wire
protocol, all in one flat directory, with no README, no index and no gates of
its own. A newcomer cannot tell the baseline guide from a one-off capture
record, and nothing mechanical confirms that a statement such as "GAP-044
remains open" still agrees with the gap register.

After this work a reader opens `README.md`, picks an entry point by task, and
reaches any document in at most three links. Documents are grouped into eight
subject sets under `docs/`, each with an overview, a reading order and a
generated evidence index. Running `make all` proves that every link and anchor
resolves, every cited gap, ledger entry and evidence artefact exists, prose
about gap status agrees with the register, Mermaid diagrams render, tables are
well formed, spelling follows Oxford British English, and the Python tooling
passes the df12 gates. The model is the Lody documentation tree at
`../../lody-docs.worktrees/unified-documentation-tree/`.

This is an editorial pass. It does not make new protocol observations, close
gaps, or resume the parked native and mxd investigations.

## Constraints

- No protocol claim may change meaning. Permitted edits to existing documents
  are: link targets, spelling, wrapping, table layout, captions, screen-reader
  descriptions, letter-case of headings, orientation paragraphs, and dated
  supersession notes that quote the gap register.
- The gap register keeps exactly 87 gaps. Every `id`, `status`, `question`,
  `closure_criteria`, `priority`, `kind` and `depends_on` value stays
  byte-identical. Only source locations, coverage locations and link targets
  inside strings may change.
- In existing documents, no heading may be added, removed or reordered, and a
  heading's anchor slug must not change. Case-only edits are allowed because
  the slug is lowercased. This keeps the 543 audited sections in one-to-one
  correspondence with their successors.
- `scripts/` and every file in it keep their current paths and content. The
  sibling `mothra` repository's `Makefile` runs them by path, and its evidence
  records name them.
- `gap-register.json` and `gap-analysis.md` stay at the repository root,
  because `mothra/scripts/render-protocol-gap-analysis.py` hard-codes that
  location. `gap-analysis.md` is generated and is never edited by hand.
- Nothing under `mothra/evidence/` that already exists may be modified. New
  audit revisions are added beside the old ones.
- The main checkouts at `/data/leynos/Projects/hotline-protocol-docs` and
  `/data/leynos/Projects/mothra` are not edited directly. All work happens in
  linked worktrees on branches named `documentation-reconcilliation`.
- No native run, Ghidra query, emulator start or mxd build is performed.
- `docs/documentation-style-guide.md` is a verbatim copy of the df12 guide and
  is not edited here.
- Format, lint and test commands run sequentially, never in parallel.
- Each change is committed separately after its gates pass.

## Tolerances (exception triggers)

- Scope: this ExecPlan file is excluded from all counts. Moves of existing
  documents are expected (102 files). Beyond moves, stop and escalate if more
  than 45 new non-ExecPlan files or 6,000 net new lines of code and
  documentation are needed, or if the Python tooling exceeds 1,800 lines
  excluding tests.
- Meaning: if reconciling two documents requires choosing between claims that
  the retained evidence does not decide, stop for that item, record it in the
  reconciliation log, and continue with the rest. If more than ten such items
  accumulate, stop and escalate.
- Register: if any step would add, remove, re-status or re-word a gap, stop.
- Mothra code: if `mothra/scripts/` or `mothra/Makefile` must change, stop and
  escalate. Changes to three Markdown links in `mothra/README.md` and
  `mothra/docs/protocol-handoff.md`, and a new audit revision directory, are
  inside tolerance.
- Dependencies: the tools named in `Interfaces and dependencies` are approved.
  Any other new dependency triggers escalation.
- Iterations: if a gate still fails after five attempts at one cause, stop.
- Ambiguity: if a document fits two sets and the choice changes a reader's
  route, record the choice in `Decision log`; if more than five documents are
  contested, stop and present the alternatives.

## Risks

- Risk: an audit refresh silently records the wrong source location for a gap.
  Severity: high. Likelihood: medium. Mitigation: obligation INV-AUDIT below;
  the refresh tool must first reproduce revision 89 byte for byte, and the
  mothra renderer's own `--check` is the independent oracle.
- Risk: relocating 102 documents breaks some of roughly 2,200 relative links.
  Severity: medium. Likelihood: high without tooling. Mitigation: the move is
  performed by a tested script, and the link gate runs before and after.
- Risk: historical evidence in mothra names the old flat paths.
  Severity: low. Likelihood: certain. Mitigation: those records are pinned to
  commit hashes and remain true of those commits; `docs/repository-layout.md`
  carries an old-to-new path table.
- Risk: the spelling gate flags protocol tokens such as `FILP`, `alis` and
  hexadecimal fragments, tempting unsafe edits to quoted bytes. Severity:
  medium. Likelihood: high. Mitigation: wrap wire tokens in backticks, which
  the gate ignores, or add exact entries to `typos.local.toml`; never alter a
  quoted byte string.
- Risk: summaries in new overviews drift from the documents they summarize.
  Severity: medium. Likelihood: medium. Mitigation: every summary sentence in a
  set overview links to the section that states it, and overviews introduce no
  claim of their own.
- Risk: `typos-config-builder` and `uv` need network access to GitHub and
  PyPI. Severity: low. Likelihood: low. Mitigation: the gate falls back to a
  packaged dictionary snapshot; record the fallback if used.
- Risk: the 236 legacy scripts become subject to stricter lint through a new
  root `pyproject.toml`. Severity: medium. Likelihood: certain unless
  prevented. Mitigation: `scripts/ruff.toml` pins the legacy scripts to the
  default configuration that mothra's gates already apply.

## Progress

- [x] (2026-11-15 12:33Z) Surveyed this repository, the Lody exemplar, the
  netsuke gates, the df12 Python template and the mothra coupling.
- [x] (2026-11-15 12:33Z) Drafted this ExecPlan.
- [ ] Approval of the plan and of decisions D1 to D4.
- [ ] EP-M0: paired worktrees and recorded baseline.
- [ ] EP-M1: tooling foundation and link gate.
- [ ] EP-M2: audit refresh tool proven against revision 89.
- [ ] EP-M3: documents relocated into sets; audit revision 90.
- [ ] EP-M4: on-ramps, orientation documents and diagrams.
- [ ] EP-M5: evidence correlation and reconciliation; audit revision 91.
- [ ] EP-M6: style conformance and cross-references; audit revision 92.
- [ ] EP-M7: final validation, mothra handoff update and retrospective.

## Surprises & discoveries

- Observation: every one of the 102 authored documents is a byte-hashed input
  to the gap audit held in mothra. Evidence:
  `mothra/evidence/protocol-gap-analysis/2026-11-15/revision-89/`
  `manifest.json` lists 102 inputs, and `validate` in
  `mothra/scripts/render-protocol-gap-analysis.py` raises "Audit input changed;
  refresh the review" on any hash difference. Impact: every editing milestone
  must end with a new audit revision.
- Observation: relative links of the form `../mothra/...` do not resolve from
  a linked worktree, because the worktree does not sit beside mothra. Evidence:
  1,053 such links resolve from the main checkout only. Impact: EP-M0 creates a
  mothra worktree beside this one.
- Observation: prose already disagrees with the register in at least four
  places. Evidence: `native-pm-preparation.md` and `native-ui-focus-witness.md`
  say GAP-044 remains open, `native-settings-preparation.md` says GAP-015 stays
  open, and `native-diagnostic-existing-preparation.md` says GAP-037 remains
  open; the register marks all three Resolved. `native-104-variants.md` writes
  the identifier in lower case. Impact: the status check in EP-M5 has known
  positives to detect.
- Observation: seven gaps (GAP-009, 013, 056, 058, 060, 066 and 069) are
  mentioned nowhere outside `gap-analysis.md`, and 48 non-test scripts are
  cited by no document. Impact: inputs to the correlation pass.
- Observation: the existing documents are close to clean. With the Lody
  markdownlint configuration only 18 MD049 emphasis-style findings appear, no
  local link is broken, and default `typos` reports 90 findings, mostly
  protocol tokens.

## Decision log

- Decision D1 (proposed, needs approval): relocate the documents into a
  `docs/<set>/` tree instead of adding an index over the flat directory.
  Rationale: the request is to model the tree on Lody's, and 103 siblings
  defeat orientation however good the index. Every edit already forces an audit
  refresh, so relocation adds a mechanical path remap, not a new class of work.
  The alternative keeps all paths and adds overview pages only; it is safer for
  mothra and weaker for readers. Date/Author: 2026-11-15, planning agent.
- Decision D2 (proposed, needs approval): the df12 Python standards apply to
  the new documentation tooling under `tools/` and `tests/`. The 236 legacy
  capture and verification scripts in `scripts/` are left byte-identical.
  Rationale: they are evidence-producing artefacts named by path in mothra
  records and gated by mothra's `Makefile`; rewriting about 61,600 lines to a
  stricter standard is a separate project with its own evidence risk.
  Date/Author: 2026-11-15, planning agent.
- Decision D3 (proposed, needs approval): this plan may add audit revisions
  90 to 92 under `mothra/evidence/protocol-gap-analysis/` and update the links
  in `mothra/README.md` and `mothra/docs/protocol-handoff.md`, on a mothra
  branch, without touching mothra code. Rationale: the audit cannot stay valid
  otherwise. The handoff note says not to start a new investigation; an
  editorial refresh is not one, but the owner should confirm. Date/Author:
  2026-11-15, planning agent.
- Decision D4 (proposed, needs approval): stale status statements in dated
  preparation and witness records are not rewritten. A dated note is added
  beneath them giving the register's current status. Rationale: the records are
  historical; rewriting them would falsify what was known at the time.
  Date/Author: 2026-11-15, planning agent.
- Decision D5: evidence citations stay as inline links to mothra artefacts,
  ledger identifiers and gap identifiers. Lody-style `E-…` row identifiers are
  not retrofitted. Rationale: 743 evidence links and 521 ledger citations
  already carry stable identities; a generated index gives the reverse lookup
  without touching each claim. Date/Author: 2026-11-15, planning agent.
- Decision D6: set overviews and orientation documents are not audit inputs.
  Rationale: they state nothing that a member document does not state, and the
  link-per-sentence rule makes that checkable by a reviewer. Date/Author:
  2026-11-15, planning agent.
- Decision D7: from the df12 template's lint chain, adopt Ruff, `ty`,
  `interrogate`, Pylint with the df12 messages, and pytest. Omit the dead-code,
  duplication, workflow-lint and mutation gates. Rationale: there is no
  installable package and no workflow here, and those gates are built around
  both. Date/Author: 2026-11-15, planning agent.

## Outcomes & retrospective

Not yet started. To be completed at EP-M7.

## Context and orientation

Three sibling checkouts matter. Paths are given from `/data/leynos/Projects/`.

`hotline-protocol-docs` is this repository. Its root holds 103 Markdown files.
`protocol.md` is the baseline guide. About fifteen `*-contracts.md` and related
files refine it by subject. About forty `native-*-preparation.md` and
`native-*-witness.md` files record one planned or executed capture against the
native server each. `classic-*`, `mac-peer-*` and `identified-client-source.md`
describe peer clients. `mxd-*` and `internal-compatibility-matrix.md` concern
mxd, the server implementation this documentation serves. `gap-register.json`
is the canonical list of 87 open questions ("gaps"), and `gap-analysis.md` is
rendered from it. `scripts/` holds 236 Python files: capture planners,
`verify_*.py` checkers for retained evidence, and `unittest` tests beside them.
`fixtures/banner/` holds four image fixtures. There is no `README.md`,
`Makefile`, `pyproject.toml` or `AGENTS.md`.

`mothra` holds the evidence. `mothra/evidence/` contains the Ghidra query
records, capture corpora and the audit snapshots.
`mothra/docs/baseline-validity-ledger.md` is the "ledger": numbered findings
such as V003, M008 and C004 that the documents cite.
`mothra/evidence/hotline-server-1.9/claims.json` lists the valid ledger
identifiers. `mothra/Makefile` runs Ruff and `ty` over this repository's
`scripts/`, runs the `verify_*.py` checkers against named corpora, and has a
`gap-check` target that runs the renderer in `--check` mode.

An "audit revision" is a directory such as
`mothra/evidence/protocol-gap-analysis/2026-11-15/revision-89/`. Its
`manifest.json` lists each input document with a SHA-256 hash and a frozen
snapshot; `sections.json` lists every heading of every input with its line
range and anchor; `SHA256SUMS` covers the directory. The register's `sources`
and `review_coverage` entries must match `sections.json` exactly. Revision 89
has 102 inputs and 543 sections. No script produces a revision; each was
assembled by hand or by an agent.

The exemplar is `lody-docs.worktrees/unified-documentation-tree/`. Its
`README.md` has a table of sets, a table of entry points by task, one Mermaid
overview and a section on running the checks. `docs/contents.md` lists every
document once with a reason to open it. `docs/repository-layout.md` and
`docs/developers-guide.md` serve maintainers. Each `docs/<set>/README.md` gives
scope, neighbouring sets, a one-page numbered summary, a documents table,
conventions, and what the set does not establish. Each set has an
`evidence.md`. Tooling sits in `scripts/` with pytest tests in `tests/`.

The df12 documentation style guide lives at
`agent-helper-scripts/documentation-library/documentation-style-guide.md`,
commit `991af8457b0d7ccda90ad3da11f93f5f155da822`. Its rules that bear on this
work: Oxford British spelling (`en-GB-oxendict`); sentence-case headings; prose
wrapped at 80 columns and code at 120; tables not wrapped; a caption under
every table (`_Table 1: …_`) and figure (`_Figure 1: …_`); a paragraph
beginning "For screen readers:" before each Mermaid diagram; no first or second
person outside `README.md`; acronyms expanded on first use; and the canonical
files `docs/contents.md`, `docs/repository-layout.md` and
`docs/developers-guide.md`.

The gates come from `netsuke/Makefile`:
`mdtablefix --check --git
--include-untracked --wrap --renumber --breaks --ellipsis --fences`;
`markdownlint-cli2 "**/*.md"`; `typos-config-builder gate --repository .` at
tag `v0.1.3`, which generates `typos.toml` from a shared Oxford dictionary plus
the local overlay `typos.local.toml`; and `nixie --no-sandbox`, which renders
every Mermaid block.

The Python standards come from
`agent-template-python/template/pyproject.toml.jinja` and
`template/docs/scripting-standards.md`, as practised in `episodic`: Ruff with
the template's rule selection, numpy-style docstrings, complexity limit 8, `ty`
for type checking, pytest tests, Cyclopts for command lines, `pathlib`
throughout, and modules under 400 lines.

## Conformance basis

No Terms of Reference, technical design or ADR exists for this work. The
upstream authority is the request of 15 November 2026, restated as:

- REQ-1: reconcile the documents with one another and with the register.
- REQ-2: correlate documents with their evidence.
- REQ-3: add on-ramps, orientation and cross-references, modelled on Lody.
- REQ-4: follow the df12 documentation style guide at commit `991af84`.
- REQ-5: validate with nixie, mdtablefix, spelling and markdownlint as
  netsuke does.
- REQ-6: Python tooling follows the df12 Python standards.
- REQ-7: include Mermaid diagrams where they help, validated by nixie.

Trace links:

```plaintext
REQ-1 -> EP-M5 -> make evidence-check (status and identifier checks), docs/reconciliation-log.md
REQ-2 -> EP-M5 -> docs/<set>/evidence.md generated; make evidence-check
REQ-3 -> EP-M3, EP-M4, EP-M6 -> make links-check (reachability, contents)
REQ-4 -> EP-M1, EP-M6 -> make markdownlint, make style-check
REQ-5 -> EP-M1, EP-M6 -> make check-fmt, markdownlint, spelling, nixie
REQ-6 -> EP-M1, EP-M2 -> make lint-python, typecheck, test
REQ-7 -> EP-M4, EP-M6 -> make nixie
audit validity (inherited) -> EP-M2, EP-M3, EP-M5, EP-M6 -> make audit-check
```

## Verification plan

The tooling introduces six obligations. Third-party tools (markdownlint,
mdtablefix, typos, nixie, Ruff, `ty`) are axioms at their documented
interfaces. The mothra renderer's `validate` function is treated as an
independent oracle, not re-verified. A further axiom is the heading-slug rule
the renderer uses: lowercase, drop characters other than word characters,
hyphens and spaces, then replace spaces with hyphens. The link tool must use
the same rule, and a test pins it against the 543 anchors in revision 89.

- Obligation INV-LINK: every relative link and fragment in every tracked
  Markdown file resolves to an existing file and heading or explicit anchor.
  Method: parameterized tests over link forms, plus a run over the real tree.
  Domain: inline links, reference definitions, same-file fragments, links into
  mothra, links inside fenced code (ignored). Artefact:
  `tests/test_check_links.py`. Evidence: `make links-check` exits 0.
  Non-vacuity: the run must report at least 2,000 links checked; tests seed a
  missing file, a missing anchor and a duplicate-slug case, each rejected with
  a message naming the link.
- Obligation INV-REACH: every Markdown document under `docs/` other than
  `docs/execplans/` appears exactly once in `docs/contents.md` and exactly once
  in a set overview's documents table. Method: parameterized tests and the real
  run. Artefact: `tests/test_check_links.py`. Non-vacuity: seeded unlisted and
  doubly listed documents are rejected.
- Obligation INV-MOVE: relocation changes nothing but link targets. For each
  moved document, the heading sequence and every line containing no link are
  identical before and after, and every link resolves to the moved counterpart
  of its old target. Method: a Hypothesis property test of the link rewriter
  (for any source, target and move map, resolving the rewritten link from the
  new location equals the mapped old resolution) plus an after-the-fact
  comparison over the real tree. Artefact: `tests/test_migrate_layout.py`.
  Non-vacuity: generators must produce moves that change directory depth in
  both directions, classification counts are asserted, and a rewriter that
  returns its input unchanged must fail.
- Obligation INV-AUDIT: a refreshed audit revision is exactly what the mothra
  renderer accepts, and gap content is preserved. Lemma: with headings neither
  added, removed nor reordered, the n-th section of the old snapshot
  corresponds to the n-th section of the new file. Method: golden test
  reproducing revision 89 from unchanged inputs; parameterized tests for a
  shifted line range and a relocated path; then the oracle. Artefact:
  `tests/test_refresh_audit.py`. Evidence: `make audit-check` exits 0 and a
  comparison prints `87 gaps, 0 protected fields changed`. Non-vacuity: a
  seeded heading insertion must be refused with exit code 1; a seeded change to
  one `closure_criteria` string must be detected.
- Obligation INV-EVID: every cited ledger identifier is in `claims.json`,
  every gap identifier is in the register, every mothra evidence link resolves,
  every script path cited exists in one of the two repositories, and the
  generated evidence indexes are current. Method: parameterized tests and the
  real run. Artefact: `tests/test_check_evidence.py`. Non-vacuity: the run must
  report at least 400 ledger citations and 700 evidence links; seeded unknown
  identifiers and a stale index are rejected.
- Obligation INV-STATUS: no sentence asserts a gap status that contradicts
  the register, unless it sits in a dated supersession note. Method:
  parameterized tests over phrasings, and the real run. Artefact:
  `tests/test_check_evidence.py`. Evidence: the check fails on the four known
  cases before EP-M5 and passes after. Non-vacuity: those four cases are the
  red state. Residual gap: the phrase list is finite, so an unusual wording can
  escape; the reconciliation review in EP-M5 reads every sentence that names a
  gap whose status is Resolved.

Prose reconciliation beyond these checks is review work. It is recorded per set
in `docs/reconciliation-log.md`, not claimed as verified.

## Plan of work

Stage A, understand and prepare, is EP-M0. Create the paired worktrees so that
both repositories' relative-path assumptions hold, and record the baseline:
`make -C ../mothra gap-check` passes against the unchanged tree, and the counts
in `Surprises & discoveries` are reproduced.

Stage B and C, tooling built test-first, are EP-M1 and EP-M2. Add
`pyproject.toml`, `Makefile`, `.markdownlint-cli2.jsonc`, `typos.local.toml`,
`.gitignore` entries, `scripts/ruff.toml`, `AGENTS.md` and the style guide
copy. Write `tools/check_links.py` and then `tools/refresh_audit.py`, each from
failing tests. The documentation gates are wired in EP-M1 but only the Python
and link gates are required to pass until EP-M6, because fixing document
findings earlier would invalidate the audit before the refresh tool exists.

Stage C continues with the content milestones. EP-M3 relocates documents with
`tools/migrate_layout.py`, driven by the move map in `Artefacts and notes`,
rewrites link targets in the documents and in the register's strings, and cuts
revision 90. EP-M4 writes the orientation layer as new files. EP-M5 adds
`tools/check_evidence.py`, generates the evidence indexes, reconciles drift and
cuts revision 91. EP-M6 applies the style guide inside existing documents, adds
neighbour links and diagrams, turns on every gate in `make all`, and cuts
revision 92.

Stage D is EP-M7: delete the one-off migration script and its test, run every
gate in both repositories, update the mothra handoff links, and write the
retrospective.

## Milestones and plateaus

- EP-M0, baseline. Outcome: sibling worktrees exist and the baseline is
  recorded in this plan. Requirements: none discharged. Evidence:
  `make -C ../mothra gap-check` exits 0. Conformance: no tracked file changed.
  Recovery: remove the mothra worktree and symlink. Remaining: all.
  Compatibility: none.
- EP-M1, tooling foundation. Outcome:
  `make lint-python typecheck test links-check` pass on the flat tree;
  documentation gates run and their finding counts are recorded. Requirements:
  REQ-5 and REQ-6 advanced. Evidence: INV-LINK. Conformance: no existing
  document or script changed; `ruff check scripts` output unchanged from
  baseline. Recovery: revert the commits. Remaining: content. Compatibility:
  none.
- EP-M2, audit refresh. Outcome: `tools/refresh_audit.py` reproduces
  revision 89. Requirements: audit validity. Evidence: INV-AUDIT golden test.
  Conformance: nothing written under mothra. Recovery: revert. Compatibility:
  none.
- EP-M3, relocation. Outcome: 102 documents live under `docs/<set>/`; all
  links resolve; revision 90 is accepted. Requirements: REQ-3 advanced.
  Evidence: INV-MOVE, INV-LINK, `make audit-check`. Conformance:
  `git diff -M --stat` shows renames with link-only changes; register protected
  fields unchanged; `scripts/` untouched. Recovery: revert the single
  relocation commit in each repository. Remaining: orientation, correlation,
  style. Compatibility: none; old paths are not aliased. Old-to-new paths are
  tabulated in `docs/repository-layout.md` for readers of pinned evidence.
- EP-M4, on-ramps. Outcome: `README.md`, `docs/contents.md`,
  `docs/repository-layout.md`, `docs/developers-guide.md` and eight set
  overviews exist with at least five validated Mermaid diagrams. Requirements:
  REQ-3, REQ-7. Evidence: INV-REACH, `make nixie`. Conformance: only new files;
  every overview sentence that summarizes a claim carries a link. Recovery:
  revert. Compatibility: none.
- EP-M5, correlation and reconciliation. Outcome: generated
  `docs/<set>/evidence.md` indexes; status drift resolved by dated notes;
  `docs/reconciliation-log.md` lists every discrepancy examined and its
  disposition; revision 91. Requirements: REQ-1, REQ-2. Evidence: INV-EVID,
  INV-STATUS, `make audit-check`. Conformance: no claim changed meaning; 87
  gaps. Recovery: revert the milestone's commits in both repositories.
  Compatibility: none.
- EP-M6, style and cross-references. Outcome: every gate in `make all`
  passes; revision 92. Requirements: REQ-4, REQ-5, REQ-7. Evidence: gate
  transcripts. Conformance: heading anchor sequences identical to revision
  91. Recovery: revert per set; each set is a separate commit.
  Compatibility: none.
- EP-M7, completion. Outcome: both repositories pass their full gates;
  mothra links updated; retrospective written; status COMPLETE.

## Concrete steps

All commands run from the worktree root
`/data/leynos/Projects/hotline-protocol-docs.worktrees/documentation-reconcilliation`
unless stated.

EP-M0. Create the sibling arrangement, then record the baseline:

```sh
git -C /data/leynos/Projects/mothra worktree add \
  /data/leynos/Projects/hotline-protocol-docs.worktrees/mothra \
  -b documentation-reconcilliation
ln -s documentation-reconcilliation ../hotline-protocol-docs
make -C ../mothra gap-check
```

The symlink makes mothra's hard-coded `../hotline-protocol-docs` resolve to
this worktree. Expect `gap-check` to print nothing and exit 0. If the mothra
worktree already exists, skip the first command.

EP-M1. For each tool, write the tests, run them and see them fail for the
stated reason, then implement:

```sh
make test          # red: ModuleNotFoundError or failing assertions
make test          # green after implementation
make lint-python
make typecheck
make links-check
```

Expected final line of the link gate:

```plaintext
103 documents, 2,2xx links, 0 failures
```

EP-M2. The golden test copies revision 89 into a temporary directory, runs the
refresh against unchanged inputs, and compares `sections.json` and the register
byte for byte.

EP-M3. Relocate, refresh and check, in this order:

```sh
uv run tools/migrate_layout.py --dry-run
uv run tools/migrate_layout.py
make links-check
uv run tools/refresh_audit.py --mothra ../mothra --revision 90
python3 ../mothra/scripts/render-protocol-gap-analysis.py
make audit-check
```

The fifth command regenerates `gap-analysis.md` from the updated register.
Commit this repository first, then mothra, and record both hashes in
`Artefacts and notes`.

EP-M4 to EP-M6 repeat the pattern: edit one set, run `make fmt`, run the gates
in the order `check-fmt`, `markdownlint`, `nixie`, `links-check`,
`evidence-check`, commit; at the end of the milestone refresh the audit with
the next revision number, regenerate `gap-analysis.md`, run `make audit-check`,
and commit both repositories.

EP-M7:

```sh
make all
make -C ../mothra check
```

## Validation and acceptance

The work is accepted when all of the following can be observed.

A reader starting at `README.md` finds a table of the eight sets, a table of
entry points by task, and a diagram of how the guide, contracts, evidence and
register relate; each set overview lists its documents with one line each;
`docs/contents.md` lists every document once.

`make all` exits 0 and its help text names every gate.
`make -C ../mothra check` exits 0. `git status --short scripts` is empty and
`git diff main -- scripts` is empty.

Comparing `gap-register.json` on `main` with the branch reports 87 gaps and no
change to any protected field.

Red-Green-Refactor evidence is recorded per tool in `Artefacts and notes`: the
failing test run before implementation, the passing run after, and the lint,
type-check and test run after refactoring. The four known status contradictions
fail `make evidence-check` at the start of EP-M5 and pass at its end.

Quality criteria:

- Tests: `make test` passes; every tool has happy-path and failure-path
  tests, and the property test for INV-MOVE reports its classifications.
- Verification: INV-LINK, INV-REACH, INV-MOVE, INV-AUDIT, INV-EVID and
  INV-STATUS discharged as specified, with non-vacuity counts recorded.
- Lint and type checks:
  `make lint-python typecheck check-fmt markdownlint spelling nixie` pass.
- Performance: `make all` completes in under five minutes on this machine.
- Security: tools read and write only inside the two worktrees; the refresh
  tool refuses to overwrite an existing revision directory.

## Idempotence and recovery

Every check is read-only and repeatable. `tools/migrate_layout.py` refuses to
run if any source is missing or any destination exists, so a second run is a
no-op with a clear message. `tools/refresh_audit.py` refuses an existing
revision directory; to retry, delete the uncommitted directory and rerun.
Generated files (`typos.toml`, `docs/<set>/evidence.md`, `gap-analysis.md`) are
regenerated, never patched. Each milestone is a small number of commits in each
repository, so recovery is `git revert` of those commits, mothra first. On
completion, remove the symlink `../hotline-protocol-docs`; the mothra worktree
is removed after its branch merges.

## Artefacts and notes

Proposed sets and move map. Every file moves to `docs/<set>/` under its current
name.

- `protocol` (15): `protocol`, `core-field-schemas`, `operation-contracts`,
  `session-transport-contracts`, `native-wire-details`, `error-outcomes`,
  `failure-representatives`, `parameter-multiplicity`, `date-contracts`,
  `request-500-contract`, `receive-limit-origin`, `bitmap-boundaries`,
  `diagnostic-replies`, `diagnostic-formatting-trace`,
  `diagnostic-transfer-boundaries`.
- `presence-and-messaging` (8): `presence-messaging-contracts`,
  `presence-defaults`, `notification-104-variants`, `native-104-variants`,
  `rate304-contract`, `rate304-recipient-predicate`, `native-console-broadcast`,
  `native-ban-notices`.
- `accounts-and-privileges` (9): `privilege-contracts`, `privilege-bits`,
  `account-attribute-trace`, `account-write-ordering`,
  `classic-account-constructors`, `classic-privilege-discovery`,
  `native-ban-file-format`, `native-configured-ban-static`,
  `native-configured-ban-ui-resources`.
- `files-and-transfers` (6): `filesystem-and-board-contracts`,
  `transfer-contracts`, `alias-record-v2`, `native-path-fields`,
  `native-download-send-path`, `native-transfer-stall`.
- `news` (2): `news-contracts`, `legacy-board-format`.
- `peers` (10): `identified-client-source`, `peer-tolerance-matrix`,
  `peer-profile-rules`, `classic-login-proxy`, `classic-native-baseline`,
  `classic-field161-matrix`, `classic-roster-subject-115`,
  `classic-server-name-162`, `mac-peer-first-session`,
  `mac-peer-isolated-session`.
- `mxd` (8): `internal-compatibility-matrix` and the seven `mxd-*` files.
- `native-evidence` (42): `native-capture-workflow`,
  `native-control-readiness`, `runtime-recovery-20261113`, and every remaining
  `native-*` file, which are the preparation, witness, cleanup, readiness and
  sequence records.
- `provenance` (2 moved): `baseline-correction-map`, `evidence-portability`.
  Its overview also introduces the root-level register and gap analysis.

Planned diagrams, each with a screen-reader description and caption: in
`README.md`, how the guide, contracts, native evidence, ledger and register
relate; in the `protocol` overview, the session sequence from handshake through
login to transactions; in `files-and-transfers`, the transfer handover from
request to the data connection; in `native-evidence`, the preparation, capture,
witness and verifier life cycle; in `provenance`, the gap state machine Open,
Investigating, Resolved and Deferred; in `docs/developers-guide.md`, the edit,
gate, audit-refresh and commit loop. Diagrams inside existing documents are
added only where a described flow has three or more steps and the text already
states each step.

Transcripts and commit hashes are added here as milestones complete.

## Interfaces and dependencies

Tools and pins: Python 3.14; `uv`; Ruff 0.16.8; `ty` 0.0.56; pytest with
Hypothesis; Cyclopts; `interrogate`; Pylint 4.0.9 with `df12-python-lints`
v0.4.0; mdtablefix 0.6.1; markdownlint-cli2 (0.20.0 is installed); nixie;
`typos-config-builder` v0.1.3. No external process is invoked from Python, so
no process library is needed.

New files at the end of EP-M2:

- `pyproject.toml`: project metadata with `requires-python = ">=3.14"`, a
  `dev` dependency group, and the Ruff, Pylint and pytest tables copied from
  the df12 template with `target-version = "py314"`.
- `scripts/ruff.toml`: default Ruff settings for the legacy scripts.
- `Makefile` with `.NOTPARALLEL:` and the targets `help`, `all`, `fmt`,
  `check-fmt`, `markdownlint`, `spelling`, `nixie`, `links-check`,
  `evidence-check`, `style-check`, `audit-check`, `lint-python`, `typecheck` and
  `test`. `MOTHRA ?= $(firstword $(wildcard ../mothra ../../mothra))`.
  `markdownlint` depends on `spelling`, as in netsuke. `audit-check` runs
  `python3 $(MOTHRA)/scripts/render-protocol-gap-analysis.py --check`.
- `.markdownlint-cli2.jsonc`: netsuke's rules plus Lody's `MD024`
  `siblings_only`, `MD033` allowing `a` and `br`, and `MD049` underscore;
  ignoring `.uv-cache`, `.uv-tools` and `scripts/__pycache__`.
- `typos.local.toml` (authored) and `typos.toml` (generated).
- `docs/documentation-style-guide.md`: verbatim copy at `991af84`.
- `AGENTS.md`: the gates, the audit-refresh rule, and the constraints above.

Each tool is a Cyclopts application with a `main` entry point, numpy-style
docstrings, typed signatures, and exit codes 0 for success, 1 for findings and
2 for missing inputs:

```python
# tools/check_links.py
def check(root: Path, *, mothra: Path | None = None) -> Report: ...

# tools/refresh_audit.py
def refresh(root: Path, mothra: Path, revision: int, *, today: dt.date) -> Revision: ...

# tools/migrate_layout.py  (deleted in EP-M7)
def rewrite_link(link: str, source: PurePosixPath, moves: Mapping[PurePosixPath, PurePosixPath]) -> str: ...

# tools/check_evidence.py
def check(root: Path, mothra: Path, *, write: bool = False) -> Report: ...

# tools/check_style.py
def check(root: Path) -> Report: ...
```

`check_style` reports tables without a caption and Mermaid blocks without a
preceding screen-reader paragraph or a following figure caption, and skips the
generated `gap-analysis.md`. `check_evidence` pairs each mothra corpus with its
verifier by reading the recipes in `mothra/Makefile`, and writes one row per
corpus: corpus link, verifier, citing documents and sections, related gaps, and
ledger identifiers.
