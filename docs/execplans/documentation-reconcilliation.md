# Reconcile, correlate and orient the Hotline Protocol documentation

This ExecPlan (execution plan) is a living document. The sections `Constraints`,
`Tolerances`, `Risks`, `Progress`, `Surprises & discoveries`, `Decision log`,
`Outcomes & retrospective`, `Conformance basis`, and `Verification plan` must
be kept up to date as work proceeds.

Status: IN PROGRESS

## Purpose / big picture

The repository holds 103 Markdown documents about the Hotline 1.9 wire
protocol, all in one flat directory, with no README, no index and no gates of
its own. The evidence those documents cite, the ledger of baseline findings,
the gap-register renderer and the audit snapshots all live in a second
repository, `mothra`, which is meant to be a general reverse-engineering
toolset and should know nothing about Hotline. The eight documents about mxd,
the server implementation this documentation serves, grew by accretion and are
hard to follow.

After this work:

- A reader opens `README.md`, picks an entry point by task, and reaches any
  document in at most three links. Documents sit in eight subject sets under
  `docs/`, each with an overview, a reading order and a generated evidence
  index.
- This repository is self-contained. Its evidence, ledger, renderer and checks
  live here, and `make all` passes with no Hotline-specific file present in
  mothra.
- mothra contains only general tooling. Searching its tracked files for
  Hotline-specific names finds nothing.
- The few remaining references from these documents to mothra are absolute
  GitHub links pinned to a commit.
- The mxd set reads as one coherent account: current status first, then the
  compatibility policy, the accepted corrections, the client trials and the
  how-to, each stated once.
- Every Python script in the repository, the 236 inherited capture and
  verification scripts included, meets the df12 Python standards, with its
  behaviour shown unchanged.
- A reader who wants to regenerate a piece of evidence finds directions here
  that use the mothra toolset. Those directions assume a working toolset and
  link to mothra for its set-up; they do not repeat it.
- `make all` proves that every link and anchor resolves, every cited gap,
  ledger entry and evidence artefact exists, prose about gap status agrees with
  the register, Mermaid diagrams render, tables are well formed, spelling
  follows Oxford British English, and the Python tooling passes the df12 gates.

The model for the tree is the Lody documentation at
`../../lody-docs.worktrees/unified-documentation-tree/`.

This is an editorial and structural pass. It makes no new protocol observation,
closes no gap, and does not resume the parked native and mxd investigations.
The script work is a behaviour-preserving refactor.

## Constraints

- No protocol or mxd claim may change meaning. Permitted edits to existing
  prose are: link targets, spelling, wrapping, table layout, captions,
  screen-reader descriptions, letter-case of headings, orientation paragraphs,
  and dated supersession notes that quote the gap register. The mxd set may
  additionally be reorganized under the rules of EP-M7.
- The gap register keeps exactly 87 gaps. Every `id`, `status`, `question`,
  `closure_criteria`, `priority`, `kind` and `depends_on` value stays
  byte-identical. Only source locations, coverage locations and link targets
  inside strings may change.
- Outside the mxd set and the set-up passages moved to mothra, no heading in
  an existing document may be added, removed or reordered, and a heading's
  anchor slug must not change. Case-only edits are allowed because the slug is
  lowercased.
- Evidence files are never modified. They move from `mothra/evidence/` to
  `evidence/` in this repository with identical bytes and identical paths
  beneath `evidence/`, so every existing `SHA256SUMS` file still verifies from
  the repository root. Formatters and linters never touch `evidence/`.
- Path strings inside existing evidence that name `../mothra/` or the old flat
  document paths are historical and stay as written.
- Legacy scripts keep their behaviour. Capture planners, control scripts and
  `verify_*.py` checkers keep their file names and their documented command
  lines, because documents and evidence records cite them. Every verifier must
  reach the same verdict on every retained corpus before and after, and every
  planner must emit byte-identical plans.
- Large and binary evidence is stored through Git LFS (Large File Storage),
  which keeps a small pointer in Git and the content in a separate store. The
  rule is fixed: under `evidence/`, every `*.png`, `*.pcap` and `*.gz` file is
  an LFS object; everything else, JSON of any size included, is ordinary Git.
  The content of each file is unchanged. No file outside `evidence/` uses LFS.
- Every tracked `*.json` file must parse and must be in the canonical layout
  the repository already uses: two-space indentation, keys in their existing
  order, non-ASCII characters written literally, and one trailing newline.
  Authored JSON outside `evidence/` is brought to that layout by `make fmt`.
  JSON under `evidence/` is checked and never rewritten, because its bytes are
  covered by recorded hashes.
- General guidance on installing or setting up the mothra toolset is not
  written or kept in this repository. Where an existing document contains it,
  the passage moves to mothra in general form and is replaced by a link.
- After EP-M4, mothra must not name this repository, Hotline, mxd, SynHX or
  shx in any tracked file, and this repository must not contain a relative link
  into a mothra checkout.
- mothra's history is not rewritten. Removal is by forward commits on a
  branch. Nothing is merged into either repository's `main` by this plan.
- The main checkouts at `/data/leynos/Projects/hotline-protocol-docs` and
  `/data/leynos/Projects/mothra` are not edited. Work happens in linked
  worktrees on branches named `documentation-reconcilliation`. The one
  exception is pushing mothra's existing `main` to `origin`, which the owner
  has authorized.
- No native run, Ghidra query, emulator start or mxd build is performed.
- `docs/documentation-style-guide.md` is a verbatim copy of the df12 guide and
  is not edited here.
- Format, lint and test commands run sequentially, never in parallel.
- Each change is committed separately after its gates pass.

## Tolerances (exception triggers)

- Scope: this ExecPlan file, imported files and pure moves are excluded from
  all counts, as is the script refactor of EP-M5, which has its own limit
  below. Stop and escalate if more than 65 new authored files or 8,500 net new
  lines of code and documentation are needed, or if new Python tooling exceeds
  2,200 lines excluding tests.
- Meaning: if reconciling two documents requires choosing between claims that
  the retained evidence does not decide, stop for that item, record it in the
  reconciliation log, and continue with the rest. If more than ten such items
  accumulate, stop and escalate.
- Register: if any step would add, remove, re-status or re-word a gap, stop.
- Classification: if a mothra file is partly general and partly
  Hotline-specific and cannot be split by deleting or parameterizing the
  specific part in under 50 changed lines, stop for that file and escalate.
- Script behaviour: if any verifier verdict, planner output or existing test
  outcome differs after a change to a legacy script, stop work on that script
  family, revert the change and escalate. Do not adjust a test or a golden file
  to make a refactor pass.
- Suppressions: lint suppressions in legacy scripts must be line-scoped and
  carry a reason. If more than 40 are needed in total, or any file-wide or
  rule-wide exemption beyond those in the df12 template, stop and escalate.
- Untestable scripts: if a script that drives the emulator or a live server
  has no test and cannot be given one without a native run, refactor it only as
  far as mechanical fixes allow, list it in `Decision log`, and continue. If
  more than fifteen scripts fall in this class, stop and escalate.
- Script effort: if the script milestone exceeds 25,000 changed lines
  excluding moved tests, stop and report before continuing.
- Dependencies: the tools named in `Interfaces and dependencies` are approved.
  Any other new dependency triggers escalation.
- Iterations: if a gate still fails after five attempts at one cause, stop.
- Ambiguity: if a document fits two sets and the choice changes a reader's
  route, record the choice in `Decision log`; if more than five documents are
  contested, stop and present the alternatives.

## Risks

- Risk: an audit refresh silently records the wrong source location for a gap.
  Severity: high. Likelihood: medium. Mitigation: obligation INV-AUDIT; the
  refresh tool must first reproduce revision 89 byte for byte, and the existing
  renderer's `--check` is the independent oracle.
- Risk: the import drops or alters an evidence file. Severity: high.
  Likelihood: low. Mitigation: obligation INV-IMPORT compares the content hash
  of every imported file with mothra's and re-runs all 415 `SHA256SUMS` files.
- Risk: removing material from mothra before this repository can stand alone
  loses the only working copy of a check. Severity: high. Likelihood: low.
  Mitigation: EP-M4 starts only after EP-M3's ported checks pass here; mothra
  `main` is pushed first, so the pre-removal state is recoverable from `origin`.
- Risk: pushing mothra publishes about 987 MiB of Hotline evidence into its
  permanent history. Severity: medium. Likelihood: certain. Mitigation: the
  owner authorized the push; it is recorded as decision D8 so the consequence
  is explicit.
- Risk: this repository's working tree grows to about 1 GB. Severity: low.
  Likelihood: certain. Mitigation: Git LFS keeps about 642 MiB of it out of the
  Git object store, and a clone can skip it with `GIT_LFS_SKIP_SMUDGE=1`.
- Risk: the first push uploads about 642 MiB to GitHub's LFS store, which is
  metered for storage and bandwidth. Severity: medium. Likelihood: certain.
  Mitigation: EP-M0 records the account's LFS quota and the expected upload
  before anything is pushed; if the quota is short, stop and escalate.
- Risk: a checkout without LFS content holds pointer files, so a verifier or
  a `SHA256SUMS` check fails confusingly. Severity: medium. Likelihood: medium.
  Mitigation: `make lfs-check` runs first in every evidence target and fails
  with a message naming `git lfs pull`.
- Risk: relocating 102 documents breaks some of roughly 2,200 relative links.
  Severity: medium. Likelihood: high without tooling. Mitigation: moves are
  performed by a tested script and the link gate runs before and after.
- Risk: reorganizing the mxd documents loses or duplicates a finding.
  Severity: high. Likelihood: medium. Mitigation: obligation INV-MXD, a claim
  inventory made before any edit and reconciled after.
- Risk: refactoring about 61,600 lines of evidence-producing scripts changes
  what a verifier accepts. Severity: high. Likelihood: medium. Mitigation:
  obligation INV-SCRIPT; verdicts, plans and test outcomes are captured as
  goldens before the first change and compared after every family.
- Risk: the evidence-recreation directions cannot be exercised end to end,
  because no native run is permitted in this pass. Severity: medium.
  Likelihood: certain. Mitigation: every offline step is executed; steps that
  need the emulator are checked for the existence and command-line validity of
  each script they name, and the guide states which parts were not re-run.
- Risk: parallel sub-agents overwrite one another's work or report success
  that the gates do not bear out. Severity: medium. Likelihood: medium.
  Mitigation: disjoint edit lists, commits by the lead or journeyman only, and
  no progress recorded without scrutineer evidence; see
  `Delegation and escalation`.
- Risk: the spelling gate flags protocol tokens such as `FILP` and `alis`,
  tempting unsafe edits to quoted bytes. Severity: medium. Likelihood: high.
  Mitigation: wrap wire tokens in backticks, which the gate ignores, or add
  exact entries to `typos.local.toml`; never alter a quoted byte string.
- Risk: summaries in new overviews drift from the documents they summarize.
  Severity: medium. Likelihood: medium. Mitigation: every summary sentence in a
  set overview links to the section that states it.
- Risk: mothra holds untracked, Hotline-specific runtime state under `state/`
  that legacy scripts reference. Severity: low. Likelihood: certain.
  Mitigation: out of scope; it is local, untracked and unpublished. Record it
  in the retrospective as residual.

## Progress

- [x] (2026-11-15 12:33Z) Surveyed this repository, the Lody exemplar, the
  netsuke gates, the df12 Python template and the mothra coupling.
- [x] (2026-11-15 12:33Z) Drafted this ExecPlan (commit `8dc6714`).
- [x] (2026-11-15 12:55Z) Revised for three owner directions: mothra becomes
  general, mothra links become GitHub links, and the mxd set is tidied.
- [x] (2026-11-15 13:20Z) Owner settled D1, D2 (full scope), D4 and D10, and
  asked for evidence-recreation directions; plan revised.
- [x] (2026-11-15 14:50Z) Revised to store large evidence through Git LFS.
- [x] (2026-11-15 15:05Z) Added the delegation and escalation protocol.
- [x] (2026-11-15 15:20Z) Kept JSON in Git and added a JSON formatting gate.
- [x] (2026-11-15 15:40Z) Owner approved implementation.
- [ ] EP-M0 in progress (completed: secret-pattern scan of mothra's tracked
  files, clean; JSON census; repository visibility check. Running: baseline
  gates, mothra classification, set-up passage census. Held: the push of mothra
  `main`, pending the owner's confirmation; the LFS quota reading).
- [ ] EP-M0: baseline, mothra pushed, LFS quota checked, classification
  manifest.
- [ ] EP-M1: tooling foundation and link gate.
- [ ] EP-M2: audit refresh tool proven against revision 89.
- [ ] EP-M3: Hotline material imported; repository self-contained; revision 90.
- [ ] EP-M4: mothra generalized on a branch and pushed.
- [ ] EP-M5: all scripts meet the df12 Python standards; revision 91.
- [ ] EP-M6: documents relocated into sets; revision 92.
- [ ] EP-M7: mxd set consolidated; revision 93.
- [ ] EP-M8: on-ramps, orientation, recreation guide and diagrams.
- [ ] EP-M9: evidence correlation and reconciliation; revision 94.
- [ ] EP-M10: style conformance and cross-references; revision 95.
- [ ] EP-M11: final validation and retrospective.

## Surprises & discoveries

- Observation: every one of the 102 authored documents is a byte-hashed input
  to the gap audit. Evidence: revision 89's `manifest.json` lists 102 inputs,
  and `validate` in `mothra/scripts/render-protocol-gap-analysis.py` raises
  "Audit input changed; refresh the review" on any hash difference. Impact:
  every editing milestone ends with a new audit revision.
- Observation: mothra is mostly Hotline material. Evidence: 17,585 of its
  roughly 17,700 tracked files are under `evidence/`, totalling 987 MiB; its
  `Makefile` lints and runs this repository's scripts by relative path. Impact:
  EP-M3 and EP-M4.
- Observation: mothra `main` is 278 commits ahead of `origin/main`. Evidence:
  `git -C ../../mothra status -sb`. Impact: GitHub links cannot resolve until
  it is pushed; EP-M0 pushes it.
- Observation: relative links of the form `../mothra/...` (1,053 of them) do
  not resolve from a linked worktree. Impact: until EP-M3, checks that follow
  those links take the mothra location as a parameter.
- Observation: prose already disagrees with the register in at least four
  places. Evidence: `native-pm-preparation.md` and `native-ui-focus-witness.md`
  say GAP-044 remains open, `native-settings-preparation.md` says GAP-015 stays
  open, and `native-diagnostic-existing-preparation.md` says GAP-037 remains
  open; the register marks all three Resolved. Impact: known positives for the
  status check in EP-M9.
- Observation: seven gaps (GAP-009, 013, 056, 058, 060, 066 and 069) are
  mentioned nowhere outside `gap-analysis.md`, and 48 non-test scripts are
  cited by no document. Impact: inputs to the correlation pass.
- Observation: the mxd documents are organized by the order in which work
  happened. Evidence: three titles carry commit hashes; four have no section
  headings or only two; the same three corrections are described in
  `mxd-validation.md`, in their own documents and in
  `internal-compatibility-matrix.md`; current status, history and procedure are
  interleaved. Impact: EP-M7.
- Observation: the legacy scripts are far from the df12 standard. Evidence:
  with episodic's Ruff configuration and Ruff 0.16.8, `scripts/` has 7,079
  findings (chiefly magic values, missing docstrings, `unittest` assertions,
  bare `ValueError` messages and complexity) and 74 files need reformatting; 47
  modules exceed 400 lines; 107 use `argparse`; 12 use `subprocess`; the 88
  test files hold 758 `unittest` tests. Impact: EP-M5 is the largest milestone.
- Observation: `native-capture-workflow.md` opens with "Prepare the emulator
  and application", which mixes general emulator set-up with Hotline-specific
  preparation. Impact: EP-M4 and EP-M8 split it.
- Observation: `leynos/mothra` and `leynos/hotline-protocol-docs` are both
  public on GitHub, and mothra's unpushed commits track
  `evidence/hotline-server-1.9/inputs/HLserver19.pef`, the server binary under
  analysis, with its decompilations. Evidence: `gh repo view` reports `PUBLIC`
  for both; `git ls-files` lists the file. A pattern scan of tracked text for
  private keys and common token formats found nothing. Impact: the authorized
  push would publish the binary; the push is held and the question put to the
  owner. The same file will enter this public repository in EP-M3.
- Observation: the GitHub LFS quota cannot be read with the current token.
  Evidence: the billing endpoint asks for the `user` scope. Impact: the quota
  check in EP-M0 is unresolved; nothing in this plan pushes LFS content, so it
  matters only when the owner pushes this branch.
- Observation: of 5,141 evidence JSON files, 155 are not in the canonical
  layout and one does not parse
  (`evidence/gap-remediation/2026-11-14/native-ban-expiry-first-01/raw/readiness-generic.json`).
  None has a duplicate key. Evidence: a census run on 15 November 2026. The
  155 are raw tool replies and single-line status files. Impact: 156 entries go
  into the exceptions file that INV-JSON provides for; none is rewritten.
- Observation: the existing documents are otherwise close to clean. With the
  Lody markdownlint configuration only 18 MD049 findings appear, no local link
  is broken, and default `typos` reports 90 findings, mostly protocol tokens.

## Decision log

- Decision D1 (accepted by the owner, 2026-11-15): relocate the documents into a
  `docs/<set>/` tree instead of adding an index over the flat directory.
  Rationale: the request is to model the tree on Lody's, and 103 siblings
  defeat orientation however good the index. Date/Author: 2026-11-15, planning
  agent.
- Decision D2 (settled by the owner, 2026-11-15): the df12 Python standards
  apply in full to every Python file, including the 236 legacy scripts and
  those imported from mothra. The planning agent had proposed limiting them to
  new tooling; the owner chose full scope. Consequence: milestone EP-M5 and
  obligation INV-SCRIPT.
- Decision D3 (settled by the owner, 2026-11-15): mothra is a general
  reverse-engineering and validation toolset. Everything Hotline-specific moves
  here. This replaces the earlier proposal to add audit revisions inside mothra.
- Decision D4 (accepted by the owner, 2026-11-15): stale status statements in
  dated preparation and witness records are not rewritten. A dated note is
  added beneath them giving the register's current status. Rationale: the
  records are historical. Date/Author: 2026-11-15, planning agent.
- Decision D5: evidence citations stay as inline links to evidence artefacts,
  ledger identifiers and gap identifiers. Lody-style `E-…` row identifiers are
  not retrofitted. Rationale: 743 evidence links and 521 ledger citations
  already carry stable identities; a generated index supplies the reverse
  lookup. Date/Author: 2026-11-15, planning agent.
- Decision D6: set overviews and orientation documents are not audit inputs.
  Rationale: they state nothing that a member document does not state.
  Date/Author: 2026-11-15, planning agent.
- Decision D7: from the df12 template's lint chain, adopt Ruff, `ty`,
  `interrogate`, Pylint with the df12 messages, and pytest, for every Python
  file. Omit the dead-code, duplication, workflow-lint and mutation gates.
  Rationale: there is no installable package and no workflow here. Date/Author:
  2026-11-15, planning agent.
- Decision D8 (settled by the owner, 2026-11-15): mothra `main` may be pushed
  to `origin`. Consequence accepted: the Hotline evidence remains in mothra's
  published history; later commits remove it from the tree.
- Decision D9 (revised by the owner, 2026-11-15): the imported evidence uses
  Git LFS under the rule in `Constraints`. It is imported with its history:
  `git filter-repo` selects the paths on a scratch clone,
  `git lfs migrate import` converts the qualifying files throughout that
  scratch history, and the result is merged as an unrelated history. The
  planning agent had proposed ordinary Git; the owner asked for LFS. Measured
  effect: 537 PNG files (307 MiB), 241 packet captures (295 MiB) and 17 gzip
  files (39 MiB) become LFS objects, about 642 MiB in all; the remaining 16,790
  or so files (roughly 345 MiB, mostly JSON and text) stay in Git. A first
  draft also sent every file of 1 MiB or more to LFS; the owner asked for JSON
  to stay in Git, and with JSON excluded only two such files remained, so the
  size clause was dropped.
- Decision D10 (accepted by the owner, 2026-11-15): the mxd set is reorganized
  into the six documents listed under EP-M7. Rationale: one document per reader
  question, each finding stated once. Date/Author: 2026-11-15, planning agent.
- Decision D11 (settled by the owner, 2026-11-15): links from these documents
  to mothra are absolute GitHub URLs. They are written as permalinks,
  `https://github.com/leynos/mothra/blob/<commit>/<path>`, pinned to the commit
  pushed in EP-M0. Rationale for pinning: the target files are edited in EP-M4,
  and a permalink keeps the cited text stable.
- Decision D12: legacy scripts that need mothra's general tooling at run time
  find it through an environment variable `MOTHRA_ROOT`, defaulting to a
  sibling checkout. Rationale: a file-system dependency on a tool is not a
  document link, and the dependency runs one way only. Date/Author: 2026-11-15,
  planning agent.

- Decision D13: scripts run in the project environment through `uv run`, as
  episodic's do, and carry no per-script dependency header. Rationale: they
  import one another as sibling modules, which a self-contained script header
  does not support. Date/Author: 2026-11-15, planning agent.
- Decision D14: tests for legacy scripts move from `scripts/test_*.py` to
  `scripts/tests/`, as the df12 scripting standards prescribe, and become
  pytest tests. Modules over 400 lines are split into a module of the same name
  plus helper modules, so cited file names survive. Date/Author: 2026-11-15,
  planning agent.
- Decision D15 (settled by the owner, 2026-11-15): this repository gives
  directions for recreating its evidence with the mothra toolset and gives no
  general toolset set-up guidance. The directions live in
  `docs/native-evidence/recreating-evidence.md`, and each row of a generated
  evidence index links to the procedure that recreates that corpus.

## Outcomes & retrospective

Not yet started. To be completed at EP-M11.

## Context and orientation

Paths in this section are given from `/data/leynos/Projects/`.

`hotline-protocol-docs` is this repository, remote
`git@github.com:leynos/hotline-protocol-docs`. Its root holds 103 Markdown
files. `protocol.md` is the baseline guide. About fifteen `*-contracts.md` and
related files refine it by subject. About forty `native-*-preparation.md` and
`native-*-witness.md` files each record one planned or executed capture against
the native server. `classic-*`, `mac-peer-*` and `identified-client-source.md`
describe peer clients. `mxd-*` and `internal-compatibility-matrix.md` concern
mxd. `gap-register.json` is the canonical list of 87 open questions ("gaps"),
and `gap-analysis.md` is rendered from it. `scripts/` holds 236 Python files:
capture planners, `verify_*.py` checkers for retained evidence, and `unittest`
tests beside them; 76 of them locate evidence with
`Path(__file__).resolve().parents[2] / "mothra/..."`. There is no `README.md`,
`Makefile`, `pyproject.toml` or `AGENTS.md`.

`mothra`, remote `git@github.com:leynos/mothra`, currently mixes two things.
The general part is a SheepShaver emulator harness (`sheepshaver.md`,
`scripts/build-sheepshaver`, `scripts/mac_runtime.py`,
`scripts/mac_network_isolation.py`, `scripts/stage_mac_application.py` and
similar), Ghidra wrappers (`ghidra`, `ghidra-mcp`, `.mcp.json`), and guides
such as `docs/runtime-storage.md`. The Hotline-specific part is:

- `evidence/`: Ghidra query records, capture corpora and audit snapshots.
- `docs/baseline-validity-ledger.md`, the "ledger": numbered findings such as
  V003, M008 and C004 that the documents cite. Valid identifiers are listed in
  `evidence/hotline-server-1.9/claims.json`.
- `docs/gap-remediation-worklog.md`, `docs/protocol-handoff.md`,
  `docs/delegation/`, `docs/debugging/`, `docs/execplans/` and `shx-peer.md`.
- `scripts/render-protocol-gap-analysis.py` (the renderer),
  `scripts/package-protocol-evidence.py`, and verifiers and harnesses for mxd,
  shx and SynHX.
- Most of the `Makefile`, which lints and type-checks
  `../hotline-protocol-docs/scripts` and runs its verifiers against corpora.

An "audit revision" is a directory such as
`evidence/protocol-gap-analysis/2026-11-15/revision-89/`. Its `manifest.json`
lists each input document with a SHA-256 hash and a frozen snapshot;
`sections.json` lists every heading of every input with its line range and
anchor; `SHA256SUMS` covers the directory. The register's `sources` and
`review_coverage` entries must match `sections.json` exactly. Revision 89 has
102 inputs and 543 sections. No script produces a revision today.

The exemplar is `lody-docs.worktrees/unified-documentation-tree/`. Its
`README.md` has a table of sets, a table of entry points by task, one Mermaid
overview and a section on running the checks. `docs/contents.md` lists every
document once with a reason to open it. `docs/repository-layout.md` and
`docs/developers-guide.md` serve maintainers. Each `docs/<set>/README.md` gives
scope, neighbouring sets, a one-page numbered summary, a documents table,
conventions, and what the set does not establish. Tooling sits in `scripts/`
with pytest tests in `tests/`.

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
`mdtablefix --check --wrap --renumber --breaks --ellipsis --fences`;
`markdownlint-cli2`; `typos-config-builder gate --repository .` at tag
`v0.1.3`, which generates `typos.toml` from a shared Oxford dictionary plus the
local overlay `typos.local.toml`; and `nixie --no-sandbox`, which renders every
Mermaid block.

The Python standards come from
`agent-template-python/template/pyproject.toml.jinja` and
`template/docs/scripting-standards.md`, as practised in `episodic`: Ruff with
the template's rule selection, numpy-style docstrings, complexity limit 8, `ty`
for type checking, pytest tests, Cyclopts for command lines, `pathlib`
throughout, and modules under 400 lines.

## Conformance basis

No Terms of Reference, technical design or ADR exists for this work. The
upstream authority is the owner's request and later directions, all of
15 November 2026:

- REQ-1: reconcile the documents with one another and with the register.
- REQ-2: correlate documents with their evidence.
- REQ-3: add on-ramps, orientation and cross-references, modelled on Lody.
- REQ-4: follow the df12 documentation style guide at commit `991af84`.
- REQ-5: validate with nixie, mdtablefix, spelling and markdownlint as netsuke
  does.
- REQ-6: every Python script follows the df12 Python standards, the legacy
  scripts included.
- REQ-7: include Mermaid diagrams where they help, validated by nixie.
- REQ-8: nothing in mothra is specific to the Hotline work.
- REQ-9: links to mothra are absolute GitHub links.
- REQ-10: the mxd validation documents are tidied into a coherent set.
- REQ-11: the documents give directions for recreating the evidence with the
  mothra toolset, without general guidance on setting that toolset up.
- REQ-12: large binary evidence uses Git LFS; JSON stays in Git and is held
  to a formatting gate.

Trace links:

```plaintext
REQ-1  -> EP-M9 -> make evidence-check (status, identifiers); docs/reconciliation-log.md
REQ-2  -> EP-M9 -> docs/<set>/evidence.md generated; make evidence-check
REQ-3  -> EP-M6, EP-M8, EP-M10 -> make links-check (reachability, contents)
REQ-4  -> EP-M1, EP-M10 -> make markdownlint, make style-check
REQ-5  -> EP-M1, EP-M10 -> make check-fmt, markdownlint, spelling, nixie
REQ-6  -> EP-M1, EP-M2, EP-M5 -> make lint-python, typecheck, test; INV-SCRIPT
REQ-7  -> EP-M8, EP-M10 -> make nixie
REQ-8  -> EP-M3, EP-M4 -> INV-IMPORT; mothra name search empty; mothra make check
REQ-9  -> EP-M3 -> make links-check (no relative mothra link; permalink shape and target)
REQ-10 -> EP-M7 -> INV-MXD claim inventory reconciled
REQ-11 -> EP-M4, EP-M8, EP-M9 -> INV-RECREATE; docs/native-evidence/recreating-evidence.md
REQ-12 -> EP-M1, EP-M3 -> make lfs-check, make json-check; INV-IMPORT, INV-JSON
audit validity (inherited) -> EP-M2, EP-M3, EP-M6, EP-M7, EP-M9, EP-M10 -> make audit-check
```

## Verification plan

Third-party tools (markdownlint, mdtablefix, typos, nixie, Ruff, `ty`, Git,
`git filter-repo`) are axioms at their documented interfaces. The existing
renderer's `validate` function is an independent oracle and is not re-verified.
A further axiom is the heading-slug rule the renderer uses: lowercase, drop
characters other than word characters, hyphens and spaces, then replace spaces
with hyphens. The link tool uses the same rule, and a test pins it against the
543 anchors in revision 89.

- Obligation INV-LINK: every relative link and fragment in every tracked
  Markdown file outside `evidence/` resolves to an existing file and heading or
  explicit anchor; no link is a relative path into a mothra checkout; every
  `github.com/leynos/mothra` link is a `blob/<40-hex>/<path>` permalink whose
  path exists at that commit in the local mothra clone. Method: parameterized
  tests over link forms, plus a run over the real tree. Artefact:
  `tests/test_check_links.py`. Evidence: `make links-check` exits 0.
  Non-vacuity: the run must report at least 2,000 links checked; tests seed a
  missing file, a missing anchor, a `../mothra/` link, a branch-named GitHub
  link and a permalink to an absent path, each rejected with a message naming
  the link.
- Obligation INV-REACH: every Markdown document under `docs/`, other than
  `docs/execplans/` and imported working records, appears exactly once in
  `docs/contents.md` and exactly once in a set overview's documents table.
  Method: parameterized tests and the real run. Non-vacuity: seeded unlisted
  and doubly listed documents are rejected.
- Obligation INV-IMPORT: every file selected by the classification manifest
  exists here with the same content as at the pushed mothra commit, no
  unselected file was imported, the LFS rule holds exactly, and every
  `SHA256SUMS` under `evidence/` verifies from the repository root. Method:
  exhaustive comparison of the SHA-256 of each file's content in mothra with,
  for an ordinary file, the SHA-256 of the blob here and, for an LFS file, the
  object identifier in its pointer, which is the SHA-256 of the content; a
  check that the set of LFS paths equals the set the rule selects; then
  `sha256sum --check` over all sums files with LFS content present. Artefact:
  `tools/check_import.py` with `tests/test_check_import.py`. Evidence:
  `17,5xx files, 0 differences` and 415 sums files verified. Non-vacuity: tests
  seed an altered blob, a missing file, an extra file, a PNG left in ordinary
  Git and a JSON file wrongly in LFS; the real run asserts the expected file
  count and exactly the 795 LFS objects measured.
- Obligation INV-MOVE: relocation changes nothing but link targets. For each
  moved document, the heading sequence and every line containing no link are
  identical before and after, and every link resolves to the moved counterpart
  of its old target. Method: a Hypothesis property test of the link rewriter
  (for any source, target and move map, resolving the rewritten link from the
  new location equals the mapped old resolution) plus a comparison over the
  real tree. Artefact: `tests/test_migrate_layout.py`. Non-vacuity: generators
  must produce moves that change directory depth in both directions,
  classification counts are asserted, and a rewriter that returns its input
  unchanged must fail.
- Obligation INV-AUDIT: a refreshed audit revision is exactly what the
  renderer accepts, and gap content is preserved. Lemma: with headings neither
  added, removed nor reordered, the n-th section of the old snapshot
  corresponds to the n-th section of the new file; for the mxd set, an explicit
  reviewed section map supplies the correspondence instead. Method: golden test
  reproducing revision 89 from unchanged inputs; parameterized tests for a
  shifted line range, a relocated path and a mapped section; then the oracle.
  Artefact: `tests/test_refresh_audit.py`. Evidence: `make audit-check` exits 0
  and a comparison prints `87 gaps, 0 protected fields changed`. Non-vacuity: a
  seeded heading insertion without a map entry must be refused; a seeded change
  to one `closure_criteria` string must be detected.
- Obligation INV-MXD: every claim in the eight original mxd documents appears
  in the reorganized set with the same meaning, exactly once as a full
  statement, or is recorded as a removed duplicate with the location of the
  retained statement. Method: a claim inventory, one row per factual statement,
  commit hash, count, date and evidence link, built before editing and
  reconciled after; a mechanical check that every evidence link, commit hash,
  SHA-256 value and number of three or more digits in the originals occurs in
  the new set. Artefact: `docs/reconciliation-log.md` and
  `tests/test_check_evidence.py`. Non-vacuity: the mechanical check is run
  first against a copy with one hash deleted and must fail. Residual gap:
  meaning preservation of prose rests on review, not proof.
- Obligation INV-EVID: every cited ledger identifier is in `claims.json`,
  every gap identifier is in the register, every evidence link resolves, every
  script path cited exists, and the generated evidence indexes are current.
  Method: parameterized tests and the real run. Artefact:
  `tests/test_check_evidence.py`. Non-vacuity: the run must report at least 400
  ledger citations and 700 evidence links; seeded unknown identifiers and a
  stale index are rejected.
- Obligation INV-STATUS: no sentence asserts a gap status that contradicts the
  register, unless it sits in a dated supersession note. Method: parameterized
  tests over phrasings, and the real run. Evidence: the check fails on the four
  known cases before EP-M9 and passes after. Residual gap: the phrase list is
  finite; the review in EP-M9 reads every sentence that names a Resolved gap.
- Obligation INV-SCRIPT: refactoring a legacy script changes no observable
  behaviour. Three oracles are captured as goldens in EP-M0 and EP-M3, before
  any refactor: the verdict, exit code and output of every `verify_*.py`
  checker on every retained corpus it is run against; the byte content of every
  plan that a `*_cases.py` planner emits offline; and the name and outcome of
  every existing test. Lemma: converting a `unittest` test to pytest preserves
  what it asserts, shown by a one-to-one mapping of test names with no test
  deleted and assertion counts per test not reduced. Method: golden comparison
  after each script family, plus parameterized tests for each documented
  command line, which must still parse to the same arguments after the move to
  Cyclopts. Artefact: `tests/goldens/`, `tests/test_legacy_goldens.py` and
  `tools/capture_goldens.py`. Evidence: `make evidence-verify` and `make test`
  report the baseline counts, and the golden comparison prints `0 differences`.
  Non-vacuity: a negative control alters one comparison constant in one
  verifier and one byte in one emitted plan, and each must be reported; the
  baseline must show at least one verifier per corpus named in
  `evidence-verify` and at least 758 tests. Residual gap: scripts that only run
  against a live emulator are covered by their tests and plans, not by
  execution.
- Obligation INV-RECREATE: every corpus listed in a generated evidence index
  maps either to a procedure in the recreation guide or to a stated reason it
  cannot be recreated, and every script and command the guide names exists and
  parses. Method: parameterized tests and the real run, as part of
  `tools/check_evidence.py`; each named command is invoked with `--help`.
  Evidence: `make evidence-check` reports the corpus count with none unmapped.
  Non-vacuity: a seeded corpus with no procedure, and a seeded reference to a
  script that does not exist, are rejected. Residual gap: procedures that need
  the emulator are not executed in this pass, and the guide says so.
- Obligation INV-JSON: every tracked `*.json` file parses, and its bytes equal
  the canonical rendering of its parsed value: two-space indentation, key order
  preserved, non-ASCII characters literal, one trailing newline. Method:
  parameterized tests over layouts, plus a run over every tracked JSON file.
  Rationale: the rendering is a pure function of the parsed value, so equality
  is decidable per file and the finite set of layout faults can be enumerated.
  Artefact: `tools/check_json.py` with `tests/test_check_json.py`. Evidence:
  `make json-check` prints the file count and `0 failures`; before the import
  it covers `gap-register.json` and the two fixture files, and after it about
  5,140 evidence files as well. Non-vacuity: tests seed a syntax error, a
  duplicate key, tab indentation, a missing trailing newline, an escaped
  non-ASCII character and trailing whitespace, each rejected by name; a
  duplicate key is a failure because parsing would silently drop it. Known
  state: the three authored files and a sample of 400 evidence files already
  conform. If any evidence file does not, it is not rewritten; it is listed
  with its SHA-256 in an exceptions file that the gate reads, and the count is
  reported in the retrospective.
- Obligation INV-GENERAL: no tracked file on the mothra branch contains
  `hotline`, `hlserver`, `mxd`, `synhx`, `shx`, `HOTL`, `GAP-` followed by
  digits, or `protocol-docs`, in any letter case, and mothra's `make check`
  passes. Method: `git grep` over the branch plus the gate. Non-vacuity: the
  same search on the pushed `main` reports hundreds of matches.

Prose reconciliation beyond these checks is review work, recorded per set in
`docs/reconciliation-log.md` and not claimed as verified.

## Plan of work

Stage A is EP-M0. Record the baseline, push mothra `main`, and write the
classification manifest: one line for every tracked mothra path outside
`evidence/`, marked import, stay, or split, with the reason.

Stage B and C, tooling built test-first, are EP-M1 and EP-M2. Add
`pyproject.toml`, `Makefile`, `.markdownlint-cli2.jsonc`, `typos.local.toml`,
`.gitignore` and `.gitattributes` entries, a temporary `scripts/ruff.toml` that
holds the legacy scripts at their present rules, `AGENTS.md` and the style
guide copy. Write `tools/check_links.py` and then `tools/refresh_audit.py`,
each from failing tests. Documentation gates are wired in EP-M1 but only the
Python and link gates must pass until EP-M10, because fixing document findings
earlier would invalidate the audit before the refresh tool exists.

EP-M3 makes this repository self-contained. Import the selected mothra paths
with history. Rewrite `../mothra/evidence/` links to in-repository links and
every other mothra link to a GitHub permalink. Change the path expressions in
the legacy scripts. Bring over the renderer and the Hotline check targets from
mothra's `Makefile`. Capture the INV-SCRIPT goldens. Cut revision 90 inside
this repository.

EP-M4 generalizes mothra on a branch: delete what was imported, reduce its
`Makefile`, `README.md` and remaining guides to general tooling, and push the
branch. General emulator and toolset set-up passages found in this repository's
documents move to mothra in general form in the same milestone.

EP-M5 brings every legacy script to the df12 standard, one family at a time. A
family is a planner, its control script, its verifier and their tests, for
example the rate-304 family. Shared libraries (`protocol_capture`, `pcap_tcp`,
`native_packet_evidence`, `verify_native_core` and similar) go first. For each
family: convert its tests to pytest under `scripts/tests/`; apply formatting
and safe automatic fixes; then work through the remaining findings by adding
docstrings and annotations, naming magic values, replacing bare exceptions with
domain errors, reducing complexity by extracting functions, splitting modules
over 400 lines, moving command lines to Cyclopts and external processes to
`cuprum`; run the goldens; commit. When the last family is done, delete
`scripts/ruff.toml` so the root configuration governs everything.

EP-M6 relocates documents into sets with `tools/migrate_layout.py`. EP-M7
reorganizes the mxd set. EP-M8 writes the orientation layer as new files,
including the evidence-recreation guide. EP-M9 adds `tools/check_evidence.py`,
generates the evidence indexes and reconciles drift. EP-M10 applies the style
guide inside existing documents, adds neighbour links and diagrams, and turns
on every gate in `make all`. EP-M11 deletes the one-off migration tooling, runs
every gate in both repositories and writes the retrospective.

## Milestones and plateaus

- EP-M0, baseline. Outcome: baseline results, the GitHub LFS quota and the
  classification manifest are recorded in this plan; mothra `main` is on
  `origin`. Evidence: `make gap-check` in the mothra main checkout exits 0; the
  legacy `unittest` suite count is recorded; `git -C mothra status -sb` shows
  no commits ahead. Conformance: no tracked file changed in either repository.
  Recovery: none needed; the push adds commits only. Compatibility: none.
- EP-M1, tooling foundation. Outcome:
  `make lint-python typecheck test links-check` pass on the flat tree, with the
  mothra location passed as a parameter; documentation gate finding counts are
  recorded. Requirements: REQ-5, REQ-6 advanced. Evidence: INV-LINK in its
  pre-import form. Conformance: no existing document or script changed.
  Recovery: revert.
- EP-M2, audit refresh. Outcome: `tools/refresh_audit.py` reproduces revision
  89 from a read-only copy. Evidence: INV-AUDIT golden test. Conformance:
  nothing written outside this worktree. Recovery: revert.
- EP-M3, self-contained repository. Outcome: evidence, ledger, working
  records, renderer and Hotline verifiers live here; the legacy tests and every
  ported check target pass with `MOTHRA_ROOT` unset where they need no
  emulator; no relative mothra link remains; revision 90 is accepted.
  Requirements: REQ-8 (this side), REQ-9. Evidence: INV-IMPORT, INV-LINK,
  `make audit-check`, `make evidence-verify`. Conformance: script diffs touch
  path expressions only; 87 gaps unchanged. Recovery: revert the merge commit
  and the commits after it. Remaining: mothra still holds its copy.
  Compatibility: none; the old sibling layout is not supported afterwards.
- EP-M4, mothra generalized. Outcome: the mothra branch contains general
  tooling only and passes its reduced `make check`; the branch is pushed.
  Requirements: REQ-8. Evidence: INV-GENERAL. Conformance: this repository's
  `make all` subset from EP-M3 still passes against the mothra branch.
  Recovery: the branch is not merged; delete it to undo. Compatibility: none.
- EP-M5, script standards. Outcome: every Python file passes the df12 gates
  under one configuration; tests are pytest under `scripts/tests/`; no module
  exceeds 400 lines; revision 91 covers documents whose cited test paths
  changed. Requirements: REQ-6. Evidence: INV-SCRIPT;
  `make lint-python typecheck test evidence-verify`. Conformance: verifier
  verdicts, planner output and test outcomes identical to the goldens; planner,
  control and verifier file names unchanged; no suppression beyond tolerance.
  Recovery: each family is its own commit and can be reverted alone. Remaining:
  none for scripts. Compatibility: none; the `unittest` entry points are not
  kept.
- EP-M6, relocation. Outcome: documents live under `docs/<set>/`; revision 92
  is accepted. Requirements: REQ-3 advanced. Evidence: INV-MOVE, INV-LINK,
  `make audit-check`. Conformance: `git diff -M --stat` shows renames with
  link-only changes. Recovery: revert the relocation commit. Compatibility:
  none; old paths are tabulated in `docs/repository-layout.md`, not aliased.
- EP-M7, mxd set. Outcome: six documents replace eight; revision 93 is
  accepted. Requirements: REQ-10. Evidence: INV-MXD, INV-AUDIT with the section
  map, INV-LINK. Conformance: no finding changed; every inbound link from other
  sets and from the register updated. Recovery: revert the milestone's commits.
- EP-M8, on-ramps. Outcome: `README.md`, `docs/contents.md`,
  `docs/repository-layout.md`, `docs/developers-guide.md`, the set overviews and
  `docs/native-evidence/recreating-evidence.md` exist with at least five
  validated Mermaid diagrams. Requirements: REQ-3, REQ-7, REQ-11 advanced.
  Evidence: INV-REACH, `make nixie`. Conformance: new files only. Recovery:
  revert.
- EP-M9, correlation and reconciliation. Outcome: generated
  `docs/<set>/evidence.md` indexes; status drift resolved by dated notes;
  `docs/reconciliation-log.md` lists every discrepancy examined and its
  disposition; every indexed corpus maps to a recreation procedure or a stated
  reason; revision 94. Requirements: REQ-1, REQ-2, REQ-11. Evidence: INV-EVID,
  INV-STATUS, INV-RECREATE. Conformance: no claim changed meaning; 87 gaps.
  Recovery: revert.
- EP-M10, style and cross-references. Outcome: every gate in `make all`
  passes; revision 95. Requirements: REQ-4, REQ-5, REQ-7. Conformance: heading
  anchor sequences identical to revision 94. Recovery: revert per set; each set
  is a separate commit.
- EP-M11, completion. Outcome: both repositories pass their full gates;
  retrospective written; status COMPLETE. Merging either branch is left to the
  owner.

The mxd set after EP-M7, with the source of each document:

- `README.md`: scope, the pinned mxd revisions, the hold of 13 November 2026,
  a one-page summary and the reading order. New.
- `validation-status.md`: what has been validated, at which revision, with
  which results, and what remains; the pickup point for resuming work. From
  `mxd-validation.md`.
- `compatibility-matrix.md`: native, SynHX and mxd policy side by side. From
  `internal-compatibility-matrix.md`, with its mxd review sections moved to the
  documents below.
- `corrections.md`: the three accepted corrections (framing limits, direct
  replies, login extras), each under the same four headings: native baseline,
  behaviour before, correction, acceptance evidence. From
  `mxd-limit-contracts.md`, `mxd-direct-ack-correction.md` and
  `mxd-login-extras-correction.md`.
- `assertion-reconciliation.md`: the map from mxd test assertions to protocol
  requirements. From `mxd-reconciliation.md` and the review sections of the
  matrix.
- `classic-client-trials.md`: the two trials and their limits, followed by
  the procedure for running a Classic peer against an isolated fixture. From
  `mxd-classic-login.md` and `mxd-peer-capture-workflow.md`.

Titles describe the subject; commit hashes move into a "Revisions examined"
table in the overview. Statements of what happened in what order move to a
short history section at the end of each document.

The recreation guide, `docs/native-evidence/recreating-evidence.md`, is a
how-to organized by the kind of evidence a reader wants to regenerate. It opens
with what the reader must already have, each item a GitHub permalink to the
mothra guide that covers it, and repeats none of that guidance. Its sections
are: static analysis records from the Ghidra oracle; native server captures, as
the cycle of preparation packet, supervised run, witness record and verifier;
peer client captures for the Classic client and shx; mxd fixture trials; audit
revisions and the gap analysis; and building the portable evidence package.
Each section gives the Hotline-specific inputs, the exact commands, the
expected output, the verifier that accepts the result, and what cannot be
recreated and why. It links into the existing per-fixture sections of
`native-capture-workflow.md` and the preparation records, and does not restate
them.

## Delegation and escalation

The work is carried out by a lead and teams of specialist sub-agents. The lead
is the main agent holding this plan. It owns the plan, the decision log, every
commit and push, and every exchange with the owner. Sub-agents receive bounded
packets and report back; they do not widen their own scope.

Roles:

- Journeyman: leads one milestone, or one coherent part of it, end to end. It
  splits the work into packets, hands them to artisans and scribes, integrates
  the results, asks for gate runs, keeps the milestone's entries in `Progress`
  current and returns a milestone report to the lead.
- Artisan: implements one packet of code, such as one tool with its tests or
  one script family in EP-M5. It edits only the files its packet lists.
- Scribe: carries out one packet of prose, such as one set overview, the
  style pass over one set, one document of the mxd set or one section of the
  recreation guide.
- Wyvern: fast, read-only reconnaissance. It classifies, counts and extracts,
  and changes nothing: the mothra classification manifest, the mxd claim
  inventory, section maps, link and citation censuses.
- Scrutineer: runs the gates and returns the commands, exit codes and
  captured failures. It never edits a tracked file. It is the only sub-agent
  that runs tests, linters or formatters in check mode, and only one scrutineer
  runs at a time, so gates never run in parallel.
- Alchemist: tests one stated hypothesis about a failure whose cause is not
  evident, such as a golden difference in EP-M5 or an audit mismatch. The lead
  or journeyman first writes the hypothesis, the prediction that would refute
  it and the test; the alchemist reports refuted or not refuted with evidence,
  and fixes nothing.

Use by milestone:

- EP-M0: wyverns classify mothra's tracked paths and take the baseline
  censuses; a scrutineer records the baseline gate results. The lead pushes
  mothra `main` itself.
- EP-M1 and EP-M2: one journeyman; one artisan per tool, in sequence, because
  the tools share modules; a scrutineer for each red, green and refactor run.
- EP-M3: the lead performs the import and merge itself, because it rewrites
  history in a scratch clone and changes the repository's shape. Artisans then
  take the path-expression change by script family, and a scribe takes the link
  rewrite review.
- EP-M4: one journeyman in the mothra worktree, with scribes for the guides
  and an artisan for the `Makefile`; a scrutineer runs the name search and
  mothra's gates. The lead pushes the branch.
- EP-M5: one journeyman per wave. The shared libraries are one serial wave.
  After that, up to four artisans work at once, each on one script family with
  a disjoint file list. A scrutineer runs the goldens and gates after each
  family, one family at a time.
- EP-M6: the lead runs the relocation script; a scrutineer verifies it.
- EP-M7: a wyvern builds the claim inventory; one scribe per target document,
  in sequence, because findings move between documents; the lead reviews the
  reconciled inventory.
- EP-M8: scribes, one per set overview and one for the recreation guide, up
  to four at once; a scrutineer runs `nixie` and the link gate.
- EP-M9: an artisan for `tools/check_evidence.py`; wyverns list every
  sentence that names a Resolved gap; scribes add the dated notes.
- EP-M10: one scribe per set, up to four at once, each confined to its set's
  directory.
- EP-M11: a scrutineer runs every gate in both repositories; the lead writes
  the retrospective.

Every packet states, in this order: its identifier (milestone, a sequence
number and a short name, for example `EP-M5-014 rate304 family`); the objective
in one sentence; the files it may edit, as an explicit list; the files it
should read; the constraints from this plan that apply, quoted, not
paraphrased; the acceptance evidence a scrutineer will collect; what is out of
scope; and the stop conditions below. A packet that cannot be written this
completely is not ready to hand out.

Rules that hold for every sub-agent:

- Two agents never hold packets with overlapping edit lists at the same time.
- No sub-agent commits, pushes, deletes evidence, or edits the plan's
  `Constraints`, `Tolerances` or `Decision log`.
- A report is a claim until a scrutineer's evidence or the lead's own
  inspection of the diff supports it. Nothing is ticked in `Progress` on a
  report alone.
- The journeyman or lead commits each accepted packet separately, after its
  gates pass.

Escalation protocol. A sub-agent stops at once, without attempting a
workaround, when any of these occurs: it would need to edit a file outside its
packet; an instruction in the packet conflicts with what it finds; a constraint
or tolerance in this plan would be breached; a claim's meaning would have to
change; a verifier verdict, planner output or test outcome would differ; or it
has made two attempts at the same failure. It then returns one of four
statuses, with what it did, what it found, the evidence and the options it sees:

- `DONE`: the packet is complete and ready for the scrutineer.
- `BLOCKED`: it cannot proceed and needs something it does not have.
- `NEEDS-DECISION`: there is more than one valid way forward and the choice
  affects the result.
- `OUT-OF-PACKET`: finishing requires work the packet does not cover.

Escalation runs upward one level at a time:

1. Artisan, scribe, wyvern, scrutineer or alchemist reports to the
   journeyman, or to the lead where no journeyman is assigned.
2. The journeyman resolves the matter only if the answer lies inside its
   milestone and inside this plan: it may reissue a corrected packet, split
   one, or assign an alchemist. It records what it did in its milestone report.
   Anything else goes to the lead.
3. The lead resolves the matter if this plan already decides it, and records
   the outcome in `Decision log` or `Surprises & discoveries`.
4. The lead stops and asks the owner when a tolerance is reached, a
   constraint would be violated, the approved design cannot be followed, an
   outward-facing or irreversible step is not already authorized, or two
   requirements conflict. The plan's status becomes `BLOCKED` until the owner
   answers. Work that does not depend on the answer continues.

A packet that comes back `BLOCKED` twice is not reissued a third time at the
same level; it moves up. An unexplained failure is never retried in the hope
that it passes: it gets a written hypothesis and an alchemist, or it goes up.

## Concrete steps

All commands run from the worktree root
`/data/leynos/Projects/hotline-protocol-docs.worktrees/documentation-reconcilliation`
unless stated.

EP-M0:

```sh
make -C /data/leynos/Projects/mothra gap-check
git -C /data/leynos/Projects/mothra push origin main
git -C /data/leynos/Projects/mothra rev-parse origin/main
```

Record the printed commit as the permalink pin. Expect `gap-check` to print
nothing and exit 0.

EP-M1 and EP-M2. For each tool, write the tests, run them and see them fail for
the stated reason, then implement:

```sh
make test          # red, then green after implementation
make lint-python
make typecheck
make links-check MOTHRA=/data/leynos/Projects/mothra
```

EP-M3. Build the filtered history in the scratch directory, never in a real
checkout, then merge it:

```sh
git clone --no-local /data/leynos/Projects/mothra "$SCRATCH/mothra-import"
git -C "$SCRATCH/mothra-import" filter-repo --paths-from-file "$SCRATCH/import-paths.txt"
git -C "$SCRATCH/mothra-import" lfs migrate import --everything \
  --include='evidence/**/*.png,evidence/**/*.pcap,evidence/**/*.gz'
git lfs install --local
git remote add mothra-import "$SCRATCH/mothra-import"
git fetch mothra-import
git merge --allow-unrelated-histories mothra-import/main
git remote remove mothra-import
uv run tools/check_import.py --mothra /data/leynos/Projects/mothra
```

The `migrate` command rewrites only the scratch clone and writes the matching
`.gitattributes` entries. After the merge, `git lfs fetch mothra-import --all`
copies the objects into this repository's store before the remote is removed;
run it between the `fetch` and `merge` lines if the merge reports missing
objects. `$SCRATCH` is the session scratch directory. `import-paths.txt` is
generated from the classification manifest. Imported documents are then moved
to their places in ordinary commits, links and script paths are rewritten, and:

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
make evidence-verify
uv run tools/refresh_audit.py --revision 90
python3 scripts/render_protocol_gap_analysis.py
make audit-check
```

Expect the `unittest` count to equal the EP-M0 baseline plus the imported tests.

EP-M4. In a mothra worktree:

```sh
git -C /data/leynos/Projects/mothra worktree add \
  /data/leynos/Projects/mothra.worktrees/documentation-reconcilliation \
  -b documentation-reconcilliation
```

Delete the imported paths, edit the remaining files, then from that worktree:

```sh
make check
git grep -niE 'hotline|hlserver|mxd|synhx|shx|HOTL|GAP-[0-9]|protocol-docs'
git push -u origin documentation-reconcilliation
```

Expect the search to print nothing.

EP-M5. Once, before the first refactor, and again after each family:

```sh
uv run tools/capture_goldens.py --check
uv run pytest scripts/tests -q
make evidence-verify
make lint-python
make typecheck
```

The first command prints `0 differences`. To see remaining findings for one
family while working, run Ruff on its files alone; do not run the gates in
parallel.

EP-M6 to EP-M10 repeat one pattern: edit one set, run `make fmt`, run the gates
in the order `check-fmt`, `markdownlint`, `nixie`, `links-check`,
`evidence-check`, commit; at the end of the milestone refresh the audit with
the next revision number, regenerate `gap-analysis.md`, run `make audit-check`,
and commit.

EP-M11:

```sh
make all
make -C /data/leynos/Projects/mothra.worktrees/documentation-reconcilliation check
```

## Validation and acceptance

The work is accepted when all of the following can be observed.

A reader starting at `README.md` finds a table of the sets, a table of entry
points by task, and a diagram of how the guide, contracts, evidence and
register relate; each set overview lists its documents with one line each;
`docs/contents.md` lists every document once.

`make all` exits 0 in this repository with the mothra branch checked out beside
it, and again with no mothra checkout present for every target that needs no
emulator.

On the mothra branch, the name search in `Concrete steps` prints nothing and
`make check` exits 0.

`grep -rn '\.\./mothra' --include='*.md' . --exclude-dir=evidence` prints
nothing, and every mothra link is a GitHub permalink.

Comparing `gap-register.json` on `main` with the branch reports 87 gaps and no
change to any protected field.

The mxd overview answers, in its first screen, what was validated, at which
revision, and what is outstanding; each correction and trial is described in
one place.

A reader who wants to regenerate, say, the private-message witness opens the
recreation guide from the `native-evidence` overview or from that corpus's row
in the evidence index, and finds the inputs, commands and verifier without
being told how to install the emulator.

Red-Green-Refactor evidence is recorded per tool in `Artefacts and notes`: the
failing test run, the passing run, and the lint, type-check and test run after
refactoring.

Quality criteria:

- Tests: `make test` passes; the converted legacy suite has at least the 758
  baseline tests plus those imported, none deleted; every new tool has
  happy-path and failure-path tests.
- Verification: the twelve obligations discharged as specified, with
  non-vacuity counts recorded.
- Lint and type checks:
  `make lint-python typecheck check-fmt markdownlint spelling nixie` pass over
  every Python and Markdown file, with no separate rule set for legacy code.
- Performance: `make all` completes in under ten minutes on this machine.
- Storage: `git count-objects -vH` reports a pack under 250 MiB after the
  import, and `git lfs ls-files | wc -l` reports the expected object count.
- Security: tools write only inside this worktree; the refresh tool refuses
  to overwrite an existing revision directory; credential-bearing captures that
  the documents describe as private remain outside both repositories.

## Idempotence and recovery

Every check is read-only and repeatable. The import is built in a scratch
clone, so a failed attempt is discarded by deleting that directory; the merge
is one commit and can be reverted. `tools/migrate_layout.py` refuses to run if
any source is missing or any destination exists. `tools/refresh_audit.py`
refuses an existing revision directory; to retry, delete the uncommitted
directory and rerun. Generated files (`typos.toml`, `docs/<set>/evidence.md`,
`gap-analysis.md`) are regenerated, never patched. The mothra branch is never
merged by this plan, and mothra's pushed `main` preserves the state before
removal.

## Artefacts and notes

Proposed sets. Each file moves to `docs/<set>/` under its current name, except
in the mxd set.

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
- `peers` (10, plus `shx-peer` from mothra): `identified-client-source`,
  `peer-tolerance-matrix`, `peer-profile-rules`, `classic-login-proxy`,
  `classic-native-baseline`, `classic-field161-matrix`,
  `classic-roster-subject-115`, `classic-server-name-162`,
  `mac-peer-first-session`, `mac-peer-isolated-session`.
- `mxd` (8 become 6): see EP-M7.
- `native-evidence` (42): `native-capture-workflow`,
  `native-control-readiness`, `runtime-recovery-20261113`, and every remaining
  `native-*` file.
- `provenance`: `baseline-correction-map`, `evidence-portability`,
  `gap-register.json`, the generated `gap-analysis.md`, and from mothra the
  ledger, the remediation worklog, the handoff note, and the delegation,
  debugging and plan records under `provenance/records/`.

Provisional classification of mothra, to be completed file by file in EP-M0.
Import: all of `evidence/`; `docs/baseline-validity-ledger.md`;
`docs/gap-remediation-worklog.md`; `docs/protocol-handoff.md`;
`docs/delegation/`; `docs/debugging/`; `docs/execplans/`;
`docs/delegation-workspaces.md`; `docs/native-clock-evidence.md`; `shx-peer.md`;
`patches/shx-modern-c.patch`; and the scripts
`render-protocol-gap-analysis.py`, `package-protocol-evidence.py`,
`verify-baseline-evidence.py`, `capture-ghidra-evidence.py`,
`extract-synhxd-evidence.py`, `build-shx.py`, `shx-login-harness.c`,
`verify-shx-login-fragment.py`, `verify-synhx-profiles.py`,
`prepare_delegation_workspace.py`, and the `verify_*` scripts for mxd, request
500, classic account constructors, the alias window and the classic proxy
rehearsal, each with its test. Stay: the SheepShaver harness and its verifiers,
`mac_runtime`, `mac_network_isolation`, `stage_mac_application`,
`smoke_mac_display`, `capture_readiness`, `native_capture_receipt`,
`native_emulator_readiness`, the Ghidra wrappers, and the guides for runtime
storage, network isolation, staging, guest start-up, capture readiness, capture
receipts and emulator readiness. Split: `README.md`, `Makefile`,
`.markdownlint.json`, and any staying guide that names Hotline in an example.

Planned diagrams, each with a screen-reader description and caption: in
`README.md`, how the guide, contracts, evidence, ledger and register relate; in
the `protocol` overview, the session sequence from handshake through login to
transactions; in `files-and-transfers`, the transfer handover to the data
connection; in `native-evidence`, the preparation, capture, witness and
verifier life cycle; in `provenance`, the gap states Open, Investigating,
Resolved and Deferred; in the `mxd` overview, the validation timeline from
review through corrections and trials to the hold; in
`docs/developers-guide.md`, the edit, gate, audit-refresh and commit loop.
Diagrams inside existing documents are added only where a described flow has
three or more steps and the text already states each step.

Transcripts and commit hashes are added here as milestones complete.

## Interfaces and dependencies

Tools and pins: Python 3.14; `uv`; Ruff 0.16.8; `ty` 0.0.56; pytest with
Hypothesis; Cyclopts; `interrogate`; Pylint 4.0.9 with `df12-python-lints`
v0.4.0; mdtablefix 0.6.1; markdownlint-cli2 (0.20.0 is installed); nixie;
`typos-config-builder` v0.1.3; `git filter-repo`; Git LFS 3.7.1. New tools call
Git through `cuprum`, as the df12 scripting standards require for external
processes.

New files at the end of EP-M3:

- `pyproject.toml`: `requires-python = ">=3.14"`, a `dev` dependency group,
  and the Ruff, Pylint and pytest tables from the df12 template with
  `target-version = "py314"`.
- `scripts/ruff.toml`: default Ruff settings for the legacy scripts, present
  from EP-M1 and deleted at the end of EP-M5.
- `Makefile` with `.NOTPARALLEL:` and the targets `help`, `all`, `fmt`,
  `check-fmt`, `markdownlint`, `spelling`, `nixie`, `links-check`,
  `evidence-check`, `style-check`, `audit-check`, `evidence-verify`,
  `lfs-check`, `json-check`, `lint-python`, `typecheck` and `test`. `fmt`
  rewrites JSON outside `evidence/` only; `check-fmt` depends on `json-check`,
  which covers every tracked JSON file. `markdownlint` depends on `spelling`,
  as in netsuke. Markdown tools receive an explicit file list from
  `git ls-files '*.md' ':!evidence/**'`. `evidence-verify` carries the corpus
  checks formerly in mothra's `Makefile`. `audit-check` runs the renderer with
  `--check`.
- `.markdownlint-cli2.jsonc`: netsuke's rules plus Lody's `MD024`
  `siblings_only`, `MD033` allowing `a` and `br`, and `MD049` underscore;
  ignoring `evidence/**`, `.uv-cache` and `.uv-tools`.
- `.gitattributes`: `evidence/** -whitespace`, as in mothra, plus the LFS
  filter entries for the three extensions.
- A `lfs-check` target: fails if any path the LFS rule selects is not a
  pointer in the index, if any other path is, or if LFS content is absent from
  the working tree.
- `typos.local.toml` (authored, excluding `evidence/**`) and `typos.toml`
  (generated).
- `docs/documentation-style-guide.md`: verbatim copy at `991af84`.
- `AGENTS.md`: the gates, the audit-refresh rule, and the constraints above.

Each new tool is a Cyclopts application with a `main` entry point, numpy-style
docstrings, typed signatures, and exit codes 0 for success, 1 for findings and
2 for missing inputs:

```python
# tools/check_links.py
def check(root: Path, *, mothra: Path | None = None) -> Report: ...

# tools/refresh_audit.py
def refresh(root: Path, revision: int, *, today: dt.date, section_map: Path | None = None) -> Revision: ...

# tools/check_import.py  (deleted in EP-M11)
def compare(root: Path, mothra: Path, commit: str, selected: Sequence[PurePosixPath]) -> Report: ...

# tools/migrate_layout.py  (deleted in EP-M11)
def rewrite_link(link: str, source: PurePosixPath, moves: Mapping[PurePosixPath, PurePosixPath]) -> str: ...

# tools/check_evidence.py
def check(root: Path, *, write: bool = False) -> Report: ...

# tools/capture_goldens.py
def capture(root: Path, *, check: bool = False) -> Report: ...

# tools/check_json.py
def canonical(text: str) -> str: ...
def check(root: Path, *, write: bool = False) -> Report: ...

# tools/check_style.py
def check(root: Path) -> Report: ...
```

`check_style` reports tables without a caption and Mermaid blocks without a
preceding screen-reader paragraph or a following figure caption, and skips
`evidence/` and the generated `gap-analysis.md`. `check_evidence` pairs each
corpus with its verifier by reading the `evidence-verify` recipes, and writes
one row per corpus: corpus link, verifier, citing documents and sections,
related gaps, and ledger identifiers.

## Revision note

First revision, 15 November 2026, after three owner directions. mothra must be
a general toolset, so the plan imports all Hotline-specific material into this
repository (EP-M3) and generalizes mothra on a branch (EP-M4), replacing the
earlier design that added audit revisions inside mothra and paired the two
worktrees with a symlink. Links to mothra became GitHub permalinks, which added
a push of mothra `main` in EP-M0 and new cases to INV-LINK. The mxd documents
gained their own milestone, guarded by INV-MXD.

Second revision, 15 November 2026. The owner accepted D1, D4 and D10, chose
full scope for D2, and asked for evidence-recreation directions. The plan now
brings every legacy script to the df12 Python standards in a new milestone,
EP-M5, guarded by INV-SCRIPT with goldens captured before any refactor; the
constraint limiting script changes to path expressions was replaced by a
behaviour-preservation constraint. A recreation guide is added in EP-M8 and
checked for coverage in EP-M9 by INV-RECREATE, and general toolset set-up
passages move to mothra in EP-M4. Later milestones were renumbered, so the plan
now runs from EP-M0 to EP-M11 and audit revisions from 90 to 95. The remaining
work is unchanged in kind but larger: EP-M5 is now the biggest milestone.

Third revision, 15 November 2026. The owner asked for Git LFS. Decision D9 now
stores large and binary evidence through LFS under a fixed rule, converts it in
the scratch clone before the merge so history is kept, and adds an `lfs-check`
gate. INV-IMPORT compares content hashes instead of blob hashes and checks the
LFS rule. EP-M0 gains a quota check. No milestone was added or renumbered.

Fourth revision, 15 November 2026. The owner asked for the work to be divided
among journeyman, artisan, scribe, wyvern, scrutineer and alchemist agents with
a structured escalation protocol. A new section, `Delegation and escalation`,
assigns roles by milestone, fixes the contents of a task packet, and defines
four report statuses and a four-level escalation path. The milestones and their
acceptance evidence are unchanged.

Fifth revision, 15 November 2026. The owner asked for JSON to stay in Git under
a formatting gate. The LFS rule is now by extension only (`*.png`, `*.pcap`,
`*.gz`), about 642 MiB. A new obligation, INV-JSON, and a `json-check` target
require every tracked JSON file to parse and to match the canonical two-space
layout the repository already uses; authored JSON is formatted by `make fmt`,
and evidence JSON is checked but never rewritten.
