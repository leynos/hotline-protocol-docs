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
- The Hotline Server binary, in either fork and in any container, never
  enters a commit of this repository and never reaches GitHub in mothra.
  Mothra's local `main` is never pushed. Nothing is merged into either
  repository's `main` by this plan.
- The main checkouts at `/data/leynos/Projects/hotline-protocol-docs` and
  `/data/leynos/Projects/mothra` are not edited. Work happens in linked
  worktrees on branches named `documentation-reconcilliation`. Mothra's
  general-toolset history is built in a scratch clone and pushed from there.
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
  6,000 lines excluding tests (raised from 2,200 by decision D24).
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
  Mitigation: EP-M4 starts only after EP-M3's ported checks pass here, and
  mothra's local `main` is left untouched, so the earlier state stays
  recoverable on this machine.
- Risk: a copy of the withheld binary reaches GitHub through history, a
  container or a packet capture. Severity: high. Likelihood: low. Mitigation:
  obligation INV-WITHHELD scans every blob of every history before any push,
  and decision D20 lists the eight known paths.
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
- [x] (2026-11-15 19:05Z) Owner ruled that the server binary is not to be
  published (D20) and that modified forks are stored as binary patches (D21).
  The push of mothra `main` is cancelled.
- [x] (2026-11-15 20:10Z) Owner asked for curated evidence without noise
  (D22); mxd claim inventory complete (566 claims, 54 duplicates, 3 conflicts,
  10 tensions) in the session scratch directory.
- [x] (2026-11-15 20:40Z) Owner raised the tooling tolerance (D24) and asked
  for the SynHX naming to be clarified and a comprehensive glossary (D25).
- [x] (2026-11-18 21:00Z) Tag `evidence-sources-2026-11-15` pushed to
  `origin` on the owner's confirmation. It is annotated and resolves to
  `efea44a552ecd221ac3d12f4fdd10c6301e8102f`, the commit that the three
  imported scripts are pinned to in `scripts/pinned-sources.json`; 678 LFS
  objects (576 MB) went with it. The branch itself is still unpushed. When the
  branch is merged it must not be squashed, or the pinned commit leaves the
  history that the pin checks read.
- [x] (2026-11-18 20:00Z) EP-M5 wave 6 and the capture identity of D31
  integrated (eleven commits by cherry-pick, then `76736ea`). Wave 6 brought
  the settings, settings-transition, 121-default, ban-control and
  settings-persistence planners and verifiers to the standard, each
  characterized on the pinned bytes first. The identity work added
  `scripts/capture_identity.py` (commit, differing files, per-file hashes and
  one digest over a declared `CAPTURE_MODULES` tuple) and
  `scripts/capture_acceptance.py` (`driver_in`, `driver_is`, called once by 28
  verifiers in the position of the old comparison), split `protocol_capture`
  into five modules and migrated `capture_shx_session` and
  `peer_tolerance_run`. Results on the integrated tree: `make all` 2,104 tests;
  goldens and pin-experiment `0 differences`; continuity 10,997 passed;
  `make pin-equivalence` 13 passed in 58 minutes; `make docs-gates` clean.
  Lessons: (1) the equivalence tool did not copy `tests/data`, so every order
  test errored on both sides and passed vacuously; it now copies the tables and
  a test fails without that. (2) A migrated module must not import a name from
  a pinned module that the pinned bytes lack: `TCP_RST` now comes from
  `native_packet_evidence`. (3) Two waves landing together broke one pinned list
  (`tests/test_driver_acceptance_sites.py`); run `make all` on the combined
  tree, not on each wave. (4) Record notes in 21 documents still say a script
  is held at the earlier lint rules; they are rewritten in one pass with the
  audit revision that closes EP-M5, and one such finding is on the accepted
  list until then. `scripts/legacy-modules.txt` holds 18 entries: the board,
  liveness, path-fields, missing-alias, rate-304, configured-ban and ban-expiry
  controls, the ban-expiry clean-up, the diagnostic-load planner, the
  control-readiness script, the settings-persistence runner and planner, the
  settings-transition and 121-default capture verifiers, and four tests that
  cover them.
- [x] (2026-11-18 12:00Z) EP-M10 complete (`202c116`, `b8b1b03`, `041685e`).
  `tools/check_style.py` checks table captions, figures, fence labels, heading
  case, person and the glossary rules; `make style-check` is part of
  `make docs-gates`. Five scribes then corrected the documents set by set: 186
  captions, 57 headings changed in letter case only, a cross-reference in each
  of 104 documents, glossary links in opening paragraphs, dated notes beside
  quoted commands that no longer run, the R series in the glossary and the
  operator packets summarized in the ledger of remaining work (the owner
  consented on 2026-11-18). A comparison of every changed document with its
  earlier text shows no anchor changed. Six headings are accepted as on-screen
  labels or proper names. Revision 95: `87 gaps, 0 protected fields changed`.
  `links-check` reports `137 documents, 8048 links, 0 failures`; `make all`
  passes with 1,825 tests. Lesson: scribes editing audited documents in place
  leave the working tree failing the post-turn checks until they finish; for a
  batch like this, wait for the edits to go quiet before formatting. Also
  fixed: a renderer test pinned a digest of the live register and so failed at
  every audit revision.
- [x] (2026-11-18 12:00Z) Owner's answers of 2026-11-18 acted on. Mothra's
  branch is pushed at `2278968b622eab731e4ba2be0484cedfbab73bb7`: its kept
  isolation corpus is pinned to the snapshot commit with a check and a
  continuity test, the launcher takes `--guest-port` with no default, and
  `docs/native-emulator-readiness.md` has headings for its two phases; the name
  searches still print nothing and its `make check` passes. All 58 permalinks
  here point at that commit. The tag `evidence-sources-2026-11-15` exists
  locally on `efea44a`; its push is held for the owner's confirmation, because
  it publishes the curated evidence, including 341 decompiled function listings
  derived from the server binary. Commands for clearing agent worktrees are in
  `~/docs/hotline-agent-worktree-cleanup.md`.
- [x] (2026-11-18 02:00Z) EP-M5 leftovers integrated and the test suite
  split (`e37fc44`, then four commits ending with the capture-script
  characterization tests). The verifier golden reduces a traceback to a marker
  and its final exception line; one entry was re-recorded and the known-red
  verifier is migrated with its verdict unchanged (exit 1,
  `ValueError: capture gate source identity`), its test a strict expected
  failure pinned to that exception and message, which the golden plugin records
  as `error`. Five tests that recipes ran by path run under pytest;
  `test_mxd_direct_ack.py` became `verify_mxd_direct_ack.py` plus a test
  module. pytest also collects classes named `*Test` and `*Controls`.
  `peer_tolerance_run.py` and `capture_shx_session.py` have 62 characterization
  tests against fakes. The suite is split by module name: `make all` runs 1,769
  tests in about three minutes; `make continuity-tests` runs the 9,084
  error-order and corpus-fault tests in eight to twelve minutes.
  `make goldens-check` and `make pin-experiment` print `0 differences`. 33
  entries remain on the legacy list: fifteen scripts that record or check their
  own or a sibling's hash at capture (D31, listed there), the two ban-expiry
  capture drivers held by the suppression limit, and the settings, 121-default
  and ban-control scripts and tests that are free to migrate now.
- [x] (2026-11-17 20:00Z) EP-M5 wave 5A integrated (thirteen commits,
  diagnostics through rate 304): the remaining native families meet the
  standard, bar the scripts named below. About 2,100 findings to 0; about 4,400
  error-order rows added, stable under four hash seeds. `make all` passes with
  10,161 tests, but takes eleven minutes; `make goldens-check` and
  `make pin-experiment` print `0 differences`. 40 scripts remain on the legacy
  list. Left unmigrated because they record or check their own file's hash at
  capture (D31): `native_diagnostic_load_cases.py` and the control scripts for
  liveness, path fields, missing alias, rate 304 and configured ban. Left
  unmigrated on the suppression limit: `native_ban_expiry_control.py` and
  `native_ban_expiry_cleanup.py`, capture drivers that would need about
  thirteen. Tolerances exceeded and accepted by the lead: the wave's size
  (about 43,000 changed lines against a stop at 18,000) and five suppressions
  in the path-fields family. To do: move the corpus-replay order tests behind
  their own target so that the commit gate returns to about two minutes.
- [x] (2026-11-17 15:00Z) EP-M8 complete: `docs/developers-guide.md`
  (`1a4beef`) written by a scribe from the `Makefile`, the tools and this plan,
  and gated. With it the orientation layer holds the root `README.md`, the
  contents page, the repository layout, the developers' guide, the glossary,
  nine set overviews, the recreation guide, the ledger of remaining evidence
  work and the reconciliation log, with eleven validated Mermaid diagrams.
  `links-check` reports `137 documents, 7684 links, 0 failures`. Questions the
  guide's author could not answer from the repository, now answered in the
  guide or left for EP-M10: which register to pass as the refresh baseline (the
  last committed one); whether a make target should wrap the audit refresh (not
  yet); that no file states a commit message convention.
- [x] (2026-11-17 14:00Z) EP-M5 wave 5B integrated (eight commits, classic
  verifiers through `prepare_native_cases`): the classic, Mac peer, mxd, SynHX
  and shx verifiers, peer tolerance and the utilities meet the standard,
  including the planner dispatcher and the gap-analysis renderer, whose output
  is byte-identical. 1,170 findings to 0; about 1,300 error-order and
  characterization tests added. `make all` passes with 5,064 tests in about
  five minutes; `make goldens-check` and `make pin-experiment` print
  `0 differences`. 93 scripts remain on the legacy list. Left unmigrated:
  `verify_classic_field161_matrix.py` and its test, because the golden hashes
  the full traceback of the known-red verdict and any restructuring changes the
  frames; `peer_tolerance_run.py` and `capture_shx_session.py`, which record
  their own hash at capture (D31) and have no tests; and five tests that
  `Makefile` recipes run by path. Tolerance exceeded and accepted by the lead:
  54 line-scoped suppressions in this group, against four per family; most are
  for subprocess use, helpers that take a condition positionally and public
  signatures kept for callers. Consequence: a migrated script no longer runs
  under a bare `python3`, so commands quoted in that form need a dated note
  with the next audit revision.
- [x] (2026-11-17 09:00Z) EP-M5 wave 4 integrated (nine commits ending at the
  news and board corpus-fault tests): the login-extras, agreement, bitmap,
  article-deletion, news, move, room and board families meet the standard, bar
  `native_board_control.py`, which hashes its own file at capture and waits on
  D31. No live hash comparison was found among the 31 scripts surveyed. About
  2,000 error-order tests were added, from single and paired faults in the
  retained evidence, recorded on the pristine scripts. `make all` passes with
  3,313 tests in about two minutes; `make goldens-check` and
  `make pin-experiment` print `0 differences`. 137 scripts remain on the legacy
  list. One document cites a converted test by its old path
  (`native-board-preparation.md`, `scripts/test_native_board.py`); it is an
  accepted finding until a dated note is added with the next audit revision.
  Remaining groups: bans and settings, including the pinned ones; diagnostics,
  liveness and path fields; the classic, mxd, Mac peer and SynHX verifiers; and
  the scripts that wait on D31.
- [x] (2026-11-17 06:00Z) EP-M5, pinned scripts, first part (`0afdcc5` back
  to the characterization commits, through `edf5657`): characterization tests
  written first on the pinned bytes (122 for the three index-pinned scripts,
  the Ghidra capture script replayed against a fake bridge built from retained
  query records; 77 for `pcap_tcp`; 28 for `native_filp`; 71 for the two
  private-message scripts; 95 for `protocol_capture`), then seven of the
  sixteen migrated. `make all` passes with 1,201 tests in ninety seconds;
  `make goldens-check` and `make pin-experiment` print `0 differences`;
  `make pin-equivalence` (new target, outside `make all` because it takes eight
  minutes) passes for all seven changed scripts. 166 scripts remain on the
  legacy list. Not migrated: `protocol_capture.py`, pending D31.
- [x] (2026-11-17 03:00Z) EP-M9 complete (`f491c80`, `0a05e40`).
  `tools/check_evidence.py` checks cited ledger, gap and script identifiers,
  status sentences against the register, the ledger of remaining work, corpus
  families and the generated indexes; `make evidence-check` is part of
  `make all` (805 tests). Nine sets have a generated `evidence.md`. On the real
  tree: 606 ledger citations, 2,690 gap citations, 1,195 evidence links; no
  unknown identifier; every cited corpus falls under a family of the recreation
  guide; the ledger lists exactly the 25 unresolved gaps. The checker found
  seven contradicting sentences; a scribe's reading of all 221 sentences that
  name a Resolved gap found ten more. All seventeen keep their wording and
  carry a dated status note (D4). Two working records carry a record note.
  Loose family-name wording is reworded in six living documents (D25); general
  set-up guidance in four documents is replaced by permalinks (D17).
  `docs/reconciliation-log.md` lists every discrepancy and its disposition,
  including those left open for the owner. Revision 94:
  `87 gaps, 0 protected fields changed`, no heading changed. `links-check`
  reports `136 documents, 7676 links, 0 failures`. Accepted findings left in
  `evidence-known.json`: the toolset script names in the working record
  `missing-target-alias.md`. For EP-M10: one audited heading in
  `native-settings-preparation.md` keeps its earlier spelling by exemption in
  `typos.local.toml`; the checker's tool code is 2,520 lines, so `tools/`
  stands near 10,500 of 12,000 and the one-off relocation tool should be
  deleted before the style check is written.
- [x] (2026-11-17 00:30Z) EP-M5 wave 3 integrated (`912237d` to `e378a1b`):
  the cleanup, HTXF, correlation, handshake, account-batch, account-identity
  and live-account families meet the standard (484 findings to 0, nine
  suppressions, 68 tests converted with names unchanged). 201 error-order tests
  in `tests/` pin which error each restructured function raises first, each
  observed on the pristine script. `make all` passes with 739 tests;
  `make goldens-check` and `make pin-experiment` print `0 differences`. 173
  scripts remain on the legacy list. Not done: login extras, agreements and
  bitmaps (ungated drafts in `/data/tmp/claude-1000/jm5/`); news, rooms, moves
  and board, whose scripts show many hash hits in corpora and must be surveyed
  for live comparisons first.
- [x] (2026-11-16 22:00Z) D29 implemented (`37a06f4` to `3265ea9`).
  `scripts/pinned-sources.json` names the commit and hash for each of the
  sixteen scripts: thirteen at the published `4e62e00`, three at this branch's
  `efea44a`. Five verifiers compare the pinned bytes; `in_legacy_layout` stages
  the pinned bytes for the verifiers held under `evidence/`; no recorded hash
  or order of checks changed. `make pin-experiment` appends a comment to all
  sixteen and compares the goldens: 27 differences before, `0 differences` now.
  `make pins-check` is part of `make all` (479 tests). Remaining before the
  sixteen are refactored: characterization tests for
  `capture-ghidra-evidence.py`, `verify-baseline-evidence.py` and
  `extract-synhxd-evidence.py`, whose coverage is thin or absent; the
  capture-side self-check in `native_settings_persistence.py`, which records
  and checks the live hash of two pinned scripts; and a pushed tag on
  `efea44a`, without which a squash merge would orphan the three imported
  scripts' pin. The known-red verifier (D18) could use the same mechanism, but
  the mothra commit that carries its recorded hash, `882f976`, is in mothra's
  unpublished history.
- [x] (2026-11-16 20:30Z) EP-M8, third part (`d9ea1ec`, `cb7e07d`): the root
  `README.md`, `docs/contents.md`, `docs/repository-layout.md` and an overview
  for each of the eight remaining sets, written by three scribes and gated.
  INV-REACH holds: `links-check` reports
  `126 documents, 6029 links, 0 failures`, with every document listed once in
  the contents page and once in its set's overview. Ten Mermaid diagrams
  validate. The reachability check now counts only listings (the link that
  opens a contents item, or the first cell of an overview row). Still to do in
  EP-M8: `docs/developers-guide.md`, once the script tooling settles after D29;
  a glossary entry for "identified client"; replacing the set-up passages in
  `native-capture-workflow.md` with links.
- [x] (2026-11-16 19:00Z) EP-M5 wave 2 integrated (`1582886` to `1ae7af1`):
  the auth, shx, folder, mkdir, fork, metadata, alias and account-update
  families meet the standard (644 findings to 0, 14 suppressions, 86 tests
  converted with names unchanged), and the banner verifier's check order is
  restored and pinned by tests. `make all` passes with 432 tests;
  `make goldens-check` prints `0 differences`. 194 scripts remain on the legacy
  list. Lessons: a new test that is not a converted one belongs in `tests/`,
  because anything new under `scripts/tests/` is reported by the test golden;
  error paths are not observable on the retained corpora, so the order of
  checks is held by inspection and by synthetic cases run against the old and
  new trees, which later waves must commit. Remaining groups: cleanup, htxf,
  correlation and handshakes; account batches, identity, live accounts, login
  extras, agreements and bitmaps; news, board, rooms, moves and article
  deletion; diagnostics, liveness and path fields; bans, settings, roster
  overlap and rate 304; the classic, mxd, Mac peer and SynHX verifiers; and the
  sixteen pinned scripts once D29 is in place.
- [x] (2026-11-16 18:00Z) EP-M7 complete (`77104bf`, `acd61a2`). Five scribes
  each wrote one target document from the claim inventory and the lead wrote
  the set's `README.md`. INV-MXD: all 566 inventoried claims land exactly once
  (62, 167, 159, 73 and 105 by document); every code span, hash, number,
  evidence path and link target of the old notes is present in the new set, bar
  one code span whose backticks moved (`154=0001`). Twenty-seven paragraphs
  begin "Unreconciled:" and keep both sides of a disagreement. The run-together
  words of the old matrix ("is0.1.48", "that122is") were given their spaces and
  nothing else. `tools/refresh_audit.py` gained an `also` list for a section
  that was split, written test first. Revision 93:
  `87 gaps, 0 protected fields changed`, 590 reviewed sections (543 before,
  because the new set has more sections and each inherits coverage). `make all`
  passes with 344 tests, `make docs-gates` passes and `links-check` reports
  `5270 links, 0 failures`. For EP-M9: the scribes found sentences that the
  inventory had not enumerated and carried them; the old inventory heading
  "Sub-version 2" matched no source heading; two trials have no stated mxd
  revision; the canonical mxd revision is unreconciled.
- [x] (2026-11-16 15:30Z) EP-M6 complete (`546b65c`). `tools/migrate_layout.py`
  moved 109 documents into nine sets under `docs/` and rewrote 1,078 links; its
  INV-MOVE check passed before reflow, and a word-level comparison of every
  moved document with its earlier text shows no difference beyond link targets.
  Audit revision 92 was cut through a section map
  (`87 gaps, 0 protected fields changed`). `make all` passes with 340 tests,
  `make docs-gates` passes, `links-check` reports `4869 links, 0 failures`, and
  `make goldens-check` prints `0 differences`. Deviation from the proposed
  sets, recorded as D30: the validity ledger, `gap-register.json` and
  `gap-analysis.md` stay where they were.
- [x] (2026-11-16 13:00Z) EP-M5 wave 1 integrated (`8f2058a` to `706a046`):
  the queue, transfer, resume, framing and banner families meet the standard
  (630 findings to 0, two suppressions, 34 tests converted with names
  unchanged). `make all` passes with 306 tests; `make goldens-check` prints
  `0 differences`. Lessons: a new helper module must not be named `*_cases.py`,
  because the golden coverage test treats that name as a planner; split modules
  re-export their public names with a comment naming the consumer; constants
  whose meaning no document fixes stay local and unnamed. To restore in wave 2:
  `verify_native_banner_formats` now reads the driver hash before the
  corpus-inventory check, which changes which error is raised when both fail.
  Remaining on the legacy list: 224 scripts plus comment lines. Next waves, by
  fan-in: auth and shx; folders and mkdir; forks, metadata and account updates;
  then the long tail.
- [x] (2026-11-16 11:30Z) EP-M8, second part:
  `docs/native-evidence/recreating-evidence.md` written by a scribe and gated
  (`b9b5b90`). All 203 included corpora fall under twelve families, each with a
  procedure or a stated reason it cannot be recreated. Toolset set-up is linked
  by permalink only.
- [x] (2026-11-16 10:00Z) EP-M5 pilot integrated (`4dd0e59` to `eecc9b2`).
  Mechanism: `scripts/legacy-modules.txt` lists the scripts still held at the
  earlier rules; everything else under `scripts/`, including `scripts/tests/`,
  is gated by the root rules, and a family's commit deletes its lines. The
  `Makefile` puts the project interpreter first on `PATH`, so recipe text and
  golden keys are unchanged. `scripts/script_cli.py` imports Cyclopts lazily,
  so library modules still import under a bare `python3`. Migrated:
  `native_plan`, `native_packet_evidence`, `verify_native_core`,
  `verify_native_pm` and five test modules (290 findings to 0, three
  suppressions, 49 tests with unchanged outcomes). `make all` passes with 272
  tests and `make goldens-check` prints `0 differences`. Procedure for each
  family: survey its imports and hash comparisons; move tests to
  `scripts/tests/` with `git mv`, keeping class and method names; name a wire
  constant in `native_wire_names` only where a document fixes its meaning;
  decompose to the complexity limits; lint the touched files alone; delete the
  family's lines from the list; run `make all` and then the goldens. Pitfalls:
  never run `make fmt` for one file; Cyclopts reads parameter annotations at
  run time, so take `str` and build the `Path` in the body; measure the
  400-line limit after formatting.
- [x] (2026-11-16 08:00Z) EP-M8, first part: `docs/glossary.md` (`5726b04`) and
  `docs/provenance/remaining-evidence-work.md` (`254d945`) written by scribes
  and gated. The ledger has 25 rows (5 P0, 18 P1, 2 P2) and four prepared runs
  that have not started; operator packets outside the repository are named but
  not summarized, pending the owner's consent. Still to do for D25: reword the
  loose uses of "SynHX" (about 20 places in `internal-compatibility-matrix.md`,
  `mxd-reconciliation.md`, `protocol.md` and the validity ledger's wording,
  which cannot change because the ledger is hash-pinned). Still to do for D26:
  the check that every unresolved gap appears once (new tooling, waits on D28).
- [x] (2026-11-16 06:30Z) EP-M3 complete: the INV-SCRIPT goldens are in
  `tests/goldens/` with `tools/capture_goldens.py` and the `goldens-check`
  target. They record 89 verifier recipes (88 pass, the known-red one fails),
  196 planner invocations covering 844 plan files (one skipped: it needs the
  Mac oracle binary and stamps the wall clock) and 785 tests (784 pass, one
  known error). `make goldens-check` prints `0 differences` on this branch and
  `make all` passes with 221 tests. Negative controls: a changed comparison
  constant in `verify_native_liveness.py` and a changed byte in
  `native_news_boundary_cases.py` were each reported. The comparison takes
  three to ten minutes and is not part of `make all`. A planner's embedded
  SHA-256 of a script is recorded by script name, because it must change when
  the script is refactored.
- [x] (2026-11-16 05:00Z) EP-M4 complete. Mothra's branch
  `documentation-reconcilliation` is pushed at
  `57aeaac4f12065bfb2de3d47943f4b45622392a9`: one snapshot commit of the
  general tooling on the published initial commit (D27), then nine commits that
  remove every project reference and add three general guides
  (`docs/preparing-a-capture-run.md`,
  `docs/peer-service-in-network-namespace.md`, `docs/ghidra-decompilation.md`).
  INV-GENERAL: the name search over tracked file contents and file names prints
  nothing, and the five kept archives hold no project name. INV-WITHHELD:
  `281 blobs scanned, 0 withheld objects`. Mothra's `make check` passes with 83
  tests (81 before). `scripts/capture_readiness.py`,
  `scripts/mac_network_isolation.py`, `scripts/mac_runtime.py` and everything
  under `evidence/` are byte-identical to mothra `f9b4108`. In this repository
  the thirteen remaining relative links are permalinks to that commit,
  `links-check` runs with `--forbid-relative-mothra`
  (`4510 links, 0 failures`), and audit revision 91 is cut (`d51d1bb`).
  Residuals, for the owner: the launcher `scripts/mac_runtime.py` keeps the
  numeric guest port 5500 and host port 15500 as defaults, because kept
  evidence compares its SHA-256 in live mode; the kept corpus
  `alias-window-profile-01` keeps its `gap-remediation` path and window name.
  The instructional set-up passages in this repository's documents are replaced
  by links to the new guides in EP-M8.
- [x] (2026-11-16 03:30Z) EP-M3, third part: the inherited scripts now find
  evidence inside this repository (`b514da7`, 79 files, path expressions only),
  reach mothra's general scripts through `scripts/mothra_root.py` (`3bee830`),
  and mothra's Hotline check recipes are ported as `make evidence-verify`,
  `evidence-verify-known-red`, `test-legacy` and `typecheck-legacy` (`9b05d81`).
  `evidence-verify` is part of `make all`, which passes with 198 tests.
  Against the EP-M0 baseline, 89 of 89 ported recipes give the same exit code;
  `test-legacy` reports `Ran 785 tests` and `FAILED (errors=1)`, the one known
  error (D18). Remaining in EP-M3: capture the INV-SCRIPT goldens in the
  repository (delegated).
- [x] (2026-11-16 01:10Z) EP-M3, second part: the cited mothra documents and
  seventeen Hotline-specific scripts imported at their mothra-relative paths
  (`efea44a`); three further corpora came in with the handoff note and the
  alias plan (203 corpora, 13,854 files, 0 differences from the source); links
  rewritten to in-repository evidence and audit revision 90 cut (`cda5913`).
  `make all` passes with 198 tests and now includes `audit-check`, which reports
  `Validated 87 gaps and 543 reviewed sections;
  checked 4364 local link references`,
  the same counts as the baseline. Remaining in EP-M3: the script path change
  and the ported check recipes, in progress in an isolated worktree.
- [x] (2026-11-15 22:15Z) EP-M3, first part: import tools landed (`4bebeef`,
  `00db57f`, `bc49af4`, fixes `3804e1d` and the LFS and citation fix), and the
  curated evidence is imported (`7e85eae`): 200 corpora, 13,439 files, 757 LFS
  objects, 8 files withheld, 64 JSON exceptions. `make all` passes with 196
  tests; `make import-check` reports `13439 files compared, 0 differences`;
  `make withheld-scan` reports `9949 blobs scanned, 0 withheld objects`.
  Remaining in EP-M3: import the cited mothra documents and scripts, rewrite
  links and script paths, bring over the renderer and the check recipes,
  capture the script goldens, cut audit revision 90.
- [x] (2026-11-15 17:10Z) EP-M0 surveys complete: baseline gates,
  classification of mothra, set-up passage census, JSON census.
- [x] (2026-11-15 17:10Z) EP-M1 foundation committed (`b4d4449`), and the
  mechanical document conformance brought forward (`bf6d00e`, decision D16);
  `make check-fmt lint typecheck markdownlint nixie` pass.
- [ ] EP-M0 in progress (completed: secret-pattern scan of mothra's tracked
  files, clean; JSON census; repository visibility check. Running: baseline
  gates, mothra classification, set-up passage census. Held: the push of mothra
  `main`, pending the owner's confirmation; the LFS quota reading).
- [x] (2026-11-15 19:05Z) EP-M0 complete except the LFS quota reading, which
  needs a token scope the lead does not have. The push moved to EP-M4.
- [x] (2026-11-15) EP-M1: tooling foundation, JSON gate (`04efcbe`), Markdown
  model (`c48e996`) and link gate with reachability rule (`b3bd149`);
  `make all` is green and includes `json-check` and `links-check`.
- [x] (2026-11-15) EP-M2: audit refresh tool proven against revision 89
  (`002aaae`); the golden test and mothra's `validate` pass.
- [x] EP-M3: Hotline material imported; repository self-contained; revision 90
  (see the dated entries above).
- [x] EP-M4: mothra generalized on a branch and pushed (see the entry dated
  2026-11-16 05:00Z).
- [ ] EP-M5: all scripts meet the df12 Python standards; revision 91.
- [x] EP-M6: documents relocated into sets; revision 92 (see the entry dated
  2026-11-16 15:30Z).
- [x] EP-M7: mxd set consolidated; revision 93 (see the entry dated
  2026-11-16 18:00Z).
- [x] EP-M8: on-ramps, orientation, recreation guide and diagrams (see the
  entries dated 2026-11-16 08:00Z, 11:30Z and 20:30Z, and 2026-11-17 15:00Z).
- [x] EP-M9: evidence correlation and reconciliation; revision 94 (see the
  entry dated 2026-11-17 03:00Z).
- [x] EP-M10: style conformance and cross-references; revision 95 (see the
  entry dated 2026-11-18 12:00Z).
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
- Observation: the baseline is red from one cause. Evidence (scrutineer,
  15 November 2026): mothra `make test` stops in `capture-check` with
  `ValueError: capture gate source identity`, and the legacy suite here reports
  `Ran 758 tests`, `FAILED (errors=1)`, the one error being
  `test_original_corpus_replays` with the same message. Every other mothra
  target passed, including `gap-check` (87 gaps, 543 sections, 4,364 links).
  Because `make` stops there, the later `capture-check` recipes have not been
  exercised through it. Impact: decision D18.
- Observation: of mothra's 106 tracked paths outside `evidence/`, 64 import
  wholesale, 21 stay and 21 need splitting; the splits are mostly fixed ports
  (15500, 5500 to 5503), instance names and evidence links in general guides
  and scripts. No script basename collides with one here. Mothra's general
  targets also read `evidence/runtime-network/` and
  `evidence/runtime-supervision/`, which must be classified at EP-M3.
- Observation: mdtablefix joins a run of links separated only by commas into
  one unbreakable line. Impact: two such lists gained articles so they wrap.
- Observation: the import selects 17,603 files in 263 commits, and 790 of
  them fall under the LFS rule, not the 795 counted earlier. Evidence: a
  scratch clone filtered and converted on 15 November 2026. The earlier count
  included `evidence/runtime-network/` and `evidence/runtime-supervision/`,
  which hold evidence about the general toolset and stay in mothra.
- Observation: the curation tool selects 200 corpora (13,439 files, about
  852 MiB), one fewer than the lead's estimate; `export-cache-cleanup-01` is
  cited by nothing in the citing set. Evidence: `evidence/curation.json`.
- Observation: in mothra itself, 84 `SHA256SUMS` entries name files that
  were never committed (`hotline-protocol-docs.tar.gz` and `mothra.tar.gz` under
  `export-cache-recovery-03`). Evidence: the sums verifier in source mode.
  Impact: none here; that corpus is excluded as noise, and over the imported
  tree the verifier reports 213 sums files, 13,454 entries, 13,431 ok, 23
  external and no failures.
- Observation: `git lfs ls-files` lists staged files that share one object
  only once, so it reported 684 of 757 LFS paths before the first commit.
  Impact: the LFS gate reads the index instead.
- Observation: the withheld set is three distinct objects, not two: the data
  fork, the resource fork and the AppleDouble container.
- Observation: the safety layer of this environment refuses commands that
  name a packet-capture file. Impact: the lead inspects such files only through
  the repository's tools and index metadata, never directly.
- Observation: run one at a time in the original layout, 104 of mothra's 106
  check recipes pass. The two that fail are the field-161 verifier and the
  legacy test suite, both with the known `capture gate source identity` error.
  Evidence: a per-recipe run on 15 November 2026, kept in the session scratch
  directory as `baseline-verdicts.json`. Impact: this is the script baseline
  for INV-SCRIPT.
- Observation: the evidence index pins the hashes of three helper scripts
  (`capture-ghidra-evidence.py`, `extract-synhxd-evidence.py` and
  `verify-baseline-evidence.py`) and of the validity ledger. Evidence:
  `evidence/hotline-server-1.9/manifest.json`, read by the ledger verifier.
  Impact: these four files stay byte-identical, so the three scripts cannot be
  refactored in EP-M5 without a decision on how the verifier should treat the
  pinned copies; the ledger is excluded from reflow and spelling.
- Observation: the Markdown and spelling gates examine tracked files only, so
  a new document is not checked until it is staged. Impact: stage before gating.
- Observation: an audit revision cut here has no counterpart in the source
  commit. Impact: `evidence/local-corpora.json` records such corpora, and the
  curation check accepts them.
- Observation: the existing documents are otherwise close to clean. With the
  Lody markdownlint configuration only 18 MD049 findings appear, no local link
  is broken, and default `typos` reports 90 findings, mostly protocol tokens.
- Observation: the renderer's link regex skips links written with a space
  after the opening parenthesis, so two links in `mxd-validation.md` and
  `protocol.md` were never checked. Evidence: `]( mxd-reconciliation.md)` and
  `]( native-console-broadcast.md)`. Impact: `tools/check_links.py` checks them
  (the real run examines 4,370 links against the renderer's 4,364) and both
  resolve.
- Observation: revision 89's manifest carries run-description keys that a fresh
  revision makes untrue: `snapshot_policy` ("reuse byte-identical older
  snapshots") and `reused_prior_snapshots` (100). Impact: `refresh_audit.py`
  carries every non-input key forward unchanged, as directed; the new revision
  snapshots all inputs afresh, so those two values need a reviewed edit by the
  lead.
- Observation: the cuprum release pinned here treats a `cwd=` keyword as a
  command-line flag. Impact: the tools call `git -C <dir>`.
- Observation: new Python tooling measures 2,289 lines with docstrings and
  blanks (876 lines of code) after three tools. Impact: against the 2,200-line
  scope tolerance this needs a ruling on which measure applies; reported to the
  lead.

- Ten corpus-held verifiers locate helper modules through a checkout named
  `hotline-protocol-docs` and cannot be edited, because they sit under
  `evidence/`. The `Makefile` macro `in_legacy_layout` runs them from a scratch
  tree of that name holding a copy of `scripts/` and a hard-linked `evidence/`.
  Evidence: `make evidence-verify` passes in a worktree of another name.
- `ty` reports eight diagnostics on the inherited scripts: two unresolved
  imports of `mcp` in the hash-pinned `capture-ghidra-evidence.py`, and six
  `bytes | None` arguments in `classic_login_proxy.py`. `typecheck-legacy` is
  therefore defined but kept out of `make all` until EP-M5.
- Twenty-one corpora hold frozen copies of earlier versions of scripts that
  EP-M3 edited; their `SHA256SUMS` cover the frozen copies and nothing compares
  them with the live files, so the edits break no recorded hash.
- The inherited verifiers and one test write a `state/` directory at the
  repository root; it is ignored (`b1cae01`).

- Each audit revision cut here must also be listed in
  `evidence/local-corpora.json`, or `curation-check` reports it as present but
  not included. Revision 91 was added by hand; `tools/refresh_audit.py` should
  add the entry itself before the next revision.
- Mothra's local clone needs the published branch fetched
  (`git fetch origin documentation-reconcilliation`) for the link check to
  confirm permalink paths; the fetch adds a remote-tracking ref only.

- The SynHX dates given in D25 were not all right. The archive dates 0.1.42
  to 30 June 2001 (the first `README.synhxd` revision is 1 August 2001); the
  client README places the client split at 0.1.47 and the client changelog at
  0.1.48; the server changelog dates 0.1.48 to 1 September and 0.1.48.1 to
  2 September 2001; the client README names hx without a version. The glossary
  states what the archive shows. The conclusion of D25 stands: shx is the
  client of the SynHX family.
- D25 asks for three ledger identifier series; the validity ledger has two,
  V001 to V074 and M001 to M009. The `C004` cited in this plan's trace table is
  not a ledger identifier. The glossary describes two series.
- The ledger scribe found disagreements that the documents do not settle,
  recorded neutrally in the ledger: canonical mxd is `cb907885` in
  `mxd-validation.md` but `48129491` in GAP-011, GAP-085 and GAP-086; GAP-036's
  progress text is inconsistent about which traces remain; GAP-016 does not
  name its five remaining fixture groups. These go to the EP-M9 reconciliation
  log.

- Findings from writing the recreation guide, for EP-M9 and EP-M10:
  - One `evidence-verify` recipe runs plain `sha256sum` over a sums file that
    lists the withheld server binary, so it fails in a clone without the local
    copy. It should use `tools/check_sums.py`. The recipe text is a golden
    key, so change it between script waves and re-key the golden.
  - The documents name `make ledger-check` and `make check`, which this
    `Makefile` does not define.
  - Six procedures are described differently by two documents, for example
    the private-message and 121-default witnesses name a different verifier
    from their preparation documents; section 14 of the guide lists them.
  - Set-up passages to replace with links to the toolset guides:
    `native-capture-workflow.md` (the emulator build, runtime preparation,
    launch and readiness passages near the start, and the Sleuth Kit
    installation) and the `mac_runtime.py prepare` commands in
    `runtime-recovery-20261113.md`; borderline, the host dependency
    installation in `shx-peer.md` and the namespace guard in
    `classic-login-proxy.md`.
  - Ten absolute local paths remain in six documents.

- Status drift and stale statements found while writing the overviews, for
  the EP-M9 reconciliation log (none changed yet):
  - `docs/protocol/protocol.md` says the native option-one 110 ban notice
    "still need[s] a disposable-server trial";
    `docs/presence-and-messaging/native-ban-notices.md` records that trial as
    witnessed, and two other documents cite the witness.
  - `native-104-variants.md` and `native-pm-preparation.md` say GAP-044
    remains open; the register lists it as Resolved, with closure text that
    says other type-104 variants remain.
  - The handoff note says "revision 89" and that the canonical documents are
    in a sibling checkout; the alias record says "audit88". Both are working
    records kept as written, so each needs a dated note, not an edit.
  - One peer document names the candidate "Hotline Client 1.9.2 for OSX and
    OS9" and two name it "Hotline Client 1.9.2 Classic".
  - Overlaps without contradiction: two inventories of type-104 producers;
    the 64 single-bit captures described in two sets; the shx 0.1.48 identity
    repeated in four peer documents.
- `mdtablefix` joins a run of comma-separated inline links into one long
  line. Long runs of gap links in the overviews are reference links for that
  reason.

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
- Decision D8 (settled by the owner, 2026-11-15; superseded in part by D20):
  mothra may be pushed to `origin`. Under D20 what is pushed is the filtered
  general-toolset history, never the local `main`.
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
  pushed in EP-M4. Until then the handful of links to mothra's general guides
  stay relative, and the link gate's switch that forbids them is turned on at
  the end of EP-M4. Rationale for pinning: a permalink keeps the cited text
  stable.
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

- Decision D16: the mechanical conformance of the existing documents (reflow
  with mdtablefix, underscore emphasis, Oxford spelling) was brought forward
  from EP-M10 to EP-M1. Rationale: the repository's post-turn checks run
  `make check-fmt lint typecheck markdownlint` after every turn, so the
  Markdown gates must pass from the start. Consequence: the documents in this
  branch do not match the hashes of audit revision 89 from commit `bf6d00e`
  until revision 90 is cut in EP-M3; the main checkout is unaffected. The
  generated `gap-analysis.md` is excluded from reflow and spelling, and the
  heading `Preparation and later authorised capture` keeps its spelling because
  its anchor is audited. EP-M10 keeps captions, screen-reader text, sentence
  case, person and cross-references. Date/Author: 2026-11-15, lead.
- Decision D17: only instructional set-up guidance moves to mothra: the
  emulator preparation and Sleuth Kit passages of `native-capture-workflow.md`
  and the namespace-supervision procedure of `mxd-peer-capture-workflow.md`.
  Statements inside dated preparation and witness records about what a
  particular run checked are run records and stay. Rationale: the census found
  32 general and 53 mixed passages, most of them in historical records that the
  constraints forbid rewriting. Date/Author: 2026-11-15, lead.
- Decision D18: the red baseline is recorded, not repaired. One verifier,
  `verify_classic_field161_matrix.py`, rejects its corpus because the hash of
  mothra's `scripts/capture_readiness.py` no longer matches the manifest. The
  INV-SCRIPT goldens record that verdict as the starting state. Date/Author:
  2026-11-15, lead.

- Decision D19 (escalated to the owner, 2026-11-15): the tolerance on new
  Python tooling, 2,200 lines excluding tests, was reached at the end of EP-M2.
  The three tools delivered so far total 2,289 lines counted with docstrings
  and blank lines, or 876 lines of code, and five planned tools remain. The
  df12 standards require a numpy-style docstring on every function, which more
  than doubles the raw count. Options: count code lines only and keep 2,200; or
  keep the raw count and raise the limit to about 6,000. No further tool is
  started until the owner chooses. Work that adds no tooling continues.
  Date/Author: 2026-11-15, lead.

- Decision D20 (settled by the owner, 2026-11-15): the Hotline Server binary
  is not published; it is not this project's to publish. Its hashes and
  provenance are. The binary's two forks appear in the evidence eight times:
  the data fork (616,821 bytes, SHA-256 `ad7040db…e4cd1b`) at
  `hotline-server-1.9/inputs/HLserver19.pef`, at `catalog-11183.data` in
  `native-ban-one-01` and `native-runtime-recovery-01`, and at
  `server-data.bin` in `native-ban-expiry-later-01`; the resource fork (38,460
  bytes, SHA-256 `fe83a2cf…c48b12`) at the matching `.rsrc` and
  `server-rsrc.bin` paths; and an AppleDouble container of the resource fork at
  `batch-09/inputs/HLserver19.appledouble`. No other tracked file contains
  either fork: a block-similarity scan of every non-text evidence file, packet
  captures included, found only these. Consequences:
  - These paths are removed from every commit of the imported history and of
    any mothra history that is pushed. They are listed in `.gitignore`, so a
    local copy can sit in place and local verification behaves as before.
  - `evidence/withheld.json` records each withheld path with its size,
    SHA-256 and reason. Checks treat a withheld file as expected to be absent
    and verify it against the recorded hash when it is present.
  - Mothra's local `main`, whose commits contain the binary, is never pushed.
    What is pushed is a filtered history with every imported path removed.
    This replaces the earlier constraint that mothra's history is not
    rewritten: the unpushed commits are rewritten in a scratch clone, and the
    local `main` is left as it is for the owner to replace.
  - A verifier that needs a withheld file reports that the input is withheld
    and absent, as a distinct outcome from failure. This is the one permitted
    addition to script behaviour.
- Decision D21 (settled by the owner, 2026-11-15): a file that is a modified
  or wrapped copy of a withheld fork is published as a binary patch against the
  withheld original, not as the file itself. The format is BSDIFF40, as written
  by the `bsdiff4` Python package and read by `bspatch`; the patch is stored
  beside the original path with the suffix `.bsdiff`, and
  `evidence/withheld.json` records the base hash, the patch hash and the hash
  of the reconstructed file. Today one file qualifies: the AppleDouble
  container, which is an 82-byte header followed by the resource fork.
  Rationale for the format: it is small, widely implemented, and needs only one
  pinned Python dependency. The exact identical copies need no patch; their
  hash is the base hash.

- Decision D22 (settled by the owner, 2026-11-15): the evidence is curated
  on import: relevant evidence comes in, noise does not. The unit is the
  corpus, a dated directory such as
  `evidence/gap-remediation/2026-11-13/native-pm-01`, kept whole so that its
  manifest and `SHA256SUMS` stay valid. A corpus is relevant if a protocol
  document, the gap register, the validity ledger, a capture or verifier
  script, or a retained check recipe cites a path inside it, or if a relevant
  corpus's manifest, plan or sums file cites it (closure). Measured on
  15 November 2026: 201 of 360 corpora are relevant (13,489 files, about 854
  MiB); 159 are noise (4,096 files, about 133 MiB), chiefly 35 export reviews,
  16 integration records, storage and recovery housekeeping, and 75 superseded
  audit revisions. Consequences:
  - The import is a snapshot of mothra at commit `f9b4108`, not a history
    merge. The 263 commits of evidence churn are themselves noise. This
    replaces the history-preserving import of D9; the LFS rule of D9 stands.
  - `evidence/curation.json` lists every corpus with its disposition and the
    reason, so the selection can be checked and repeated.
  - Of mothra's working documents, only those the protocol documents cite
    come in: the validity ledger, `native-clock-evidence.md`, `shx-peer.md`
    and the cited delegation and plan records. The remediation worklog, the
    handoff note, the debugging plans and the uncited delegation packets are
    process records and are not imported.
  - Corpora that support only mothra's general guides, such as
    `slirp-lowmem-01` and `guest-capture-startup-01`, are neither imported
    nor deleted from mothra's general history; EP-M4 keeps them there.
  - Files inside a relevant corpus are not pruned, because doing so would
    invalidate its recorded hashes.
- Decision D23: the tooling tolerance of D19 is applied to lines of code,
  excluding docstrings, comments and blank lines, with the limit kept at 2,200.
  Rationale: the owner was asked three times, gave further directions that
  require new tools, and expressed no objection to the recommended reading; the
  standing instruction is that requested changes are actioned. At the end of
  EP-M2 the count stood at 876. The owner may overrule this. Date/Author:
  2026-11-15, lead.

- Decision D24 (settled by the owner, 2026-11-15): the owner accepted an
  increase in the tooling size tolerance. The limit on new Python tooling is
  now 6,000 lines excluding tests, counted with docstrings and blank lines,
  which is the figure offered in D19. This supersedes the code-line reading of
  D23; the code-line count is still reported for each tool as a guide.

- Decision D25 (settled by the owner, 2026-11-15): the documentation gains a
  comprehensive glossary at `docs/glossary.md`, and the relation between the
  SynHX names is stated plainly wherever it matters. The source archive at
  `../synhxd` shows that "Synapse Hotline X" is a fork of hx and hxd 0.1.41;
  its server was first named `synhxd` (0.1.42, August 2001); at 0.1.47 the
  client was split out as `shx` (0.1.48, 31 August 2001) and the server became
  `shxd` (0.1.48.1). So shx is the client of the SynHX family, not an earlier
  client replaced by one called SynHX. The existing documents use "SynHX" 52
  times in 10 files and "shx" 46 times in 12 without stating this. The glossary
  covers at least:
  - the peers and implementations: Hotline Server 1.9 and its build label,
    the Classic client, hx, hxd, SynHX, synhxd, shx, shxd and mxd;
  - wire terms: transaction, request, reply, notification, field and its
    numbering, the handshake tags, the transfer protocol and its stream
    tags, forks, flattened files and aliases;
  - evidence terms: oracle, corpus, preparation, witness, verifier, capture
    plan, readback, source prediction, observed, unresolved, withheld file;
  - register and provenance terms: gap and its kinds, priorities and
    statuses, ledger entry and its three identifier series, audit revision,
    correction map;
  - the work-packet labels that appear in titles and prose, such as A26 and
    C52, with what each series denotes;
  - toolset terms the documents rely on: the emulator, the disassembler, the
    container format of the binary, the forensic file-system tools.
  Each entry gives a one- or two-sentence definition, the document that is
  authoritative for it, and, for a factual claim such as the SynHX lineage, a
  citation of retained evidence. Existing statements that use a family name
  loosely are reworded to name the thing meant, without changing the claim.

- Decision D26: the documentation gains one ledger of remaining evidence
  work, `docs/provenance/remaining-evidence-work.md`. The owner asked on
  15 November 2026 whether a clear ledger existed; none does. The remaining
  work is spread over five places: the `resolution.progress` strings of the 25
  gaps that are not Resolved; mothra's `docs/protocol-handoff.md`, which names
  the prepared and unstarted `native-wire-boundary-06` run; the four open
  milestones of mothra's `docs/execplans/missing-target-alias.md`; the
  untracked operator packets under mothra's `state/delegation/`, of which
  `c179-wire-bootstrap/handoff.md` is the latest; and `mxd-validation.md` for
  the parked mxd work. The ledger has one row for each unresolved gap: what its
  closure criterion still needs, the kind of work (native capture, static
  analysis, peer capture, mxd validation or a decision), what has been
  prepared, what blocks it, and where to pick it up. A second table lists
  prepared runs that have not started, with their preconditions. To support it,
  the handoff note and the missing-target alias plan are imported after all, as
  records under `docs/provenance/records/`, and the content of the latest
  operator packet is summarized with the owner's consent, since it sits in
  untracked state. A check requires every gap that is not Resolved to appear in
  the ledger exactly once and no Resolved gap to appear. The ledger is written
  in EP-M8 and reviewed against the register in EP-M9. Date/Author: 2026-11-15,
  lead.

- Decision D27: mothra's published branch is a single snapshot commit of the
  general tooling on top of its published initial commit, not a filtered
  history, and it keeps only evidence that does not name this project.
  Rationale: filtering by path left 98 commits whose messages and earlier file
  versions name Hotline, the audit and the gaps, which conflicts with the
  owner's rule that nothing in mothra is specific to this project; the history
  of the general tools is short and of little value beside that rule.
  Consequences: the EP-M4 commands that call `git filter-repo` are replaced by
  a keep-list filter followed by `git commit-tree` onto `4ef7b8d`; mothra keeps
  `evidence/runtime-network`, `evidence/runtime-supervision` and
  `alias-window-profile-01`; the corpora `guest-capture-startup-01`,
  `receipt-builder-rehearsal-01`, `runtime-retirement-01` and
  `runtime-storage-audit-01` name the project inside hashed files, are cited by
  nothing here, and so are neither published in mothra nor imported (D22). They
  remain in the owner's local mothra checkout. Mothra's
  `scripts/capture_readiness.py` and `scripts/mac_network_isolation.py` stay
  byte-identical, because verifiers here compare their SHA-256. Date/Author:
  2026-11-16, lead.

- Decision D28 (superseded by the owner's ruling below): the tooling tolerance
  of D24 is exceeded. With the golden tools, `tools/` holds 6,199 lines against
  the limit of 6,000, and the relocation tool, the evidence check and the style
  check are still to be written. Options: raise the limit to about 8,000, or
  hold it and condense the seven golden modules. The lead recommends raising
  it. Until the owner rules, no further tooling is added; work continues on
  milestones that change `scripts/` and documents only. Date/Author:
  2026-11-16, lead.

- Decision D29 (superseded by the owner's ruling below): sixteen scripts cannot
  change without turning a verifier red, so REQ-6 at full scope (D2) cannot be
  met for them as they stand. Three are pinned by the evidence index
  (`capture-ghidra-evidence.py`, `extract-synhxd-evidence.py`,
  `verify-baseline-evidence.py`). Thirteen more have their live bytes compared
  with hashes recorded at capture: `protocol_capture`, `pcap_tcp`,
  `native_filp`, `native_pm_cases`, `verify_native_pm_packet`,
  `native_121_default_cases`, `verify_native_121_default`,
  `native_settings_transition_cases`, `verify_native_settings_transition`,
  `native_settings_cases`, `verify_native_settings`, `native_control_readiness`
  and `native_ban_control_cases`. Evidence: a comment appended to every script
  gave 26 golden differences, and none once these were restored. The hashes sit
  in manifests under `evidence/` and in constants in other verifiers. Options:
  pin all sixteen as recorded exceptions held at the earlier rules (the lead's
  recommendation); keep frozen original copies for the comparisons and refactor
  the live files; or change the comparing verifiers, which alters protected
  comparison logic. Until the owner rules, the sixteen stay byte-identical and
  listed in `scripts/legacy-modules.txt`, and the other scripts proceed.
  Consequence for documents, to be handled in EP-M8 and EP-M9: quoted commands
  of the form `python3 scripts/<name>.py` need the project interpreter once the
  script is migrated, quoted `unittest discover` commands no longer find
  converted tests, and abbreviated options are no longer accepted. Date/Author:
  2026-11-16, lead.

- Decision D28 (settled by the owner, 2026-11-16): the tooling tolerance is
  doubled. The limit on new Python tooling is 12,000 lines excluding tests,
  counted with docstrings and blank lines. This supersedes D24 and closes the
  question recorded above; tooling work resumes.
- Decision D29 (settled by the owner, 2026-11-16): the blind comparison of a
  live script's bytes with a recorded hash is replaced by a reference to the
  file at a given Git commit. In the owner's words, "as long as there is test
  coverage that spans that committed version and the refactored version, you
  have continuity of evidentiary basis". Consequences:
  - A record in the repository names, for each of the sixteen scripts, the
    commit at which its bytes carry the recorded hash. A helper returns the
    bytes of a script at its pinned commit.
  - Verifiers in `scripts/` that compared live bytes compare the pinned
    bytes instead; the recorded hash constants and the manifests under
    `evidence/` are unchanged.
  - Verifiers held under `evidence/` cannot be edited and hash files in the
    `scripts/` directory beside them; the `in_legacy_layout` recipe stages the
    pinned bytes of the hash-referenced files for them.
  - Continuity: the goldens were captured with the pinned bytes in place and
    must print `0 differences` with the refactored scripts, and a test runs
    the tests of each pinned script against both its pinned and its current
    version.
  - The sixteen scripts then join the script-standards work, so REQ-6 holds
    at full scope with no exception.
  - The check needs the pinned commit in the local history, so it does not
    work in a shallow clone; the recreation guide says so.
  Date/Author: 2026-11-16, owner; recorded by the lead.

- Decision D30: three files do not move in EP-M6.
  `docs/baseline-validity-ledger.md` is hash-pinned by the evidence index, and
  moving it would change its relative links and so its bytes.
  `gap-register.json` and the generated `gap-analysis.md` stay at the root
  because the renderer, the audit refresh, the `Makefile` and the tests read
  them by name; moving them is possible later as its own change and gains
  little. The relocation is committed as one change with the reflow that longer
  link targets require, checked by word-level equality, and not as two commits
  with an audit revision each. The relocation tool came to 1,283 lines with
  docstrings (513 of code), inside the ceiling of D28; it is deleted in EP-M11.
  Date/Author: 2026-11-16, lead.

- Decision D31 (question; see the ruling below): how `protocol_capture.py`
  identifies itself in new captures. `run_plan` records `driver_sha256`, the
  SHA-256 of the module's own file. The module exceeds 400 lines and must be
  split to meet the standard; a split leaves a facade, so a new capture would
  record the hash of the facade and not of the code that captured. Existing
  evidence is unaffected, because D29 pins it. Options: record the Git commit
  of the scripts tree in new captures and compute `driver_sha256` over the
  whole capture module set in a fixed order (the lead's recommendation, since
  it applies D29 to new evidence too); keep the file whole as one recorded
  exception to the 400-line limit; or split and hash the facade, which
  identifies the driver weakly. Until the owner rules, the module stays on the
  legacy list with its characterization tests in place. The same question
  applies to `native_control_readiness.py`,
  `verify_native_settings_transition.py` and `verify_native_121_default.py`,
  which also record their own hash at capture, and to the capture-side
  self-check in `native_settings_persistence.py`. Date/Author: 2026-11-17,
  lead. Complete list, found by search and confirmed by reading (2026-11-18).
  Each script records the SHA-256 of its own file, or of a sibling, when a
  capture or plan is made:
  - `protocol_capture.py` (`driver_sha256`), later compared by more than
    twenty verifiers against corpus copies, constants or manifests;
  - `capture_shx_session.py` (`driver_sha256`) and `peer_tolerance_run.py`
    (`source_runner_sha256`, `source_fixture_sha256`), compared with the
    corpus's own source hashes;
  - `native_control_readiness.py`, `native_configured_ban_control.py`,
    `verify_native_settings_transition.py` and `verify_native_121_default.py`
    (`driver_sha256`; the last two are capture drivers despite their names);
  - `native_diagnostic_load_cases.py` and `native_settings_persistence.py`
    (`driver_sha256`, compared by their verifiers);
  - `native_settings_persistence_cases.py`, which records four sibling files
    that `native_settings_persistence.py` then re-hashes at capture;
  - the planner and control pairs for board, path fields and missing alias,
    where the planner writes `source-hashes.json` for itself and its control
    and the control compares the live files at run time;
  - the control scripts for rate 304 and liveness (`source_sha256`,
    `cases_sha256`).
  Where a planner in such a pair has been migrated, it was kept as one module
  so that its own bytes still mean one file.

- Decision D31, ruling (settled by the owner, 2026-11-18): the lead's
  recommendation is accepted. A new capture records the Git commit of the
  scripts tree, and its driver hash is computed over the whole capture module
  set in a fixed order, not over one file. Consequences:
  - A capture script may be split into modules; what identifies the driver is
    the commit and the digest of the set.
  - Existing corpora are untouched and keep verifying against the pinned
    bytes (D29). A verifier accepts either form: the recorded single-file hash
    for a corpus captured before this change, or the commit and module-set
    digest for one captured after it.
  - The capture-time self-checks, where a control compares live files with
    hashes its planner recorded, compare the module-set digest in the same
    way.
  - The fifteen scripts listed above join the script-standards work.
- Decision D32 (settled by the owner, 2026-11-18): the suppression limit is
  raised for capture drivers, the scripts that start processes, open sockets or
  drive a capture. For that class the limit of four per family does not apply;
  each suppression is still scoped to one line and states its reason, and the
  count is reported. The two ban-expiry capture drivers join the
  script-standards work.

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
- REQ-13: the relation of shx to SynHX is clarified, and the documentation
  includes a comprehensive glossary.

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
REQ-13 -> EP-M8, EP-M9 -> INV-GLOSSARY; docs/glossary.md
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
  count and exactly the 790 LFS objects measured.
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
- Obligation INV-WITHHELD: no object reachable from any ref that is pushed,
  or from this repository's branch, has the SHA-256 of a withheld fork or
  begins with the PEF container magic at the binary's size, and every withheld
  entry has a recorded size and hash. For each patch, applying it to the
  withheld base reproduces a file with the recorded hash. Method: exhaustive
  scan of every blob in each history (`git cat-file --batch`), plus
  parameterized tests of the patch round trip. Artefact:
  `tools/check_withheld.py` with `tests/test_check_withheld.py`. Evidence: the
  scan prints the blob count and `0 withheld objects`. Non-vacuity: the same
  scan run against mothra's local `main` must report the eight known objects'
  two blob identifiers; tests seed a blob with a withheld hash and a patch
  whose base hash is wrong.
- Obligation INV-GLOSSARY: every term on a maintained list of required terms
  has exactly one entry in `docs/glossary.md`; entries are in alphabetical
  order with unique anchors; every set overview links to the glossary; and
  every work-packet label and every ledger or gap identifier series used in a
  document is covered by an entry. Method: parameterized tests and the real
  run, as part of `tools/check_style.py`; the label check scans the documents
  for the label pattern and requires each series letter to be defined. Evidence:
  `make style-check` reports the term count with none missing. Non-vacuity: a
  seeded missing term, a duplicated entry, an out-of-order entry and an
  undefined label series are each rejected. Residual gap: the check shows that
  a term is defined, not that the definition is right; definitions are reviewed
  against their cited sources in EP-M9.
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
  classification manifest are recorded in this plan. Evidence: `make gap-check`
  in the mothra main checkout exits 0; the legacy `unittest` suite count is
  recorded. Conformance: no tracked file changed in either repository.
  Recovery: none needed. Compatibility: none.
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
- EP-M4, mothra generalized. Outcome: a filtered mothra history contains
  general tooling only and passes its reduced `make check`; it is pushed as a
  branch, and the links from this repository to mothra become permalinks to it.
  Requirements: REQ-8, REQ-9. Evidence: INV-GENERAL, INV-WITHHELD. Conformance:
  this repository's `make all` subset from EP-M3 still passes against the
  mothra branch. Recovery: the branch is not merged; delete it to undo.
  Compatibility: none.
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
- EP-M8, on-ramps. Outcome: `docs/glossary.md`, `README.md`,
  `docs/contents.md`, `docs/repository-layout.md`, `docs/developers-guide.md`,
  the set overviews and `docs/native-evidence/recreating-evidence.md` exist
  with at least five validated Mermaid diagrams. Requirements: REQ-3, REQ-7,
  REQ-13, REQ-11 advanced. Evidence: INV-REACH, `make nixie`. Conformance: new
  files only. Recovery: revert.
- EP-M9, correlation and reconciliation. Outcome: generated
  `docs/<set>/evidence.md` indexes; status drift resolved by dated notes;
  `docs/reconciliation-log.md` lists every discrepancy examined and its
  disposition; every indexed corpus maps to a recreation procedure or a stated
  reason; every use of a SynHX family name says which program is meant, and
  each glossary definition has been checked against its cited source; revision
  94. Requirements: REQ-1, REQ-2, REQ-11, REQ-13. Evidence: INV-EVID,
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

Packet captures are a special case. The environment refuses any command that
names a packet-capture file, and that refusal is not worked around. The
repository's tools copy, hash and store captures without anyone naming them. If
a task needs something done to captures that those tools cannot do, the lead
stops and writes a bounded packet for the owner to pass to another agent. That
packet states exactly which paths are concerned and what is to be done, and
says in plain terms that the captures are not to be inspected, modified or
opened (owner's direction, 15 November 2026).

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
```

Expect `gap-check` to exit 0. Nothing is pushed in this milestone.

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

EP-M4. Build mothra's general-toolset history in the scratch directory, so that
no pushed commit ever contained the imported paths or the binary:

```sh
git clone --no-local /data/leynos/Projects/mothra "$SCRATCH/mothra-general"
git -C "$SCRATCH/mothra-general" filter-repo --invert-paths \
  --paths-from-file "$SCRATCH/import-paths.txt"
```

Edit the remaining files there on a branch named
`documentation-reconcilliation`, committing as usual, then:

```sh
make check
git grep -niE 'hotline|hlserver|mxd|synhx|shx|HOTL|GAP-[0-9]|protocol-docs'
uv run tools/check_withheld.py --repository "$SCRATCH/mothra-general"
git push -u origin documentation-reconcilliation
```

Expect the search to print nothing and the scan to print `0 withheld objects`.
`origin/main` holds only the initial commit, which the filtered history keeps
unchanged, so the pushed branch descends from it.

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

Red-Green-Refactor evidence for EP-M1 and EP-M2 (commands run from the
repository root; the stubs raise `NotImplementedError`, so every red failure is
the missing behaviour, not a missing import):

- `tools/check_json.py` (`04efcbe`). Red:
  `uv run --group dev pytest -q tests/test_check_json.py tests/test_repo_files.py`
  gave `20 failed`. Green: the same command gave `20 passed`. Refactor:
  `make all` exited 0 (Ruff, interrogate 100%, Pylint 10.00/10, `ty` clean,
  tests), confirmed by a scrutineer run. Real run: `make json-check` printed
  `3 files, 0 failures`.
- `tools/markdown_model.py` (`c48e996`). Red: 18 failed in
  `tests/test_markdown_model.py`. Green: 18 passed, including the pin of the
  slug rule against all 543 sections of revision 89 from their frozen
  snapshots. Scrutineer: `make check-fmt-python`, `make lint`, `make typecheck`,
  `make test`, `make json-check` all exit 0 after one fixture fix.
- `tools/check_links.py`, `tools/mothra_links.py`, `tools/check_reach.py`
  (`b3bd149`). Red: `tests/test_check_links.py` gave `23 failed`. Green: all 76
  tests passed. Scrutineer: `make all` exit 0. Real run: `make links-check`
  printed `106 documents, 4370 links, 0 failures`.
- `tools/refresh_audit.py` with `audit_model.py`, `audit_workspace.py`,
  `audit_io.py` and `section_map.py` (`002aaae`). Red: 26 failed, all
  `NotImplementedError`. Green: 102 passed, including the golden test
  (`tests/test_refresh_golden.py`): `sections.json` byte-identical to revision
  89's, every gap's `sources` and every coverage entry unchanged,
  `87 gaps, 0 protected fields changed`, and mothra's `validate` raising
  nothing on the refreshed tree. Scrutineer: `make all` exit 0 (102 passed),
  `make audit-check` printed
  `Validated 87 gaps and 543 reviewed sections;
  checked 4364 local link references`,
  and `git -C ../../mothra status --short` was empty.

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

Sixth revision, 15 November 2026. The owner ruled that the Hotline Server
binary must not be published and that modified forks are to be stored as binary
patches. Decisions D20 and D21 withhold the eight copies of the binary's forks
from every history, record their hashes in `evidence/withheld.json`, and store
the one wrapped copy as a BSDIFF40 patch. Mothra's local `main` is no longer
pushed; EP-M4 instead builds and pushes a filtered general-toolset history, and
the GitHub permalinks are pinned to that commit. A new obligation,
INV-WITHHELD, scans every blob before any push. The scratch import must be
rebuilt without the withheld paths.

Seventh revision, 15 November 2026. The owner asked for relevant evidence to be
cleaned up and included without noise. Decision D22 makes the import a curated
snapshot at corpus granularity with a recorded selection, drops the history
merge, and limits imported working documents to those the protocol documents
cite. Decision D23 applies the tooling tolerance to lines of code. EP-M3
changes accordingly: it copies the selected corpora, writes
`evidence/curation.json` and `evidence/withheld.json`, and verifies content
hashes against mothra at `f9b4108`.

Eighth revision, 15 November 2026. The owner asked for the shx and SynHX
relation to be clarified and recommended a comprehensive glossary. Decision D25
adds `docs/glossary.md` to EP-M8, a terminology review to EP-M9 and a new
obligation, INV-GLOSSARY, checked by the style tool.
