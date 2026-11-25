# Remaining evidence work

This ledger brings together the evidence-capture work that remains for the
Hotline 1.9 protocol documentation. It reports what the sources record. It does
not decide anything, does not add, remove, re-status or re-word any
[gap](../glossary.md#gap), and does not state a protocol fact that its sources
do not state. The gap register, `gap-register.json`, remains the authority.
Where this ledger and the register differ, the register governs.

This document belongs to the [provenance](README.md) set; the
[glossary](../glossary.md) defines the terms it uses.

## Purpose and status

The register's `last_updated` date is 2026-11-24. It records 87 gaps: 62 are
Resolved, 24 are Investigating and 1 is Open. The 25 gaps that are not Resolved
appear in Table 1, ordered by priority (P0, then P1, then P2) and then by
identifier. Of these, 5 are P0, 18 are P1 and 2 are P2.

Work is parked. Further mxd validation is on hold at the user's instruction of
13 November 2026. The protocol handoff note records that no new investigation
or native run should start without resumption.

## Keeping the ledger in step with the register

Every gap whose status is not Resolved must appear exactly once in Table 1, and
no Resolved gap may appear in it. A check is to enforce this rule. When the
register changes, this ledger is updated to match. The register is never edited
to match this ledger.

The register's `kind` field (Decision, Missing, Unanswered, Ambiguous or
Evidence) describes the gap rather than the work needed, so Table 1 does not
repeat it. The kind of work in Table 1 is one of five values:

- **Native capture:** a new run against the native Hotline Server 1.9 binary,
  in an isolated and owned environment, with packets and screens retained.
- **Static analysis:** reading the server or client binary, for example by
  decompilation or cross-reference queries, without a live run.
- **Peer capture:** a run against an identified Hotline client, with its
  packets retained.
- **mxd validation:** tests, fixes or client trials against the mxd
  implementation, which is kept outside this repository. This work is on hold.
- **Decision:** a choice of scope or policy by the owner, which evidence alone
  cannot make.

Where a gap needs two kinds of work, the row names the kind used by the next
step and mentions the other in the "What remains" cell. The next step is taken
from the register's `resolution.progress` text, or, where that text is silent,
from the closure criterion.

## Remaining gaps

The counts by kind of work are: native capture, 15 gaps; static analysis, 5
gaps; peer capture, 1 gap; mxd validation, 1 gap; decision, 3 gaps. Each gap
has a subsection under "Per-gap detail", which gives the closure criterion
condensed from the register and the sources of each claim.

| Gap                                      | Priority | Status        | Title                                                  | Kind of work    | What remains                                                                                                    | Prepared                                                                                        | Blocked by                                    | Pick up                                                                                         |
| ---------------------------------------- | -------- | ------------- | ------------------------------------------------------ | --------------- | --------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| [GAP-001](../../gap-analysis.md#gap-001) | P1       | Open          | Define the supported 1.9 subset                        | Decision        | Operation-by-profile scope matrix                                                                               | [mxd reconciliation](../mxd/assertion-reconciliation.md)                                        | None; owner unassigned                        | [mxd validation](../mxd/validation-status.md)                                                   |
| [GAP-005](../../gap-analysis.md#gap-005) | P0       | Investigating | Connection timers and liveness                         | Native capture  | Timer and state table; native clock, wake cause, configuration, idle beyond 600 s                               | [Liveness witness](../native-evidence/native-liveness-witness.md)                               | None                                          | [Liveness witness](../native-evidence/native-liveness-witness.md)                               |
| [GAP-011](../../gap-analysis.md#gap-011) | P0       | Investigating | Frame, transaction and buffering limits                | Static analysis | Later writes and aggregate buffering; format-5 Prefs observed after shutdown                                    | [Receive-limit origin](../protocol/receive-limit-origin.md)                                     | None                                          | [Receive-limit origin](../protocol/receive-limit-origin.md)                                     |
| [GAP-016](../../gap-analysis.md#gap-016) | P0       | Investigating | Absent, empty and zero-valued fields                   | Native capture  | Five fixture groups, listed under "Explicitly unmeasured cells" in the presence defaults                        | [Presence defaults](../presence-and-messaging/presence-defaults.md)                             | None; GAP-072 waits on it                     | [Presence defaults](../presence-and-messaging/presence-defaults.md)                             |
| [GAP-018](../../gap-analysis.md#gap-018) | P0       | Investigating | Text encoding and transformations                      | Peer capture    | Identified-peer byte fixtures; peer text policy                                                                 | [Identified client source](../peers/identified-client-source.md)                                | None; GAP-082 waits on it                     | [Identified client source](../peers/identified-client-source.md)                                |
| [GAP-019](../../gap-analysis.md#gap-019) | P0       | Investigating | Semantic length limits and truncation                  | Native capture  | Unmeasured length cells; 1024-byte diagnostic boundary                                                          | [Diagnostic boundary preparation](../native-evidence/native-diagnostic-boundary-preparation.md) | None; packet needs parent approval            | [Diagnostic boundary preparation](../native-evidence/native-diagnostic-boundary-preparation.md) |
| [GAP-020](../../gap-analysis.md#gap-020) | P1       | Investigating | Date and timestamp semantics                           | Native capture  | Timezone, alternate-year, subsecond and rollover fixtures                                                       | [Date contracts](../protocol/date-contracts.md)                                                 | None; GAP-067 waits on it                     | [Date contracts](../protocol/date-contracts.md)                                                 |
| [GAP-021](../../gap-analysis.md#gap-021) | P1       | Investigating | ACK versus completion, durability and retry            | Native capture  | Disconnect, persistence, retry and post-ACK failure fixtures                                                    | [Account write ordering](../accounts-and-privileges/account-write-ordering.md)                  | None                                          | [Account write ordering](../accounts-and-privileges/account-write-ordering.md)                  |
| [GAP-026](../../gap-analysis.md#gap-026) | P1       | Investigating | Meaning and lifetime of login extras                   | Static analysis | Meaning of field 161; change and lifetime rules                                                                 | [Classic field 161 matrix](../peers/classic-field161-matrix.md)                                 | None                                          | [Classic field 161 matrix](../peers/classic-field161-matrix.md)                                 |
| [GAP-031](../../gap-analysis.md#gap-031) | P1       | Investigating | Complete privilege bitmap registry                     | Static analysis | Meanings of unknown bits; Classic client label mapping                                                          | [Privilege bits](../accounts-and-privileges/privilege-bits.md)                                  | None                                          | [Privilege bits](../accounts-and-privileges/privilege-bits.md)                                  |
| [GAP-033](../../gap-analysis.md#gap-033) | P1       | Investigating | User, room, article and reference identifier lifetimes | Native capture  | Transfer and reference lifetimes; user, room and reference reuse and wrap                                       | [Presence and messaging](../presence-and-messaging/presence-messaging-contracts.md)             | None; GAP-036 waits on it                     | [Presence and messaging](../presence-and-messaging/presence-messaging-contracts.md)             |
| [GAP-036](../../gap-analysis.md#gap-036) | P1       | Investigating | Disconnect notification and cleanup                    | Native capture  | Online idle beyond 600 s; broader room and transfer cleanup; kick and timeout traces named in the progress text | [Liveness witness](../native-evidence/native-liveness-witness.md)                               | GAP-033                                       | [Liveness witness](../native-evidence/native-liveness-witness.md)                               |
| [GAP-045](../../gap-analysis.md#gap-045) | P1       | Investigating | Flood, spam and throttling outcomes                    | Native capture  | Corrected 304 rate control; native 60-second boundary; other limits                                             | [Rate 304 preparation](../native-evidence/native-rate304-preparation.md)                        | None; needs a reviewed packet and a fresh lab | [Rate 304 preparation](../native-evidence/native-rate304-preparation.md)                        |
| [GAP-050](../../gap-analysis.md#gap-050) | P1       | Investigating | Delete semantics and failures                          | Static analysis | A safe post-mutation failure stimulus; Files-root and protected-target deletes                                  | [Filesystem and board contracts](../files-and-transfers/filesystem-and-board-contracts.md)      | None                                          | [Filesystem and board contracts](../files-and-transfers/filesystem-and-board-contracts.md)      |
| [GAP-053](../../gap-analysis.md#gap-053) | P1       | Investigating | Move collision and metadata behaviour                  | Native capture  | Cross-volume move; interrupted move failure                                                                     | [Filesystem and board contracts](../files-and-transfers/filesystem-and-board-contracts.md)      | None                                          | [Filesystem and board contracts](../files-and-transfers/filesystem-and-board-contracts.md)      |
| [GAP-054](../../gap-analysis.md#gap-054) | P1       | Investigating | Alias creation and resolution                          | Native capture  | Genuine missing-target response with full provenance                                                            | [Missing-target alias preparation](../native-evidence/native-missing-alias-preparation.md)      | None; each step needs root approval           | [Alias plan](records/missing-target-alias.md)                                                   |
| [GAP-064](../../gap-analysis.md#gap-064) | P1       | Investigating | Transfer completion, failure and persistence           | Native capture  | Cause of the 98,304-byte stall; disk-full, large-size and restart fixtures                                      | [Native transfer stall](../files-and-transfers/native-transfer-stall.md)                        | Stall cause unknown                           | [Native transfer stall](../files-and-transfers/native-transfer-stall.md)                        |
| [GAP-067](../../gap-analysis.md#gap-067) | P1       | Investigating | Article navigation, flavour and date semantics         | Native capture  | Navigation at 100 siblings and 30 flavours; date boundaries                                                     | [News contracts](../news/news-contracts.md)                                                     | GAP-020                                       | [News contracts](../news/news-contracts.md)                                                     |
| [GAP-068](../../gap-analysis.md#gap-068) | P1       | Investigating | Posting and new-article discovery                      | Native capture  | Post flags; discovery of every allocated ID; persistence; invalid requests                                      | [News contracts](../news/news-contracts.md)                                                     | GAP-018; GAP-067                              | [News contracts](../news/news-contracts.md)                                                     |
| [GAP-070](../../gap-analysis.md#gap-070) | P1       | Investigating | News hierarchy and structure mutations                 | Native capture  | Alias and root variants; interrupted category writes                                                            | [News contracts](../news/news-contracts.md)                                                     | None                                          | [News contracts](../news/news-contracts.md)                                                     |
| [GAP-071](../../gap-analysis.md#gap-071) | P1       | Investigating | Account field 111                                      | Static analysis | Human meaning of field 111; indirect consumers                                                                  | [Account attribute trace](../accounts-and-privileges/account-attribute-trace.md)                | None                                          | [Account attribute trace](../accounts-and-privileges/account-attribute-trace.md)                |
| [GAP-072](../../gap-analysis.md#gap-072) | P1       | Investigating | Account update, placeholder and identity rules         | Native capture  | Rename and conflict; protected and self deletion; forced storage failure                                        | [Native wire details](../protocol/native-wire-details.md)                                       | GAP-016; GAP-071                              | [Native wire details](../protocol/native-wire-details.md)                                       |
| [GAP-082](../../gap-analysis.md#gap-082) | P1       | Investigating | Heuristic text-decoding policy                         | Decision        | mxd text-decoding policy; ambiguity corpus                                                                      | [Peer tolerance matrix](../peers/peer-tolerance-matrix.md)                                      | GAP-018                                       | [Compatibility matrix](../mxd/compatibility-matrix.md)                                          |
| [GAP-085](../../gap-analysis.md#gap-085) | P2       | Investigating | mxd implementation and test evidence                   | mxd validation  | Reconcile stale mxd assertions; map requirements; on hold                                                       | [mxd validation](../mxd/validation-status.md)                                                   | GAP-001                                       | [mxd validation](../mxd/validation-status.md)                                                   |
| [GAP-086](../../gap-analysis.md#gap-086) | P2       | Investigating | Release/proof acceptance criteria                      | Decision        | Release owner, subset, deferred-gap rule and Kani scope                                                         | [mxd validation](../mxd/validation-status.md)                                                   | GAP-001; GAP-085                              | [mxd validation](../mxd/validation-status.md)                                                   |

_Table 1: Gaps that are not Resolved, ordered by priority and identifier._

## Prepared runs that have not started

Table 2 lists each prepared run that has no witness document, or whose
preparation has not produced one. The stated preconditions and reasons are
taken from the named documents.

| Run or packet                                                              | Gap                           | Preparation document                                                                                                                                                | Stated preconditions                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Why not started                                                                                                                                                                                                                                                                                           |
| -------------------------------------------------------------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R06, `native-wire-boundary-06`                                             | Not named in the handoff note | [Protocol handoff](protocol-handoff.md); [stopped preparation manifest](../../evidence/gap-remediation/2026-11-15/native-wire-stopped-preparation-01/manifest.json) | Do not start without resumption. Follow the reviewed operator packet kept outside this repository. Root supervises the fixed 720-second epoch and the full preflight, case, postflight and retirement. Recheck source pins and actual identities. Only one tool may serve the Ghidra endpoint at a time. The c179 operator packet proposes a GUI start-up wrapper for this run, which needs independent root review and an exact source pin before any boot, and a parent grant after the preceding boot succeeds. | Stopped. The handoff records no session directory, no display, no cutoff, no virtual machine, no GUI action and no protocol case. The c179 packet records no UI, display, virtual machine, service, image or protocol action in its own run.                                                              |
| Native 303 final-text boundary case                                        | GAP-019                       | [Native 303 final-text boundary preparation](../native-evidence/native-diagnostic-boundary-preparation.md)                                                          | Parent approval of a new isolated native instance, with an exact stopped base and fresh runtime, display, ports, capture directory and lease. Admin privilege bit 24 and the owned fixture proved in the instance. Zero existing downloads. General Options saved at 8, 8 and 5 and restored afterwards. Fresh output paths that do not yet exist.                                                                                                                                                                 | The document is labelled "proposal only" and says that no VM, service, native socket or image action is authorized by the packet.                                                                                                                                                                         |
| Corrected observer-UID 304 rate control                                    | GAP-045                       | [Native 304 rate and reset preparation](../native-evidence/native-rate304-preparation.md)                                                                           | A new disposable runtime from a stopped immutable base. Unused paths. Live identity, capture and lock gates. At least 390 seconds remaining in an epoch of at most 12 minutes. A 210-second case hard stop. An unchanged 18-action control preflight on the same process.                                                                                                                                                                                                                                          | The document states that the control is "offline prepared and has not run against native 1.9". Earlier labs, `native-rate304-01` to `-03`, were retired.                                                                                                                                                  |
| Missing-target alias positive rehearsal (M2) and missing-target epoch (M3) | GAP-054                       | [Missing-target alias preparation](../native-evidence/native-missing-alias-preparation.md); [alias plan](records/missing-target-alias.md)                           | Root validation of pins. A separately reviewed Finder receipt. Unlink only after a positive 206 response and root approval. A named 1800-second profile. At least 390 seconds of case reserve. New paths that do not yet exist.                                                                                                                                                                                                                                                                                    | No positive M2 result has been obtained. Live-01 timed out at the Finder receipt. Live-02 failed the 390-second gate after readiness. Live-03 was retired after an operator deviation. R04 was aborted at a parent checkpoint. The plan's R05 receipt operation is pre-authored, and no START is granted. |

_Table 2: Prepared runs that have not started, with their preconditions and the
reason each has not started._

## Preparation documents and their witnesses

Each preparation document is paired below with the witness document that
records its run. The pairing is by name or by the witness's own statement. A
preparation without a witness is listed in Table 2, or has its reason stated
here.

- [Liveness preparation](../native-evidence/native-liveness-preparation.md) has
  [Liveness witness](../native-evidence/native-liveness-witness.md).
- [Configured-address ban preparation](../native-evidence/native-configured-ban-preparation.md)
  has
  [Configured-address ban witness](../native-evidence/native-configured-ban-witness.md).
- [Roster overlap preparation](../native-evidence/native-roster-overlap-preparation.md)
  has
  [Roster overlap witness](../native-evidence/native-roster-overlap-witness.md).
- [Temporary-ban expiry preparation](../native-evidence/native-ban-expiry-preparation.md)
  has
  [First epoch witness](../native-evidence/native-ban-expiry-first-witness.md)
  and
  [Later epoch witness](../native-evidence/native-ban-expiry-later-witness.md).
- [Permanent-ban control preparation](../native-evidence/native-ban-control-preparation.md)
  has
  [Permanent-ban control witness](../native-evidence/native-ban-control-witness.md).
- [Settings preparation](../native-evidence/native-settings-preparation.md) has
  [Settings witness](../native-evidence/native-settings-witness.md).
- [Same-session 304 transition preparation](../native-evidence/native-settings-transition-prep.md)
  has
  [Same-session 304 transition witness](../native-evidence/native-settings-transition-witness.md).
- [Settings persistence preparation](../native-evidence/native-settings-persistence-preparation.md)
  has
  [Settings persistence witness](../native-evidence/native-settings-persistence-witness.md).
- [Delayed 121 default-text preparation](../native-evidence/native-121-default-preparation.md)
  has
  [Delayed 121 default witness](../native-evidence/native-121-default-witness.md).
- [Message board preparation](../native-evidence/native-board-preparation.md)
  has [Message board witness](../native-evidence/native-board-witness.md).
- [Private-message fixture preparation](../native-evidence/native-pm-preparation.md)
  has [Private-message 104 witness](../native-evidence/native-pm-witness.md).
- [Existing-file diagnostic preparation](../native-evidence/native-diagnostic-existing-preparation.md)
  has
  [Existing-file diagnostic witness](../native-evidence/native-diagnostic-existing-witness.md).
- [Near-boundary diagnostic preparation](../native-evidence/native-diagnostic-near-preparation.md)
  has
  [Near-boundary diagnostic witness](../native-evidence/native-diagnostic-near-witness.md).
- [Native path-field preparation](../native-evidence/native-path-fields-preparation.md)
  has [Native path-field witness](../files-and-transfers/native-path-fields.md),
  which names itself the witness for the completed twelve-case run.
- [Native 304 rate and reset preparation](../native-evidence/native-rate304-preparation.md)
  has no witness of its own. The
  [measured 304 sequence](../native-evidence/native-rate304-sequence.md) and the
  [failed first pair](../native-evidence/native-rate304-first-pair.md) record
  earlier runs. The corrected control has not run; see Table 2.
- [Native 303 final-text boundary preparation](../native-evidence/native-diagnostic-boundary-preparation.md)
  has no witness. It is a proposal; see Table 2.
- [Missing-target alias positive rehearsal preparation](../native-evidence/native-missing-alias-preparation.md)
  has no witness. The positive M2 result has not been obtained; see Table 2.
- R06 has no preparation document. Its stopped preparation is
  recorded in the manifest cited in Table 2.

Three witnesses have no preparation document: the
[Ban reload witness](../native-evidence/native-ban-reload-witness.md), the
[Diagnostic density witness](../native-evidence/native-diagnostic-density-witness.md)
and
[One Log focus event witness](../native-evidence/native-ui-focus-witness.md).
The focus event witness's preparation plan is kept under the evidence tree, at
`evidence/gap-remediation/2026-11-14/native-ui-focus-01/preparation/plan.md`.

## Parked mxd work

The [mxd validation record](../mxd/validation-status.md) has been on hold since
13 November 2026. It preserves the findings made before the hold. It is not a
release sign-off, and it does not claim full native compatibility.

- Recorded results: three corrections were accepted before the hold. They cover
  frame and logical transaction limits, direct replies, and successful-login
  extras. In the first Classic trial, a 48-character password was not fully
  transmitted, because only the first 31 bytes were sent. In the second trial,
  a 24-character password was fully transmitted and authentication succeeded.
  That trial stalled at Loading Agreement, and no 121, 300 or 212 request
  followed. The second trial lasted 93 seconds against an authorized 30-second
  window. The overrun is recorded as a process deviation.
- Startup hand-off: the record notes that the current implementation has no
  121 command branch and sends no 109 notification to a logged-in client.
- Resumption items, in the order the record gives them:
  1. Reconcile guide claims, and design and test the 109 and 121 startup
     sequence.
  2. Complete one identified Classic startup before claiming roster, banner or
     general interoperability.
  3. Complete the requirement-to-test map and the stale-assertion review under
     GAP-085.
  4. Resolve the native byte-encoding question against mxd's ASCII server-name
     policy, and the remaining compatibility choices.
  5. Obtain the release subset, the sign-off owner and the proof obligations
     for GAP-001 and GAP-086.

The [mxd peer runtime record](records/mxd-peer-runtime.md) reports that the mxd
fixture for the Classic client, C14 to C19, was prepared, started and then
stopped. Its client capture is recorded separately.

## Delegated peer work

- The [Mac client candidate](records/mac-peer-candidate.md) record covers
  static identity only. The candidate was not launched, installed or connected
  to a server. Its embedded version resource reads `1.9.1.0`, while its archive
  and application labels read 1.9.2. Its next action needs a separately
  reviewed disposable guest and capture plan. No such plan is in this checkout.
- The [Classic login proxy rehearsal](records/classic-proxy-rehearsal.md)
  record covers one synthetic serve-path rehearsal, B29. Two real Classic UI
  attempts, B30 and B31, produced no connection. The record authorizes no new
  UI trial.

## Material outside this repository

The operator packets that drive the capture work are kept outside this
repository. They are untracked, unpublished and read here for their process
state only; no packet content is reproduced, and no host, account, address,
path or credential is recorded. This summary reflects the packets as read on
2026-11-16. The packets themselves remain outside the repository.

| Packet                                                  | Date       | Run or gap concerned                                                                        | Stated state                                                                                                                  | Next step named                                                                                                                                                                                                                      |
| ------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `c179-wire-bootstrap/handoff.md`                        | Not stated | R06 (`native-wire-boundary-06`) start-up through the GUI; no gap named                      | Author-only. The proposed wrapper is not yet reviewed. No UI, display, virtual machine, service, image or protocol action ran | Independent root review and an exact source pin of the wrapper before any boot; a parent grant of the known start-up sequence after the preceding boot succeeds; a fresh screenshot and hash before each input                       |
| `b145-broadcast-boundary/handoff.md`                    | Not stated | Offline plans for a transaction 355 request boundary of 4,096 and 4,097 bytes; no gap named | Proposed and unbound. No recorder, socket, service, virtual machine, image or native action ran                               | A new runtime record and operator identity from the parent; regenerated plan hashes; live identity and port checks; a validated A7 readback; a live authorization. A semantic verifier and paired captures are still unbuilt         |
| `b147-storage-audit/b148-author-only-handoff.md`        | Not stated | Storage clean-up of three exact roots from the storage audit; not a gap run                 | Author-only plateau. Nothing was deleted, and no authorization record exists                                                  | Root and independent review of the cleanup source; a separate authorization record before any run                                                                                                                                    |
| `b150-export-cache-cleanup/b150-author-only-handoff.md` | Not stated | Storage clean-up of one export cache root; not a gap run                                    | Author-only plateau. Nothing was deleted, and no authorization record exists                                                  | A review that binds the cleanup source hash; a root-created authorization record; a fresh gate before invocation                                                                                                                     |
| `b154-old-runtime-retirement/handoff.md`                | 2026-11-15 | Retirement of four old runtime roots; not a gap run                                         | Preparation. Read-only inspection and small-artefact preservation only. No deletion is authorized                             | A parent review that binds the inventory and small-artefact hashes to a committed recovery packet; resolution of obsolete runbook commands; reconciliation of the owner census and the physical-space measurements before retirement |

_Table 3: Operator packets read on 2026-11-16, with the run each concerns, its
stated state and the next step it names._

The latest packet is `c179-wire-bootstrap/handoff.md`, named by Decision D26 in
the documentation reconciliation plan. For the next R06 capture it says that
the server must first be started through the GUI, using a wrapper that is still
proposed. That wrapper needs independent root review and an exact source pin
before any boot. The parent grants the known start-up sequence only after the
preceding boot succeeds, and the operator checks each fresh screenshot before
every input. The screenshots of the earlier R04 start-up are not coordinates
for R06 without a fresh capture. The packet records no protocol observation.

## Source disagreements

The following statements in the sources differ. They are recorded neutrally.
The register and the evidence decide the facts; this section does not.

- Audit revision. The [protocol handoff](protocol-handoff.md), line 7, says
  the current protocol audit is "revision 89". The
  [missing-target alias plan](records/missing-target-alias.md), line 6, says
  "audit88". The [gap analysis](../../gap-analysis.md), line 14, says "Revision
  90 follows", and its input snapshots are under `revision-91`.
  `gap-register.json`, lines 6 and 7, cite `revision-91`, and its `method` text
  at line 10 describes revision 90.
- Canonical mxd revision. The
  [mxd validation record](../mxd/validation-status.md), lines 10 and 94, says
  canonical mxd remains at `cb907885` and that no newer mxd changes have been
  imported. `gap-register.json` line 646 (GAP-011) names canonical mxd
  `48129491`. Line 4977 (GAP-085) names commits `50360beb` and `48129491`, and
  also "Canonical source cb907". Line 5043 (GAP-086) names mxd `48129491`.
- Location of the canonical protocol documents. The
  [protocol handoff](protocol-handoff.md), lines 9 and 10, says the canonical
  protocol documents are in a sibling `hotline-protocol-docs` checkout. This
  checkout is that repository and holds the documents. Decision D26, in
  `docs/execplans/documentation-reconcilliation.md`, lines 704 and 706, names
  `docs/protocol-handoff.md` and `docs/execplans/missing-target-alias.md` as
  mothra's files. Both are in this checkout.
- Missing-target alias status. The plan's header, lines 3 to 14, and its
  Progress checklist, lines 209 to 215, list M2b as the next step and M2, M3
  and M4 as open. The later revision notes, lines 1139 to 1219, record a
  stopped R04 preparation, a capacity recovery, a parent-checkpoint abort at
  lines 1186 to 1194, and a pre-authored R05 receipt operation at line 1207.
  The revision notes are undated, so the order of the R04 events is not stated.

## Per-gap detail

The subsections below give, for each gap in Table 1, what the register still
needs, what has been prepared, what blocks it, and where to start reading.
Quoted text is taken from the register.

### GAP-001

- **Still needed:** "Publish an operation-by-profile scope matrix with required,
  deferred and excluded states, including replies to unsupported operations."
  The progress text says that the original scope decision remains open, and
  that the delegated review selects no states.
- **Prepared:** [mxd reconciliation](../mxd/assertion-reconciliation.md) and
  [mxd validation](../mxd/validation-status.md).
- **Blocked by:** no `depends_on` entries. The owner is recorded as unassigned.
  The mxd work that informs it is on hold.
- **Pick up:** the section "Open compatibility gaps and QA requirements" of the
  [compatibility matrix](../mxd/compatibility-matrix.md), which the register
  cites.

### GAP-005

- **Still needed:** "Provide a timer/state table with units, reset conditions,
  configurable values and close outcomes, distinguishing native observations
  from mxd limits." The progress text records open items: lower-layer and
  configured timing, native clock and wake-cause questions, the online idle
  case beyond 600 seconds, and broader room and transfer cleanup. It also says
  that no hard 30-second deadline is claimed.
- **Prepared:** the
  [liveness preparation](../native-evidence/native-liveness-preparation.md) and
  its [liveness witness](../native-evidence/native-liveness-witness.md), which
  the register cites as accepted. The checkout holds no prepared packet for the
  online idle case.
- **Blocked by:** no `depends_on` entries.
- **Pick up:** the
  [liveness witness](../native-evidence/native-liveness-witness.md), then the
  section on selected-request and partial-input timing in
  [session transport contracts](../protocol/session-transport-contracts.md).

### GAP-011

- **Still needed:** "Document native comparisons/configuration and explicit mxd
  limits with inclusive boundaries, overflow checks and boundary fixtures." The
  progress text says that "No negative xref proves absence of later writes". It
  lists native later-write and configuration questions, aggregate buffering,
  global buffering bounds and a release policy as open.
- **Kind chosen by the scribe:** static analysis. The next step is the
  later-write trace. The 24 November trace identifies two stack outputs of the
  startup preferences loader and the following banned-list input. Native
  configuration capture remains outstanding.
- **Prepared:** [receive-limit origin](../protocol/receive-limit-origin.md),
  [mxd limit contracts](../mxd/corrections.md), and the framing corpus
  `evidence/gap-remediation/2026-11-12/native-framing-01/manifest.json`.
- **Blocked by:** no `depends_on` entries.
- **Pick up:** [receive-limit origin](../protocol/receive-limit-origin.md).

### GAP-016

- **Still needed:** "Add per-field presence/default tables and fixtures for all
  four cases, especially credentials, settings and partial account updates."
  The progress text records that independent review accepts the
  presence-default registry and "five explicit remaining fixture groups". The
  register does not list them; the registry does, numbered 1 to 5, under
  [Explicitly unmeasured cells](../presence-and-messaging/presence-defaults.md#explicitly-unmeasured-cells).
  They are: login and settings controls with one NUL and with zero widths;
  account-key and name cases for transactions 349 to 353; chat, private-message
  and kick text, option and target cases; invitation and room target, room and
  subject cases; and the numeric fields of the transfer and news requests.
- **Prepared:**
  [presence defaults](../presence-and-messaging/presence-defaults.md).
- **Blocked by:** no `depends_on` entries. GAP-072 depends on this gap.
- **Pick up:**
  [presence defaults](../presence-and-messaging/presence-defaults.md), sections
  "Credentials and session settings", "Account replacements and related lookup"
  and "Explicitly unmeasured cells".

### GAP-018

- **Still needed:** "Publish per-field byte/string rules with non-ASCII,
  embedded-NUL, CR/LF and complemented-credential fixtures from identified
  peers." The progress text says that "Byte preservation is not a general
  decoding or peer policy", and that the full historical peer and broader
  encoding requirements remain active.
- **Prepared:**
  [identified client source](../peers/identified-client-source.md), and the
  second full-peer corpus
  `evidence/gap-remediation/2026-11-13/native-shx-02/manifest.json`.
- **Blocked by:** no `depends_on` entries. GAP-082 depends on this gap.
- **Pick up:** [identified client source](../peers/identified-client-source.md),
  section "Full native peer acceptance matrix".

### GAP-019

- **Still needed:** "Record field-specific limits and units, max/max-plus-one
  behaviour and aggregate limits, preserving native versus mxd-policy
  distinctions." The progress text lists unmeasured cells, including a
  source-derived 1024-byte cap on the final 303 output, whose at-cap runtime
  clipping is unobserved.
- **Prepared:** the
  [diagnostic boundary preparation](../native-evidence/native-diagnostic-boundary-preparation.md),
  which is a proposal with no witness. Earlier evidence: the
  [near-boundary witness](../native-evidence/native-diagnostic-near-witness.md),
  whose capture failed overall, and the
  [diagnostic formatting trace](../protocol/diagnostic-formatting-trace.md).
- **Blocked by:** no `depends_on` entries. The proposed packet needs parent
  approval of a new isolated instance.
- **Pick up:** the diagnostic boundary preparation, section "Dedicated-session
  prerequisites and authority gate".

### GAP-020

- **Still needed:** "Trace each date producer/consumer and document epoch,
  timezone, units, range and conversion fixtures including rollover cases." The
  progress text says that the nominal 1904 seconds epoch is established by
  Apple API documentation, while guest timezone, alternate year, subsecond and
  rollover behaviour remain unmeasured.
- **Prepared:** [date contracts](../protocol/date-contracts.md) and the
  [native clock evidence](../native-evidence/native-clock-evidence.md).
- **Blocked by:** no `depends_on` entries. GAP-067 depends on this gap.
- **Pick up:** [date contracts](../protocol/date-contracts.md), section "What
  would settle conversion and rollover".

### GAP-021

- **Still needed:** "Specify completion points, post-ACK failure signalling,
  persistence and retry/idempotency rules per operation with
  disconnect-boundary fixtures." The progress text says that forced I/O
  interruption, lost ACK and restart durability remain unproved, and that no OS
  or power-loss durability has been measured.
- **Prepared:**
  [account write ordering](../accounts-and-privileges/account-write-ordering.md),
  and the live account and restart evidence in
  [native wire details](../protocol/native-wire-details.md).
- **Blocked by:** no open dependencies. GAP-003 and GAP-007 are Resolved.
- **Pick up:**
  [account write ordering](../accounts-and-privileges/account-write-ordering.md).

### GAP-026

- **Still needed:** "Define the value schemas, configuration sources and
  change/lifetime rules with sample configured/no-banner replies." The progress
  text says that the meaning of field 161, and its exhaustive change and
  lifetime semantics, remain unresolved. Direct-store discovery covers only the
  constructor store and the login load, not indexed, derived or aliased writes.
  A subsequent
  [read inventory](../../evidence/gap-remediation/2026-11-24/field161-readers-01/manifest.json)
  found the login load as the sole candidate among the displacement-based load
  forms checked. The startup path retains the constructor object in a global.
  The field meaning and possible indirect accesses remain open.
- **Kind chosen by the scribe:** static analysis, for the indexed, derived and
  aliased writes. Native capture of change and lifetime samples follows.
- **Prepared:** [classic field 161 matrix](../peers/classic-field161-matrix.md),
  [classic server-name 162 witness](../peers/classic-server-name-162.md), the
  [peer tolerance matrix](../peers/peer-tolerance-matrix.md), and the
  `all-direct-store-candidates.json` file in
  `evidence/gap-remediation/2026-11-13/native-login-extras-01/`.
- **Blocked by:** no `depends_on` entries.
- **Pick up:** [classic field 161 matrix](../peers/classic-field161-matrix.md).

### GAP-031

- **Still needed:** "Publish a 64-bit MSB-first registry with per-bit evidence,
  unknown/reserved distinctions and serialization/enforcement fixtures." The
  progress text says that 27 positions are explicitly unknown, and that no
  label-to-bit map has been inferred. It also says that a round trip "is not
  proof that unknown bits are reserved or ignored".
- **Kind chosen by the scribe:** static analysis of the Classic client, which
  the progress text bounds but does not complete. Native enforcement fixtures
  for unknown bits follow.
- **Prepared:** [privilege bits](../accounts-and-privileges/privilege-bits.md),
  [privilege contracts](../accounts-and-privileges/privilege-contracts.md) and
  [Classic privilege discovery](../accounts-and-privileges/classic-privilege-discovery.md).
- **Blocked by:** no `depends_on` entries. GAP-032, which is Resolved, depends
  on this gap.
- **Pick up:** [privilege bits](../accounts-and-privileges/privilege-bits.md).

### GAP-033

- **Still needed:** "Provide a domain-specific identifier registry with
  allocation/reuse rules and stale-ID/wrap fixtures." The progress text records
  the 16-bit user counter and the room allocator as recovered. Transfer and
  transaction domains are documented separately. User, room and reference reuse
  and wrap lifetimes remain open.
- **Prepared:**
  the
  [session transport contracts](../protocol/session-transport-contracts.md), the
  [core field schemas](../protocol/core-field-schemas.md) and
  [presence and messaging](../presence-and-messaging/presence-messaging-contracts.md).
- **Blocked by:** no open dependencies. GAP-036 depends on this gap.
- **Pick up:**
  [presence and messaging](../presence-and-messaging/presence-messaging-contracts.md),
  section "Captured private rooms, invitations and chat bytes".

### GAP-036

- **Still needed:** "Trace normal EOF, timeout, kick and failure teardown, then
  document and fixture 302 and associated room/transfer cleanup ordering." The
  progress text records an identified 302 producer, account deletion captures
  and a finite liveness capture. It states that the online idle case beyond 600
  seconds and broader room and transfer cleanup are not covered. Its earlier
  sentence still lists kick and timeout traces as required.
- **Prepared:** the
  [liveness preparation](../native-evidence/native-liveness-preparation.md) and
  the [liveness witness](../native-evidence/native-liveness-witness.md).
- **Blocked by:** GAP-033, which is Investigating. GAP-035 is Resolved.
- **Pick up:**
  [liveness witness](../native-evidence/native-liveness-witness.md).

### GAP-045

- **Still needed:** "Trace per-operation limits/configuration and publish
  bounded timing/rate fixtures plus explicit mxd policy where parity is
  intentionally different." The progress text says that "This does not
  establish a calibrated native 60-second boundary, ban expiry, persistence,
  full transfer health or other flood limits." The corrected observer-UID
  control is prepared offline and has not run.
- **Prepared:** the
  [rate 304 preparation](../native-evidence/native-rate304-preparation.md), the
  [measured 304 sequence](../native-evidence/native-rate304-sequence.md),
  the [failed first pair](../native-evidence/native-rate304-first-pair.md), the
  [startup gate witness](../native-evidence/native-rate304-startup-gate.md)
  and the [rate 304 contract](../presence-and-messaging/rate304-contract.md).
- **Blocked by:** no `depends_on` entries. A lab needs a new runtime and a
  separately reviewed packet.
- **Pick up:** the
  [rate 304 preparation](../native-evidence/native-rate304-preparation.md),
  section "Prepared scope".

### GAP-050

- **Still needed:** "Trace deletion helpers and define permission, recursion,
  failure/atomicity and refresh outcomes with controlled fixtures." The
  progress text says that "No safe post-mutation failure stimulus has been
  established." Files-root and protected-target deletes, and controlled partial
  failure, remain outstanding.
- **Kind chosen by the scribe:** static analysis, to find a safe failure
  stimulus. Native capture follows it.
- **Prepared:**
  [filesystem and board contracts](../files-and-transfers/filesystem-and-board-contracts.md),
  and the remaining-leaf audit
  `evidence/gap-remediation/2026-11-14/remaining-leaf-audits-01/manifest.json`.
- **Blocked by:** no open dependencies. GAP-032 and GAP-047 are Resolved.
- **Pick up:**
  [filesystem and board contracts](../files-and-transfers/filesystem-and-board-contracts.md),
  section "Captured move and Trash outcomes".

### GAP-053

- **Still needed:** "Document resolver and move outcomes, including
  same-location, collision and partial-failure fixtures; bound any
  platform-specific semantics." The progress text says that "Actual other
  volume and interrupted I/O/partial-failure acceptance remains unexecuted."
- **Prepared:**
  [filesystem and board contracts](../files-and-transfers/filesystem-and-board-contracts.md),
  section "Captured move and Trash outcomes", and the native move corpus
  `evidence/gap-remediation/2026-11-13/native-move-01/manifest.json`.
- **Blocked by:** no open dependencies. GAP-047 is Resolved.
- **Pick up:**
  [filesystem and board contracts](../files-and-transfers/filesystem-and-board-contracts.md).

### GAP-054

- **Still needed:** "a genuine missing-target response and its complete
  provenance remain required", as the closure text states. The live and chain
  cases, and the target-in-Trash case, are captured. The positive M2 result has
  not been obtained, the M3 absence test has not run, and the M4 corpus does
  not exist.
- **Prepared:** the
  [missing-target alias preparation](../native-evidence/native-missing-alias-preparation.md),
  the [alias plan](records/missing-target-alias.md), and the R04 abort corpus
  `evidence/gap-remediation/2026-11-14/native-alias-prestage-abort-02/manifest.json`.
- **Blocked by:** no open dependencies. GAP-047 and GAP-049 are Resolved. Each
  step needs its own root approval under the plan's gates.
- **Pick up:** the [alias plan](records/missing-target-alias.md). Read its
  Progress checklist together with the revision notes at its end, because the
  two disagree (see Source disagreements).

### GAP-064

- **Still needed:** "Define completion and interruption outcomes per direction,
  including large-size representation and partial-file retention, with
  controlled failure fixtures." The progress text lists disk-full, large-size,
  restart durability and the remaining interruption states as required. The
  [transfer stall record](../files-and-transfers/native-transfer-stall.md)
  describes a full download that stopped at the same 98,304-byte prefix in the
  second and third disposable labs. Its cause is recorded as unknown.
- **Prepared:** the
  [transfer stall record](../files-and-transfers/native-transfer-stall.md), the
  [focus event witness](../native-evidence/native-ui-focus-witness.md),
  and
  [diagnostic transfer boundaries](../protocol/diagnostic-transfer-boundaries.md).
- **Blocked by:** the stall cause is unknown. No `depends_on` entry is open;
  GAP-055 and GAP-056 are Resolved.
- **Pick up:**
  [native transfer stall](../files-and-transfers/native-transfer-stall.md).

### GAP-067

- **Still needed:** "Document navigation graphs, flavour selection/errors and
  news-date conversion using branching-thread, absent-body and boundary
  fixtures." The progress text says that the 100-sibling, 30-flavour and
  date-boundary cases remain open. It notes that the 100-link search helper
  bypasses public ID 102.
- **Prepared:** [news contracts](../news/news-contracts.md).
- **Blocked by:** GAP-020, which is Investigating. GAP-066 is Resolved.
- **Pick up:** [news contracts](../news/news-contracts.md), section "Reading
  bodies and navigation".

### GAP-068

- **Still needed:** "Publish post field/default and flag tables plus
  discovery/notification/persistence behaviour for new threads, replies and
  invalid requests." The progress text says that polling no longer exposes
  every allocated ID, because ID 102 is still readable but is omitted from the
  listing. The meaning of the flags, partial failures and persistence remain
  open.
- **Prepared:** [news contracts](../news/news-contracts.md) and the news corpora
  under `evidence/gap-remediation/2026-11-13/`.
- **Blocked by:** GAP-018 and GAP-067, both Investigating.
- **Pick up:** [news contracts](../news/news-contracts.md).

### GAP-070

- **Still needed:** "Publish object/path grammars and 380/381/382
  permission/conflict/recursive-effect tables with nested and failure
  fixtures." The progress text says that alias and root variants, and
  interrupted or partial category writes, remain active.
- **Prepared:** [news contracts](../news/news-contracts.md), section "Structure
  operation effects and conflicts".
- **Blocked by:** no open dependencies. GAP-032, GAP-047 and GAP-065 are
  Resolved.
- **Pick up:** [news contracts](../news/news-contracts.md).

### GAP-071

- **Still needed:** "Trace reads/storage/use of 111 and add an account field
  schema with absent, empty and representative-value fixtures." Absent, empty
  and value updates have been captured, and field 111 is omitted from the 352
  outputs. The progress text says that the human meaning, and any later reads
  or use, remain unresolved. The consumer audits found a whole-record
  preservation consumer, not a field-specific semantic read.
- **Kind chosen by the scribe:** static analysis of the consumers. The progress
  text leaves that work as the open step.
- **Prepared:**
  [account attribute trace](../accounts-and-privileges/account-attribute-trace.md),
  the
  [classic account constructors](../accounts-and-privileges/classic-account-constructors.md),
  and the alias trace
  `evidence/gap-remediation/2026-11-14/account111-alias-trace-01/manifest.json`.
- **Blocked by:** no open dependencies. GAP-072 depends on this gap.
- **Pick up:**
  [account attribute trace](../accounts-and-privileges/account-attribute-trace.md).

### GAP-072

- **Still needed:** "Define 350-353 mutation/default/atomicity rules with
  existing-password preservation, literal-x, rename/conflict and
  protected-delete fixtures." The progress text lists rename and conflict,
  protected and self deletion, and forced storage failures as remaining.
  Built-in identities are untested.
- **Prepared:** [native wire details](../protocol/native-wire-details.md),
  section "Captured account replacement and password boundaries", and
  [operation contracts](../protocol/operation-contracts.md).
- **Blocked by:** GAP-016 and GAP-071, both Investigating. GAP-022 is Resolved.
- **Pick up:** [native wire details](../protocol/native-wire-details.md).

### GAP-082

- **Still needed:** "Document the policy decision and exact state/field rules
  with an ambiguity corpus; validate interoperability independently of named
  heuristic tests." The progress text says that the existing mxd heuristic is
  "a distinct policy requiring ambiguity corpus and full interoperability
  evidence".
- **Prepared:** [peer tolerance matrix](../peers/peer-tolerance-matrix.md), and
  the credential obfuscation section of the
  [compatibility matrix](../mxd/compatibility-matrix.md).
- **Blocked by:** GAP-018, which is Investigating. GAP-080 is Resolved.
- **Pick up:** [compatibility matrix](../mxd/compatibility-matrix.md),
  section "Credential obfuscation and text compatibility".

### GAP-085

- **Still needed:** "Record checkout/revision, reviewed assertions, commands and
  outputs; fix or retire stale expectations and map passing cases to protocol
  requirements." The progress text says that the disputed classifier and
  login-extra expectations still pass and require implementation
  reconciliation. The mxd work is on hold.
- **Kind chosen by the scribe:** mxd validation. The register's `kind` is
  "Evidence", which describes the gap rather than the work.
- **Prepared:** [mxd reconciliation](../mxd/assertion-reconciliation.md),
  [mxd limit contracts](../mxd/corrections.md), and the frozen mxd source
  evidence `evidence/gap-remediation/2026-11-13/delegated-mxd-01/manifest.json`.
- **Blocked by:** GAP-001, which is Open.
- **Pick up:** [mxd validation](../mxd/validation-status.md), section
  "Repeatability and deferred validation", item 3.

### GAP-086

- **Still needed:** "Publish current sign-off criteria and owners at an
  identified revision, including deferred gaps and the scope/results of any
  Kani claims." The progress text says that Kani was not run, and that no
  release owner, subset, deferred-gap rule or proof result has been invented.
- **Prepared:** [compatibility matrix](../mxd/compatibility-matrix.md),
  section "Scope and status labels"; the
  [baseline correction map](baseline-correction-map.md); and
  [mxd validation](../mxd/validation-status.md).
- **Blocked by:** GAP-001 and GAP-085. GAP-080 and GAP-084 are Resolved.
- **Pick up:** [mxd validation](../mxd/validation-status.md), section
  "Repeatability and deferred validation", item 5.
