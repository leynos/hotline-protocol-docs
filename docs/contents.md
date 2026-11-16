# Documentation contents

This is the index for the Hotline 1.9 protocol documentation. Each Markdown
document under `docs/` appears once, with a line on why a reader would open it.
The [project README](../README.md) explains how the document sets relate.
Execution plans live in `docs/execplans/` and are not indexed here.

## At the repository root

- [Project README](../README.md): the entry point, with the reader journeys, the
  document sets and the checks to run.
- [Agent instructions](../AGENTS.md): the rules for contributors and agents,
  including the rules that protect the evidence.
- [Gap analysis](../gap-analysis.md): the report generated from the gap
  register, reviewed against the current audit revision.
- [Gap register](../gap-register.json): the canonical list of open questions,
  each tied to the document sections that raise it.

## Repository documents

- [Glossary](glossary.md): the terms the protocol documents use, each with the
  document that is authoritative for it.
- [Reconciliation log](reconciliation-log.md): every discrepancy found when the
  documents were reconciled, with its disposition and the questions that only
  the owner or new evidence can settle.
- [Repository layout](repository-layout.md): where each path lives, what it
  holds, who maintains it, and where each document was moved from.
- [Developers' guide](developers-guide.md): how to change a document, add
  evidence or change a script or tool, and which gates protect each.
- [Documentation style guide](documentation-style-guide.md): the conventions
  every document follows, copied verbatim from upstream and not edited here.
- [Baseline validity ledger](baseline-validity-ledger.md): the first static
  baseline, recording which claims the native server binary supports,
  contradicts or leaves unverified, with the corrections and open questions it
  records.

## Protocol

The Hotline 1.9 protocol as documented from the [native](glossary.md#native)
server: the baseline guide, and the registries and contracts that refine it,
including each [gap](glossary.md#gap) the evidence leaves open.

- [Protocol overview](protocol/README.md): what the set covers and how its
  documents relate.
- [Protocol guide](protocol/protocol.md): the baseline guide to Hotline 1.9
  transactions, based on observed behaviour of the native server, with explicit
  gaps where the evidence is incomplete.
- [Operation contracts](protocol/operation-contracts.md): the catalogue of the
  45 explicit client-request handlers, with directions, session rules and
  notifications.
- [Core field schemas](protocol/core-field-schemas.md): field schemas for
  session, settings, roster, chat, private message and room operations.
- [Native wire details](protocol/native-wire-details.md): static analysis of the
  native server binary that refines the baseline, including parameter parsing
  and scalar access.
- [Parameter multiplicity](protocol/parameter-multiplicity.md): the canonical
  rule for which parameters may repeat, and in what order, for the native
  server.
- [Session and transport contracts](protocol/session-transport-contracts.md):
  configured endpoints, identifier allocation and captured handshake boundaries.
- [Error outcomes](protocol/error-outcomes.md): the registry of wire status and
  failure classes, drawn from the direct callers of the native reply-error
  setter.
- [Failure representatives](protocol/failure-representatives.md): one retained
  request and its measured result for each of five failure classes.
- [Request 500](protocol/request-500-contract.md): when the native server
  dispatches request 500, and the empty direct success reply it sends.
- [Date contracts](protocol/date-contracts.md): the eight-byte date form on the
  wire, the clock values that feed it, and the clock boundaries.
- [Receive-limit origin](protocol/receive-limit-origin.md): a bounded GAP-011
  note on where the native receive limit originates, from read-only queries.
- [Bitmap boundaries](protocol/bitmap-boundaries.md): a 13-capture corpus that
  tests privilege bitmap replacement and width on field 110.
- [Diagnostic replies](protocol/diagnostic-replies.md): five measured exchanges
  of transaction 303 diagnostics from a Mac OS 9 native server.
- [Diagnostic formatting trace](protocol/diagnostic-formatting-trace.md): how
  the 303 diagnostic text is formatted and how its length is written to field
  101.
- [Diagnostic transfer boundaries](protocol/diagnostic-transfer-boundaries.md):
  a failed attempt to capture a 303 reply during an active transfer, and what
  it does not supply.
- [Evidence index](protocol/evidence.md): the corpora, ledger identifiers and
  gap identifiers that the protocol documents cite, with the documents that
  cite each.

## Presence and messaging

Presence, notifications, messages and the rate-304 settings path.

- [Presence and messaging overview](presence-and-messaging/README.md): what the
  set covers and how its documents relate.
- [Presence defaults](presence-and-messaging/presence-defaults.md): a context
  table of field presence and defaults for presence and messaging fields; it
  does not close GAP-016.
- [Presence and messaging contracts](presence-and-messaging/presence-messaging-contracts.md):
  settings, login visibility, send order and administration observations.
- [Type-104 producer matrix](presence-and-messaging/native-104-variants.md): the
  producers of type-104 notifications and the field sets each one cites, from
  source and captures.
- [Type-104 notification variants](presence-and-messaging/notification-104-variants.md):
  the payload grammars of type-104 notifications, separating each traced
  producer from what a receiver can distinguish.
- [Temporary ban notice](presence-and-messaging/native-ban-notices.md): a
  bounded observation of the option-one ban notice; expiry and reload remain
  open.
- [Console broadcast](presence-and-messaging/native-console-broadcast.md): one
  controlled guest session of a console broadcast, with its corpus and
  connections.
- [Rate 304 source prediction](presence-and-messaging/rate304-contract.md): a
  source prediction of the settings rate path, to be compared with the later
  native sequence.
- [Rate 304 recipient predicates](presence-and-messaging/rate304-recipient-predicate.md):
  a static reading of the recipient predicates for rate-304 notifications, from
  the frozen source corpus.
- [Evidence index](presence-and-messaging/evidence.md): the corpora, ledger
  identifiers and gap identifiers that the presence and messaging documents
  cite, with the documents that cite each.

## Accounts and privileges

- [Accounts and privileges overview](accounts-and-privileges/README.md): what
  the set covers and how its documents relate.
- [Account attribute trace](accounts-and-privileges/account-attribute-trace.md):
  the stored record of account field 111 and its consumers, traced by read-only
  queries.
- [Account write ordering](accounts-and-privileges/account-write-ordering.md):
  the direct account writer in the native binary; no failed-write fixture was
  run.
- [Classic account constructors](accounts-and-privileges/classic-account-constructors.md):
  a read-only trace of how the identified Classic client builds account
  requests.
- [Classic privilege discovery](accounts-and-privileges/classic-privilege-discovery.md):
  defined strings found in one import of the Classic client's privilege editor.
- [Native ban file format](accounts-and-privileges/native-ban-file-format.md):
  the observed v2 layout of the `Banned` data fork, from three stopped images
  and the reader, writer and constructor.
- [Configured ban application](accounts-and-privileges/native-configured-ban-static.md):
  static [preparation](glossary.md#preparation) that narrows the remaining
  type-104 producer; not a network fixture.
- [Configured-ban Options resources](accounts-and-privileges/native-configured-ban-ui-resources.md):
  reconnaissance of the native resource fork for the configured-ban Options,
  read without starting a guest.
- [Privilege bits](accounts-and-privileges/privilege-bits.md): the per-bit
  index of the access bitmap, linking source uses and native controls.
- [Privilege contracts](accounts-and-privileges/privilege-contracts.md): the
  privilege registry and how its bits compose, from a review of the three
  privilege accessors.
- [Evidence index](accounts-and-privileges/evidence.md): the corpora, ledger
  identifiers and gap identifiers that the accounts and privileges documents
  cite, with the documents that cite each.

## Files and transfers

- [Files and transfers overview](files-and-transfers/README.md): what the set
  covers and how its documents relate.
- [Alias record v2](files-and-transfers/alias-record-v2.md): the decoder for an
  extracted AliasRecord payload; it resolves no target.
- [Filesystem and board contracts](files-and-transfers/filesystem-and-board-contracts.md):
  file-info target kinds, native Toolbox calls and legacy-board operations,
  from preserved handlers.
- [Download send path](files-and-transfers/native-download-send-path.md): a
  static trace of request 202 into an attached ordinary download; it does not
  explain the 98,304-byte prefix.
- [Structured path fields](files-and-transfers/native-path-fields.md): one
  disposable run for fields 212 and 325, with an offline verifier.
- [Transfer stall](files-and-transfers/native-transfer-stall.md): a failed lab
  baseline in which a 1,049,073-byte transfer stalled; it cannot count as a ban
  result.
- [Transfer contracts](files-and-transfers/transfer-contracts.md): refinements
  of the transfer gaps, from request and acceptor captures and ordinary-file
  sessions.
- [Evidence index](files-and-transfers/evidence.md): the corpora, ledger
  identifiers and gap identifiers that the files and transfers documents cite,
  with the documents that cite each.

## News

- [News overview](news/README.md): what the set covers and how its documents
  relate.
- [Legacy board format](news/legacy-board-format.md): bytes recovered
  statically from the pinned native binary; not a captured board post.
- [News contracts](news/news-contracts.md): static and captured findings on
  nested news categories and articles; unknown words remain opaque.
- [Evidence index](news/evidence.md): the corpora, ledger identifiers and gap
  identifiers that the news documents cite, with the documents that cite each.

## Peers

The identified [Classic client](glossary.md#classic-client) and shx peers, the
Classic login proxy, and the field-tolerance evidence for each.

- [Peers overview](peers/README.md): what the set covers and how its documents
  relate.
- [Peer profile rules](peers/peer-profile-rules.md): the two identified builds
  used as interoperability targets, and the rule for an unknown peer.
- [Identified shx source profile](peers/identified-client-source.md): a retained
  source snapshot of the historical shx client, and bounded callback results.
- [Historical shx peer](peers/shx-peer.md): how the historical shx 0.1.48
  source was built, and the profile recorded for that build.
- [shx field tolerance](peers/peer-tolerance-matrix.md): a controlled matrix of
  field tolerance for one complete terminal shx 0.1.48 build.
- [HOPE extensions](peers/hope-extensions.md): the unofficial HOPE login,
  cipher and compression extension, as read from SynHX and GtkHx source.
- [Classic login proxy](peers/classic-login-proxy.md): the protocol-specific
  proxy used to vary field 161 in Login107 acknowledgements.
- [Classic native baseline](peers/classic-native-baseline.md): two attempts at a
  baseline session through the proxy, whose acknowledgement matched the native
  one.
- [Classic field-161 matrix](peers/classic-field161-matrix.md): three local
  sessions through the proxy, comparing field-161 widths and omissions.
- [Classic roster with field 115](peers/classic-roster-subject-115.md): one
  controlled observation of a roster reply that carries field 115.
- [Classic server name field 162](peers/classic-server-name-162.md): one
  controlled field-162 modification, and the client's acceptance of it.
- [First Classic Mac session](peers/mac-peer-first-session.md): wire
  observations from one manual connection by a Classic Mac candidate client.
- [Isolated Classic session](peers/mac-peer-isolated-session.md): one
  controlled login by the archived Classic candidate, in a loopback-only
  network namespace.
- [Evidence index](peers/evidence.md): the corpora, ledger identifiers and gap
  identifiers that the peers documents cite, with the documents that cite each.

## mxd validation

The [mxd](glossary.md#mxd) set records how the mxd server has been checked
against the protocol documents, what was corrected, and where the work stopped.

- [mxd validation overview](mxd/README.md): the scope and pinned revisions of
  the set, and the state of the work.
- [Validation status](mxd/validation-status.md): what has been validated, at
  which revisions, with which results, and what remains.
- [Compatibility matrix](mxd/compatibility-matrix.md): native behaviour, SynHX
  and identified client evidence, and mxd policy, compared item by item.
- [Assertion reconciliation](mxd/assertion-reconciliation.md): the mxd test
  assertions reviewed against the corrected baseline.
- [Accepted corrections](mxd/corrections.md): the three corrections accepted in
  mxd, covering framing limits, direct replies and login extras.
- [Classic client trials](mxd/classic-client-trials.md): two Classic client
  trials against an isolated fixture, their limits, and how a trial is run.
- [Evidence index](mxd/evidence.md): the corpora, ledger identifiers and gap
  identifiers that the documents of this set cite. Generated.

## Native evidence

[Preparations](glossary.md#preparation) set out a run, and
[witnesses](glossary.md#witness) record one that was executed. This set holds
both for the native server, with the guide to recreating the evidence.

- [Native evidence overview](native-evidence/README.md): what the set covers
  and how the preparations and witnesses relate.
- [Recreating the evidence](native-evidence/recreating-evidence.md): how each
  retained corpus was produced, how to re-verify it offline, and how to produce
  it again where the sources allow.
- [Capture workflow](native-evidence/native-capture-workflow.md): how native
  protocol captures are reproduced, and what needs the Mac application and
  emulator.
- [Clock and log source](native-evidence/native-clock-evidence.md): source
  provenance for the native clock path, from read-only queries and one retained
  screenshot.
- [Runtime recovery, 13 November 2026](native-evidence/runtime-recovery-20261113.md):
  restoring a native oracle after a host restart, with guest writes kept to a
  new image.
- [Delayed 121 default preparation](native-evidence/native-121-default-preparation.md):
  the offline route and fixture plan for the A37 observation.
- [Delayed 121 default witness](native-evidence/native-121-default-witness.md):
  one 70-action, two-case delayed agreement observation between full readbacks.
- [Permanent-ban control preparation](native-evidence/native-ban-control-preparation.md):
  the fixture plan that the C56 permanent-ban witness exercised.
- [Permanent-ban control witness](native-evidence/native-ban-control-witness.md):
  one option-two ban in a disposable lab; the full-file baseline was not
  exercised.
- [Temporary-ban expiry preparation](native-evidence/native-ban-expiry-preparation.md):
  a plan for a separately authorized control-only run; no expiry result is
  claimed.
- [Temporary-ban expiry cleanup](native-evidence/native-ban-expiry-cleanup.md):
  the cleanup stage that restores the owned accounts after the final probe.
- [Temporary-ban first epoch](native-evidence/native-ban-expiry-first-witness.md):
  a control-only record of the first epoch; it does not establish the expiry
  boundary.
- [Temporary-ban later epoch](native-evidence/native-ban-expiry-later-witness.md):
  a control-only witness of a later epoch on the same disposable server.
- [Persisted-ban reload](native-evidence/native-ban-reload-witness.md): one
  read-only restart observation of the image that held the option-two control
  ban.
- [Message-board preparation](native-evidence/native-board-preparation.md): a
  plan for the 101, 102 and 103 board case, which it does not run.
- [Message-board witness](native-evidence/native-board-witness.md): a finite
  isolated fixture that exercises the board requests and their size boundaries.
- [Message-board readiness failure](native-evidence/native-board-readiness-failure.md):
  a board lab that stopped at its readiness control after the server had opened
  its listener.
- [Configured-address ban preparation](native-evidence/native-configured-ban-preparation.md):
  a packet for one Options, Ban and Save observation; it boots no lab.
- [Configured-address ban witness](native-evidence/native-configured-ban-witness.md):
  a control-only fixture observing the connected-client notice when an address
  is banned.
- [Control readiness](native-evidence/native-control-readiness.md): the profile
  for a separately authorized control-operation fixture on an owned disposable
  server.
- [Diagnostic boundary preparation](native-evidence/native-diagnostic-boundary-preparation.md):
  a proposal for one finite diagnostic cell of GAP-019; it authorizes no action.
- [Existing-file diagnostic preparation](native-evidence/native-diagnostic-existing-preparation.md):
  the prepared A8 packet for diagnostics with existing downloads.
- [Existing-file diagnostic witness](native-evidence/native-diagnostic-existing-witness.md):
  the A8 phase-1 witness, with one active and one waiting download.
- [Diagnostic density witness](native-evidence/native-diagnostic-density-witness.md):
  one fixed density capture of transaction 303 with existing downloads (A9).
- [Near-boundary diagnostic preparation](native-evidence/native-diagnostic-near-preparation.md):
  a prepared A11 packet, not run, that predicts a field-101 length close to
  1,024 bytes.
- [Near-boundary diagnostic witness](native-evidence/native-diagnostic-near-witness.md):
  a failed A12 capture that recorded two successful 303 replies before it
  failed.
- [Preonline liveness preparation](native-evidence/native-liveness-preparation.md):
  a prepared control-only fixture for GAP-005 and GAP-036, not yet run against
  the Mac server.
- [Preonline liveness witness](native-evidence/native-liveness-witness.md): one
  finite lab run of preonline connections against an isolated server.
- [Missing-target alias preparation](native-evidence/native-missing-alias-preparation.md):
  the positive rehearsal (M2) for a missing-target alias.
- [Path-field preparation](native-evidence/native-path-fields-preparation.md):
  the matrix preparation for the twelve-case run, whose result is in the files
  and transfers set.
- [Private-message preparation](native-evidence/native-pm-preparation.md): the
  offline fixture preparation for two named admin sessions (A26).
- [Private-message witness](native-evidence/native-pm-witness.md): one
  seven-request 108 sequence between two admin sessions (A29).
- [Rate 304 preparation](native-evidence/native-rate304-preparation.md): an
  offline-prepared observer control for the rate and reset tests, not yet run
  against native 1.9.
- [Rate 304 sequence](native-evidence/native-rate304-sequence.md): a
  disposable-server run with a failed coordinator report, after measured rate
  observations.
- [Rate 304 first pair](native-evidence/native-rate304-first-pair.md): a failed
  fixture, retained to bound the next rate and reset test.
- [Rate 304 startup gate](native-evidence/native-rate304-startup-gate.md): a
  lab run that stopped before protocol contact at its startup gate.
- [Roster overlap preparation](native-evidence/native-roster-overlap-preparation.md):
  a control-only case preparation for GAP-035 that neither boots a guest nor
  sends traffic.
- [Roster overlap witness](native-evidence/native-roster-overlap-witness.md):
  one outstanding roster request observed while another session renamed itself.
- [Settings field 113 preparation](native-evidence/native-settings-preparation.md):
  the packet defining the GAP-015, GAP-016 and GAP-017 case for transaction 304.
- [Settings field 113 witness](native-evidence/native-settings-witness.md): one
  bounded live matrix for transaction 304, field 113.
- [Same-session 304 transition preparation](native-evidence/native-settings-transition-prep.md):
  the offline preparation for the A33 transition witness.
- [Same-session 304 transition witness](native-evidence/native-settings-transition-witness.md):
  one eight-stage transaction 304 sequence between full readbacks.
- [Settings persistence preparation](native-evidence/native-settings-persistence-preparation.md):
  the preparation for the A46 and A48 runs, which used one private working
  image.
- [Settings persistence witness](native-evidence/native-settings-persistence-witness.md):
  a bounded before-and-after restart test for settings persistence.
- [Download stall focus event](native-evidence/native-ui-focus-witness.md): one
  failed 29-action readback of a stalled download, with its timeout and partial
  transfer.
- [Evidence index](native-evidence/evidence.md): the corpora, ledger
  identifiers and gap identifiers that the native evidence documents cite, with
  the documents that cite each.

## Provenance

- [Provenance overview](provenance/README.md): the evidence baseline, the
  handoff and the working records, and where each is kept.
- [Evidence portability](provenance/evidence-portability.md): the packaging
  procedure that makes the sibling mothra references reproducible (GAP-087).
- [Baseline correction map](provenance/baseline-correction-map.md): how the
  12 November 2026 validity ledger is applied to the protocol guide and the
  compatibility matrix.
- [Protocol documentation handoff](provenance/protocol-handoff.md): a note of
  15 November 2026 that pauses the work and records the audit state for
  resumption.
- [Remaining evidence work](provenance/remaining-evidence-work.md): the ledger
  of evidence capture that remains, with detail for each open gap; the register
  governs where they differ.
- [Evidence index](provenance/evidence.md): the corpora, ledger identifiers and
  gap identifiers that the provenance documents cite, with the documents that
  cite each.

## Provenance records

Working records of individual runs, kept under `docs/provenance/records/`.

- [Missing-target alias](provenance/records/missing-target-alias.md): a retired
  attempt to observe a genuinely missing alias target; no protocol request ran.
- [Classic proxy rehearsal](provenance/records/classic-proxy-rehearsal.md): one
  synthetic proxy rehearsal and two Classic attempts that never opened a
  connection.
- [Mac client candidate](provenance/records/mac-peer-candidate.md): the static
  identity of an acquired Mac client candidate, which was not launched or
  connected.
- [mxd peer runtime](provenance/records/mxd-peer-runtime.md): one isolated mxd
  listener prepared, started and stopped for a Classic client capture.
