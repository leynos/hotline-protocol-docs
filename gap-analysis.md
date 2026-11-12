# Hotline 1.9 protocol documentation gap analysis

Reviewed on 2026-11-12: the corrected protocol guide, compatibility matrix and
correction map. This register tracks gaps in the specification after the
validity-ledger corrections. It does not reopen corrected findings or claim to
resolve the remaining unknowns.

The sweep records **87 gaps** across **128 reviewed document sections**. These
are documentation questions and proposed investigation priorities, not
confirmed binary defects, security severity ratings or mxd test failures.

## Scope, evidence and status

Documentation review plus read-only Ghidra MCP follow-up against the recorded
Hotline 1.9 data fork, and revision-specific mxd source/test review (55
focused tests passed). The original audit and validity ledger remain
immutable; current sources have been reviewed and re-snapshotted. No native
runtime/client captures or Kani proof results are claimed. Entries remain
Investigating while their acceptance criteria are unmet.

The corrected documents deliberately contain unresolved statements. Unanswered
entries refine those into actionable questions. Missing and Ambiguous entries
record omissions or under-specified requirements found by this sweep. Evidence
entries need independent peer/runtime or mxd results; Decision entries need an
explicit scope or compatibility policy.

The prior oracle is the Mac PPC PEF data fork with SHA-256
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`. The
[validity ledger](../mothra/docs/baseline-validity-ledger.md) and its hashed
snapshots are unchanged. Listed Ghidra functions are investigation leads from
that baseline. Dispositions cite subsequent evidence where available.

The initial audit had all entries Open and unassigned. Deferred means a
recorded scope/policy decision, not a solved protocol question. Resolved
requires cited evidence, the corrected documentation and a checked closure
criterion. A correction-map disposition or a function capture alone does not
close a gap.

### Priority meanings

| Priority | Meaning |
| --- | --- |
| P0 | Core codec, session/login or baseline-fixture work needed before claiming a usable core contract. |
| P1 | Blocks completion of the named feature or a cross-cutting compatibility policy if that feature is in scope. |
| P2 | Secondary operation semantics, evidence portability, peer coverage or project QA that still needs a recorded decision/result. |

These priorities are recommendations. GAP-001 and GAP-086 must establish the
actual supported subset and release criteria; this audit does not invent mxd
roadmap commitments. Client window rendering, tracker behaviour and HTTP
tunnelling remain outside the stated wire-guide scope and are not counted as
missing mandatory functionality.

### Counts

| Dimension | Counts |
| --- | --- |
| Priority | P0: 20, P1: 56, P2: 11 |
| Kind | Ambiguous: 10, Decision: 3, Evidence: 5, Missing: 12, Unanswered: 57 |
| Status | Investigating: 73, Open: 11, Resolved: 3 |

## Suggested investigation order

Begin with core field schemas, framing/error/ID rules, nonempty-password
encoding and the complete login state machine (GAP-002–GAP-025). Build
provenanced native session fixtures alongside that work (GAP-084). Then
complete presence/permission/message contracts, followed by the in-scope file,
transfer, news and administration schemas. Peer-corpus identification
(GAP-080) and verification of mxd claims (GAP-085) can proceed independently.
Dependency links identify shared prerequisite artefacts; they do not imply the
unknown question has already been answered.

## Input provenance

Audit captured at `2026-11-12T14:29:28.717785+00:00`. The source checkout has
Git HEAD `d3b455ced23d814bf3accc78012cc7b49ef9eb8b` with modified/untracked
reviewed files. The hashes below identify the actual reviewed worktree
contents; HEAD alone does not. Source line ranges in entries refer to the
frozen snapshots, while section links point to the current documents.

| Reviewed input | SHA-256 | Frozen copy |
| --- | --- | --- |
| [protocol.md](protocol.md) | `27bdb25cd68c69a98acfa25651221ebee41f75a251bd95fb15160c212269fc95` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-12/revision-06/inputs/protocol.md.txt) |
| [internal-compatibility-matrix.md](internal-compatibility-matrix.md) | `e301db771babc2de1912a55e535da89cdb356e6c48451738de138c6a47f5926c` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-12/revision-06/inputs/internal-compatibility-matrix.md.txt) |
| [baseline-correction-map.md](baseline-correction-map.md) | `a92254a423773367c1b1e35421bf4718c165f957031f371e55b486cdcb648c30` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-12/revision-06/inputs/baseline-correction-map.md.txt) |
| [native-wire-details.md](native-wire-details.md) | `e80a9b0d883f04eec35f1188d7ec433265d6145fe554a061dc38f8a144698dbb` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-12/revision-06/inputs/native-wire-details.md.txt) |
| [operation-contracts.md](operation-contracts.md) | `4f17fb5d19261c6dfcf69dc972fc1ed4bc25fd395c2a3f101b0ee202d445b3e6` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-12/revision-06/inputs/operation-contracts.md.txt) |
| [transfer-contracts.md](transfer-contracts.md) | `04345646656b104dcee0bbbd693e5fbac8a8ee388613a631eb28f88b4a0f8ab0` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-12/revision-06/inputs/transfer-contracts.md.txt) |
| [news-contracts.md](news-contracts.md) | `2fee4f5073a0c7892df9f898c0a9f68210e79b9e3093342fbb7c04f17dfb485f` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-12/revision-06/inputs/news-contracts.md.txt) |
| [presence-messaging-contracts.md](presence-messaging-contracts.md) | `774e1ffa4f0da764d99fbc1c256b34623d88c2b68aee65f7bb7d6275f3a857be` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-12/revision-06/inputs/presence-messaging-contracts.md.txt) |
| [core-field-schemas.md](core-field-schemas.md) | `222dd10892ba1578054a53af5d86fe922a2681b0a81861804248045797154121` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-12/revision-06/inputs/core-field-schemas.md.txt) |
| [session-transport-contracts.md](session-transport-contracts.md) | `31921752d68f0b1aebb0425752c1b456ec32ac7cf4c6ad49078f5ff52009c0a0` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-12/revision-06/inputs/session-transport-contracts.md.txt) |

[Audit
manifest](../mothra/evidence/protocol-gap-analysis/2026-11-12/revision-06/manifest.json);
[machine-readable register](gap-register.json). No field or behaviour is
silently made normative by being listed as a question.

## Gap index

| ID | Priority | Kind | Area | Question | Status |
| --- | --- | --- | --- | --- | --- |
| [GAP-001](#gap-001) | P1 | Decision | Specification | Define the supported 1.9 subset | Open |
| [GAP-002](#gap-002) | P0 | Missing | Specification | Canonical transaction and field schemas | Resolved |
| [GAP-003](#gap-003) | P0 | Missing | Specification | Error-code and failure-outcome registry | Investigating |
| [GAP-004](#gap-004) | P0 | Unanswered | Session and transport | Transaction ID lifecycle and correlation | Investigating |
| [GAP-005](#gap-005) | P0 | Missing | Session and transport | Connection timers and liveness | Investigating |
| [GAP-006](#gap-006) | P1 | Missing | Specification | Complete direction and reply-contract catalogue | Investigating |
| [GAP-007](#gap-007) | P0 | Missing | Session and transport | Allowed operations by session state | Resolved |
| [GAP-008](#gap-008) | P0 | Unanswered | Session and transport | Handshake failures and stream boundaries | Investigating |
| [GAP-009](#gap-009) | P1 | Unanswered | Session and transport | Sub-version 3 and direct HTXF relationship | Investigating |
| [GAP-010](#gap-010) | P1 | Unanswered | Session and transport | Listening endpoints and data-port arithmetic | Investigating |
| [GAP-011](#gap-011) | P0 | Unanswered | Framing and parsing | Frame, transaction and buffering limits | Investigating |
| [GAP-012](#gap-012) | P0 | Unanswered | Framing and parsing | Fragment reassembly edge cases | Investigating |
| [GAP-013](#gap-013) | P0 | Missing | Framing and parsing | Accepted envelope values and reserved bytes | Investigating |
| [GAP-014](#gap-014) | P0 | Unanswered | Framing and parsing | TLV structural validation | Investigating |
| [GAP-015](#gap-015) | P0 | Ambiguous | Values and encoding | Field-specific scalar types | Investigating |
| [GAP-016](#gap-016) | P0 | Ambiguous | Values and encoding | Absent, empty and zero-valued fields | Investigating |
| [GAP-017](#gap-017) | P0 | Unanswered | Framing and parsing | Repeated scalar fields and ordering | Investigating |
| [GAP-018](#gap-018) | P0 | Unanswered | Values and encoding | Text encoding and transformations | Investigating |
| [GAP-019](#gap-019) | P0 | Missing | Values and encoding | Semantic length limits and truncation | Investigating |
| [GAP-020](#gap-020) | P1 | Unanswered | Values and encoding | Date and timestamp semantics | Investigating |
| [GAP-021](#gap-021) | P1 | Ambiguous | Specification | ACK versus completion, durability and retry | Investigating |
| [GAP-022](#gap-022) | P0 | Unanswered | Authentication and settings | Native nonempty-password encoding | Investigating |
| [GAP-023](#gap-023) | P0 | Ambiguous | Authentication and settings | Login-name lookup and guest fallback | Investigating |
| [GAP-024](#gap-024) | P0 | Ambiguous | Authentication and settings | Client-version and optional login inputs | Investigating |
| [GAP-025](#gap-025) | P0 | Unanswered | Authentication and settings | Complete login/agreement state machine | Investigating |
| [GAP-026](#gap-026) | P1 | Missing | Authentication and settings | Meaning and lifetime of login extras | Investigating |
| [GAP-027](#gap-027) | P1 | Unanswered | Authentication and settings | Agreement absence, bypass and text rules | Investigating |
| [GAP-028](#gap-028) | P1 | Ambiguous | Authentication and settings | Banner metadata variants and lifecycle | Investigating |
| [GAP-029](#gap-029) | P1 | Unanswered | Authentication and settings | Settings update defaults and persistence | Investigating |
| [GAP-030](#gap-030) | P1 | Unanswered | Authentication and settings | Settings option edge cases and automatic-response defaults | Investigating |
| [GAP-031](#gap-031) | P1 | Unanswered | Presence and permissions | Complete privilege bitmap registry | Investigating |
| [GAP-032](#gap-032) | P1 | Unanswered | Presence and permissions | Privilege composition and inheritance | Investigating |
| [GAP-033](#gap-033) | P1 | Missing | Presence and permissions | User, room, article and reference identifier lifetimes | Investigating |
| [GAP-034](#gap-034) | P1 | Unanswered | Presence and permissions | Colour/status bitmap semantics | Investigating |
| [GAP-035](#gap-035) | P1 | Unanswered | Presence and permissions | Roster and update ordering | Investigating |
| [GAP-036](#gap-036) | P1 | Unanswered | Presence and permissions | Disconnect notification and cleanup | Investigating |
| [GAP-037](#gap-037) | P2 | Ambiguous | Presence and permissions | Diagnostic-text output contract | Open |
| [GAP-038](#gap-038) | P1 | Unanswered | Chat and messaging | Room access and main-chat membership | Investigating |
| [GAP-039](#gap-039) | P1 | Unanswered | Chat and messaging | Invitation lifecycle and partial failures | Investigating |
| [GAP-040](#gap-040) | P1 | Ambiguous | Chat and messaging | Room snapshot and notification ordering | Investigating |
| [GAP-041](#gap-041) | P1 | Unanswered | Chat and messaging | Subject update validation | Investigating |
| [GAP-042](#gap-042) | P1 | Unanswered | Chat and messaging | Chat formatting and option 109 | Investigating |
| [GAP-043](#gap-043) | P1 | Unanswered | Chat and messaging | Private-message routing truth table | Investigating |
| [GAP-044](#gap-044) | P1 | Missing | Chat and messaging | Type-104 variant schemas | Investigating |
| [GAP-045](#gap-045) | P1 | Unanswered | Chat and messaging | Flood, spam and throttling outcomes | Investigating |
| [GAP-046](#gap-046) | P1 | Unanswered | Chat and messaging | Legacy-board data and update contract | Open |
| [GAP-047](#gap-047) | P1 | Unanswered | Files and paths | Structured path format | Investigating |
| [GAP-048](#gap-048) | P1 | Unanswered | Files and paths | File-list record layout | Investigating |
| [GAP-049](#gap-049) | P1 | Ambiguous | Files and paths | File-info variant matrix | Open |
| [GAP-050](#gap-050) | P1 | Unanswered | Files and paths | Delete semantics and failures | Open |
| [GAP-051](#gap-051) | P1 | Unanswered | Files and paths | Folder creation semantics | Open |
| [GAP-052](#gap-052) | P1 | Unanswered | Files and paths | Rename/comment partial updates | Open |
| [GAP-053](#gap-053) | P1 | Unanswered | Files and paths | Move collision and metadata behaviour | Open |
| [GAP-054](#gap-054) | P1 | Unanswered | Files and paths | Alias creation and resolution | Open |
| [GAP-055](#gap-055) | P1 | Unanswered | Transfer protocol | Sixteen-byte HTXF header and reference matching | Investigating |
| [GAP-056](#gap-056) | P1 | Unanswered | Transfer protocol | Flattened file and fork stream | Investigating |
| [GAP-057](#gap-057) | P1 | Ambiguous | Transfer protocol | Download and preview response conditions | Investigating |
| [GAP-058](#gap-058) | P1 | Unanswered | Transfer protocol | Resume-data format and offset negotiation | Investigating |
| [GAP-059](#gap-059) | P1 | Unanswered | Transfer protocol | Folder-download stream state machine | Investigating |
| [GAP-060](#gap-060) | P1 | Unanswered | Transfer protocol | Folder-upload stream state machine | Investigating |
| [GAP-061](#gap-061) | P1 | Unanswered | Transfer protocol | Queue notification 211 and scheduling | Investigating |
| [GAP-062](#gap-062) | P1 | Unanswered | Transfer protocol | Reference cleanup 214 semantics | Investigating |
| [GAP-063](#gap-063) | P1 | Unanswered | Transfer protocol | Banner data stream and absence | Investigating |
| [GAP-064](#gap-064) | P1 | Missing | Transfer protocol | Transfer completion, failure and persistence | Investigating |
| [GAP-065](#gap-065) | P1 | Unanswered | News | Category records and version threshold | Investigating |
| [GAP-066](#gap-066) | P1 | Unanswered | News | Serialized article-list format | Investigating |
| [GAP-067](#gap-067) | P1 | Unanswered | News | Article navigation, flavour and date semantics | Investigating |
| [GAP-068](#gap-068) | P1 | Unanswered | News | Posting and new-article discovery | Investigating |
| [GAP-069](#gap-069) | P1 | Unanswered | News | Recursive article deletion | Investigating |
| [GAP-070](#gap-070) | P1 | Unanswered | News | News hierarchy and structure mutations | Investigating |
| [GAP-071](#gap-071) | P1 | Unanswered | Administration | Account field 111 | Investigating |
| [GAP-072](#gap-072) | P1 | Unanswered | Administration | Account update, placeholder and identity rules | Investigating |
| [GAP-073](#gap-073) | P1 | Unanswered | Administration | Account changes and active sessions | Investigating |
| [GAP-074](#gap-074) | P1 | Unanswered | Administration | Kick/ban option branches | Investigating |
| [GAP-075](#gap-075) | P2 | Unanswered | Administration | Standalone transaction 111 | Resolved |
| [GAP-076](#gap-076) | P2 | Unanswered | Administration | Server-originated broadcast and eligibility | Investigating |
| [GAP-077](#gap-077) | P2 | Unanswered | Administration | Request 348 schema and purpose | Investigating |
| [GAP-078](#gap-078) | P2 | Unanswered | Administration | Request 349 schema and batch outcomes | Investigating |
| [GAP-079](#gap-079) | P2 | Unanswered | Session and transport | Request 500 purpose and scheduling | Investigating |
| [GAP-080](#gap-080) | P1 | Evidence | Compatibility and evidence | Identified peer corpus and fallback classifier | Investigating |
| [GAP-081](#gap-081) | P2 | Evidence | Compatibility and evidence | Client tolerance of extra fields | Investigating |
| [GAP-082](#gap-082) | P1 | Decision | Compatibility and evidence | Heuristic text-decoding policy | Investigating |
| [GAP-083](#gap-083) | P2 | Evidence | Compatibility and evidence | Historical SynHX source identity and applicability | Open |
| [GAP-084](#gap-084) | P0 | Evidence | Compatibility and evidence | Native conformance fixtures beyond one illustrative frame | Open |
| [GAP-085](#gap-085) | P2 | Evidence | Compatibility and evidence | mxd implementation and test evidence | Investigating |
| [GAP-086](#gap-086) | P2 | Decision | Compatibility and evidence | Release/proof acceptance criteria | Investigating |
| [GAP-087](#gap-087) | P2 | Missing | Documentation provenance | Portable, versioned evidence and document references | Investigating |

## Specification

### GAP-001

#### Define the supported 1.9 subset

- **Tracking:** P1; Decision; Open; owner: Unassigned.
- **Sources:** [protocol.md — Hotline Server Protocol 1.9: Transactions and
  Functionality
  Guide](protocol.md#hotline-server-protocol-19-transactions-and-functionality-guide)
  (snapshot lines 1–29); [internal-compatibility-matrix.md — Open
  compatibility gaps and QA
  requirements](internal-compatibility-matrix.md#open-compatibility-gaps-and-qa-requirements)
  (snapshot lines 237–267)
- **Question:** Which of the 45 requests and server notifications must mxd
  implement now, defer explicitly, or reject, and which peer profiles are
  acceptance targets?
- **Implementation impact:** An open-ended baseline cannot define feature
  completion or compatible rejection behaviour.
- **Close when:** Publish an operation-by-profile scope matrix with required,
  deferred and excluded states, including replies to unsupported operations.
- **Prior ledger entries:** V001, V074, M008, M009
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c)
- **Depends on:** No prerequisite recorded.

### GAP-002

#### Canonical transaction and field schemas

- **Tracking:** P0; Missing; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2 General transaction
  frame](protocol.md#2-general-transaction-frame) (snapshot lines 73–97);
  [protocol.md — 2.1 Parameter list (payload
  block)](protocol.md#21-parameter-list-payload-block) (snapshot lines
  98–141); [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 275–300); [protocol.md — User Account Management – Client Initiates
  (Admin) (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 895–928)
- **Question:** For every in-scope request, reply and notification, which
  fields are required, optional, conditional or repeatable, with what widths
  and value domains?
- **Implementation impact:** Lists of fields that a handler reads are not
  sufficient to build a compatible encoder or validator.
- **Close when:** Provide a schema registry for the core operations, marking
  each remaining unknown with a gap ID; include direction, cardinality, width,
  conditions and defaults.
- **Prior ledger entries:** V013, V015, V023, V069
- **Investigation leads:**
  [100568b0](../mothra/evidence/hotline-server-1.9/queries/D-100568b0.c),
  [10056b90](../mothra/evidence/hotline-server-1.9/queries/D-10056b90.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"evidence": ["[Core schema
  registry](core-field-schemas.md)", "[Complete handler
  inventory](operation-contracts.md#request-catalogue)", "[Preserved native
  baseline](../mothra/evidence/hotline-server-1.9/manifest.json)"],
  "binary_sha256":
  "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b",
  "closure": "Published a core operation registry with direction, logical
  scalar/repeated occurrence, widths/byte caps, default/absence behaviour and
  conditions. Remaining type, boundary, routing and fixture unknowns retain
  their separate gap IDs as required by this criterion. This closes the
  registry deliverable, not all codec/runtime acceptance questions."}

### GAP-003

#### Error-code and failure-outcome registry

- **Tracking:** P0; Missing; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 4 Reply
  semantics](protocol.md#4-reply-semantics) (snapshot lines 193–214);
  [protocol.md — Disconnecting a User (Transaction 110 & 111) – Admin/Server
  Use](protocol.md#disconnecting-a-user-transaction-110--111--adminserver-use)
  (snapshot lines 929–950)
- **Question:** Which statuses, field-100 forms and connection outcomes apply
  to each failure, including errors in operations without a normal ACK?
- **Implementation impact:** Implementations cannot distinguish recoverable
  failure, success, silent rejection and impending disconnect consistently.
- **Close when:** Document a failure table and representative bytes for
  authentication, permission, missing-object, malformed-request and
  unsupported-operation cases.
- **Prior ledger entries:** V012, V044, V053, V065, V067, V071
- **Investigation leads:**
  [10058a10](../mothra/evidence/hotline-server-1.9/queries/D-10058a10.c),
  [1000ef30](../mothra/evidence/hotline-server-1.9/queries/D-1000ef30.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Traced online unknown-operation reply status
  1 with field 100 and distinguished pre-online close. Complete failure table
  and native representative packets remain required.", "evidence":
  ["[Operation contracts](operation-contracts.md)", "[Compatibility
  review](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-006

#### Complete direction and reply-contract catalogue

- **Tracking:** P1; Missing; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 4 Reply
  semantics](protocol.md#4-reply-semantics) (snapshot lines 193–214);
  [protocol.md — Sending a Chat Message (Transaction 105) – Client
  Initiates](protocol.md#sending-a-chat-message-transaction-105--client-initiates)
  (snapshot lines 473–484); [protocol.md — Leaving a Chat Room (Transaction
  116) – Client
  Initiates](protocol.md#leaving-a-chat-room-transaction-116--client-initiates)
  (snapshot lines 506–515); [protocol.md — Changing User Settings (Transaction
  304) – Client
  Initiates](protocol.md#changing-user-settings-transaction-304--client-initiates)
  (snapshot lines 457–470)
- **Question:** Which operation/direction/session-state combinations are
  accepted, and what direct success/error replies or subsequent notifications
  belong to each? The current ACK/Push prose is not a complete catalogue.
- **Implementation impact:** Implementers must infer dispatch direction and
  negative-outcome rules from scattered handler descriptions rather than one
  complete contract.
- **Close when:** Publish an operation-by-direction/state table distinguishing
  direct success replies, error replies, emitted notifications and
  acceptance/completion semantics.
- **Prior ledger entries:** V039, V038, V041, V044
- **Investigation leads:**
  [10058a70](../mothra/evidence/hotline-server-1.9/queries/D-10058a70.c),
  [10058ca0](../mothra/evidence/hotline-server-1.9/queries/D-10058ca0.c)
- **Depends on:** [GAP-002](#gap-002), [GAP-003](#gap-003)
- **Disposition:** {"progress": "Published all 45 request paths, reply
  directions and known notification producers; unknown 111/211/302 schemas and
  exhaustive branch completion contracts remain open.", "evidence":
  ["[Operation contracts](operation-contracts.md)", "[Compatibility
  review](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-021

#### ACK versus completion, durability and retry

- **Tracking:** P1; Ambiguous; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 4 Reply
  semantics](protocol.md#4-reply-semantics) (snapshot lines 193–214);
  [protocol.md — Sending an Instant Message (Transaction 108) – Client
  Initiates](protocol.md#sending-an-instant-message-transaction-108--client-initiates)
  (snapshot lines 559–585); [protocol.md — Posting a News Article (Transaction
  410) – Client
  Initiates](protocol.md#posting-a-news-article-transaction-410--client-initiates)
  (snapshot lines 855–866); [protocol.md — User Account Management – Client
  Initiates (Admin) (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 895–928)
- **Question:** When an ACK precedes routing or mutation side effects, what
  has it committed to, and what can fail or be retried afterwards?
- **Implementation impact:** A client may treat acceptance as
  delivered/durable success and duplicate non-idempotent operations on
  reconnect.
- **Close when:** Specify completion points, post-ACK failure signalling,
  persistence and retry/idempotency rules per operation with
  disconnect-boundary fixtures.
- **Prior ledger entries:** V044, V045, V065, V067
- **Investigation leads:**
  [1000f4e0](../mothra/evidence/hotline-server-1.9/queries/D-1000f4e0.c),
  [10010470](../mothra/evidence/hotline-server-1.9/queries/D-10010470.c),
  [10014df0](../mothra/evidence/hotline-server-1.9/queries/D-10014df0.c)
- **Depends on:** [GAP-003](#gap-003), [GAP-007](#gap-007)
- **Disposition:** {"progress": "Added transfer-worker completion
  distinctions: enqueueing download bytes versus upload expected-byte
  counting, finalization and data closure. Persistence and disconnect-boundary
  fixtures remain required.", "evidence": ["[Transfer
  contracts](transfer-contracts.md)", "[Batch
  04](../mothra/evidence/gap-remediation/2026-11-12/batch-04/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

## Session and transport

### GAP-004

#### Transaction ID lifecycle and correlation

- **Tracking:** P0; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2 General transaction
  frame](protocol.md#2-general-transaction-frame) (snapshot lines 73–97);
  [protocol.md — 3 Fragmentation rules](protocol.md#3-fragmentation-rules)
  (snapshot lines 165–192)
- **Question:** Are zero, duplicate, wrapped or reused IDs accepted, how are
  client and server ID spaces separated, and how are unsolicited replies
  treated?
- **Implementation impact:** Correlation and reassembly can attach a reply or
  payload to the wrong outstanding operation.
- **Close when:** Specify ID allocation, lifetime, wrap/reuse and notification
  correlation rules; exercise zero, collision and late-reply cases.
- **Prior ledger entries:** V007, V008, V010, V022
- **Investigation leads:**
  [10058d70](../mothra/evidence/hotline-server-1.9/queries/D-10058d70.c),
  [100590e0](../mothra/evidence/hotline-server-1.9/queries/D-100590e0.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Recorded per-connection
  increment/zero-skipping wrap and fragment matching. Collision, reuse and
  late-reply fixtures remain required.", "evidence": ["[Operation
  contracts](operation-contracts.md)", "[Compatibility
  review](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-005

#### Connection timers and liveness

- **Tracking:** P0; Missing; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 1 Session-initialization
  handshake](protocol.md#1-session-initialization-handshake) (snapshot lines
  38–72); [protocol.md — 4 Reply semantics](protocol.md#4-reply-semantics)
  (snapshot lines 193–214); [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 275–300); [protocol.md — Additional Observed Requests and Scope
  Gaps](protocol.md#additional-observed-requests-and-scope-gaps) (snapshot
  lines 975–1012)
- **Question:** What are the handshake, login, agreement, idle and
  partial-frame deadlines, and what traffic resets them?
- **Implementation impact:** A client can wait forever or disconnect a
  compatible session prematurely without a liveness contract.
- **Close when:** Provide a timer/state table with units, reset conditions,
  configurable values and close outcomes, distinguishing native observations
  from mxd limits.
- **Prior ledger entries:** V012, V020, V074
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Added ordinary file/banner pending-connection
  and connected-upload inactivity timer comparisons in seconds. Other
  transport/folder timer and bounded timing fixtures remain required.",
  "evidence": ["[Transfer contracts](transfer-contracts.md)", "[Batch
  04](../mothra/evidence/gap-remediation/2026-11-12/batch-04/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-007

#### Allowed operations by session state

- **Tracking:** P0; Missing; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 1 Session-initialization
  handshake](protocol.md#1-session-initialization-handshake) (snapshot lines
  38–72); [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 275–300); [protocol.md — Agreement Acceptance (Transaction 121) –
  Client
  Initiates](protocol.md#agreement-acceptance-transaction-121--client-initiates)
  (snapshot lines 315–337); [protocol.md — Additional Observed Requests and
  Scope Gaps](protocol.md#additional-observed-requests-and-scope-gaps)
  (snapshot lines 975–1012)
- **Question:** What can be sent before authentication, after login ACK, while
  agreement is pending, after early completion and during shutdown?
- **Implementation impact:** The guide has transaction descriptions but no
  complete dispatch/state contract for a server implementation.
- **Close when:** Publish a state/operation table including invalid
  transitions, replayed login/agreement requests and state-specific failures,
  backed by traces or dispatcher analysis.
- **Prior ledger entries:** V023, V026, V027
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c),
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c),
  [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"evidence": ["[Native
  dispatcher](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c)",
  "[Unknown-operation
  error](../mothra/evidence/gap-remediation/2026-11-12/batch-03/queries/B03-D-10014640.c)",
  "[State/operation
  table](operation-contracts.md#session-eligibility-and-invalid-transitions)",
  "[Login visibility
  sequence](presence-messaging-contracts.md#settings-and-login-visibility)"],
  "binary_sha256":
  "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b",
  "closure": "Published allowed operations, invalid pre-online closes,
  replayed online login/agreement errors, failure waiting and disconnected
  teardown states, backed by dispatcher analysis as allowed by the closure
  criterion. Removed the planned GAP-025 prerequisite because dispatch was
  established directly; full configured sequence captures remain
  GAP-025/084."}

### GAP-008

#### Handshake failures and stream boundaries

- **Tracking:** P0; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 1 Session-initialization
  handshake](protocol.md#1-session-initialization-handshake) (snapshot lines
  38–72)
- **Question:** How are short, long, pipelined, wrong-magic, wrong-version or
  unsupported-sub-version handshakes consumed, replied to and closed?
- **Implementation impact:** The happy-path twelve/eight-byte layouts do not
  specify initial stream recovery or rejection.
- **Close when:** Record positive and negative handshake exchanges with exact
  byte consumption, response status, pipelining behaviour and closure order.
- **Prior ledger entries:** V003, V004, V005, V006
- **Investigation leads:**
  [10058650](../mothra/evidence/hotline-server-1.9/queries/D-10058650.c),
  [10058770](../mothra/evidence/hotline-server-1.9/queries/D-10058770.c),
  [100587f0](../mothra/evidence/hotline-server-1.9/queries/D-100587f0.c),
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Published positive/negative handshake bytes
  and static call order, exact 12-byte availability boundary and
  success-before-admission caveat. Actual short-read/pipelining/drain/close
  native fixtures remain required.", "evidence": ["[Session transport
  contracts](session-transport-contracts.md)", "[Core
  schemas](core-field-schemas.md)", "[Batch
  07](../mothra/evidence/gap-remediation/2026-11-12/batch-07/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-009

#### Sub-version 3 and direct HTXF relationship

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 1 Session-initialization
  handshake](protocol.md#1-session-initialization-handshake) (snapshot lines
  38–72); [protocol.md — Transfer Connection and Reference
  Cleanup](protocol.md#transfer-connection-and-reference-cleanup) (snapshot
  lines 780–797)
- **Question:** When does the TRTP sub-version-3 path apply, on which
  endpoint, and how does it relate to a direct sixteen-byte HTXF header?
- **Implementation impact:** An implementer could perform the wrong handshake
  on a transfer socket despite knowing each observed magic.
- **Close when:** Trace the two entry paths and document complete
  endpoint-specific sequences, transitions and fixture bytes.
- **Prior ledger entries:** V004, V059, V060
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c),
  [1000bd20](../mothra/evidence/hotline-server-1.9/queries/D-1000bd20.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Traced sub-version-3 detach/dispose handover
  preserving the same transport into pending HTXF, versus direct data-port
  HTXF entry. Published endpoint-specific sequences; native
  coalescing/positive/negative stream fixtures remain required.", "evidence":
  ["[Session transport contracts](session-transport-contracts.md)", "[Core
  schemas](core-field-schemas.md)", "[Batch
  07](../mothra/evidence/gap-remediation/2026-11-12/batch-07/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-010

#### Listening endpoints and data-port arithmetic

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — File Services (Files and
  Folders)](protocol.md#file-services-files-and-folders) (snapshot lines
  614–624); [protocol.md — Transfer Connection and Reference
  Cleanup](protocol.md#transfer-connection-and-reference-cleanup) (snapshot
  lines 780–797)
- **Question:** How are control/data listeners selected and configured, and is
  the data port always the base port plus one in this build?
- **Implementation impact:** File-transfer connection setup cannot be derived
  from a tentative port convention.
- **Close when:** Trace listener creation and configuration; document endpoint
  mapping, exceptions and verified client connection examples.
- **Prior ledger entries:** V060
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c),
  [1000bd20](../mothra/evidence/hotline-server-1.9/queries/D-1000bd20.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Traced configured base port (default 5500),
  ordinary base/base+1 and alternative-wrapper base+2/base+3 binds.
  Constructor modes are kept separate from unproven TLS/HTTP labels.
  Runtime/overflow/client connection fixtures remain required.", "evidence":
  ["[Session transport contracts](session-transport-contracts.md)", "[Core
  schemas](core-field-schemas.md)", "[Batch
  07](../mothra/evidence/gap-remediation/2026-11-12/batch-07/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-079

#### Request 500 purpose and scheduling

- **Tracking:** P2; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Additional Observed Requests and Scope
  Gaps](protocol.md#additional-observed-requests-and-scope-gaps) (snapshot
  lines 975–1012)
- **Question:** Is 500 a liveness operation or something else, who sends it
  and when, and does its ACK affect idle deadlines?
- **Implementation impact:** Naming it a keepalive or scheduling it
  periodically would invent a contract from an empty-ACK handler.
- **Close when:** Identify client/server call sites or captures, document its
  purpose/timing/state eligibility, and explicitly scope support.
- **Prior ledger entries:** V074
- **Investigation leads:**
  [10018c00](../mothra/evidence/hotline-server-1.9/queries/D-10018c00.c)
- **Depends on:** [GAP-005](#gap-005)
- **Disposition:** {"progress": "Recorded request 500 empty-ACK behaviour and
  state eligibility: rejected before online. A peer-side scheduling/purpose
  source remains required.", "evidence": ["[Operation
  contracts](operation-contracts.md)", "[Compatibility
  review](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

## Framing and parsing

### GAP-011

#### Frame, transaction and buffering limits

- **Tracking:** P0; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 3 Fragmentation
  rules](protocol.md#3-fragmentation-rules) (snapshot lines 165–192)
- **Question:** Is the image's 2 MiB value changed at runtime, does it bound a
  frame or aggregate transaction, and how are totals, fragments and concurrent
  buffers limited?
- **Implementation impact:** The existing image constant does not define safe
  or interoperable allocation and framing boundaries.
- **Close when:** Document native comparisons/configuration and explicit mxd
  limits with inclusive boundaries, overflow checks and boundary fixtures.
- **Prior ledger entries:** V009, V010, V021
- **Investigation leads:**
  [100590e0](../mothra/evidence/hotline-server-1.9/queries/D-100590e0.c),
  [10058e80](../mothra/evidence/hotline-server-1.9/queries/D-10058e80.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Captured explicit startup assignment of 512
  KiB to receive-limit global, superseding the image-only 2 MiB assumption for
  that path. Indirect future writes, configurability, aggregate bounds and
  boundary fixtures remain required.", "evidence": ["[Session transport
  contracts](session-transport-contracts.md)", "[Core
  schemas](core-field-schemas.md)", "[Batch
  07](../mothra/evidence/gap-remediation/2026-11-12/batch-07/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-012

#### Fragment reassembly edge cases

- **Tracking:** P0; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 3 Fragmentation
  rules](protocol.md#3-fragmentation-rules) (snapshot lines 165–192)
- **Question:** What happens when type/total changes, fragments interleave,
  lengths overrun or underfill, transactions are abandoned, or a partial frame
  ends in EOF?
- **Implementation impact:** A codec implementing only ordinary concatenation
  has no specified outcome for common malformed or interrupted input.
- **Close when:** Publish reassembly invariants and a test matrix covering
  keys, length consistency, overshoot, underflow, abandonment and partial TCP
  delivery.
- **Prior ledger entries:** V009, V010, V020
- **Investigation leads:**
  [100590e0](../mothra/evidence/hotline-server-1.9/queries/D-100590e0.c),
  [10058e80](../mothra/evidence/hotline-server-1.9/queries/D-10058e80.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Documented ID/reply-state grouping,
  overwritten type/total, completion on accumulated length at least total and
  unmatched reply handling. TCP/reassembly negative fixtures remain
  required.", "evidence": ["[Operation contracts](operation-contracts.md)",
  "[Compatibility
  review](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-013

#### Accepted envelope values and reserved bytes

- **Tracking:** P0; Missing; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2 General transaction
  frame](protocol.md#2-general-transaction-frame) (snapshot lines 73–97);
  [protocol.md — 4 Reply semantics](protocol.md#4-reply-semantics) (snapshot
  lines 193–214)
- **Question:** How are nonzero flags, reply markers other than zero/one,
  nonzero request error words, unsupported types and nonzero reply types
  handled?
- **Implementation impact:** Writer conventions do not define the
  input-validation contract.
- **Close when:** Specify accepted and rejected header values for each
  direction and their failure outcomes, supported by receiver checks and
  negative fixtures.
- **Prior ledger entries:** V002, V007, V012, V022
- **Investigation leads:**
  [10058fd0](../mothra/evidence/hotline-server-1.9/queries/D-10058fd0.c),
  [100590e0](../mothra/evidence/hotline-server-1.9/queries/D-100590e0.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Documented nonzero reply-byte discrimination
  and lack of a flags whitelist in the traced receiver. Full
  direction-specific negative fixtures remain required.", "evidence":
  ["[Operation contracts](operation-contracts.md)", "[Compatibility
  review](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-014

#### TLV structural validation

- **Tracking:** P0; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2.1 Parameter list (payload
  block)](protocol.md#21-parameter-list-payload-block) (snapshot lines
  98–141); [protocol.md — 3 Fragmentation
  rules](protocol.md#3-fragmentation-rules) (snapshot lines 165–192)
- **Question:** What happens with a missing count, count/length mismatch,
  truncated values, trailing bytes, zero field IDs, unknown fields or maximum
  field counts?
- **Implementation impact:** The record shape alone is insufficient for a
  deterministic parameter decoder.
- **Close when:** Define exact consumption, bounds, unknown-field and
  trailing-data rules; add byte fixtures at every boundary and mismatch class.
- **Prior ledger entries:** V013, V014, V020
- **Investigation leads:**
  [100566e0](../mothra/evidence/hotline-server-1.9/queries/D-100566e0.c),
  [100572d0](../mothra/evidence/hotline-server-1.9/queries/D-100572d0.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Documented valid-prefix indexing, short
  payloads and trailing bytes. Boundary fixtures and handler-level outcomes
  remain required.", "evidence": ["[Native wire
  details](native-wire-details.md)", "[Batch
  01](../mothra/evidence/gap-remediation/2026-11-12/batch-01/manifest.json)",
  "[Batch
  02](../mothra/evidence/gap-remediation/2026-11-12/batch-02/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-017

#### Repeated scalar fields and ordering

- **Tracking:** P0; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2.1 Parameter list (payload
  block)](protocol.md#21-parameter-list-payload-block) (snapshot lines
  98–141); [protocol.md — Chat Invitations (Transactions 112, 113, 114) –
  Private
  Chats](protocol.md#chat-invitations-transactions-112-113-114--private-chats)
  (snapshot lines 528–547)
- **Question:** Beyond observed list/invitation cases, are duplicate scalars
  rejected, first-wins, last-wins or accumulated, and is order meaningful?
- **Implementation impact:** Preserving repetitions is necessary but does not
  determine how each schema resolves ambiguous duplicates.
- **Close when:** Define multiplicity and ordering by transaction/field and
  test repeated scalars, interleaved repeated records and reordered inputs.
- **Prior ledger entries:** V014, V040, V042, M006
- **Investigation leads:**
  [100568b0](../mothra/evidence/hotline-server-1.9/queries/D-100568b0.c),
  [100572d0](../mothra/evidence/hotline-server-1.9/queries/D-100572d0.c),
  [10017f30](../mothra/evidence/hotline-server-1.9/queries/D-10017f30.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Established sorted binary-search scalar
  selection without a first/last guarantee and original-order indexed
  iteration. Duplicate/reorder fixtures remain required.", "evidence":
  ["[Native wire details](native-wire-details.md)", "[Batch
  01](../mothra/evidence/gap-remediation/2026-11-12/batch-01/manifest.json)",
  "[Batch
  02](../mothra/evidence/gap-remediation/2026-11-12/batch-02/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

## Values and encoding

### GAP-015

#### Field-specific scalar types

- **Tracking:** P0; Ambiguous; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2.1 Parameter list (payload
  block)](protocol.md#21-parameter-list-payload-block) (snapshot lines
  98–141); [protocol.md — User Account Management – Client Initiates (Admin)
  (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 895–928); [protocol.md — Downloading a File (Transaction
  202) – Client
  Initiates](protocol.md#downloading-a-file-transaction-202--client-initiates)
  (snapshot lines 638–655)
- **Question:** Which numeric fields permit one/two/four bytes, which are
  fixed-width or signed, and how are booleans, sentinel values and invalid
  widths interpreted?
- **Implementation impact:** The generic reader's three-byte-to-zero behaviour
  could be mistaken for a valid zero or applied to a fixed-width field.
- **Close when:** Give each core scalar an explicit wire type, allowed
  widths/range and invalid-width outcome, including references and privilege
  bitmaps.
- **Prior ledger entries:** V015, V029, V051, V069
- **Investigation leads:**
  [10056a90](../mothra/evidence/hotline-server-1.9/queries/D-10056a90.c),
  [10056b90](../mothra/evidence/hotline-server-1.9/queries/D-10056b90.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Documented generic 1/2/3/4/overlong numeric
  accessor behaviour. A complete field-specific scalar registry remains
  required.", "evidence": ["[Native wire details](native-wire-details.md)",
  "[Batch
  01](../mothra/evidence/gap-remediation/2026-11-12/batch-01/manifest.json)",
  "[Batch
  02](../mothra/evidence/gap-remediation/2026-11-12/batch-02/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-016

#### Absent, empty and zero-valued fields

- **Tracking:** P0; Ambiguous; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2.1 Parameter list (payload
  block)](protocol.md#21-parameter-list-payload-block) (snapshot lines
  98–141); [protocol.md — 5 Worked example
  (Login)](protocol.md#5-worked-example-login) (snapshot lines 215–249);
  [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 275–300); [protocol.md — Changing User Settings (Transaction 304) –
  Client
  Initiates](protocol.md#changing-user-settings-transaction-304--client-initiates)
  (snapshot lines 457–470)
- **Question:** Which operations distinguish an omitted field, a zero-length
  TLV, an empty string and numeric zero, and what defaults are applied?
- **Implementation impact:** The native writer omits empty fields while
  documented readers sometimes reset state when fields are absent.
- **Close when:** Add per-field presence/default tables and fixtures for all
  four cases, especially credentials, settings and partial account updates.
- **Prior ledger entries:** V011, V018, V037, V068
- **Investigation leads:**
  [100568b0](../mothra/evidence/hotline-server-1.9/queries/D-100568b0.c),
  [10056c70](../mothra/evidence/hotline-server-1.9/queries/D-10056c70.c),
  [10004d50](../mothra/evidence/hotline-server-1.9/queries/D-10004d50.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Documented account 353
  absent/empty/NUL/literal-x password cases and cleared-record defaults;
  settings and other presence tables remain open.", "evidence": ["[Native wire
  details](native-wire-details.md)", "[Batch
  01](../mothra/evidence/gap-remediation/2026-11-12/batch-01/manifest.json)",
  "[Batch
  02](../mothra/evidence/gap-remediation/2026-11-12/batch-02/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-018

#### Text encoding and transformations

- **Tracking:** P0; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Binary Message Formats (Hotline Protocol
  1.9)](protocol.md#binary-message-formats-hotline-protocol-19) (snapshot
  lines 30–37); [internal-compatibility-matrix.md — Credential obfuscation and
  text
  compatibility](internal-compatibility-matrix.md#credential-obfuscation-and-text-compatibility)
  (snapshot lines 79–101); [protocol.md — Receiving a Chat Message
  (Transaction 106) – Server
  Initiates](protocol.md#receiving-a-chat-message-transaction-106--server-initiates)
  (snapshot lines 485–493); [protocol.md — Listing Files in a Folder
  (Transaction 200) – Client
  Initiates](protocol.md#listing-files-in-a-folder-transaction-200--client-initiates)
  (snapshot lines 625–637)
- **Question:** Which charset, normalization, NUL handling and line-ending
  rules apply to credentials, names, paths, chat, news and error text?
- **Implementation impact:** A generic UTF-8 or XOR heuristic can change valid
  native text and fail to round-trip names or message content.
- **Close when:** Publish per-field byte/string rules with non-ASCII,
  embedded-NUL, CR/LF and complemented-credential fixtures from identified
  peers.
- **Prior ledger entries:** V016, V019, V048, M005
- **Investigation leads:**
  [10056c70](../mothra/evidence/hotline-server-1.9/queries/D-10056c70.c),
  [10056cb0](../mothra/evidence/hotline-server-1.9/queries/D-10056cb0.c),
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Established credential complement and exact
  256-byte login normalization table. Other text fields and identified-peer
  byte fixtures remain required.", "evidence": ["[Native wire
  details](native-wire-details.md)", "[Batch
  01](../mothra/evidence/gap-remediation/2026-11-12/batch-01/manifest.json)",
  "[Batch
  02](../mothra/evidence/gap-remediation/2026-11-12/batch-02/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-019

#### Semantic length limits and truncation

- **Tracking:** P0; Missing; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2.1 Parameter list (payload
  block)](protocol.md#21-parameter-list-payload-block) (snapshot lines
  98–141); [protocol.md — Changing User Settings (Transaction 304) – Client
  Initiates](protocol.md#changing-user-settings-transaction-304--client-initiates)
  (snapshot lines 457–470); [protocol.md — Sending a Chat Message (Transaction
  105) – Client
  Initiates](protocol.md#sending-a-chat-message-transaction-105--client-initiates)
  (snapshot lines 473–484); [protocol.md — User Account Management – Client
  Initiates (Admin) (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 895–928)
- **Question:** What byte/character limits and truncation or rejection rules
  apply to every name, password, message, subject, comment and body?
- **Implementation impact:** The 65,535-byte TLV limit does not describe
  smaller buffers, truncation, multibyte strings or advertised transfer sizes.
- **Close when:** Record field-specific limits and units, max/max-plus-one
  behaviour and aggregate limits, preserving native versus mxd-policy
  distinctions.
- **Prior ledger entries:** V013, V016, V023, V037, V051
- **Investigation leads:**
  [10056c70](../mothra/evidence/hotline-server-1.9/queries/D-10056c70.c),
  [1000fc20](../mothra/evidence/hotline-server-1.9/queries/D-1000fc20.c),
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Recorded account handler byte caps and the
  separate 31-byte native local setter. The complete semantic-limit registry
  remains required.", "evidence": ["[Native wire
  details](native-wire-details.md)", "[Batch
  01](../mothra/evidence/gap-remediation/2026-11-12/batch-01/manifest.json)",
  "[Batch
  02](../mothra/evidence/gap-remediation/2026-11-12/batch-02/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-020

#### Date and timestamp semantics

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2.2 Date
  parameters](protocol.md#22-date-parameters) (snapshot lines 142–164);
  [protocol.md — Reading a News Article (Transaction 400) – Client
  Initiates](protocol.md#reading-a-news-article-transaction-400--client-initiates)
  (snapshot lines 833–854)
- **Question:** What epoch/units apply to the supplied filesystem value, how
  do nonzero milliseconds and other years work, and is news date 330
  equivalent?
- **Implementation impact:** The observed 1904/zero/value structure cannot yet
  be converted or compared reliably across all date fields.
- **Close when:** Trace each date producer/consumer and document epoch,
  timezone, units, range and conversion fixtures including rollover cases.
- **Prior ledger entries:** V017, V064
- **Investigation leads:**
  [10058070](../mothra/evidence/hotline-server-1.9/queries/D-10058070.c),
  [1002c910](../mothra/evidence/hotline-server-1.9/queries/D-1002c910.c),
  [10005ac0](../mothra/evidence/hotline-server-1.9/queries/D-10005ac0.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Traced native news date creation through
  GetDateTime plus fixed 1904 year and zero milliseconds. Article list/read
  copy stored bytes. Timezone, rollover and receiver conversion fixtures
  remain required.", "evidence": ["[News contracts](news-contracts.md)",
  "[Folder states](transfer-contracts.md#folder-download-control-states)",
  "[Batch
  05](../mothra/evidence/gap-remediation/2026-11-12/batch-05/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

## Authentication and settings

### GAP-022

#### Native nonempty-password encoding

- **Tracking:** P0; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 275–300); [protocol.md — 5 Worked example
  (Login)](protocol.md#5-worked-example-login) (snapshot lines 215–249);
  [protocol.md — User Account Management – Client Initiates (Admin) (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 895–928); [internal-compatibility-matrix.md — Credential
  obfuscation and text
  compatibility](internal-compatibility-matrix.md#credential-obfuscation-and-text-compatibility)
  (snapshot lines 79–101)
- **Question:** What exact bytes does the 1.9 server expect for nonempty
  passwords in login and account mutation, independent of SynHX's helper?
- **Implementation impact:** The guide cannot yet supply a working
  nonempty-password authentication fixture.
- **Close when:** Trace account storage and comparisons, then capture
  successful and failed logins plus account changes using known nonempty
  credentials.
- **Prior ledger entries:** V019, V023, V068, V069, M005
- **Investigation leads:**
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c),
  [10014bc0](../mothra/evidence/hotline-server-1.9/queries/D-10014bc0.c),
  [100146f0](../mothra/evidence/hotline-server-1.9/queries/D-100146f0.c),
  [10014df0](../mothra/evidence/hotline-server-1.9/queries/D-10014df0.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Traced native setter, reader/writer, recovery
  and exact-length login comparison; documented bytewise-complement password
  representation. Known-credential success/failure and mutation captures
  remain required.", "evidence": ["[Native wire
  details](native-wire-details.md)", "[Batch
  01](../mothra/evidence/gap-remediation/2026-11-12/batch-01/manifest.json)",
  "[Batch
  02](../mothra/evidence/gap-remediation/2026-11-12/batch-02/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-023

#### Login-name lookup and guest fallback

- **Tracking:** P0; Ambiguous; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 275–300); [protocol.md — User Account Management – Client Initiates
  (Admin) (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 895–928)
- **Question:** Are absent, empty, NUL-containing or differently cased logins
  equivalent; how are complemented bytes normalized and guest permissions
  chosen?
- **Implementation impact:** The guest-name path and account-name
  transformations are not a complete authentication lookup contract.
- **Close when:** Document transformation order, canonicalization and
  absent/empty/unknown account outcomes using lookup-helper evidence and
  fixtures.
- **Prior ledger entries:** V019, V023, V027
- **Investigation leads:**
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Traced complement, 256-byte normalization, CR
  replacement and guest fallback order. Unknown/absent/empty account fixtures
  remain required.", "evidence": ["[Native wire
  details](native-wire-details.md)", "[Batch
  01](../mothra/evidence/gap-remediation/2026-11-12/batch-01/manifest.json)",
  "[Batch
  02](../mothra/evidence/gap-remediation/2026-11-12/batch-02/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-024

#### Client-version and optional login inputs

- **Tracking:** P0; Ambiguous; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 275–300); [protocol.md — 2.1 Parameter list (payload
  block)](protocol.md#21-parameter-list-payload-block) (snapshot lines
  98–141); [internal-compatibility-matrix.md — Compatibility
  matrix](internal-compatibility-matrix.md#compatibility-matrix) (snapshot
  lines 34–54)
- **Question:** Are fields 160/102/104 mandatory, what defaults apply if
  omitted or malformed, and does saved version affect anything besides the
  named banner/news paths?
- **Implementation impact:** A field-read list can be mistaken for required
  input and can select the wrong login-completion path.
- **Close when:** Supply a login input-condition table covering presence,
  widths, zero, version boundaries and each dependent feature without using
  version as conclusive client identity.
- **Prior ledger entries:** V023, V024, V027, V062, M002
- **Investigation leads:**
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c),
  [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c),
  [10005710](../mothra/evidence/hotline-server-1.9/queries/D-10005710.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Published login field types/defaults, full
  32-bit saved version, narrowed icon/early-completion condition and distinct
  category15/banner151 thresholds. Identified-client and optional/version
  boundary fixtures remain required.", "evidence": ["[Session transport
  contracts](session-transport-contracts.md)", "[Core
  schemas](core-field-schemas.md)", "[Batch
  07](../mothra/evidence/gap-remediation/2026-11-12/batch-07/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-025

#### Complete login/agreement state machine

- **Tracking:** P0; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 275–300); [protocol.md — Server Agreement (Transaction 109) – Server
  Initiates](protocol.md#server-agreement-transaction-109--server-initiates)
  (snapshot lines 301–314); [protocol.md — Agreement Acceptance (Transaction
  121) – Client
  Initiates](protocol.md#agreement-acceptance-transaction-121--client-initiates)
  (snapshot lines 315–337)
- **Question:** What are the exact ACK, 109, 354, 122 and 301 ordering and
  state transitions for early completion, ordinary acceptance, no agreement,
  repeated 121 and delayed acceptance?
- **Implementation impact:** Two observed completion paths do not yet define a
  deterministic interoperable session sequence.
- **Close when:** Provide state/sequence tables and captured fixtures for each
  configured path, including duplicate/out-of-state requests and visibility
  timing.
- **Prior ledger entries:** V025, V026, V027, V029, V035
- **Investigation leads:**
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c),
  [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c),
  [10004d50](../mothra/evidence/hotline-server-1.9/queries/D-10004d50.c)
- **Depends on:** [GAP-022](#gap-022), [GAP-024](#gap-024)
- **Disposition:** {"progress": "Documented login ACK/301/online/354/109
  ordering for early completion and 121 ACK/settings/301/online/354 ordering.
  Configuration/path native session fixtures remain required.", "evidence":
  ["[Presence, messaging and
  administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-026

#### Meaning and lifetime of login extras

- **Tracking:** P1; Missing; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 275–300); [internal-compatibility-matrix.md — Login reply and banner
  policy](internal-compatibility-matrix.md#login-reply-and-banner-policy)
  (snapshot lines 55–78)
- **Question:** What are field 161's identifier semantics, widths and
  invalidation rules, and field 162's encoding/limits; how do they relate to
  banner 122 and download 212?
- **Implementation impact:** An implementation can send the right IDs with
  incompatible values or stale banner identity.
- **Close when:** Define the value schemas, configuration sources and
  change/lifetime rules with sample configured/no-banner replies.
- **Prior ledger entries:** V023, V024, V025, M003, M004
- **Investigation leads:**
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c),
  [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Separated current configuration reads in
  agreement/banner helpers from unconditional login extras. Exact
  community/banner identifier configuration source and change/lifetime
  fixtures remain required.", "evidence": ["[Presence, messaging and
  administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-027

#### Agreement absence, bypass and text rules

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Server Agreement (Transaction 109) – Server
  Initiates](protocol.md#server-agreement-transaction-109--server-initiates)
  (snapshot lines 301–314); [protocol.md — Agreement Acceptance (Transaction
  121) – Client
  Initiates](protocol.md#agreement-acceptance-transaction-121--client-initiates)
  (snapshot lines 315–337)
- **Question:** When is 154 emitted, how do absent/empty/unreadable agreement
  text and account bypass privileges behave, and must a client send 121 after
  early completion?
- **Implementation impact:** Agreement omission or bypass may produce a
  different readiness flow than the prose implies.
- **Close when:** Document the configuration/account condition matrix and its
  wire/state outcomes; include absent, empty and configured agreement
  fixtures.
- **Prior ledger entries:** V025, V027, V028
- **Investigation leads:**
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c),
  [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Published account-bit-27, present-buffer and
  absent-buffer agreement outcomes, including empty 109 rather than inventing
  154 for absent text. Configuration/account native fixtures remain
  required.", "evidence": ["[Presence, messaging and
  administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-028

#### Banner metadata variants and lifecycle

- **Tracking:** P1; Ambiguous; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Banner Metadata (Transaction 122) – Server
  Initiates](protocol.md#banner-metadata-transaction-122--server-initiates)
  (snapshot lines 338–352); [protocol.md — Banner Download (Transaction 212) –
  Client
  Initiates](protocol.md#banner-download-transaction-212--client-initiates)
  (snapshot lines 767–779)
- **Question:** Which four-byte type tags and field-153 representations are
  valid, when are they required, and how does an early-completed session
  obtain metadata without a later 121?
- **Implementation impact:** The URL and image paths are described
  conditionally without a full schema or availability sequence.
- **Close when:** Enumerate supported type/field combinations, conditions and
  ordering, including no-banner, URL, image and metadata changes.
- **Prior ledger entries:** V025, V027, V058
- **Investigation leads:**
  [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c),
  [10012f40](../mothra/evidence/hotline-server-1.9/queries/D-10012f40.c)
- **Depends on:** [GAP-025](#gap-025), [GAP-026](#gap-026)
- **Disposition:** {"progress": "Published version/type/buffer branch table
  for 122: URL metadata buffer required; non-URL banner bytes required with
  optional 153. Configured/absent/changed-banner native fixtures remain
  required.", "evidence": ["[Presence, messaging and
  administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-029

#### Settings update defaults and persistence

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Changing User Settings (Transaction 304) –
  Client
  Initiates](protocol.md#changing-user-settings-transaction-304--client-initiates)
  (snapshot lines 457–470); [protocol.md — Agreement Acceptance (Transaction
  121) – Client
  Initiates](protocol.md#agreement-acceptance-transaction-121--client-initiates)
  (snapshot lines 315–337)
- **Question:** Which omitted/empty 102/104/113/215 values reset, preserve or
  derive state, and what changes are session-only or durable?
- **Implementation impact:** The warning against patch semantics still leaves
  callers unable to construct a safe partial update.
- **Close when:** Document field-by-field update/default/persistence rules and
  before/after state plus emitted-301 fixtures.
- **Prior ledger entries:** V028, V037, V038
- **Investigation leads:**
  [10004d50](../mothra/evidence/hotline-server-1.9/queries/D-10004d50.c),
  [10016ad0](../mothra/evidence/hotline-server-1.9/queries/D-10016ad0.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Documented per-field session settings
  defaults/clearing and named byte caps, plus native 301 fan-out. Restart
  persistence and before/after native fixtures remain required.", "evidence":
  ["[Presence, messaging and
  administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-030

#### Settings option edge cases and automatic-response defaults

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Agreement Acceptance (Transaction 121) – Client
  Initiates](protocol.md#agreement-acceptance-transaction-121--client-initiates)
  (snapshot lines 315–337); [protocol.md — Changing User Settings (Transaction
  304) – Client
  Initiates](protocol.md#changing-user-settings-transaction-304--client-initiates)
  (snapshot lines 457–470); [protocol.md — Sending an Instant Message
  (Transaction 108) – Client
  Initiates](protocol.md#sending-an-instant-message-transaction-108--client-initiates)
  (snapshot lines 559–585)
- **Question:** How are unknown 113 bits, auto-response enable/disable
  transitions, missing 215 and default-response text handled across 121 and
  304?
- **Implementation impact:** The three known bits do not define all
  transitions or distinguish stored text from active automatic response.
- **Close when:** Specify bit acceptance and transition tables, default
  text/encoding, and enable/disable/update fixtures without conflating PM
  enumerants.
- **Prior ledger entries:** V028, V037, V043, V045
- **Investigation leads:**
  [10004d50](../mothra/evidence/hotline-server-1.9/queries/D-10004d50.c),
  [1000f4e0](../mothra/evidence/hotline-server-1.9/queries/D-1000f4e0.c)
- **Depends on:** [GAP-029](#gap-029)
- **Disposition:** {"progress": "Documented only option bits 0/1/2 assigned,
  auto-response clearing, exact default text bytes and 127-byte cap.
  Transition/encoding native fixtures remain required.", "evidence":
  ["[Presence, messaging and
  administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

## Presence and permissions

### GAP-031

#### Complete privilege bitmap registry

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Access Privilege Bits (Field
  110)](protocol.md#access-privilege-bits-field-110) (snapshot lines 362–400)
- **Question:** What do all unlisted bits, including 18/19 and 41-63, mean,
  and which bits are reserved, ignored or preserved?
- **Implementation impact:** The corrected observed subset cannot support full
  account editing or a complete permission model.
- **Close when:** Publish a 64-bit MSB-first registry with per-bit evidence,
  unknown/reserved distinctions and serialization/enforcement fixtures.
- **Prior ledger entries:** V029, V030, V031, V073
- **Investigation leads:**
  [10008a90](../mothra/evidence/hotline-server-1.9/queries/D-10008a90.c),
  [100053e0](../mothra/evidence/hotline-server-1.9/queries/D-100053e0.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Reconfirmed MSB-first direct bitmap access in
  all three privilege helpers. The complete named registry and enforcement
  fixtures remain required.", "evidence": ["[Native wire
  details](native-wire-details.md)", "[Batch
  01](../mothra/evidence/gap-remediation/2026-11-12/batch-01/manifest.json)",
  "[Batch
  02](../mothra/evidence/gap-remediation/2026-11-12/batch-02/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-032

#### Privilege composition and inheritance

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Access Privilege Bits (Field
  110)](protocol.md#access-privilege-bits-field-110) (snapshot lines 362–400);
  [protocol.md — File Services (Files and
  Folders)](protocol.md#file-services-files-and-folders) (snapshot lines
  614–624); [protocol.md — Managing News Structure (Transactions 380, 381,
  382) – Client Initiates
  (Admin/Mods)](protocol.md#managing-news-structure-transactions-380-381-382--client-initiates-adminmods)
  (snapshot lines 878–892)
- **Question:** How do general, folder and news helpers combine account
  rights, path-specific rules, inheritance and administrator overrides?
- **Implementation impact:** Knowing a bit number does not establish which
  request on which object is authorized.
- **Close when:** Document decision tables for the three helper domains,
  including inherited/overridden rights and forbidden operations.
- **Prior ledger entries:** V030, V053, V055, V056, V065, V073
- **Investigation leads:**
  [10008a90](../mothra/evidence/hotline-server-1.9/queries/D-10008a90.c),
  [10008ab0](../mothra/evidence/hotline-server-1.9/queries/D-10008ab0.c),
  [10008ad0](../mothra/evidence/hotline-server-1.9/queries/D-10008ad0.c)
- **Depends on:** [GAP-031](#gap-031)
- **Disposition:** {"progress": "All three accessors are byte-identical direct
  session bitmap reads, with no inheritance or admin bypass in those helpers.
  Per-operation composition tables remain required.", "evidence": ["[Native
  wire details](native-wire-details.md)", "[Batch
  01](../mothra/evidence/gap-remediation/2026-11-12/batch-01/manifest.json)",
  "[Batch
  02](../mothra/evidence/gap-remediation/2026-11-12/batch-02/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-033

#### User, room, article and reference identifier lifetimes

- **Tracking:** P1; Missing; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Retrieving the User List (Transaction 300) –
  Client
  Initiates](protocol.md#retrieving-the-user-list-transaction-300--client-initiates)
  (snapshot lines 401–426); [protocol.md — Chat Invitations (Transactions 112,
  113, 114) – Private
  Chats](protocol.md#chat-invitations-transactions-112-113-114--private-chats)
  (snapshot lines 528–547); [protocol.md — Transfer Connection and Reference
  Cleanup](protocol.md#transfer-connection-and-reference-cleanup) (snapshot
  lines 780–797)
- **Question:** What are each ID's wire width, allocation scope, sentinel
  values, wrap/reuse rules and persistence across reconnects or restart?
- **Implementation impact:** A shared numeric value can be misinterpreted
  across object/session lifetimes or truncated using the wrong width.
- **Close when:** Provide a domain-specific identifier registry with
  allocation/reuse rules and stale-ID/wrap fixtures.
- **Prior ledger entries:** V032, V042, V051, V061, V064
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c),
  [10011870](../mothra/evidence/hotline-server-1.9/queries/D-10011870.c),
  [10017f30](../mothra/evidence/hotline-server-1.9/queries/D-10017f30.c),
  [10013040](../mothra/evidence/hotline-server-1.9/queries/D-10013040.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Recovered 16-bit user counter zero-skipping
  without collision scan and separate random/counter room allocator with
  live-room collision scan. Transfer/transaction domains remain separately
  documented; stale/reuse/wrap fixtures still required.", "evidence":
  ["[Session transport contracts](session-transport-contracts.md)", "[Core
  schemas](core-field-schemas.md)", "[Batch
  07](../mothra/evidence/gap-remediation/2026-11-12/batch-07/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-034

#### Colour/status bitmap semantics

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Retrieving the User List (Transaction 300) –
  Client
  Initiates](protocol.md#retrieving-the-user-list-transaction-300--client-initiates)
  (snapshot lines 401–426); [protocol.md — User Appearance and Updates
  (Transaction 301 & 302) – Server
  Initiates](protocol.md#user-appearance-and-updates-transaction-301--302--server-initiates)
  (snapshot lines 427–445)
- **Question:** What does each field-112/packed-roster status bit represent
  and when does it change relative to settings, privileges or away state?
- **Implementation impact:** Clients can decode record lengths yet display or
  propagate incompatible presence state.
- **Close when:** Trace status construction and publish a separate status-bit
  registry plus state-transition examples.
- **Prior ledger entries:** V032, V035
- **Investigation leads:**
  [10005000](../mothra/evidence/hotline-server-1.9/queries/D-10005000.c),
  [10004f30](../mothra/evidence/hotline-server-1.9/queries/D-10004f30.c),
  [10011870](../mothra/evidence/hotline-server-1.9/queries/D-10011870.c)
- **Depends on:** [GAP-018](#gap-018)
- **Disposition:** {"progress": "Published six status masks from assembly,
  including single-bit idle extraction and exact aggregate privilege
  predicate. Status-transition native fixtures remain required.", "evidence":
  ["[Presence, messaging and
  administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-035

#### Roster and update ordering

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Retrieving the User List (Transaction 300) –
  Client
  Initiates](protocol.md#retrieving-the-user-list-transaction-300--client-initiates)
  (snapshot lines 401–426); [protocol.md — User Appearance and Updates
  (Transaction 301 & 302) – Server
  Initiates](protocol.md#user-appearance-and-updates-transaction-301--302--server-initiates)
  (snapshot lines 427–445); [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 275–300)
- **Question:** Does 301 include the subject user, when is a session visible
  in 300, and how are snapshots ordered against concurrent changes and 354?
- **Implementation impact:** A client can miss or double-apply a user when
  initial roster and updates overlap.
- **Close when:** Document eligibility, recipient and ordering rules, with
  initial login, rename and snapshot-race event traces.
- **Prior ledger entries:** V032, V034, V035, V037
- **Investigation leads:**
  [10011870](../mothra/evidence/hotline-server-1.9/queries/D-10011870.c),
  [10004f30](../mothra/evidence/hotline-server-1.9/queries/D-10004f30.c),
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c)
- **Depends on:** [GAP-025](#gap-025), [GAP-033](#gap-033),
  [GAP-034](#gap-034)
- **Disposition:** {"progress": "Traced online/ready fan-out including online
  self, and initial login 301 before new-session online flag. Snapshot
  concurrency and delivered ordering fixtures remain required.", "evidence":
  ["[Presence, messaging and
  administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-036

#### Disconnect notification and cleanup

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — User Appearance and Updates (Transaction 301 &
  302) – Server
  Initiates](protocol.md#user-appearance-and-updates-transaction-301--302--server-initiates)
  (snapshot lines 427–445); [protocol.md — Leaving a Chat Room (Transaction
  116) – Client
  Initiates](protocol.md#leaving-a-chat-room-transaction-116--client-initiates)
  (snapshot lines 506–515); [protocol.md — Disconnecting a User (Transaction
  110 & 111) – Admin/Server
  Use](protocol.md#disconnecting-a-user-transaction-110--111--adminserver-use)
  (snapshot lines 929–950)
- **Question:** Which teardown paths emit 302, which fields/recipients are
  used, and when are rooms, queued transfers and IDs cleaned up?
- **Implementation impact:** The known explicit-leave path does not specify
  global disconnect consistency.
- **Close when:** Trace normal EOF, timeout, kick and failure teardown, then
  document and fixture 302 and associated room/transfer cleanup ordering.
- **Prior ledger entries:** V035, V041, V072
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c),
  [10018620](../mothra/evidence/hotline-server-1.9/queries/D-10018620.c),
  [10015e70](../mothra/evidence/hotline-server-1.9/queries/D-10015e70.c)
- **Depends on:** [GAP-033](#gap-033), [GAP-035](#gap-035)
- **Disposition:** {"progress": "Identified native 302 producer with UID 103
  after per-room 118 and empty-room removal. Departing session is removed
  before fan-out; transfers clean via owner checks later. EOF/kick/timeout
  native traces remain required.", "evidence": ["[Presence, messaging and
  administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-037

#### Diagnostic-text output contract

- **Tracking:** P2; Ambiguous; Open; owner: Unassigned.
- **Sources:** [protocol.md — Viewing User Info (Transaction 303) – Client
  Initiates](protocol.md#viewing-user-info-transaction-303--client-initiates)
  (snapshot lines 446–456)
- **Question:** Are the 303 text labels, line endings, address representation
  and transfer summaries stable protocol content or
  build/configuration-dependent presentation?
- **Implementation impact:** An implementation may promise exact native text
  or parse it as a stable structure without evidence.
- **Close when:** Define mandatory versus descriptive content, encoding/limits
  and representative replies; explicitly state whether exact textual parity is
  required.
- **Prior ledger entries:** V036, V048
- **Investigation leads:**
  [10016150](../mothra/evidence/hotline-server-1.9/queries/D-10016150.c)
- **Depends on:** No prerequisite recorded.

## Chat and messaging

### GAP-038

#### Room access and main-chat membership

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Sending a Chat Message (Transaction 105) –
  Client
  Initiates](protocol.md#sending-a-chat-message-transaction-105--client-initiates)
  (snapshot lines 473–484); [protocol.md — Joining a Chat Room (Transaction
  115) – Client
  Initiates](protocol.md#joining-a-chat-room-transaction-115--client-initiates)
  (snapshot lines 494–505); [protocol.md — Chat Invitations (Transactions 112,
  113, 114) – Private
  Chats](protocol.md#chat-invitations-transactions-112-113-114--private-chats)
  (snapshot lines 528–547); [protocol.md — Additional Admin Privileges
  Note](protocol.md#additional-admin-privileges-note) (snapshot lines 966–974)
- **Question:** Is the main room implicit, and what authorizes join, send,
  invite, topic edit or administrative access to a private room?
- **Implementation impact:** The presence of a room ID and bit-11 check does
  not specify all membership/permission requirements.
- **Close when:** Publish room-state and permission tables with
  member/non-member, owner/admin, missing-room and main-chat cases.
- **Prior ledger entries:** V039, V040, V041, V042, V073
- **Investigation leads:**
  [1000fc20](../mothra/evidence/hotline-server-1.9/queries/D-1000fc20.c),
  [100183c0](../mothra/evidence/hotline-server-1.9/queries/D-100183c0.c),
  [10017f30](../mothra/evidence/hotline-server-1.9/queries/D-10017f30.c),
  [10018760](../mothra/evidence/hotline-server-1.9/queries/D-10018760.c)
- **Depends on:** [GAP-031](#gap-031), [GAP-032](#gap-032),
  [GAP-033](#gap-033)
- **Disposition:** {"progress": "Documented actual room handler checks: join
  and subject do not enforce invitation/owner/membership privilege in these
  handlers; main-chat routing is separate. Missing/member/nonmember native
  fixtures remain required.", "evidence": ["[Presence, messaging and
  administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-039

#### Invitation lifecycle and partial failures

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Chat Invitations (Transactions 112, 113, 114) –
  Private
  Chats](protocol.md#chat-invitations-transactions-112-113-114--private-chats)
  (snapshot lines 528–547)
- **Question:** How are duplicate target UIDs, declined/expired invitations,
  repeated joins, disconnected invitees and mixed valid/invalid target lists
  handled?
- **Implementation impact:** Repeated UID support alone does not define
  whether a request partially succeeds or how invitation state expires.
- **Close when:** Document 112/113/114 lifecycle, recipient outcomes,
  atomicity and retries; include mixed-target and disconnect/reject fixtures.
- **Prior ledger entries:** V042, V041
- **Investigation leads:**
  [10017f30](../mothra/evidence/hotline-server-1.9/queries/D-10017f30.c),
  [100188e0](../mothra/evidence/hotline-server-1.9/queries/D-100188e0.c),
  [10018340](../mothra/evidence/hotline-server-1.9/queries/D-10018340.c)
- **Depends on:** [GAP-038](#gap-038)
- **Disposition:** {"progress": "Documented notification-only invitation
  behaviour, target filtering, repeated-target iteration, refusal/automatic
  feedback and rejection routed as room chat 106. Lifecycle, partial-target
  and disconnect native fixtures remain required.", "evidence": ["[Presence,
  messaging and administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-040

#### Room snapshot and notification ordering

- **Tracking:** P1; Ambiguous; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Joining a Chat Room (Transaction 115) – Client
  Initiates](protocol.md#joining-a-chat-room-transaction-115--client-initiates)
  (snapshot lines 494–505); [protocol.md — Leaving a Chat Room (Transaction
  116) – Client
  Initiates](protocol.md#leaving-a-chat-room-transaction-116--client-initiates)
  (snapshot lines 506–515); [protocol.md — Chat Room Notifications
  (Transactions 117 & 118) – Server
  Initiates](protocol.md#chat-room-notifications-transactions-117--118--server-initiates)
  (snapshot lines 516–527)
- **Question:** When is subject 115 omitted versus empty, does the joining
  user appear in the returned roster, and how do 117/118 interleave with
  join/leave replies?
- **Implementation impact:** Two peers can construct different room membership
  from the same partially specified sequence.
- **Close when:** Specify subject presence, roster inclusion and event
  ordering, including repeated join, last-member leave and concurrent
  membership changes.
- **Prior ledger entries:** V040, V041
- **Investigation leads:**
  [100183c0](../mothra/evidence/hotline-server-1.9/queries/D-100183c0.c),
  [10018620](../mothra/evidence/hotline-server-1.9/queries/D-10018620.c)
- **Depends on:** [GAP-034](#gap-034), [GAP-038](#gap-038)
- **Disposition:** {"progress": "Documented 117 before add, post-add roster
  ACK, repeated-join no duplicate push, nonempty leave 118 and last-member
  deletion. Concurrent native fixtures remain required.", "evidence":
  ["[Presence, messaging and
  administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-041

#### Subject update validation

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Chat Subject Management (Transactions 119 &
  120)](protocol.md#chat-subject-management-transactions-119--120) (snapshot
  lines 548–556)
- **Question:** Who may change a topic, what are the maximum length/encoding
  rules, and do absent and empty 115 both clear it?
- **Implementation impact:** The current description establishes a setter/send
  site without a complete authorized update contract.
- **Close when:** Document topic permissions and input/default rules with
  denied, empty, omitted, boundary-length and successful notifications.
- **Prior ledger entries:** V041, V073
- **Investigation leads:**
  [10018760](../mothra/evidence/hotline-server-1.9/queries/D-10018760.c)
- **Depends on:** [GAP-018](#gap-018), [GAP-019](#gap-019),
  [GAP-038](#gap-038)
- **Disposition:** {"progress": "Documented subject requester unused, no
  membership/privilege check in this handler, 255-byte cap, missing/empty
  clearing and omitted empty 115 in notification. Denied/missing/boundary
  native fixtures remain required.", "evidence": ["[Presence, messaging and
  administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-042

#### Chat formatting and option 109

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Sending a Chat Message (Transaction 105) –
  Client
  Initiates](protocol.md#sending-a-chat-message-transaction-105--client-initiates)
  (snapshot lines 473–484); [protocol.md — Receiving a Chat Message
  (Transaction 106) – Server
  Initiates](protocol.md#receiving-a-chat-message-transaction-106--server-initiates)
  (snapshot lines 485–493)
- **Question:** What are option-109 values/defaults, exact server formatting,
  newline/NUL handling and recipient rules for main versus room chat?
- **Implementation impact:** The delivered text cannot be reproduced from raw
  client input using the current guide.
- **Close when:** Trace formatting and fan-out helpers and record
  ordinary/action/system, multiline and permission-denied examples with
  byte-level text rules.
- **Prior ledger entries:** V039, V048
- **Investigation leads:**
  [1000fc20](../mothra/evidence/hotline-server-1.9/queries/D-1000fc20.c)
- **Depends on:** [GAP-018](#gap-018), [GAP-019](#gap-019)
- **Disposition:** {"progress": "Documented action option exactly 1, ordinary
  fallback for other values, actual recipient helper predicates and lack of
  sender membership check in room chat handler. Exact multiline/non-ASCII
  formatting fixtures remain required.", "evidence": ["[Presence, messaging
  and administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-043

#### Private-message routing truth table

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Sending an Instant Message (Transaction 108) –
  Client
  Initiates](protocol.md#sending-an-instant-message-transaction-108--client-initiates)
  (snapshot lines 559–585)
- **Question:** How do options 1-4, both peers' refusal/automatic-response
  flags, empty text and quoted field 214 combine, including post-ACK rejection
  or automatic-response loops?
- **Implementation impact:** The guide lists enumerants but does not fully
  specify who receives what in each state.
- **Close when:** Publish a sender/recipient/options decision table with ACKs
  and emitted 104 fields for each supported case.
- **Prior ledger entries:** V043, V044, V045
- **Investigation leads:**
  [1000f4e0](../mothra/evidence/hotline-server-1.9/queries/D-1000f4e0.c)
- **Depends on:** [GAP-030](#gap-030)
- **Disposition:** {"progress": "Published PM sender/recipient/auto-response
  truth table, pre-routing ACK and permitted original delivery alongside auto
  response. Native fixtures for each branch remain required.", "evidence":
  ["[Presence, messaging and
  administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-044

#### Type-104 variant schemas

- **Tracking:** P1; Missing; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Receiving a Private Message (Transaction 104) –
  Server
  Initiates](protocol.md#receiving-a-private-message-transaction-104--server-initiates)
  (snapshot lines 586–598); [protocol.md — Disconnecting a User (Transaction
  110 & 111) – Admin/Server
  Use](protocol.md#disconnecting-a-user-transaction-110--111--adminserver-use)
  (snapshot lines 929–950); [protocol.md — Sending a Chat Message (Transaction
  105) – Client
  Initiates](protocol.md#sending-a-chat-message-transaction-105--client-initiates)
  (snapshot lines 473–484)
- **Question:** Which fields identify user messages, server/admin notices,
  refusals and kick notices; are sender UID/name/options mandatory in each
  variant?
- **Implementation impact:** A single parser cannot reliably distinguish
  notice origin or field requirements from a description of related messages.
- **Close when:** Define discriminators and per-variant required/optional
  fields, with fixtures for each known producer.
- **Prior ledger entries:** V043, V045, V046, V048, V072
- **Investigation leads:**
  [1000f4e0](../mothra/evidence/hotline-server-1.9/queries/D-1000f4e0.c),
  [1000fc20](../mothra/evidence/hotline-server-1.9/queries/D-1000fc20.c),
  [10015e70](../mothra/evidence/hotline-server-1.9/queries/D-10015e70.c)
- **Depends on:** [GAP-003](#gap-003), [GAP-043](#gap-043)
- **Disposition:** {"progress": "Separated routed user/feedback 104 schemas
  from data-only console/kick notices and chat-denial forms. All known
  producers and byte-level native variant fixtures still need completion.",
  "evidence": ["[Presence, messaging and
  administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-045

#### Flood, spam and throttling outcomes

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Sending a Chat Message (Transaction 105) –
  Client
  Initiates](protocol.md#sending-a-chat-message-transaction-105--client-initiates)
  (snapshot lines 473–484); [protocol.md — Sending an Instant Message
  (Transaction 108) – Client
  Initiates](protocol.md#sending-an-instant-message-transaction-108--client-initiates)
  (snapshot lines 559–585); [protocol.md — Broadcasting a Message (Transaction
  355) – Admin/Server
  Initiated](protocol.md#broadcasting-a-message-transaction-355--adminserver-initiated)
  (snapshot lines 951–965); [protocol.md — Changing User Settings (Transaction
  304) – Client
  Initiates](protocol.md#changing-user-settings-transaction-304--client-initiates)
  (snapshot lines 457–470)
- **Question:** What counters, windows, limits and reset conditions cause
  rejection, delayed handling, ACK-then-close or disconnection for each
  operation?
- **Implementation impact:** Ordinary traffic and retry policies can trigger
  undocumented native rate behaviour.
- **Close when:** Trace per-operation limits/configuration and publish bounded
  timing/rate fixtures plus explicit mxd policy where parity is intentionally
  different.
- **Prior ledger entries:** V038, V039, V044, V046
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c),
  [1000fc20](../mothra/evidence/hotline-server-1.9/queries/D-1000fc20.c),
  [1000f4e0](../mothra/evidence/hotline-server-1.9/queries/D-1000f4e0.c),
  [1000f990](../mothra/evidence/hotline-server-1.9/queries/D-1000f990.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Documented dispatcher request flood
  threshold/window and ban duration argument; per-operation configuration and
  timing fixtures remain required.", "evidence": ["[Native wire
  details](native-wire-details.md)", "[Batch
  01](../mothra/evidence/gap-remediation/2026-11-12/batch-01/manifest.json)",
  "[Batch
  02](../mothra/evidence/gap-remediation/2026-11-12/batch-02/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-046

#### Legacy-board data and update contract

- **Tracking:** P1; Unanswered; Open; owner: Unassigned.
- **Sources:** [protocol.md — Legacy Message Board (Transactions 101, 102,
  103)](protocol.md#legacy-message-board-transactions-101-102-103) (snapshot
  lines 599–613)
- **Question:** What are the aggregate 101 format, append/replace rules for
  103, post size limits, persistence and 102 update ordering/recipients?
- **Implementation impact:** Keeping the old board in scope does not yet
  provide an interoperable read/post/update implementation.
- **Close when:** Document board serialization and mutation semantics with
  multi-post, empty, boundary-size and update-recipient fixtures.
- **Prior ledger entries:** V047
- **Investigation leads:**
  [1000f130](../mothra/evidence/hotline-server-1.9/queries/D-1000f130.c),
  [1000f260](../mothra/evidence/hotline-server-1.9/queries/D-1000f260.c)
- **Depends on:** No prerequisite recorded.

## Files and paths

### GAP-047

#### Structured path format

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Listing Files in a Folder (Transaction 200) –
  Client
  Initiates](protocol.md#listing-files-in-a-folder-transaction-200--client-initiates)
  (snapshot lines 625–637); [protocol.md — Moving Files/Folders (Transaction
  208) – Client
  Initiates](protocol.md#moving-filesfolders-transaction-208--client-initiates)
  (snapshot lines 716–725); [protocol.md — Listing News Categories
  (Transaction 370) – Client
  Initiates](protocol.md#listing-news-categories-transaction-370--client-initiates)
  (snapshot lines 809–821)
- **Question:** What are the counts, component records, reserved bytes, root
  representation, limits and normalization rules for fields 202/212/325, and
  do those fields share a grammar?
- **Implementation impact:** Control transactions cannot address filesystem or
  news objects from unspecified opaque bytes.
- **Close when:** Trace path encoders/resolvers and provide separate field
  grammars and root/nested/non-ASCII/invalid-component fixtures; prove any
  claimed equivalence.
- **Prior ledger entries:** V049, V050, V062
- **Investigation leads:**
  [1002b0e0](../mothra/evidence/hotline-server-1.9/queries/D-1002b0e0.c),
  [100100a0](../mothra/evidence/hotline-server-1.9/queries/D-100100a0.c),
  [100102c0](../mothra/evidence/hotline-server-1.9/queries/D-100102c0.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Documented file-path component framing and
  different last-component/traversal handling. News-path equivalence,
  sanitization and invalid-component fixtures remain required.", "evidence":
  ["[Native wire details](native-wire-details.md)", "[Batch
  01](../mothra/evidence/gap-remediation/2026-11-12/batch-01/manifest.json)",
  "[Batch
  02](../mothra/evidence/gap-remediation/2026-11-12/batch-02/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-048

#### File-list record layout

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Listing Files in a Folder (Transaction 200) –
  Client
  Initiates](protocol.md#listing-files-in-a-folder-transaction-200--client-initiates)
  (snapshot lines 625–637)
- **Question:** What are the exact field-200 offsets, metadata/tag meanings,
  size widths, entry kinds, sort order and empty-list representation?
- **Implementation impact:** A client cannot render or navigate file listings
  from the current field ID alone.
- **Close when:** Specify the nested record grammar and listing order with
  file/folder/alias/non-ASCII/empty/multiple-entry fixtures.
- **Prior ledger entries:** V049
- **Investigation leads:**
  [100100a0](../mothra/evidence/hotline-server-1.9/queries/D-100100a0.c)
- **Depends on:** [GAP-018](#gap-018), [GAP-047](#gap-047)
- **Disposition:** {"progress": "Documented the 20-byte fixed file-list
  header, name length, repeated 200 records and builder iteration.
  Target-kind/listing-order fixtures remain required.", "evidence": ["[Native
  wire details](native-wire-details.md)", "[Batch
  01](../mothra/evidence/gap-remediation/2026-11-12/batch-01/manifest.json)",
  "[Batch
  02](../mothra/evidence/gap-remediation/2026-11-12/batch-02/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-049

#### File-info variant matrix

- **Tracking:** P1; Ambiguous; Open; owner: Unassigned.
- **Sources:** [protocol.md — Getting File/Folder Info (Transaction 206) –
  Client
  Initiates](protocol.md#getting-filefolder-info-transaction-206--client-initiates)
  (snapshot lines 691–705)
- **Question:** Which fields and widths occur for files, folders, aliases and
  special items, including descriptive 205/206, raw 213 and size/date
  omissions?
- **Implementation impact:** Removing the universal four-character assumption
  still leaves multiple incompatible response schemas.
- **Close when:** Publish a target-kind/field-presence/type matrix with
  representative metadata and empty/unknown-value cases.
- **Prior ledger entries:** V017, V054
- **Investigation leads:**
  [10016ba0](../mothra/evidence/hotline-server-1.9/queries/D-10016ba0.c)
- **Depends on:** [GAP-020](#gap-020)

### GAP-050

#### Delete semantics and failures

- **Tracking:** P1; Unanswered; Open; owner: Unassigned.
- **Sources:** [protocol.md — Deleting a File (Transaction 204) – Client
  Initiates](protocol.md#deleting-a-file-transaction-204--client-initiates)
  (snapshot lines 669–679)
- **Question:** Can 204 remove nonempty folders, which errors apply to
  missing/root/protected targets, and what state/notifications follow a
  partial filesystem failure?
- **Implementation impact:** A successful ACK is not a complete
  destructive-operation contract.
- **Close when:** Trace deletion helpers and define permission, recursion,
  failure/atomicity and refresh outcomes with controlled fixtures.
- **Prior ledger entries:** V053
- **Investigation leads:**
  [100140e0](../mothra/evidence/hotline-server-1.9/queries/D-100140e0.c)
- **Depends on:** [GAP-032](#gap-032), [GAP-047](#gap-047)

### GAP-051

#### Folder creation semantics

- **Tracking:** P1; Unanswered; Open; owner: Unassigned.
- **Sources:** [protocol.md — Creating a New Folder (Transaction 205) – Client
  Initiates](protocol.md#creating-a-new-folder-transaction-205--client-initiates)
  (snapshot lines 680–690)
- **Question:** How are name/path defaults, existing names, invalid names,
  missing parents and per-folder privilege checks handled by 205?
- **Implementation impact:** An encoder can issue a valid TLV request but
  cannot predict creation or error outcomes.
- **Close when:** Document input conditions, conflicts, permission and
  success/error responses for 205 with exact fixtures.
- **Prior ledger entries:** V053, V050
- **Investigation leads:**
  [100143f0](../mothra/evidence/hotline-server-1.9/queries/D-100143f0.c)
- **Depends on:** [GAP-032](#gap-032), [GAP-047](#gap-047)

### GAP-052

#### Rename/comment partial updates

- **Tracking:** P1; Unanswered; Open; owner: Unassigned.
- **Sources:** [protocol.md — Setting File/Folder Info (Transaction 207) –
  Client
  Initiates](protocol.md#setting-filefolder-info-transaction-207--client-initiates)
  (snapshot lines 706–715)
- **Question:** Do omitted/empty 210 and 211 preserve, clear or reject values,
  and what happens when one permitted sub-operation succeeds and another
  fails?
- **Implementation impact:** The guide allows both fields without defining
  partial success, atomicity or comment/rename permission combinations.
- **Close when:** Publish the field-presence/permission/conflict matrix and
  before/after outcomes for rename-only, comment-only and combined requests.
- **Prior ledger entries:** V053, V054
- **Investigation leads:**
  [100170c0](../mothra/evidence/hotline-server-1.9/queries/D-100170c0.c)
- **Depends on:** [GAP-016](#gap-016), [GAP-032](#gap-032),
  [GAP-047](#gap-047)

### GAP-053

#### Move collision and metadata behaviour

- **Tracking:** P1; Unanswered; Open; owner: Unassigned.
- **Sources:** [protocol.md — Moving Files/Folders (Transaction 208) – Client
  Initiates](protocol.md#moving-filesfolders-transaction-208--client-initiates)
  (snapshot lines 716–725)
- **Question:** How do destination conflicts, aliases, cross-volume moves and
  interrupted filesystem operations affect 208 and its ACK/error result?
- **Implementation impact:** The operation name does not establish overwrite,
  rollback or metadata preservation rules.
- **Close when:** Document resolver and move outcomes, including
  same-location, collision and partial-failure fixtures; bound any
  platform-specific semantics.
- **Prior ledger entries:** V053, V050
- **Investigation leads:**
  [100177d0](../mothra/evidence/hotline-server-1.9/queries/D-100177d0.c)
- **Depends on:** [GAP-047](#gap-047)

### GAP-054

#### Alias creation and resolution

- **Tracking:** P1; Unanswered; Open; owner: Unassigned.
- **Sources:** [protocol.md — Creating an Alias (Shortcut) (Transaction 209) –
  Client
  Initiates](protocol.md#creating-an-alias-shortcut-transaction-209--client-initiates)
  (snapshot lines 726–735)
- **Question:** What alias object is created, how is its name chosen, and when
  do listing/info/download resolve its target rather than expose the alias
  itself?
- **Implementation impact:** Portable symlink assumptions can produce
  different list, metadata and transfer results.
- **Close when:** Trace alias creation/resolution and document
  source/destination/default-name rules with live, missing-target and
  alias-to-alias cases.
- **Prior ledger entries:** V053, V054
- **Investigation leads:**
  [10017c10](../mothra/evidence/hotline-server-1.9/queries/D-10017c10.c),
  [10016ba0](../mothra/evidence/hotline-server-1.9/queries/D-10016ba0.c),
  [100121a0](../mothra/evidence/hotline-server-1.9/queries/D-100121a0.c)
- **Depends on:** [GAP-047](#gap-047), [GAP-049](#gap-049)

## Transfer protocol

### GAP-055

#### Sixteen-byte HTXF header and reference matching

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Transfer Connection and Reference
  Cleanup](protocol.md#transfer-connection-and-reference-cleanup) (snapshot
  lines 780–797); [protocol.md — Banner Download (Transaction 212) – Client
  Initiates](protocol.md#banner-download-transaction-212--client-initiates)
  (snapshot lines 767–779)
- **Question:** What are every offset/width, type value, reserved field and
  reference-matching rule, and how do unknown, expired or other-session
  references fail?
- **Implementation impact:** No interoperable transfer handshake can be
  encoded from the current partial description.
- **Close when:** Publish the complete header plus upload/download/banner
  matching and failure rules with valid/invalid reference and type fixtures.
- **Prior ledger entries:** V058, V059, V060
- **Investigation leads:**
  [1000bd20](../mothra/evidence/hotline-server-1.9/queries/D-1000bd20.c)
- **Depends on:** [GAP-009](#gap-009), [GAP-010](#gap-010),
  [GAP-033](#gap-033)
- **Disposition:** {"progress": "Published 16-byte HTXF offsets, reference
  parity/selector routing, ordinary-upload size use, unexamined trailing bytes
  and reference rejection/lookup behaviour. Native valid/invalid header
  fixtures and endpoint entry-path sequencing remain required.", "evidence":
  ["[Transfer contracts](transfer-contracts.md)", "[Batch
  04](../mothra/evidence/gap-remediation/2026-11-12/batch-04/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-056

#### Flattened file and fork stream

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Transfer Connection and Reference
  Cleanup](protocol.md#transfer-connection-and-reference-cleanup) (snapshot
  lines 780–797); [protocol.md — Downloading a File (Transaction 202) – Client
  Initiates](protocol.md#downloading-a-file-transaction-202--client-initiates)
  (snapshot lines 638–655); [protocol.md — Uploading a File (Transaction 203)
  – Client
  Initiates](protocol.md#uploading-a-file-transaction-203--client-initiates)
  (snapshot lines 656–668)
- **Question:** What are stream headers, metadata/fork records, lengths,
  padding, order and termination for ordinary Mac files versus raw/preview
  transfers?
- **Implementation impact:** The control ACK does not specify actual file
  contents or preserve resource forks.
- **Close when:** Trace transfer workers and publish byte grammars plus
  data/resource-fork, empty-file and metadata round-trip fixtures.
- **Prior ledger entries:** V051, V052, V059
- **Investigation leads:**
  [100121a0](../mothra/evidence/hotline-server-1.9/queries/D-100121a0.c),
  [100130f0](../mothra/evidence/hotline-server-1.9/queries/D-100130f0.c),
  [1000bd20](../mothra/evidence/hotline-server-1.9/queries/D-1000bd20.c)
- **Depends on:** [GAP-055](#gap-055)
- **Disposition:** {"progress": "Published 24-byte FILP header, 16-byte fork
  headers, INFO metadata boundaries and ordinary upload parser behaviour. Full
  metadata meaning, fork/metadata round-trip and empty-file fixtures remain
  required.", "evidence": ["[Transfer contracts](transfer-contracts.md)",
  "[Batch
  04](../mothra/evidence/gap-remediation/2026-11-12/batch-04/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-057

#### Download and preview response conditions

- **Tracking:** P1; Ambiguous; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Downloading a File (Transaction 202) – Client
  Initiates](protocol.md#downloading-a-file-transaction-202--client-initiates)
  (snapshot lines 638–655)
- **Question:** Which 204 values/defaults choose each mode, how are 108/207
  calculated and when are 107/116 omitted or mandatory?
- **Implementation impact:** A successful zero-size response or differing
  sizes cannot yet be interpreted consistently.
- **Close when:** Document mode and response-presence/size calculation tables
  with zero-size, preview, ordinary and queued fixtures.
- **Prior ledger entries:** V051
- **Investigation leads:**
  [100121a0](../mothra/evidence/hotline-server-1.9/queries/D-100121a0.c)
- **Depends on:** [GAP-055](#gap-055)
- **Disposition:** {"progress": "Recorded ordinary flattened size formula,
  resume reduction, raw preview bypass and queued reference handling. Complete
  mode/field-presence and zero-size/preview/queue native fixtures remain
  required.", "evidence": ["[Transfer contracts](transfer-contracts.md)",
  "[Batch
  04](../mothra/evidence/gap-remediation/2026-11-12/batch-04/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-058

#### Resume-data format and offset negotiation

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Uploading a File (Transaction 203) – Client
  Initiates](protocol.md#uploading-a-file-transaction-203--client-initiates)
  (snapshot lines 656–668); [protocol.md — Downloading a File (Transaction
  202) – Client
  Initiates](protocol.md#downloading-a-file-transaction-202--client-initiates)
  (snapshot lines 638–655)
- **Question:** What is the nested field-203 grammar, which forks/offsets it
  covers, and how are mismatch, completed and missing partial files handled?
- **Implementation impact:** Neither upload nor download resume can be
  implemented from a field label and mode value.
- **Close when:** Trace both directions and publish offset/fork validation and
  continuation fixtures, including fresh/resumed/completed and inconsistent
  state.
- **Prior ledger entries:** V051, V052
- **Investigation leads:**
  [100121a0](../mothra/evidence/hotline-server-1.9/queries/D-100121a0.c),
  [100130f0](../mothra/evidence/hotline-server-1.9/queries/D-100130f0.c)
- **Depends on:** [GAP-055](#gap-055), [GAP-056](#gap-056)
- **Disposition:** {"progress": "Recovered RFLT 42-byte header and 16-byte
  DATA/MACR entries, the 74-byte upload-resume output, offsets and native
  length-check limitations. Duplicate, inconsistent and boundary offset native
  fixtures remain required.", "evidence": ["[Transfer
  contracts](transfer-contracts.md)", "[Batch
  04](../mothra/evidence/gap-remediation/2026-11-12/batch-04/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-059

#### Folder-download stream state machine

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Downloading an Entire Folder (Transaction 210) –
  Client
  Initiates](protocol.md#downloading-an-entire-folder-transaction-210--client-initiates)
  (snapshot lines 736–751)
- **Question:** What are entry/path records, actions, traversal order,
  aggregate counts/sizes, skips and resume transitions for 210?
- **Implementation impact:** The known initiation fields do not describe a
  recursive transfer implementation.
- **Close when:** Provide a direction-specific state machine and complete
  small nested-folder stream fixtures, including empty, skipped and resumed
  entries.
- **Prior ledger entries:** V055, V057
- **Investigation leads:**
  [10012850](../mothra/evidence/hotline-server-1.9/queries/D-10012850.c)
- **Depends on:** [GAP-047](#gap-047), [GAP-055](#gap-055),
  [GAP-056](#gap-056)
- **Disposition:** {"progress": "Published direction-specific download control
  states, fresh/resume/skip exchange, per-file BE32 lengths and traversal
  completion. Exact item-descriptor offsets and nested/empty/skip/resume
  native fixtures remain required.", "evidence": ["[News
  contracts](news-contracts.md)", "[Folder
  states](transfer-contracts.md#folder-download-control-states)", "[Batch
  05](../mothra/evidence/gap-remediation/2026-11-12/batch-05/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-060

#### Folder-upload stream state machine

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Uploading an Entire Folder (Transaction 213) –
  Client
  Initiates](protocol.md#uploading-an-entire-folder-transaction-213--client-initiates)
  (snapshot lines 752–766)
- **Question:** How are directories/files framed, acknowledged, counted,
  resumed or rolled back in 213, and how do empty transfers complete?
- **Implementation impact:** Assuming the inverse of download would invent
  unverified control and persistence semantics.
- **Close when:** Provide the upload-specific state machine with nested,
  empty, partial and resumed transfer fixtures, including metadata and
  conflict handling.
- **Prior ledger entries:** V056, V057
- **Investigation leads:**
  [10013930](../mothra/evidence/hotline-server-1.9/queries/D-10013930.c)
- **Depends on:** [GAP-047](#gap-047), [GAP-055](#gap-055),
  [GAP-056](#gap-056)
- **Disposition:** {"progress": "Published upload descriptor framing,
  flag/path parsing, create/resume/skip controls, stream lengths,
  processed-item completion and timers. Invalid/conflicting/partial/nested
  native fixtures remain required.", "evidence": ["[News
  contracts](news-contracts.md)", "[Folder
  states](transfer-contracts.md#folder-download-control-states)", "[Batch
  05](../mothra/evidence/gap-remediation/2026-11-12/batch-05/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-061

#### Queue notification 211 and scheduling

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Downloading a File (Transaction 202) – Client
  Initiates](protocol.md#downloading-a-file-transaction-202--client-initiates)
  (snapshot lines 638–655); [protocol.md — Downloading an Entire Folder
  (Transaction 210) – Client
  Initiates](protocol.md#downloading-an-entire-folder-transaction-210--client-initiates)
  (snapshot lines 736–751); [protocol.md — File Services (Files and
  Folders)](protocol.md#file-services-files-and-folders) (snapshot lines
  614–624)
- **Question:** What fields/type/ordering does 211 use, how do queue positions
  and slots change, and when should the client connect, wait or retry?
- **Implementation impact:** Queued transfers cannot make reliable progress
  using only an initial waiting-count field.
- **Close when:** Trace queue workers and capture admission, advancement,
  notification, timeout and fairness/order behaviour under a small controlled
  queue.
- **Prior ledger entries:** V051, V055, V060
- **Investigation leads:**
  [100121a0](../mothra/evidence/hotline-server-1.9/queries/D-100121a0.c),
  [10012850](../mothra/evidence/hotline-server-1.9/queries/D-10012850.c)
- **Depends on:** [GAP-055](#gap-055)
- **Disposition:** {"progress": "Traced producer 1000cfa0: notification 211
  contains four-byte 107 and numeric 116, zero on admission and updated
  nonzero waiting positions. Concurrent scheduling, fairness, limit
  configuration and queue races still require runtime fixtures.", "evidence":
  ["[Transfer contracts](transfer-contracts.md)", "[Batch
  04](../mothra/evidence/gap-remediation/2026-11-12/batch-04/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-062

#### Reference cleanup 214 semantics

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Transfer Connection and Reference
  Cleanup](protocol.md#transfer-connection-and-reference-cleanup) (snapshot
  lines 780–797)
- **Question:** Does 214 cancel queued/active/completed transfers, who owns
  the reference, and how are zero, unknown, duplicate or racing requests
  acknowledged?
- **Implementation impact:** A provisional cancellation label does not specify
  safe client retry or resource lifecycle behaviour.
- **Close when:** Trace the cleanup helper and publish reference-state/outcome
  tables and cancellation/completion race fixtures.
- **Prior ledger entries:** V061
- **Investigation leads:**
  [10013040](../mothra/evidence/hotline-server-1.9/queries/D-10013040.c)
- **Depends on:** [GAP-033](#gap-033), [GAP-055](#gap-055),
  [GAP-061](#gap-061)
- **Disposition:** {"progress": "Traced 214 helper search order, session-owner
  checks, download-only scope, cleanup resources and unconditional handler ACK
  despite missing/unowned references. Cancellation/completion race and
  repeated-cleanup native fixtures remain required.", "evidence": ["[Transfer
  contracts](transfer-contracts.md)", "[Batch
  04](../mothra/evidence/gap-remediation/2026-11-12/batch-04/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-063

#### Banner data stream and absence

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Banner Download (Transaction 212) – Client
  Initiates](protocol.md#banner-download-transaction-212--client-initiates)
  (snapshot lines 767–779); [protocol.md — Banner Metadata (Transaction 122) –
  Server
  Initiates](protocol.md#banner-metadata-transaction-122--server-initiates)
  (snapshot lines 338–352)
- **Question:** Is banner content raw or flattened, what exact bytes/size are
  transferred, and what happens if a configured banner changes or disappears
  after metadata delivery?
- **Implementation impact:** Metadata type and an HTXF branch are insufficient
  to fetch a displayable banner reliably.
- **Close when:** Specify the banner stream, reference/size lifetime and
  missing/changed-banner errors for supported metadata types.
- **Prior ledger entries:** V025, V058, V059
- **Investigation leads:**
  [10012f40](../mothra/evidence/hotline-server-1.9/queries/D-10012f40.c),
  [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c),
  [1000bd20](../mothra/evidence/hotline-server-1.9/queries/D-1000bd20.c)
- **Depends on:** [GAP-028](#gap-028), [GAP-055](#gap-055)
- **Disposition:** {"progress": "Traced banner worker raw current-buffer
  delivery and send-time size lookup, plus absent-buffer guard and pending
  timeout. Changed/missing banner and stream lifetime fixtures remain
  required.", "evidence": ["[Transfer contracts](transfer-contracts.md)",
  "[Batch
  04](../mothra/evidence/gap-remediation/2026-11-12/batch-04/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-064

#### Transfer completion, failure and persistence

- **Tracking:** P1; Missing; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — File Services (Files and
  Folders)](protocol.md#file-services-files-and-folders) (snapshot lines
  614–624); [protocol.md — Transfer Connection and Reference
  Cleanup](protocol.md#transfer-connection-and-reference-cleanup) (snapshot
  lines 780–797); [protocol.md — Uploading an Entire Folder (Transaction 213)
  – Client
  Initiates](protocol.md#uploading-an-entire-folder-transaction-213--client-initiates)
  (snapshot lines 752–766)
- **Question:** Which byte counts or markers prove completion, and what
  survives EOF, timeout, reconnect, disk-full, oversized files or an
  interrupted upload?
- **Implementation impact:** A transfer can appear complete while lacking data
  or leave incompatible resumable state after failure.
- **Close when:** Define completion and interruption outcomes per direction,
  including large-size representation and partial-file retention, with
  controlled failure fixtures.
- **Prior ledger entries:** V051, V052, V057, V059, V061
- **Investigation leads:**
  [1000bd20](../mothra/evidence/hotline-server-1.9/queries/D-1000bd20.c),
  [100130f0](../mothra/evidence/hotline-server-1.9/queries/D-100130f0.c),
  [10013930](../mothra/evidence/hotline-server-1.9/queries/D-10013930.c)
- **Depends on:** [GAP-055](#gap-055), [GAP-056](#gap-056)
- **Disposition:** {"progress": "Recorded ordinary upload byte-count
  completion, parser finalization and closure, ordinary download enqueue
  completion and worker timeouts. Metadata restoration, partial-file
  retention, flush guarantees and controlled failure fixtures remain
  required.", "evidence": ["[Transfer contracts](transfer-contracts.md)",
  "[Batch
  04](../mothra/evidence/gap-remediation/2026-11-12/batch-04/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

## News

### GAP-065

#### Category records and version threshold

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Listing News Categories (Transaction 370) –
  Client
  Initiates](protocol.md#listing-news-categories-transaction-370--client-initiates)
  (snapshot lines 809–821); [protocol.md — News
  Hierarchy](protocol.md#news-hierarchy) (snapshot lines 800–808)
- **Question:** What are nested 320/323 record layouts and kind/count fields,
  and what peers actually send version values around literal threshold 15?
- **Implementation impact:** A known top-level field switch does not permit
  decoding or justify a displayed-version mapping.
- **Close when:** Provide both record grammars with boundary-version and mixed
  folder/category fixtures; identify peer evidence separately.
- **Prior ledger entries:** V062, M002
- **Investigation leads:**
  [10005710](../mothra/evidence/hotline-server-1.9/queries/D-10005710.c),
  [100102c0](../mothra/evidence/hotline-server-1.9/queries/D-100102c0.c)
- **Depends on:** [GAP-018](#gap-018), [GAP-047](#gap-047)
- **Disposition:** {"progress": "Verified version threshold 15, legacy
  marker/name form and modern folder/category offsets against assembly.
  Recorded emitted unnamed tail bytes instead of declaring zero padding.
  Opaque metadata meanings and version/mixed-object fixtures remain
  required.", "evidence": ["[News contracts](news-contracts.md)", "[Folder
  states](transfer-contracts.md#folder-download-control-states)", "[Batch
  05](../mothra/evidence/gap-remediation/2026-11-12/batch-05/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-066

#### Serialized article-list format

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Listing News Articles (Transaction 371) – Client
  Initiates](protocol.md#listing-news-articles-transaction-371--client-initiates)
  (snapshot lines 822–832)
- **Question:** What are field-321 headers, article records, counts, flags,
  dates, flavour records, ordering and size limits?
- **Implementation impact:** The correction to one containing field still
  leaves the article list impossible to decode.
- **Close when:** Trace the serializer and document nested offsets,
  cardinalities and empty/multiple/threaded article-list fixtures.
- **Prior ledger entries:** V063
- **Investigation leads:**
  [100059e0](../mothra/evidence/hotline-server-1.9/queries/D-100059e0.c)
- **Depends on:** [GAP-018](#gap-018), [GAP-020](#gap-020)
- **Disposition:** {"progress": "Recovered the ten-byte list header, public
  IDs/date/link/word/flavour count, bounded Pascal title/poster/flavour
  entries and 16-bit listed body sizes. Cached/rebuilt and
  empty/multiple/threaded fixtures remain required.", "evidence": ["[News
  contracts](news-contracts.md)", "[Folder
  states](transfer-contracts.md#folder-download-control-states)", "[Batch
  05](../mothra/evidence/gap-remediation/2026-11-12/batch-05/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-067

#### Article navigation, flavour and date semantics

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Reading a News Article (Transaction 400) –
  Client
  Initiates](protocol.md#reading-a-news-article-transaction-400--client-initiates)
  (snapshot lines 833–854)
- **Question:** What precisely do 331/332/335/336 identify, what are
  sentinel/end conditions, which flavours work and how is 330 constructed?
- **Implementation impact:** A client cannot traverse threads or interpret all
  article data from field names alone.
- **Close when:** Document navigation graphs, flavour selection/errors and
  news-date conversion using branching-thread, absent-body and boundary
  fixtures.
- **Prior ledger entries:** V064, V017
- **Investigation leads:**
  [10005ac0](../mothra/evidence/hotline-server-1.9/queries/D-10005ac0.c),
  [10011580](../mothra/evidence/hotline-server-1.9/queries/D-10011580.c)
- **Depends on:** [GAP-020](#gap-020), [GAP-066](#gap-066)
- **Disposition:** {"progress": "Traced exact flavour matching, separate
  search bounds, native link-to-public-ID mapping, parent/child links and
  fixed-year news dates. Complete navigation labels, flavour error translation
  and graph/boundary fixtures remain required.", "evidence": ["[News
  contracts](news-contracts.md)", "[Folder
  states](transfer-contracts.md#folder-download-control-states)", "[Batch
  05](../mothra/evidence/gap-remediation/2026-11-12/batch-05/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-068

#### Posting and new-article discovery

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Posting a News Article (Transaction 410) –
  Client
  Initiates](protocol.md#posting-a-news-article-transaction-410--client-initiates)
  (snapshot lines 855–866)
- **Question:** How do omitted/zero 326, flags 334, supported flavours and
  body limits affect creation, and how is the resulting ID or update
  discovered after ACK?
- **Implementation impact:** Posting can succeed without any specified way to
  locate the new article or distinguish parent relationships.
- **Close when:** Publish post field/default and flag tables plus
  discovery/notification/persistence behaviour for new threads, replies and
  invalid requests.
- **Prior ledger entries:** V064, V065, V066
- **Investigation leads:**
  [10010470](../mothra/evidence/hotline-server-1.9/queries/D-10010470.c)
- **Depends on:** [GAP-018](#gap-018), [GAP-067](#gap-067)
- **Disposition:** {"progress": "Traced post input caps/default sources and
  article creation before body validation/write; documented empty ACK without
  returned new ID and cache invalidation. Flags, discovery/client behaviour
  and new-thread/reply/error fixtures remain required.", "evidence": ["[News
  contracts](news-contracts.md)", "[Folder
  states](transfer-contracts.md#folder-download-control-states)", "[Batch
  05](../mothra/evidence/gap-remediation/2026-11-12/batch-05/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-069

#### Recursive article deletion

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Deleting a News Article (Transaction 411) –
  Client
  Initiates](protocol.md#deleting-a-news-article-transaction-411--client-initiates)
  (snapshot lines 867–877)
- **Question:** What values/widths does 337 accept, and how are descendants,
  orphans, navigation IDs and notifications updated on success or partial
  failure?
- **Implementation impact:** The guide intentionally removed guessed deletion
  semantics but provides no replacement contract.
- **Close when:** Trace deletion/index helpers and document
  nonrecursive/recursive outcomes with parent, leaf and failure fixtures.
- **Prior ledger entries:** V065, V066
- **Investigation leads:**
  [100108a0](../mothra/evidence/hotline-server-1.9/queries/D-100108a0.c)
- **Depends on:** [GAP-067](#gap-067)
- **Disposition:** {"progress": "Traced zero/nonzero recursive flag, recursive
  descendant helper and nonrecursive child-link rewiring with cache
  invalidation. Exact resulting graph and controlled persistence/failure
  fixtures remain required.", "evidence": ["[News
  contracts](news-contracts.md)", "[Folder
  states](transfer-contracts.md#folder-download-control-states)", "[Batch
  05](../mothra/evidence/gap-remediation/2026-11-12/batch-05/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-070

#### News hierarchy and structure mutations

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — News Hierarchy](protocol.md#news-hierarchy)
  (snapshot lines 800–808); [protocol.md — Managing News Structure
  (Transactions 380, 381, 382) – Client Initiates
  (Admin/Mods)](protocol.md#managing-news-structure-transactions-380-381-382--client-initiates-adminmods)
  (snapshot lines 878–892)
- **Question:** What nesting/type/depth rules apply, how are paths and name
  fields interpreted, and what happens on create/delete conflicts or subtree
  failures?
- **Implementation impact:** A fixed four-tier assumption was withdrawn
  without a validated structural model for mxd.
- **Close when:** Publish object/path grammars and 380/381/382
  permission/conflict/recursive-effect tables with nested and failure
  fixtures.
- **Prior ledger entries:** V050, V065, V066
- **Investigation leads:**
  [10010b70](../mothra/evidence/hotline-server-1.9/queries/D-10010b70.c),
  [10010ee0](../mothra/evidence/hotline-server-1.9/queries/D-10010ee0.c),
  [10011110](../mothra/evidence/hotline-server-1.9/queries/D-10011110.c)
- **Depends on:** [GAP-032](#gap-032), [GAP-047](#gap-047),
  [GAP-065](#gap-065)
- **Disposition:** {"progress": "Confirmed use of structured filesystem
  resolver under a news-specific root; no fixed four-tier hierarchy inferred.
  Complete structure mutation permission/conflict/recursive-effect tables and
  fixtures remain required.", "evidence": ["[News
  contracts](news-contracts.md)", "[Folder
  states](transfer-contracts.md#folder-download-control-states)", "[Batch
  05](../mothra/evidence/gap-remediation/2026-11-12/batch-05/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

## Administration

### GAP-071

#### Account field 111

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — User Account Management – Client Initiates
  (Admin) (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 895–928)
- **Question:** What is field 111's wire type, presence/default rule, stored
  meaning and effect on 350/353?
- **Implementation impact:** The documented account schema explicitly contains
  a field mxd cannot yet interpret or preserve correctly.
- **Close when:** Trace reads/storage/use of 111 and add an account field
  schema with absent, empty and representative-value fixtures.
- **Prior ledger entries:** V069
- **Investigation leads:**
  [100146f0](../mothra/evidence/hotline-server-1.9/queries/D-100146f0.c),
  [10014df0](../mothra/evidence/hotline-server-1.9/queries/D-10014df0.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Located opaque field 111 in the 734-byte
  account record, with a 64-byte input cap. Human meaning and use remain
  unproved.", "evidence": ["[Native wire details](native-wire-details.md)",
  "[Batch
  01](../mothra/evidence/gap-remediation/2026-11-12/batch-01/manifest.json)",
  "[Batch
  02](../mothra/evidence/gap-remediation/2026-11-12/batch-02/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-072

#### Account update, placeholder and identity rules

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — User Account Management – Client Initiates
  (Admin) (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 895–928)
- **Question:** How are target login, rename, absent/empty password, literal
  x, duplicate names, protected-account deletion and partial updates handled?
- **Implementation impact:** Treating the 352 placeholder as an
  unchanged-password token could overwrite credentials or target the wrong
  account.
- **Close when:** Define 350-353 mutation/default/atomicity rules with
  existing-password preservation, literal-x, rename/conflict and
  protected-delete fixtures.
- **Prior ledger entries:** V067, V068, V069, V070
- **Investigation leads:**
  [100146f0](../mothra/evidence/hotline-server-1.9/queries/D-100146f0.c),
  [100149e0](../mothra/evidence/hotline-server-1.9/queries/D-100149e0.c),
  [10014bc0](../mothra/evidence/hotline-server-1.9/queries/D-10014bc0.c),
  [10014df0](../mothra/evidence/hotline-server-1.9/queries/D-10014df0.c)
- **Depends on:** [GAP-016](#gap-016), [GAP-022](#gap-022),
  [GAP-071](#gap-071)
- **Disposition:** {"progress": "Documented exact 353 NUL preservation
  sentinel, literal-x replacement, clearing defaults and copy caps. Full
  350-353 conflict/identity/atomicity fixtures remain required.", "evidence":
  ["[Native wire details](native-wire-details.md)", "[Batch
  01](../mothra/evidence/gap-remediation/2026-11-12/batch-01/manifest.json)",
  "[Batch
  02](../mothra/evidence/gap-remediation/2026-11-12/batch-02/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-073

#### Account changes and active sessions

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — User Account Management – Client Initiates
  (Admin) (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 895–928); [protocol.md — User Access Privileges (Transaction
  354) – Server
  Initiates](protocol.md#user-access-privileges-transaction-354--server-initiates)
  (snapshot lines 353–361); [protocol.md — Additional Admin Privileges
  Note](protocol.md#additional-admin-privileges-note) (snapshot lines 966–974)
- **Question:** When do edited privileges, names or passwords affect current
  sessions, does deletion disconnect them, and what 354/301 notifications
  occur?
- **Implementation impact:** Stored account state and live authorization may
  diverge in ways clients and tests cannot predict.
- **Close when:** Trace account/session propagation and record
  live-edit/delete event sequences and persistence across reconnect/restart.
- **Prior ledger entries:** V029, V035, V070
- **Investigation leads:**
  [10014df0](../mothra/evidence/hotline-server-1.9/queries/D-10014df0.c),
  [100149e0](../mothra/evidence/hotline-server-1.9/queries/D-100149e0.c),
  [10004f30](../mothra/evidence/hotline-server-1.9/queries/D-10004f30.c)
- **Depends on:** [GAP-031](#gap-031), [GAP-072](#gap-072)
- **Disposition:** {"progress": "Traced connected-session privilege updates
  through 354 and roster helper invocation after effective identity/access
  changes. Delete paths and delivered event/persistence fixtures remain
  required.", "evidence": ["[Native wire details](native-wire-details.md)",
  "[Batch
  01](../mothra/evidence/gap-remediation/2026-11-12/batch-01/manifest.json)",
  "[Batch
  02](../mothra/evidence/gap-remediation/2026-11-12/batch-02/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-074

#### Kick/ban option branches

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Disconnecting a User (Transaction 110 & 111) –
  Admin/Server
  Use](protocol.md#disconnecting-a-user-transaction-110--111--adminserver-use)
  (snapshot lines 929–950)
- **Question:** What exactly do options 1 and 2 do, including identity
  matching, ranges/duration, optional data 101, reconnection and protected
  users?
- **Implementation impact:** Enumerated branches were observed but
  account-ban/IP-ban semantics remain guesses.
- **Close when:** Trace both ban helpers and publish
  option/outcome/expiry/protection rules with kick-only and both branch
  fixtures.
- **Prior ledger entries:** V071, V072, V073
- **Investigation leads:**
  [10015e70](../mothra/evidence/hotline-server-1.9/queries/D-10015e70.c)
- **Depends on:** [GAP-031](#gap-031), [GAP-036](#gap-036)
- **Disposition:** {"progress": "Traced option 1 timed 1800-second address ban
  and option 2 persisted version-2 address-ban list; plain kick, missing
  target and protection branches documented. Expiry/restart/protected native
  fixtures remain required.", "evidence": ["[Presence, messaging and
  administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-075

#### Standalone transaction 111

- **Tracking:** P2; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Disconnecting a User (Transaction 110 & 111) –
  Admin/Server
  Use](protocol.md#disconnecting-a-user-transaction-110--111--adminserver-use)
  (snapshot lines 929–950); [protocol.md — Additional Observed Requests and
  Scope Gaps](protocol.md#additional-observed-requests-and-scope-gaps)
  (snapshot lines 975–1012)
- **Question:** Does any native producer actually emit 111, under which
  conditions, with what fields and delivery/closure ordering?
- **Implementation impact:** A retained catalogue entry cannot yet be
  implemented or declared absent with confidence.
- **Close when:** Locate a producer and capture its schema/sequence, or
  document a bounded negative-search result and an explicit support decision.
- **Prior ledger entries:** V072, V074
- **Investigation leads:**
  [10015e70](../mothra/evidence/hotline-server-1.9/queries/D-10015e70.c),
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"evidence": ["[Shutdown producer
  10001bf0](../mothra/evidence/gap-remediation/2026-11-12/batch-06/queries/B06-D-10001bf0.c)",
  "[Online fan-out
  10005510](../mothra/evidence/gap-remediation/2026-11-12/batch-06/queries/B06-D-10005510.c)",
  "[Published schema and
  sequence](presence-messaging-contracts.md#kick-options-and-native-console-messages)"],
  "binary_sha256":
  "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b",
  "closure": "Located and captured a positive standalone-111 producer,
  field-101 schema and conditional shutdown sequence. This satisfies this
  entry’s producer/schema criterion. Delivered native packet fixtures remain
  GAP-084; no mandatory-kick interpretation is asserted."}

### GAP-076

#### Server-originated broadcast and eligibility

- **Tracking:** P2; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Broadcasting a Message (Transaction 355) –
  Admin/Server
  Initiated](protocol.md#broadcasting-a-message-transaction-355--adminserver-initiated)
  (snapshot lines 951–965)
- **Question:** Does a console-generated broadcast use the same 355 schema,
  and which connected/logged-in/refusing users receive each origin's
  broadcast?
- **Implementation impact:** The validated client-request path does not
  establish all advertised admin/server initiation cases.
- **Close when:** Trace console and fan-out paths and publish
  origin/recipient/field tables with self-recipient and session-state
  fixtures.
- **Prior ledger entries:** V046, V048
- **Investigation leads:**
  [1000f990](../mothra/evidence/hotline-server-1.9/queries/D-1000f990.c)
- **Depends on:** [GAP-044](#gap-044)
- **Disposition:** {"progress": "Identified console message 104/data-only
  versus client broadcast355 and documented online/ready recipient helper.
  Native self/state/message fixtures remain required.", "evidence":
  ["[Presence, messaging and
  administration](presence-messaging-contracts.md)", "[Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-077

#### Request 348 schema and purpose

- **Tracking:** P2; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Additional Observed Requests and Scope
  Gaps](protocol.md#additional-observed-requests-and-scope-gaps) (snapshot
  lines 975–1012)
- **Question:** What does 348 do, what fields and privileges apply, and how
  are its potentially nested account records serialized?
- **Implementation impact:** An observed dispatcher entry cannot be advertised
  as a supported account operation from its number alone.
- **Close when:** Trace handler/helper paths and provide operation semantics,
  request/reply grammar and representative success/error fixtures.
- **Prior ledger entries:** V074
- **Investigation leads:**
  [10015160](../mothra/evidence/hotline-server-1.9/queries/D-10015160.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Identified 348 as account enumeration, with
  repeated outer 101 values holding nested 102/105/106/110 TLVs and
  password-presence placeholders. Success/error native fixtures remain
  required.", "evidence": ["[Operation contracts](operation-contracts.md)",
  "[Compatibility
  review](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-078

#### Request 349 schema and batch outcomes

- **Tracking:** P2; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Additional Observed Requests and Scope
  Gaps](protocol.md#additional-observed-requests-and-scope-gaps) (snapshot
  lines 975–1012)
- **Question:** What indexed/transitive fields does 349 consume, how are batch
  entries delimited, and are failures atomic or per-entry?
- **Implementation impact:** Implementing guessed batch semantics can mutate
  only part of a request with no specified result.
- **Close when:** Trace the handler and publish batch framing,
  permission/default/partial-error rules and mixed-success fixtures.
- **Prior ledger entries:** V074
- **Investigation leads:**
  [10015500](../mothra/evidence/hotline-server-1.9/queries/D-10015500.c)
- **Depends on:** [GAP-071](#gap-071), [GAP-072](#gap-072)
- **Disposition:** {"progress": "Documented outer indexed value parsing,
  512-byte nested cap, old-name field 101, sequential mutations and mixed
  failure outcomes. Complete permission/conflict helpers and native
  mixed-result fixtures remain required.", "evidence": ["[Operation
  contracts](operation-contracts.md)", "[Compatibility
  review](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

## Compatibility and evidence

### GAP-080

#### Identified peer corpus and fallback classifier

- **Tracking:** P1; Evidence; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [internal-compatibility-matrix.md — Compatibility
  matrix](internal-compatibility-matrix.md#compatibility-matrix) (snapshot
  lines 34–54); [internal-compatibility-matrix.md — Open compatibility gaps
  and QA
  requirements](internal-compatibility-matrix.md#open-compatibility-gaps-and-qa-requirements)
  (snapshot lines 237–267)
- **Question:** Which client builds are acceptance targets, what stable
  evidence distinguishes them after removing sub-version 2, and what is the
  unknown-peer fallback?
- **Implementation impact:** Correcting a bad discriminator does not supply a
  replacement compatibility policy.
- **Close when:** Create a hashed client/capture corpus and evidence-based
  profile/fallback rules; retain reported version values separately from
  proven identities.
- **Prior ledger entries:** M001, M002, M003, M004, M007
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c),
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c)
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Identified the current mxd classifier and
  tests at an exact revision; confirmed that they retain the
  shared-sub-version identity assumption. No identified historical client
  corpus exists in this review.", "evidence": ["[Operation
  contracts](operation-contracts.md)", "[Compatibility
  review](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-081

#### Client tolerance of extra fields

- **Tracking:** P2; Evidence; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [internal-compatibility-matrix.md — Login reply and banner
  policy](internal-compatibility-matrix.md#login-reply-and-banner-policy)
  (snapshot lines 55–78); [internal-compatibility-matrix.md — Compatibility
  matrix](internal-compatibility-matrix.md#compatibility-matrix) (snapshot
  lines 34–54)
- **Question:** Which identified clients accept 161/162, 122, native roster
  output and the SynHX subject addition, and when is an omission policy
  necessary?
- **Implementation impact:** The matrix cannot justify compatibility-specific
  reply changes from another server's output alone.
- **Close when:** Run a peer-by-field acceptance matrix and record actual
  failures/tolerance before selecting omission/default policies.
- **Prior ledger entries:** M003, M004, M007, V024, V033
- **Investigation leads:**
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c),
  [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c),
  [10011870](../mothra/evidence/hotline-server-1.9/queries/D-10011870.c)
- **Depends on:** [GAP-080](#gap-080)
- **Disposition:** {"progress": "Verified execution of mxd login-extra
  omission tests, while distinguishing them from any historical client
  tolerance experiment. Peer-by-field acceptance matrix remains required.",
  "evidence": ["[Operation contracts](operation-contracts.md)",
  "[Compatibility
  review](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-082

#### Heuristic text-decoding policy

- **Tracking:** P1; Decision; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [internal-compatibility-matrix.md — Credential obfuscation and
  text
  compatibility](internal-compatibility-matrix.md#credential-obfuscation-and-text-compatibility)
  (snapshot lines 79–101); [protocol.md — Binary Message Formats (Hotline
  Protocol 1.9)](protocol.md#binary-message-formats-hotline-protocol-19)
  (snapshot lines 30–37)
- **Question:** Will mxd retain text XOR heuristics, on which fields/states,
  and how does it handle valid non-UTF-8 or ambiguous plaintext without
  irreversible mode changes?
- **Implementation impact:** Credential complementing does not decide a
  general message/news decoder and heuristics may not identify peers.
- **Close when:** Document the policy decision and exact state/field rules
  with an ambiguity corpus; validate interoperability independently of named
  heuristic tests.
- **Prior ledger entries:** M005, V016, V043, V045
- **Investigation leads:**
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c),
  [1000f4e0](../mothra/evidence/hotline-server-1.9/queries/D-1000f4e0.c)
- **Depends on:** [GAP-018](#gap-018), [GAP-080](#gap-080)
- **Disposition:** {"progress": "Published exact selected field IDs, UTF-8
  detection predicate, sticky state and inbound/outbound transforms of the
  current mxd heuristic. Ambiguity corpus, explicit policy approval and
  independent interoperability remain required.", "evidence": ["[Operation
  contracts](operation-contracts.md)", "[Compatibility
  review](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-083

#### Historical SynHX source identity and applicability

- **Tracking:** P2; Evidence; Open; owner: Unassigned.
- **Sources:** [internal-compatibility-matrix.md — Compatibility
  matrix](internal-compatibility-matrix.md#compatibility-matrix) (snapshot
  lines 34–54); [protocol.md — References and Correction
  Traceability](protocol.md#references-and-correction-traceability) (snapshot
  lines 1013–1046)
- **Question:** Which release/client/server configurations do the selected RCS
  trunk snapshots represent, and how do the default vendor branch and build
  options differ?
- **Implementation impact:** A useful historical comparison could otherwise be
  generalized to all SynHX profiles or mixed build variants.
- **Close when:** Record archive lineage, selected/default revision
  relationship, relevant build flags and the exact peers to which each source
  observation applies.
- **Prior ledger entries:** M001, M005, M007, M008
- **Investigation leads:** Needs peer/source/project evidence or an explicit
  policy decision.
- **Depends on:** No prerequisite recorded.

### GAP-084

#### Native conformance fixtures beyond one illustrative frame

- **Tracking:** P0; Evidence; Open; owner: Unassigned.
- **Sources:** [protocol.md — 5 Worked example
  (Login)](protocol.md#5-worked-example-login) (snapshot lines 215–249);
  [protocol.md — 6 Implementation
  checklist](protocol.md#6-implementation-checklist) (snapshot lines 250–264);
  [internal-compatibility-matrix.md — Open compatibility gaps and QA
  requirements](internal-compatibility-matrix.md#open-compatibility-gaps-and-qa-requirements)
  (snapshot lines 237–267)
- **Question:** Where are executable positive/negative fixtures for core
  handshake, authenticated login, both completion paths, errors and
  repeated-field handling?
- **Implementation impact:** Static paths and a hand-counted example do not
  establish end-to-end interoperability or a regression oracle.
- **Close when:** Retain identified-peer/core-session captures and expected
  decoded/events results, with a reproducible fixture runner and packet
  provenance.
- **Prior ledger entries:** V003, V007, V018, V019, V025, V027, M008
- **Investigation leads:** Needs peer/source/project evidence or an explicit
  policy decision.
- **Depends on:** [GAP-022](#gap-022), [GAP-025](#gap-025)

### GAP-085

#### mxd implementation and test evidence

- **Tracking:** P2; Evidence; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [internal-compatibility-matrix.md — Historical reported mxd
  test
  coverage](internal-compatibility-matrix.md#historical-reported-mxd-test-coverage)
  (snapshot lines 134–161); [internal-compatibility-matrix.md — Open
  compatibility gaps and QA
  requirements](internal-compatibility-matrix.md#open-compatibility-gaps-and-qa-requirements)
  (snapshot lines 237–267)
- **Question:** Do the named test/source references exist and pass at a
  recorded mxd revision, and do their assertions match the corrected protocol?
- **Implementation impact:** The matrix cannot claim supported implementation
  from unexecuted citations that may encode old assumptions.
- **Close when:** Record checkout/revision, reviewed assertions, commands and
  outputs; fix or retire stale expectations and map passing cases to protocol
  requirements.
- **Prior ledger entries:** M008, M009
- **Investigation leads:** Needs peer/source/project evidence or an explicit
  policy decision.
- **Depends on:** [GAP-001](#gap-001)
- **Disposition:** {"progress": "Reviewed frozen source/assertions and
  executed 55 focused mxd tests at 2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131.
  Disputed classifier/login-extra expectations still pass and require
  implementation reconciliation; no false native-conformance claim is made.",
  "evidence": ["[Operation contracts](operation-contracts.md)",
  "[Compatibility
  review](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

### GAP-086

#### Release/proof acceptance criteria

- **Tracking:** P2; Decision; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [internal-compatibility-matrix.md — Open compatibility gaps and
  QA
  requirements](internal-compatibility-matrix.md#open-compatibility-gaps-and-qa-requirements)
  (snapshot lines 237–267); [internal-compatibility-matrix.md — Scope and
  status labels](internal-compatibility-matrix.md#scope-and-status-labels)
  (snapshot lines 15–33); [baseline-correction-map.md — Baseline correction
  map](baseline-correction-map.md#baseline-correction-map) (snapshot lines
  1–106)
- **Question:** What protocol subset, remaining-gap policy, client coverage
  and proof/test evidence are required for QA sign-off, and are the cited
  roadmap/proof items current?
- **Implementation impact:** Neither an old roadmap pointer nor a correction
  disposition defines a release acceptance threshold.
- **Close when:** Publish current sign-off criteria and owners at an
  identified revision, including deferred gaps and the scope/results of any
  Kani claims.
- **Prior ledger entries:** M008, M009, V001
- **Investigation leads:** Needs peer/source/project evidence or an explicit
  policy decision.
- **Depends on:** [GAP-001](#gap-001), [GAP-080](#gap-080),
  [GAP-084](#gap-084), [GAP-085](#gap-085)
- **Disposition:** {"progress": "Reviewed the actual release checklist,
  checked roadmap statuses and bounded Kani harness source at the recorded
  revision. Kani was not run; release owner, native acceptance criteria and
  deliberate-deviation decisions remain open.", "evidence": ["[Operation
  contracts](operation-contracts.md)", "[Compatibility
  review](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

## Documentation provenance

### GAP-087

#### Portable, versioned evidence and document references

- **Tracking:** P2; Missing; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — References and Correction
  Traceability](protocol.md#references-and-correction-traceability) (snapshot
  lines 1013–1046); [baseline-correction-map.md — Baseline correction
  map](baseline-correction-map.md#baseline-correction-map) (snapshot lines
  1–106); [internal-compatibility-matrix.md — Scope and status
  labels](internal-compatibility-matrix.md#scope-and-status-labels) (snapshot
  lines 15–33)
- **Question:** How will readers obtain the sibling mothra evidence, identify
  the corrected uncommitted document revision and follow stable claim/line
  references after edits?
- **Implementation impact:** Working sibling-relative links and an old Git
  HEAD are not sufficient to reproduce a published baseline in another
  checkout.
- **Close when:** Publish or package the hashed evidence and corrected docs
  with stable revision/artifact references; retain historical snapshots and
  define gap refresh/closure rules.
- **Prior ledger entries:** V001, M008, M009
- **Investigation leads:** Needs peer/source/project evidence or an explicit
  policy decision.
- **Depends on:** No prerequisite recorded.
- **Disposition:** {"progress": "Created local rollback commits in both
  repositories and append-only refreshed document snapshots with
  hash/link/coverage checks. A portable published/package artifact is still
  required.", "evidence": ["[Operation contracts](operation-contracts.md)",
  "[Compatibility
  review](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1)"],
  "closure": "Not closed: remaining acceptance evidence is listed above."}

## Sweep coverage

Every heading/text block in the listed input documents was reviewed.
Parent-section rows include gaps in their child sections. A section without a
new local gap is associated with the applicable shared schema/fixture
question. This table records documentation coverage, not exhaustive coverage
of binary paths, clients or packet inputs.

| Document | Section | Snapshot lines | Related gaps |
| --- | --- | --- | --- |
| protocol.md | [Hotline Server Protocol 1.9: Transactions and Functionality Guide](protocol.md#hotline-server-protocol-19-transactions-and-functionality-guide) | 1–29 | 83 gaps; see section-specific rows and JSON register |
| protocol.md | [Binary Message Formats (Hotline Protocol 1.9)](protocol.md#binary-message-formats-hotline-protocol-19) | 30–37 | 23 gaps; see section-specific rows and JSON register |
| protocol.md | [1 Session-initialization handshake](protocol.md#1-session-initialization-handshake) | 38–72 | [GAP-005](#gap-005), [GAP-007](#gap-007), [GAP-008](#gap-008), [GAP-009](#gap-009) |
| protocol.md | [2 General transaction frame](protocol.md#2-general-transaction-frame) | 73–97 | 10 gaps; see section-specific rows and JSON register |
| protocol.md | [2.1 Parameter list (payload block)](protocol.md#21-parameter-list-payload-block) | 98–141 | [GAP-002](#gap-002), [GAP-014](#gap-014), [GAP-015](#gap-015), [GAP-016](#gap-016), [GAP-017](#gap-017), [GAP-019](#gap-019), [GAP-024](#gap-024) |
| protocol.md | [2.2 Date parameters](protocol.md#22-date-parameters) | 142–164 | [GAP-020](#gap-020) |
| protocol.md | [3 Fragmentation rules](protocol.md#3-fragmentation-rules) | 165–192 | [GAP-004](#gap-004), [GAP-011](#gap-011), [GAP-012](#gap-012), [GAP-014](#gap-014) |
| protocol.md | [4 Reply semantics](protocol.md#4-reply-semantics) | 193–214 | [GAP-003](#gap-003), [GAP-005](#gap-005), [GAP-006](#gap-006), [GAP-013](#gap-013), [GAP-021](#gap-021) |
| protocol.md | [5 Worked example (Login)](protocol.md#5-worked-example-login) | 215–249 | [GAP-016](#gap-016), [GAP-022](#gap-022), [GAP-084](#gap-084) |
| protocol.md | [6 Implementation checklist](protocol.md#6-implementation-checklist) | 250–264 | [GAP-084](#gap-084) |
| protocol.md | [User Login and Presence](protocol.md#user-login-and-presence) | 265–266 | 25 gaps; see section-specific rows and JSON register |
| protocol.md | [Session Handshake (Before Transactions Begin)](protocol.md#session-handshake-before-transactions-begin) | 267–274 | [GAP-007](#gap-007), [GAP-008](#gap-008) |
| protocol.md | [Login (Transaction 107) – Client Initiates](protocol.md#login-transaction-107--client-initiates) | 275–300 | 10 gaps; see section-specific rows and JSON register |
| protocol.md | [Server Agreement (Transaction 109) – Server Initiates](protocol.md#server-agreement-transaction-109--server-initiates) | 301–314 | [GAP-025](#gap-025), [GAP-027](#gap-027) |
| protocol.md | [Agreement Acceptance (Transaction 121) – Client Initiates](protocol.md#agreement-acceptance-transaction-121--client-initiates) | 315–337 | [GAP-007](#gap-007), [GAP-025](#gap-025), [GAP-027](#gap-027), [GAP-029](#gap-029), [GAP-030](#gap-030) |
| protocol.md | [Banner Metadata (Transaction 122) – Server Initiates](protocol.md#banner-metadata-transaction-122--server-initiates) | 338–352 | [GAP-028](#gap-028), [GAP-063](#gap-063) |
| protocol.md | [User Access Privileges (Transaction 354) – Server Initiates](protocol.md#user-access-privileges-transaction-354--server-initiates) | 353–361 | [GAP-031](#gap-031), [GAP-032](#gap-032), [GAP-073](#gap-073) |
| protocol.md | [Access Privilege Bits (Field 110)](protocol.md#access-privilege-bits-field-110) | 362–400 | [GAP-031](#gap-031), [GAP-032](#gap-032) |
| protocol.md | [Retrieving the User List (Transaction 300) – Client Initiates](protocol.md#retrieving-the-user-list-transaction-300--client-initiates) | 401–426 | [GAP-033](#gap-033), [GAP-034](#gap-034), [GAP-035](#gap-035) |
| protocol.md | [User Appearance and Updates (Transaction 301 & 302) – Server Initiates](protocol.md#user-appearance-and-updates-transaction-301--302--server-initiates) | 427–445 | [GAP-034](#gap-034), [GAP-035](#gap-035), [GAP-036](#gap-036) |
| protocol.md | [Viewing User Info (Transaction 303) – Client Initiates](protocol.md#viewing-user-info-transaction-303--client-initiates) | 446–456 | [GAP-037](#gap-037) |
| protocol.md | [Changing User Settings (Transaction 304) – Client Initiates](protocol.md#changing-user-settings-transaction-304--client-initiates) | 457–470 | [GAP-006](#gap-006), [GAP-016](#gap-016), [GAP-019](#gap-019), [GAP-029](#gap-029), [GAP-030](#gap-030), [GAP-045](#gap-045) |
| protocol.md | [Chat (Public and Private Chat Rooms)](protocol.md#chat-public-and-private-chat-rooms) | 471–472 | 13 gaps; see section-specific rows and JSON register |
| protocol.md | [Sending a Chat Message (Transaction 105) – Client Initiates](protocol.md#sending-a-chat-message-transaction-105--client-initiates) | 473–484 | [GAP-006](#gap-006), [GAP-019](#gap-019), [GAP-038](#gap-038), [GAP-042](#gap-042), [GAP-044](#gap-044), [GAP-045](#gap-045) |
| protocol.md | [Receiving a Chat Message (Transaction 106) – Server Initiates](protocol.md#receiving-a-chat-message-transaction-106--server-initiates) | 485–493 | [GAP-018](#gap-018), [GAP-042](#gap-042) |
| protocol.md | [Joining a Chat Room (Transaction 115) – Client Initiates](protocol.md#joining-a-chat-room-transaction-115--client-initiates) | 494–505 | [GAP-038](#gap-038), [GAP-040](#gap-040) |
| protocol.md | [Leaving a Chat Room (Transaction 116) – Client Initiates](protocol.md#leaving-a-chat-room-transaction-116--client-initiates) | 506–515 | [GAP-006](#gap-006), [GAP-036](#gap-036), [GAP-040](#gap-040) |
| protocol.md | [Chat Room Notifications (Transactions 117 & 118) – Server Initiates](protocol.md#chat-room-notifications-transactions-117--118--server-initiates) | 516–527 | [GAP-040](#gap-040) |
| protocol.md | [Chat Invitations (Transactions 112, 113, 114) – Private Chats](protocol.md#chat-invitations-transactions-112-113-114--private-chats) | 528–547 | [GAP-017](#gap-017), [GAP-033](#gap-033), [GAP-038](#gap-038), [GAP-039](#gap-039) |
| protocol.md | [Chat Subject Management (Transactions 119 & 120)](protocol.md#chat-subject-management-transactions-119--120) | 548–556 | [GAP-041](#gap-041) |
| protocol.md | [Private Messaging (Instant Messages)](protocol.md#private-messaging-instant-messages) | 557–558 | [GAP-021](#gap-021), [GAP-030](#gap-030), [GAP-043](#gap-043), [GAP-044](#gap-044), [GAP-045](#gap-045), [GAP-046](#gap-046) |
| protocol.md | [Sending an Instant Message (Transaction 108) – Client Initiates](protocol.md#sending-an-instant-message-transaction-108--client-initiates) | 559–585 | [GAP-021](#gap-021), [GAP-030](#gap-030), [GAP-043](#gap-043), [GAP-045](#gap-045) |
| protocol.md | [Receiving a Private Message (Transaction 104) – Server Initiates](protocol.md#receiving-a-private-message-transaction-104--server-initiates) | 586–598 | [GAP-044](#gap-044) |
| protocol.md | [Legacy Message Board (Transactions 101, 102, 103)](protocol.md#legacy-message-board-transactions-101-102-103) | 599–613 | [GAP-046](#gap-046) |
| protocol.md | [File Services (Files and Folders)](protocol.md#file-services-files-and-folders) | 614–624 | 25 gaps; see section-specific rows and JSON register |
| protocol.md | [Listing Files in a Folder (Transaction 200) – Client Initiates](protocol.md#listing-files-in-a-folder-transaction-200--client-initiates) | 625–637 | [GAP-018](#gap-018), [GAP-047](#gap-047), [GAP-048](#gap-048) |
| protocol.md | [Downloading a File (Transaction 202) – Client Initiates](protocol.md#downloading-a-file-transaction-202--client-initiates) | 638–655 | [GAP-015](#gap-015), [GAP-056](#gap-056), [GAP-057](#gap-057), [GAP-058](#gap-058), [GAP-061](#gap-061) |
| protocol.md | [Uploading a File (Transaction 203) – Client Initiates](protocol.md#uploading-a-file-transaction-203--client-initiates) | 656–668 | [GAP-056](#gap-056), [GAP-058](#gap-058) |
| protocol.md | [Deleting a File (Transaction 204) – Client Initiates](protocol.md#deleting-a-file-transaction-204--client-initiates) | 669–679 | [GAP-050](#gap-050) |
| protocol.md | [Creating a New Folder (Transaction 205) – Client Initiates](protocol.md#creating-a-new-folder-transaction-205--client-initiates) | 680–690 | [GAP-051](#gap-051) |
| protocol.md | [Getting File/Folder Info (Transaction 206) – Client Initiates](protocol.md#getting-filefolder-info-transaction-206--client-initiates) | 691–705 | [GAP-049](#gap-049) |
| protocol.md | [Setting File/Folder Info (Transaction 207) – Client Initiates](protocol.md#setting-filefolder-info-transaction-207--client-initiates) | 706–715 | [GAP-052](#gap-052) |
| protocol.md | [Moving Files/Folders (Transaction 208) – Client Initiates](protocol.md#moving-filesfolders-transaction-208--client-initiates) | 716–725 | [GAP-047](#gap-047), [GAP-053](#gap-053) |
| protocol.md | [Creating an Alias (Shortcut) (Transaction 209) – Client Initiates](protocol.md#creating-an-alias-shortcut-transaction-209--client-initiates) | 726–735 | [GAP-054](#gap-054) |
| protocol.md | [Downloading an Entire Folder (Transaction 210) – Client Initiates](protocol.md#downloading-an-entire-folder-transaction-210--client-initiates) | 736–751 | [GAP-059](#gap-059), [GAP-061](#gap-061) |
| protocol.md | [Uploading an Entire Folder (Transaction 213) – Client Initiates](protocol.md#uploading-an-entire-folder-transaction-213--client-initiates) | 752–766 | [GAP-060](#gap-060), [GAP-064](#gap-064) |
| protocol.md | [Banner Download (Transaction 212) – Client Initiates](protocol.md#banner-download-transaction-212--client-initiates) | 767–779 | [GAP-028](#gap-028), [GAP-055](#gap-055), [GAP-063](#gap-063) |
| protocol.md | [Transfer Connection and Reference Cleanup](protocol.md#transfer-connection-and-reference-cleanup) | 780–797 | [GAP-009](#gap-009), [GAP-010](#gap-010), [GAP-033](#gap-033), [GAP-055](#gap-055), [GAP-056](#gap-056), [GAP-062](#gap-062), [GAP-064](#gap-064) |
| protocol.md | [News (Bulletin Board System)](protocol.md#news-bulletin-board-system) | 798–799 | 10 gaps; see section-specific rows and JSON register |
| protocol.md | [News Hierarchy](protocol.md#news-hierarchy) | 800–808 | [GAP-065](#gap-065), [GAP-070](#gap-070) |
| protocol.md | [Listing News Categories (Transaction 370) – Client Initiates](protocol.md#listing-news-categories-transaction-370--client-initiates) | 809–821 | [GAP-047](#gap-047), [GAP-065](#gap-065) |
| protocol.md | [Listing News Articles (Transaction 371) – Client Initiates](protocol.md#listing-news-articles-transaction-371--client-initiates) | 822–832 | [GAP-066](#gap-066) |
| protocol.md | [Reading a News Article (Transaction 400) – Client Initiates](protocol.md#reading-a-news-article-transaction-400--client-initiates) | 833–854 | [GAP-020](#gap-020), [GAP-067](#gap-067) |
| protocol.md | [Posting a News Article (Transaction 410) – Client Initiates](protocol.md#posting-a-news-article-transaction-410--client-initiates) | 855–866 | [GAP-021](#gap-021), [GAP-068](#gap-068) |
| protocol.md | [Deleting a News Article (Transaction 411) – Client Initiates](protocol.md#deleting-a-news-article-transaction-411--client-initiates) | 867–877 | [GAP-069](#gap-069) |
| protocol.md | [Managing News Structure (Transactions 380, 381, 382) – Client Initiates (Admin/Mods)](protocol.md#managing-news-structure-transactions-380-381-382--client-initiates-adminmods) | 878–892 | [GAP-032](#gap-032), [GAP-070](#gap-070) |
| protocol.md | [Administrative Functions](protocol.md#administrative-functions) | 893–894 | 17 gaps; see section-specific rows and JSON register |
| protocol.md | [User Account Management – Client Initiates (Admin) (Tx 350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353) | 895–928 | 9 gaps; see section-specific rows and JSON register |
| protocol.md | [Disconnecting a User (Transaction 110 & 111) – Admin/Server Use](protocol.md#disconnecting-a-user-transaction-110--111--adminserver-use) | 929–950 | [GAP-003](#gap-003), [GAP-036](#gap-036), [GAP-044](#gap-044), [GAP-074](#gap-074), [GAP-075](#gap-075) |
| protocol.md | [Broadcasting a Message (Transaction 355) – Admin/Server Initiated](protocol.md#broadcasting-a-message-transaction-355--adminserver-initiated) | 951–965 | [GAP-045](#gap-045), [GAP-076](#gap-076) |
| protocol.md | [Additional Admin Privileges Note](protocol.md#additional-admin-privileges-note) | 966–974 | [GAP-038](#gap-038), [GAP-073](#gap-073) |
| protocol.md | [Additional Observed Requests and Scope Gaps](protocol.md#additional-observed-requests-and-scope-gaps) | 975–1012 | [GAP-005](#gap-005), [GAP-007](#gap-007), [GAP-075](#gap-075), [GAP-077](#gap-077), [GAP-078](#gap-078), [GAP-079](#gap-079) |
| protocol.md | [References and Correction Traceability](protocol.md#references-and-correction-traceability) | 1013–1046 | [GAP-083](#gap-083), [GAP-087](#gap-087) |
| internal-compatibility-matrix.md | [Internal compatibility matrix (Hotline and SynHX)](internal-compatibility-matrix.md#internal-compatibility-matrix-hotline-and-synhx) | 1–14 | 13 gaps; see section-specific rows and JSON register |
| internal-compatibility-matrix.md | [Scope and status labels](internal-compatibility-matrix.md#scope-and-status-labels) | 15–33 | [GAP-086](#gap-086), [GAP-087](#gap-087) |
| internal-compatibility-matrix.md | [Compatibility matrix](internal-compatibility-matrix.md#compatibility-matrix) | 34–54 | [GAP-024](#gap-024), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-083](#gap-083) |
| internal-compatibility-matrix.md | [Login reply and banner policy](internal-compatibility-matrix.md#login-reply-and-banner-policy) | 55–78 | [GAP-026](#gap-026), [GAP-081](#gap-081) |
| internal-compatibility-matrix.md | [Credential obfuscation and text compatibility](internal-compatibility-matrix.md#credential-obfuscation-and-text-compatibility) | 79–101 | [GAP-018](#gap-018), [GAP-022](#gap-022), [GAP-082](#gap-082) |
| internal-compatibility-matrix.md | [Repeated fields and presence records](internal-compatibility-matrix.md#repeated-fields-and-presence-records) | 102–133 | [GAP-017](#gap-017), [GAP-034](#gap-034), [GAP-035](#gap-035), [GAP-081](#gap-081) |
| internal-compatibility-matrix.md | [Historical reported mxd test coverage](internal-compatibility-matrix.md#historical-reported-mxd-test-coverage) | 134–161 | [GAP-085](#gap-085) |
| internal-compatibility-matrix.md | [Open compatibility gaps and QA requirements](internal-compatibility-matrix.md#open-compatibility-gaps-and-qa-requirements) | 237–267 | [GAP-001](#gap-001), [GAP-080](#gap-080), [GAP-084](#gap-084), [GAP-085](#gap-085), [GAP-086](#gap-086) |
| baseline-correction-map.md | [Baseline correction map](baseline-correction-map.md#baseline-correction-map) | 1–106 | [GAP-086](#gap-086), [GAP-087](#gap-087) |
| native-wire-details.md | [Hotline 1.9 native wire details](native-wire-details.md#hotline-19-native-wire-details) | 1–8 | 13 gaps; see section-specific rows and JSON register |
| native-wire-details.md | [Parameter parsing and scalar access](native-wire-details.md#parameter-parsing-and-scalar-access) | 9–35 | [GAP-014](#gap-014), [GAP-015](#gap-015), [GAP-016](#gap-016), [GAP-017](#gap-017), [GAP-018](#gap-018), [GAP-019](#gap-019) |
| native-wire-details.md | [Credential bytes, lookup and account updates](native-wire-details.md#credential-bytes-lookup-and-account-updates) | 36–55 | [GAP-016](#gap-016), [GAP-018](#gap-018), [GAP-019](#gap-019), [GAP-022](#gap-022), [GAP-023](#gap-023), [GAP-071](#gap-071), [GAP-072](#gap-072), [GAP-073](#gap-073) |
| native-wire-details.md | [Account record and field schema](native-wire-details.md#account-record-and-field-schema) | 56–93 | [GAP-016](#gap-016), [GAP-019](#gap-019), [GAP-071](#gap-071), [GAP-072](#gap-072) |
| native-wire-details.md | [Login lookup transformations](native-wire-details.md#login-lookup-transformations) | 94–108 | [GAP-018](#gap-018), [GAP-022](#gap-022), [GAP-023](#gap-023) |
| native-wire-details.md | [Changes to connected accounts](native-wire-details.md#changes-to-connected-accounts) | 109–118 | [GAP-073](#gap-073) |
| native-wire-details.md | [Structured file paths and file-list entries](native-wire-details.md#structured-file-paths-and-file-list-entries) | 119–160 | [GAP-047](#gap-047), [GAP-048](#gap-048) |
| native-wire-details.md | [Privilege access and connection timers](native-wire-details.md#privilege-access-and-connection-timers) | 161–206 | [GAP-005](#gap-005), [GAP-031](#gap-031), [GAP-032](#gap-032), [GAP-045](#gap-045) |
| internal-compatibility-matrix.md | [mxd review at 2e4c9c1](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1) | 162–184 | [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-082](#gap-082), [GAP-085](#gap-085), [GAP-086](#gap-086) |
| internal-compatibility-matrix.md | [Assertions requiring protocol reconciliation](internal-compatibility-matrix.md#assertions-requiring-protocol-reconciliation) | 185–200 | [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-085](#gap-085) |
| internal-compatibility-matrix.md | [Exact current text heuristic](internal-compatibility-matrix.md#exact-current-text-heuristic) | 201–221 | [GAP-018](#gap-018), [GAP-080](#gap-080), [GAP-082](#gap-082), [GAP-085](#gap-085) |
| internal-compatibility-matrix.md | [Proof and QA limits](internal-compatibility-matrix.md#proof-and-qa-limits) | 222–236 | [GAP-001](#gap-001), [GAP-085](#gap-085), [GAP-086](#gap-086) |
| operation-contracts.md | [Native operation and session dispatch contracts](operation-contracts.md#native-operation-and-session-dispatch-contracts) | 1–8 | 12 gaps; see section-specific rows and JSON register |
| operation-contracts.md | [Session eligibility and invalid transitions](operation-contracts.md#session-eligibility-and-invalid-transitions) | 9–29 | [GAP-003](#gap-003), [GAP-007](#gap-007), [GAP-025](#gap-025), [GAP-079](#gap-079) |
| operation-contracts.md | [Request catalogue](operation-contracts.md#request-catalogue) | 30–86 | [GAP-002](#gap-002), [GAP-006](#gap-006), [GAP-021](#gap-021) |
| operation-contracts.md | [Server notification catalogue](operation-contracts.md#server-notification-catalogue) | 87–111 | [GAP-006](#gap-006), [GAP-036](#gap-036), [GAP-044](#gap-044), [GAP-061](#gap-061), [GAP-075](#gap-075) |
| operation-contracts.md | [Frame acceptance and reassembly boundaries](operation-contracts.md#frame-acceptance-and-reassembly-boundaries) | 112–134 | [GAP-004](#gap-004), [GAP-011](#gap-011), [GAP-012](#gap-012), [GAP-013](#gap-013) |
| operation-contracts.md | [Administrative account list and batch mutation](operation-contracts.md#administrative-account-list-and-batch-mutation) | 135–165 | [GAP-021](#gap-021), [GAP-072](#gap-072), [GAP-077](#gap-077), [GAP-078](#gap-078) |
| transfer-contracts.md | [Native transfer contracts](transfer-contracts.md#native-transfer-contracts) | 1–8 | 9 gaps; see section-specific rows and JSON register |
| transfer-contracts.md | [HTXF connection header and dispatch](transfer-contracts.md#htxf-connection-header-and-dispatch) | 9–47 | [GAP-055](#gap-055) |
| transfer-contracts.md | [Reference allocation and request 214](transfer-contracts.md#reference-allocation-and-request-214) | 48–76 | [GAP-033](#gap-033), [GAP-062](#gap-062) |
| transfer-contracts.md | [Resume data: RFLT](transfer-contracts.md#resume-data-rflt) | 77–111 | [GAP-058](#gap-058) |
| transfer-contracts.md | [Flattened ordinary-file stream](transfer-contracts.md#flattened-ordinary-file-stream) | 112–141 | [GAP-056](#gap-056), [GAP-057](#gap-057) |
| transfer-contracts.md | [INFO metadata value](transfer-contracts.md#info-metadata-value) | 142–164 | [GAP-020](#gap-020), [GAP-056](#gap-056) |
| transfer-contracts.md | [Upload consumption and completion](transfer-contracts.md#upload-consumption-and-completion) | 165–181 | [GAP-056](#gap-056), [GAP-064](#gap-064) |
| transfer-contracts.md | [Queue notification 211](transfer-contracts.md#queue-notification-211) | 182–197 | [GAP-061](#gap-061) |
| transfer-contracts.md | [Banner bytes and worker timers](transfer-contracts.md#banner-bytes-and-worker-timers) | 198–219 | [GAP-005](#gap-005), [GAP-063](#gap-063), [GAP-064](#gap-064) |
| transfer-contracts.md | [Folder-download control states](transfer-contracts.md#folder-download-control-states) | 220–248 | [GAP-059](#gap-059) |
| transfer-contracts.md | [Folder-upload control states](transfer-contracts.md#folder-upload-control-states) | 249–285 | [GAP-060](#gap-060) |
| news-contracts.md | [Native nested news contracts](news-contracts.md#native-nested-news-contracts) | 1–7 | [GAP-020](#gap-020), [GAP-065](#gap-065), [GAP-066](#gap-066), [GAP-067](#gap-067), [GAP-068](#gap-068), [GAP-069](#gap-069), [GAP-070](#gap-070) |
| news-contracts.md | [Category-list variants](news-contracts.md#category-list-variants) | 8–55 | [GAP-065](#gap-065) |
| news-contracts.md | [Article-list field 321](news-contracts.md#article-list-field-321) | 56–102 | [GAP-066](#gap-066) |
| news-contracts.md | [Reading bodies and navigation](news-contracts.md#reading-bodies-and-navigation) | 103–120 | [GAP-067](#gap-067) |
| news-contracts.md | [News dates](news-contracts.md#news-dates) | 121–128 | [GAP-020](#gap-020), [GAP-067](#gap-067) |
| news-contracts.md | [Posting, partial effects and deletion](news-contracts.md#posting-partial-effects-and-deletion) | 129–159 | [GAP-021](#gap-021), [GAP-068](#gap-068), [GAP-069](#gap-069) |
| news-contracts.md | [Scope of hierarchy evidence](news-contracts.md#scope-of-hierarchy-evidence) | 160–171 | [GAP-047](#gap-047), [GAP-070](#gap-070) |
| presence-messaging-contracts.md | [Native presence, messaging and administration contracts](presence-messaging-contracts.md#native-presence-messaging-and-administration-contracts) | 1–7 | 18 gaps; see section-specific rows and JSON register |
| presence-messaging-contracts.md | [Settings and login visibility](presence-messaging-contracts.md#settings-and-login-visibility) | 8–44 | [GAP-025](#gap-025), [GAP-029](#gap-029), [GAP-030](#gap-030), [GAP-035](#gap-035) |
| presence-messaging-contracts.md | [Agreement and banner condition tables](presence-messaging-contracts.md#agreement-and-banner-condition-tables) | 45–66 | [GAP-026](#gap-026), [GAP-027](#gap-027), [GAP-028](#gap-028) |
| presence-messaging-contracts.md | [Status word, separate from the privilege bitmap](presence-messaging-contracts.md#status-word-separate-from-the-privilege-bitmap) | 67–88 | [GAP-034](#gap-034) |
| presence-messaging-contracts.md | [Disconnect teardown and notification 302](presence-messaging-contracts.md#disconnect-teardown-and-notification-302) | 89–105 | [GAP-036](#gap-036) |
| presence-messaging-contracts.md | [Private-message routing](presence-messaging-contracts.md#private-message-routing) | 106–146 | [GAP-043](#gap-043), [GAP-044](#gap-044), [GAP-045](#gap-045) |
| presence-messaging-contracts.md | [Rooms, invitations and subjects](presence-messaging-contracts.md#rooms-invitations-and-subjects) | 147–182 | [GAP-038](#gap-038), [GAP-039](#gap-039), [GAP-040](#gap-040), [GAP-041](#gap-041), [GAP-042](#gap-042) |
| presence-messaging-contracts.md | [Kick options and native console messages](presence-messaging-contracts.md#kick-options-and-native-console-messages) | 183–214 | [GAP-074](#gap-074), [GAP-075](#gap-075), [GAP-076](#gap-076) |
| core-field-schemas.md | [Core transaction field schemas](core-field-schemas.md#core-transaction-field-schemas) | 1–8 | [GAP-002](#gap-002), [GAP-015](#gap-015), [GAP-016](#gap-016), [GAP-017](#gap-017), [GAP-019](#gap-019) |
| core-field-schemas.md | [Types, occurrence and direction conventions](core-field-schemas.md#types-occurrence-and-direction-conventions) | 9–33 | [GAP-002](#gap-002), [GAP-015](#gap-015), [GAP-017](#gap-017) |
| core-field-schemas.md | [Login and settings requests](core-field-schemas.md#login-and-settings-requests) | 34–55 | [GAP-002](#gap-002), [GAP-016](#gap-016), [GAP-024](#gap-024), [GAP-029](#gap-029), [GAP-030](#gap-030) |
| core-field-schemas.md | [Login and presence outputs](core-field-schemas.md#login-and-presence-outputs) | 56–68 | [GAP-002](#gap-002), [GAP-025](#gap-025), [GAP-026](#gap-026), [GAP-027](#gap-027), [GAP-028](#gap-028), [GAP-035](#gap-035), [GAP-036](#gap-036), [GAP-037](#gap-037) |
| core-field-schemas.md | [Chat, PM and room requests](core-field-schemas.md#chat-pm-and-room-requests) | 69–86 | [GAP-002](#gap-002), [GAP-038](#gap-038), [GAP-039](#gap-039), [GAP-040](#gap-040), [GAP-041](#gap-041), [GAP-042](#gap-042), [GAP-043](#gap-043) |
| core-field-schemas.md | [Room and message outputs](core-field-schemas.md#room-and-message-outputs) | 87–105 | [GAP-002](#gap-002), [GAP-044](#gap-044), [GAP-075](#gap-075), [GAP-076](#gap-076) |
| session-transport-contracts.md | [Native session and transport contracts](session-transport-contracts.md#native-session-and-transport-contracts) | 1–7 | [GAP-008](#gap-008), [GAP-009](#gap-009), [GAP-010](#gap-010), [GAP-011](#gap-011), [GAP-024](#gap-024), [GAP-033](#gap-033) |
| session-transport-contracts.md | [Configured endpoints](session-transport-contracts.md#configured-endpoints) | 8–33 | [GAP-010](#gap-010) |
| session-transport-contracts.md | [Handshake consumption and failures](session-transport-contracts.md#handshake-consumption-and-failures) | 34–53 | [GAP-008](#gap-008) |
| session-transport-contracts.md | [Sub-version 3 versus the data endpoint](session-transport-contracts.md#sub-version-3-versus-the-data-endpoint) | 54–74 | [GAP-009](#gap-009), [GAP-055](#gap-055) |
| session-transport-contracts.md | [Receive-limit assignment at startup](session-transport-contracts.md#receive-limit-assignment-at-startup) | 75–89 | [GAP-011](#gap-011) |
| session-transport-contracts.md | [Identifier domains](session-transport-contracts.md#identifier-domains) | 90–106 | [GAP-024](#gap-024), [GAP-033](#gap-033) |

## Maintaining this analysis

Edit gap-register.json as the canonical register and regenerate this report
with the command below. Keep IDs stable: add new entries, cross-link overlaps
and retain resolved/deferred records rather than renumbering or deleting them.
Assign an owner and record evidence as work progresses; do not automatically
close an entry because its containing document was rewritten.

For Resolved, record resolution.evidence with exact binary/client hashes or
repository revisions, queries/captures/test outputs, the updated document
section and the checked closure outcome. For Deferred, record the scope
decision, rationale and revisit condition under resolution.evidence; it
remains an unanswered protocol question. Update last_updated when changing the
register.

When an audited source changes, preserve the old dated snapshots, capture a
new source manifest/section inventory and refresh affected source ranges and
coverage after review. The check deliberately rejects source drift rather than
silently moving historical references. The baseline validity ledger and its
original snapshots remain immutable.

From the sibling mothra checkout:

```sh
python3 scripts/render-protocol-gap-analysis.py
python3 scripts/render-protocol-gap-analysis.py --check
make gap-check
```

The check validates snapshot/current-source hashes, references, IDs,
dependency acyclicity, section coverage and generated-report consistency.
