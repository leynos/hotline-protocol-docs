# Glossary

This glossary defines the terms that the Hotline 1.9 protocol documents use. It
covers the peers and implementations, the wire terms, the evidence terms, the
gap register and provenance terms, the work-packet labels and the toolset
terms. Each entry names the document that is authoritative for the term. An
entry that makes a factual claim cites the retained evidence under
`../evidence/` or a named section of a document. The upstream SynHX source
archive is not retained in this repository, so entries that rely on it name the
archive files they used.

Where two documents disagree, or a source is silent, the entry says so. Where
no retained record states what a term means, the entry says that the meaning is
not stated in the retained records. Entries are sorted alphabetically within
each group.

## Peers and implementations

### Classic client

The Classic client is the identified Classic Hotline client candidate, a Mac
PowerPC client that the documents use as an interoperability target for native
1.9.

Authoritative source:
[peer profile rules](peers/peer-profile-rules.md#evaluated-build-identities).

Evidence: the executable DATA and resource-fork SHA-256 values are recorded in
the peer profile rules. The archive and application label says 1.9.2, while the
embedded `vers` resource says 1.9.1.0. Both observations are retained, and
neither is adopted as a behavioural release identity
([delegation record](provenance/records/mac-peer-candidate.md), lines 33 to
36). Vendor authenticity and any mapping to other binaries are unproved
([peer profile rules](peers/peer-profile-rules.md#evaluated-build-identities)).

### Hotline Server 1.9

Hotline Server 1.9 is the Mac PowerPC server `HLserver19`, whose observed
behaviour the protocol guide describes. Its build label is
`Hotline Connect Server 1.9.1.0`, and its code oracle is the PEF data fork with
SHA-256 `ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`.

Authoritative source: [protocol guide](protocol/protocol.md), opening section.

Evidence: both version resources in the paired resource-fork inventory read
`Hotline Connect Server 1.9.1.0`
([resource inventory](../evidence/gap-remediation/2026-11-12/batch-09/resource-inventory.json),
lines 292 to 303). The protocol guide states that this identifies the labelled
build within the intended 1.9 family, that the data-fork hash remains the code
oracle, and that the login wire version is still 190 (opening section). The
hash covers the PEF data fork, not a complete Mac distribution or its resource
fork ([validity ledger](baseline-validity-ledger.md#provenance-and-authority)).

### `hx`

`hx` is the Hotline client program from which the shx client was derived. The
shx README describes shx as "hx with modifications and bug fixes". The
identified shx build generates an executable named `hx`.

Authoritative source:
[identified client source](peers/identified-client-source.md#source-package-identities-and-configuration-applicability).

Evidence: the generated Makefile of the identified build selects terminal
objects and `hx` (the same section). The upstream SynHX source archive records
the README at `client/README,v`, which is not retained in this repository. The
retained text gives no separate release history for `hx`.

### `hxd`

`hxd` is the Hotline server program that the SynHX server package modifies.

Authoritative source: the upstream SynHX source archive, `server/README,v`,
which is not retained in this repository.

Evidence: the server README says that the Synapse Hotline X Daemon is an hxd
server with modifications (`server/README,v`, lines 41 and 42). It lists the
files that were modified in synhxd over hxd-0.1.41 (`server/README,v`, line 56).

### mxd

mxd is the project's own server implementation, whose intended Hotline 1.9
compatibility the protocol guide describes.

Authoritative source: [protocol guide](protocol/protocol.md), opening section.

Evidence: the retained ledger did not inspect an mxd checkout, run its tests or
run its `Kani` proofs, so the implementation status of mxd lies outside the
retained evidence
([internal compatibility matrix](mxd/compatibility-matrix.md), opening
section). The ledger's claim M008 refers to mxd's Rust tests
([validity ledger](baseline-validity-ledger.md#compatibility-matrix-ledger)).

### Native

Native names the Hotline Server 1.9 binary as executed in its emulator, as
opposed to a controlled receiver, a proxy or a historical source. Results that
the documents label native come from that execution.

Authoritative source:
[peer profile rules](peers/peer-profile-rules.md#evaluated-build-identities).

Evidence: "A controlled receiver is not native server execution" (the same
section). The native diagnostic witness records Hotline Server 1.9 running in a
disposable SheepShaver Mac OS 9 guest
([witness](native-evidence/native-diagnostic-existing-witness.md), opening
section).

### Peer profile

A peer profile is an evaluated protocol target: a particular executable and
configuration with measured coverage. It is not every release that carries the
same product name.

Authoritative source: [peer profile rules](peers/peer-profile-rules.md),
opening section.

Evidence: assignment requires provenance that matches the profile's opaque
executable identity and configuration. A handshake, a self-reported version or
an app name alone is insufficient
([peer profile rules](peers/peer-profile-rules.md#profile-assignment-and-unknown-peer-fallback)).

### `shx`

`shx` is the client of the SynHX family. Its README names it "Synapse Hotline X
(shx or SHX)", and the client changelog records version 0.1.48 on
31 August 2001, the entry that splits the hxd and hx code structure into two
separately downloadable packages.

Authoritative source:
[identified client source](peers/identified-client-source.md#source-package-identities-and-configuration-applicability)
for the identified build. The upstream SynHX source archive is the release
record, and it is not retained in this repository.

Evidence: the identified build uses the 0.1.48 source at commit
`adb1bf8c8cb12f7eb2fa2c01673295a6312f262b`. That revision identifies source
content only, not a configured or distributed executable
([identified client source](peers/identified-client-source.md), opening
section). The upstream client README says that "as of shx/shxd 0.1.47 the
client has been removed from the hxd (server) package" (`client/README,v`,
lines 37 and 38). The upstream client changelog records the split under 0.1.48
(`client/CHANGES,v`, lines 30 to 33). The two records therefore place the split
at 0.1.47 and 0.1.48 respectively. The client's `version.c` declares `0.1.48`
under the variable name `hxd_version` (`client/version.c,v`, line 30).

### `shxd`

`shxd` is the name of the server package in the later CVS module layout. The
archive's ChangeLog records that the module was renamed to `shxd` and `shx`
when it was split.

Authoritative source: the upstream SynHX source archive, `server/version.c,v`
and `shxd/shxd/Attic/CHANGES,v`, which are not retained in this repository.

Evidence: `server/version.c,v` declares `hxd_version = "0.1.48.1"` (line 30).
The server's CHANGES file records version 0.1.48 on 1 September 2001 and
version 0.1.48.1 on 2 September 2001 (`shxd/shxd/Attic/CHANGES,v`, lines 35 and
41). Those dates differ from the client's 31 August 2001 for 0.1.48. The rename
is recorded in the import message of
`output/shxd-20250605-222707/cvs-data/shxd-0.2/Attic/ChangeLog,v`. The server
README still uses the name synhxd (`server/README,v`, lines 41 and 42).

### SynHX

SynHX is the family name for Synapse Hotline X, the fork of hx and hxd. In the
protocol documents, "SynHX" sometimes names the historical server source and
sometimes names any client of the family. Those client uses are not established
for every client build, so a specific program should be named where it is
meant, using the entries for `shx` and `synhxd`.

Authoritative source:
[protocol guide](protocol/protocol.md#references-and-correction-traceability),
which identifies the historical SynHX comparison as the supplied
`../synhxd/server/` archive set. The archive itself is not retained in this
repository.

Evidence: the server's modifications are described as being over hxd-0.1.41
(`server/README,v`, line 56), and the client is described as "hx with
modifications and bug fixes" (`client/README,v`, line 32). The first revision of
`README.synhxd` in the archive is dated 1 August 2001
(`output/synhxd-20250605-222721/cvs-data/Attic/README.synhxd,v`), and the
command reference attributes entries to "SynHXD 0.1.42"
(`server/info/HXDCommands,v`, line 82). The archive's changelog and CHANGES
files date 0.1.42 to 30 June 2001 (`client/CHANGES,v`, line 145;
`shxd/shxd/Attic/CHANGES,v`, line 156). The client split is recorded as "as of
shx/shxd 0.1.47" in the client README and as version 0.1.48 in the client
changelog. The server is named `shxd` from version 0.1.48.1.

shx is therefore the client of the SynHX family. It is not an earlier client
that was later replaced by a client named SynHX.

The retained record of the server archives is
[the SynHX source manifest](../evidence/hotline-server-1.9/synhxd-source/manifest.json),
which records 14 archives, selected revision 1.1 and default branch 1.1.1
([validity ledger](baseline-validity-ledger.md#compatibility-matrix-ledger)).

### `synhxd`

`synhxd` is the first name of the SynHX server package. Its README calls it
"Synapse Hotline X Daemon (synhxd or synHXD)".

Authoritative source: the upstream SynHX source archive, `server/README,v`,
which is not retained in this repository. The repository's evidence directory
and extraction script keep the older name:
[synhxd-source](../evidence/hotline-server-1.9/synhxd-source/manifest.json) and
`scripts/extract-synhxd-evidence.py`.

Evidence: the first revision of `README.synhxd` in the archive is dated
1 August 2001 (`output/synhxd-20250605-222721/cvs-data/Attic/README.synhxd,v`).
The archive's changelog dates the 0.1.42 release, which the command reference
names "SynHXD 0.1.42", to 30 June 2001 (`shxd/shxd/Attic/CHANGES,v`, line 156).
The server README keeps the name synhxd after the 0.1.48.1 package
(`server/README,v`, line 41).

### Unknown peer

An unknown peer is a peer that matches no evaluated profile. For an unknown
peer the documents use the native 1.9 login producer as the wire baseline, with
no family classifier.

Authoritative source:
[peer profile rules](peers/peer-profile-rules.md#profile-assignment-and-unknown-peer-fallback).

Evidence: a shared handshake sub-version 2 and numeric field `160` do not turn
an unknown peer into SynHX or Hotline 1.8.5 (the same section).

## Wire terms

### ACK

ACK is the catalogue label for a normal-path direct reply that is visible. It
does not mean that every branch replies.

Authoritative source:
[protocol guide, reply semantics](protocol/protocol.md#4-reply-semantics).

Evidence: permission failures, flood limits and connection closure can change
the outcome (the same section).

### Alias

An alias is a Hotline shortcut that transaction 209 creates from a source name,
a source path and a destination path. The term also covers the Mac Alias
Record, which a separate document describes.

Authoritative source:
[protocol guide, file services](protocol/protocol.md#file-services-files-and-folders)
for transaction 209, and
[alias record v2](files-and-transfers/alias-record-v2.md) for the record.

Evidence: transaction 209 takes the source name in field `201`, the source path
in field `202` and the destination path in field `212`. Live aliases and chains
resolve in listing, info and download
([protocol guide](protocol/protocol.md#file-services-files-and-folders)). The
alias record decoder accepts an extracted AliasRecord payload, records identity
only and does not resolve a live target
([alias record v2](files-and-transfers/alias-record-v2.md), opening section).

### Data fork

The data fork is the data stream of a Mac file. In this repository it has two
uses: the code oracle is a PEF data fork, and the flattened transfer stream
carries the file's data fork under the `DATA` tag.

Authoritative source: [protocol guide](protocol/protocol.md), opening section,
for the oracle;
[transfer contracts](files-and-transfers/transfer-contracts.md#flattened-ordinary-file-stream)
for the stream.

Evidence: the baseline file's stream carries 1,048,576 `DATA` bytes and 317
`MACR` bytes ([transfer contracts](files-and-transfers/transfer-contracts.md),
around lines 175 and 176).

### Field

A field is one count-prefixed record in a transaction's parameter stream. Each
field has a two-byte field ID, a two-byte value length and the value bytes.

Authoritative source:
[protocol guide, parameter list](protocol/protocol.md#21-parameter-list-payload-block).

Evidence: the parameter stream begins with a two-byte field count, and an empty
native field list is `00 00` (the same section). Field IDs may repeat where a
transaction's schema permits it, and no global uniqueness rule applies (the
same section). Field IDs and transaction types are separate namespaces, so
error text in field `100` is not a standalone error transaction
([protocol guide, reply semantics](protocol/protocol.md#4-reply-semantics)).
In the worked login example, field `105` carries the login, field `106` the
password and field `160` the client version
([protocol guide, worked example](protocol/protocol.md#5-worked-example-login)).

### `FILP`

`FILP` is the magic of the flattened-file stream that a transfer connection
carries. Its header is 24 bytes: the tag `FILP`, a version word of 1, 16 bytes
that are zero from a cleared state, and a fork count of 3.

Authoritative source:
[transfer contracts, flattened ordinary-file stream](files-and-transfers/transfer-contracts.md#flattened-ordinary-file-stream).

Evidence: each of the three fork records that follow has a 16-byte header with
the tag `INFO`, `DATA` or `MACR` (the same section). A fresh stream advertises
`72 + info_length + data_length + resource_length` bytes (the same section).

### Flattened file

A flattened file is a single transfer stream that carries a Mac file's metadata
and both of its forks in the `FILP` format. Its fork records are `INFO`, `DATA`
and `MACR`.

Authoritative source:
[transfer contracts, flattened ordinary-file stream](files-and-transfers/transfer-contracts.md#flattened-ordinary-file-stream).

Evidence: a resume reduces only the fork bytes, and the header and metadata
overhead remain (the same section).

### Handshake tags

The handshake tags are the fixed values of the twelve-byte session opening: the
protocol ID `TRTP`, the sub-protocol ID `HOTL`, the version `00 01` and a
sub-version. Sub-version `00 02` denotes a normal session, and sub-version 3
enters a transfer-related handling path.

Authoritative source:
[protocol guide, session-initialization handshake](protocol/protocol.md#1-session-initialization-handshake).

Evidence: the server's reply is eight bytes, consisting of `TRTP` and a
four-byte status that is zero for success. The supplied SynHX server uses the
same normal-session magic, `TRTPHOTL 00 01 00 02`, so sub-version 2 cannot
identify SynHX uniquely (the same section).

### `HTXF`

`HTXF` is the magic of the transfer-connection header. The 16-byte header
carries the magic, a transfer reference, a size word and a 16-bit selector.

Authoritative source:
[transfer contracts, HTXF header](files-and-transfers/transfer-contracts.md#htxf-connection-header-and-dispatch).

Evidence: the reference's parity and the selector choose the branch. For
example, an odd reference with selector 2 selects a banner download (the same
section).

### Notification

A notification is a server-originated message that is not a direct reply to a
client request.

Authoritative source:
[protocol guide, general transaction frame](protocol/protocol.md#2-general-transaction-frame).

Evidence: the is-reply byte is zero for a request or a notification and one for
a reply (the same section). Sections headed "Server Initiates" describe the
server-originated transactions. Transaction 122 is an additional
server-originated banner notification
([protocol guide](protocol/protocol.md#additional-observed-requests-and-scope-gaps)).

### Push

Push is the catalogue label for a handler that routes a notification or update
without a normal direct success reply.

Authoritative source:
[protocol guide, reply semantics](protocol/protocol.md#4-reply-semantics).

### Rate304

Rate304 is the label that the repository's records use for the settings rate
path of transaction 304, Changing User Settings.

Authoritative source:
[rate-path contract](presence-and-messaging/rate304-contract.md), opening
section.

Evidence: the contract is a source prediction for the rate path's counter and
its ordinary response. The exact native 60-second interval remains uncalibrated
(the same section). The protocol guide lists transaction 304 as Changing User
Settings ([protocol guide](protocol/protocol.md#user-login-and-presence)).

### Reply

A reply is a direct response to a client request. It copies the request's ID,
sets the reply marker, uses type zero and carries a status and a parameter
stream.

Authoritative source:
[protocol guide, reply semantics](protocol/protocol.md#4-reply-semantics).

Evidence: valid unmatched replies are silent, and invalid zero-size replies
close before correlation (the same section).

### Request

A request is a client-initiated transaction, identified by its transaction
type. Sections headed "Client Initiates" describe the request types.

Authoritative source:
[protocol guide, general transaction frame](protocol/protocol.md#2-general-transaction-frame).

Evidence: the inspected dispatcher contains 45 request handlers
([protocol guide](protocol/protocol.md#additional-observed-requests-and-scope-gaps)).

### Resource fork

The resource fork is the second fork of a Mac file. The flattened transfer
stream carries it under the `MACR` tag.

Authoritative source:
[transfer contracts, flattened ordinary-file stream](files-and-transfers/transfer-contracts.md#flattened-ordinary-file-stream).

Evidence: the transfer contracts describe the baseline file's `MACR` fork as a
317-byte resource fork (around line 71). The data-fork hash of Hotline Server
1.9 does not cover its resource fork
([validity ledger](baseline-validity-ledger.md#provenance-and-authority)).

### Stream tags

Stream tags are the four-byte tags of the fork records in a `FILP` stream. The
tag `INFO` marks the metadata value, `DATA` the data fork and `MACR` the
resource fork.

Authoritative source:
[transfer contracts, flattened ordinary-file stream](files-and-transfers/transfer-contracts.md#flattened-ordinary-file-stream).

Evidence: the resume record uses `DATA` and `MACR` entries
([transfer contracts, resume data](files-and-transfers/transfer-contracts.md#resume-data-rflt)).

### Transaction

A transaction is one unit of the Hotline wire protocol after the session
handshake. Each transaction begins with a twenty-byte envelope that carries
flags, a reply marker, a type, a correlation ID, an error code, and the total
and per-frame parameter-stream lengths.

Authoritative source:
[protocol guide, general transaction frame](protocol/protocol.md#2-general-transaction-frame).

Evidence: a direct reply copies the correlation ID of its request (the same
section). Assembly, collisions and late replies are covered by the
[ID and reassembly contract](protocol/session-transport-contracts.md#transaction-ids-reassembly-and-correlation).

### Transfer protocol

The transfer protocol is the `HTXF`-headed connection that carries file, folder
and banner transfers. A control session that sends sub-version 3 is handed over
to that transfer connection after its success response.

Authoritative source:
[transfer contracts, HTXF header](files-and-transfers/transfer-contracts.md#htxf-connection-header-and-dispatch).

Evidence: the protocol guide describes the same-connection handover to `HTXF`
after the success response
([protocol guide, session-initialization handshake](protocol/protocol.md#1-session-initialization-handshake)).

## Evidence terms

### A7 readback

A7 is the label for a read-only readback of the existing file baseline, which
covers the full data and resource forks, the file listing and the metadata of
the isolated server's files. The records cite A7 as a preflight before a load
stage and as a postflight after it.

Authoritative source:
[A7 preflight manifest](../evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/manifest.json),
scope and conclusions.

Evidence: the manifest records one live readback. It does not prove disk
restart durability (the manifest's `limits` field).

### Capture plan

A capture plan is the ordered set of read-only queries and captures that the
evidence collector replays. The collector verifies the expected binary hash
before querying and checks that program metadata is unchanged after each plan
([validity ledger](baseline-validity-ledger.md#evidence-method-and-limits)).

Authoritative source:
[validity ledger](baseline-validity-ledger.md#evidence-method-and-limits).

Evidence: the plans are stored under `../evidence/hotline-server-1.9/plans/`.
The inherited capture planners are held in `scripts/`
([AGENTS.md](../AGENTS.md#what-lives-where)).

### Controlled receiver

A controlled receiver is the controlled test receiver that the documents use to
observe a client. It is not native server execution.

Authoritative source:
[peer profile rules](peers/peer-profile-rules.md#evaluated-build-identities).

Evidence: "A controlled receiver is not native server execution" (the same
section). The same section states that a native proxy tests the named rewrite.

### Corpus

A corpus is a frozen, hashed collection of retained records that a verifier
replays or checks.

Authoritative source:
[rate-path contract](presence-and-messaging/rate304-contract.md), opening
section.

Evidence: the rate-path contract cites a frozen source corpus. The Classic
corpus pins both forks of the Classic candidate
([peer profile rules](peers/peer-profile-rules.md#evaluated-build-identities)).

### Observed

Observed means supported by static analysis of the named path in the hashed 1.9
build. It does not mean exercised in a live network test.

Authoritative source: [protocol guide](protocol/protocol.md), opening section.

Evidence: the compatibility matrix uses "Source-observed" for facts established
in a named historical source snapshot, not in every client or release
([matrix scope and status labels](mxd/compatibility-matrix.md#scope-and-status-labels)).

### Oracle

The oracle is the Hotline Server 1.9 binary against which the protocol guide's
code claims are checked. The guide's oracle is a PEF data fork with the SHA-256
recorded under Hotline Server 1.9.

Authoritative source: [protocol guide](protocol/protocol.md), opening section.

Evidence: the 1.9 binary is authoritative for the behaviour of its build. The
SynHX source is comparison evidence, not evidence of what that binary does
([validity ledger](baseline-validity-ledger.md#provenance-and-authority)).

### Preparation

A preparation is an offline packet that sets up a fixture, a plan and operator
checks before a run. It does not run the case.

Authoritative source:
[native private-message fixture preparation](native-evidence/native-pm-preparation.md#native-private-message-fixture-preparation-a26),
opening section.

Evidence: the native private-message preparation was prepared offline and then
executed in the native PM witness (the same section). The isolated legacy
message board preparation states that it does not run its case
([board preparation](native-evidence/native-board-preparation.md), opening
section).

### Readback

A readback is a read request that checks a stored value after a write.

Authoritative source: [bitmap boundaries](protocol/bitmap-boundaries.md),
opening section.

Evidence: each replacement of field `110` (request 353) is followed by an
immediate readback (request 352), and the bitmap-boundary records compare the
two (the same section).

### Source prediction

A source prediction is a comparison of behaviour made from decompiled source,
without a new oracle call or native request.

Authoritative source:
[rate-path contract](presence-and-messaging/rate304-contract.md), opening
section.

Evidence: the rate-path comparison is a source prediction. The later native
sequence captures the observed result (the same section).

### Unresolved

Unresolved means that an implementer must obtain further evidence, rather than
treat the previous guide's guesses as requirements.

Authoritative source: [protocol guide](protocol/protocol.md), opening section.

Evidence: the gap analysis states that the corrected documents deliberately
contain unresolved statements, and that unanswered entries turn them into
actionable questions ([gap analysis](../gap-analysis.md), opening section).

### Verifier

A verifier is a script that checks retained evidence against its recorded
hashes and claims and reports a verdict. The inherited checkers are named
`scripts/verify_*.py`.

Authoritative source:
[AGENTS.md, what lives where](../AGENTS.md#what-lives-where).

Evidence: a verifier must reach the same verdict on every retained corpus
before and after any change to it
([AGENTS.md, rules that protect the evidence](../AGENTS.md#rules-that-protect-the-evidence)).

### Withheld file

A withheld file is a file whose bytes are not published in the repository. The
evidence records its size, hash and fork kind instead.

Authoritative source: [withheld file list](../evidence/withheld.json), `reason`
field.

Evidence: the list states that "Forks of the Hotline Server 1.9 binary are
third-party material that this project may not publish". Where a patch is
retained for a withheld file, the list records the patch's path and hashes.

### Witness

A witness is the retained record of an executed run, with its readbacks,
receipts and corpus. Preparations are exercised by witnesses.

Authoritative source:
[native ban control preparation](native-evidence/native-ban-control-preparation.md#isolated-permanent-ban-control-fixture-c52-preparation),
opening section.

Evidence: that preparation "was exercised by the C56 permanent-ban witness"
(the same section).

## Register and provenance terms

### Audit revision

An audit revision is a numbered snapshot of the protocol gap analysis. It is
stored as a directory named
`evidence/protocol-gap-analysis/<date>/revision-<number>/`, with a
`manifest.json` that records its inputs
([plan, toolset section](execplans/documentation-reconcilliation.md)).

Authoritative source: the audit revision manifests under
`../evidence/protocol-gap-analysis/`.

Evidence: the retained records do not agree on the current revision. The gap
register names revision 91 as its source manifest
([gap register](../gap-register.json), `source_manifest`). Its method text and
the gap analysis describe "Revision 90", and the
[protocol handoff](provenance/protocol-handoff.md) refers to revision 89.

### Correction map

The correction map is the table in
[the baseline correction map](provenance/baseline-correction-map.md) that gives
the disposition of every ledger entry for the current revision.

Authoritative source:
[baseline correction map](provenance/baseline-correction-map.md), opening
section.

Evidence: the map applies the 12 November 2026 ledger to the protocol guide and
the compatibility matrix. All 83 entries have a disposition. The map preserves
the initial dispositions, and later closures are tracked in the gap analysis
(the same section).

### Gap

A gap is an open question about the 1.9 specification, recorded in the gap
register. Each gap has an identifier of the form `GAP-` followed by three
digits, a priority, a kind, a status, a question and closure criteria.

Authoritative source: [gap analysis](../gap-analysis.md), opening section, and
[gap register](../gap-register.json).

Evidence: the register holds 87 gaps (the gap analysis, opening section). The
gaps are documentation questions and proposed investigation priorities. They
are not confirmed binary defects, security ratings or mxd test failures (the
same section).

### Gap kind

A gap kind classifies what a gap needs. The gap analysis defines the five kinds
in [the gap analysis](../gap-analysis.md#counts) as follows.

| Kind       | Meaning                                                                 | Gaps |
| ---------- | ----------------------------------------------------------------------- | ---: |
| Unanswered | Refines the documents' unresolved statements into actionable questions. | 57   |
| Missing    | Records an omission found by the sweep.                                 | 12   |
| Ambiguous  | Records an under-specified requirement.                                 | 10   |
| Evidence   | Needs independent peer, runtime or mxd results.                         | 5    |
| Decision   | Needs an explicit scope or compatibility policy.                        | 3    |

_Table 1: Gap kinds, their meanings and the number of gaps of each kind._

Authoritative source: [gap analysis](../gap-analysis.md), opening section for
the meanings and the counts section for the numbers.

### Gap priority

A gap priority is a recommended order of investigation for a gap. The gap
analysis states that the priorities are recommendations.

| Priority | Meaning                                                                                                                          | Gaps |
| -------- | -------------------------------------------------------------------------------------------------------------------------------- | ---: |
| P0       | Core codec, session/login or baseline-fixture work needed before claiming a usable core contract.                                | 20   |
| P1       | Blocks completion of the named feature or a cross-cutting compatibility policy if that feature is in scope.                      | 56   |
| P2       | Secondary operation semantics, evidence portability, peer coverage or project QA that still needs a recorded decision or result. | 11   |

_Table 2: Gap priorities, meanings and gap counts._

Authoritative source:
[gap analysis, priority meanings](../gap-analysis.md#priority-meanings), and its
[counts](../gap-analysis.md#counts).

### Gap status

A gap status records where a gap stands in the register.

| Status        | Meaning                                                                                                                                | Gaps |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ---: |
| Open          | The state of every entry at the first audit. One gap currently holds it.                                                               | 1    |
| Investigating | Not defined in the retained gap analysis.                                                                                              | 24   |
| Resolved      | Requires cited evidence, corrected documentation and a checked closure criterion. A correction disposition alone does not close a gap. | 62   |

_Table 3: Gap statuses, their meanings and the number of gaps at each status._

Authoritative source:
[gap analysis, scope, evidence and status](../gap-analysis.md#scope-evidence-and-status),
and its [counts](../gap-analysis.md#counts).

Evidence: the gap analysis also defines "Deferred" as a recorded scope or
policy decision, not a solved protocol question. No gap currently holds that
status.

### Ledger entry

A ledger entry is one numbered claim in the
[validity ledger](baseline-validity-ledger.md). Each entry gives its source
reference, a status and the oracle observation.

Authoritative source: [validity ledger](baseline-validity-ledger.md), opening
sections. The statuses are defined under
[status meanings](baseline-validity-ledger.md#status-meanings).

Evidence: the valid identifiers are listed in
`../evidence/hotline-server-1.9/claims.json`, which lists 83 identifiers. The
protocol guide cites them by identifier, for example `V003`
([protocol guide](protocol/protocol.md), opening section). The two claim
series are shown in Table 4.

| Series | Identifiers              | Claims about                         |
| ------ | ------------------------ | ------------------------------------ |
| V      | V001 to V074 (74 claims) | The protocol guide, snapshot P       |
| M      | M001 to M009 (9 claims)  | The compatibility matrix, snapshot M |

_Table 4: Ledger claim identifier series and the snapshot each cites._

Evidence: the rows are at lines 105 to 200 (V) and 212 to 222 (M) of the
[validity ledger](baseline-validity-ledger.md). The Ghidra query records use
the letter prefixes `A`, `C` and `D`, which are a separate series. See
[Ghidra query record](#ghidra-query-record).

### Snapshot label

Snapshot labels are the letters that the ledger uses for its frozen input
snapshots: `P` for the protocol guide and `M` for the compatibility matrix.

Authoritative source: [validity ledger](baseline-validity-ledger.md),
provenance and authority section.

Evidence: the letter `M` is also the prefix of the matrix claim series (`M001`
to `M009`). A reference such as `M:19–21` names a line range of the matrix
snapshot, while `M003` names a claim
([validity ledger](baseline-validity-ledger.md#compatibility-matrix-ledger)).

## Work-packet labels

### A-series label

An A-series label is an `A` followed by a number, such as `A7`, `A9`, `A11`,
`A26` or `A114`. The retained records attach these labels to readbacks,
witnesses, preparations and audits.

Authoritative source: none of the retained documents defines the letter. The
meaning of the letter is not stated in the retained records.

Evidence: `A26` is the native private-message fixture preparation
([native PM preparation](native-evidence/native-pm-preparation.md), title).
`A114` is an independent audit
([native rate304 sequence](native-evidence/native-rate304-sequence.md),
opening section). `A7` is a readback (see [A7 readback](#a7-readback)). The
letter therefore does not identify one kind of work (see Table 5).

### B-series label

A B-series label is a `B` followed by a number, such as `B29`, `B50`, `B82` or
`B115`. The retained records attach these labels to rehearsals, capture runs,
reviews and gates.

Authoritative source: none of the retained documents defines the letter. The
meaning of the letter is not stated in the retained records.

Evidence: `B50` is an earlier capture run that stopped before any variant, and
`B51` is the readiness gate that a later run used
([Classic 161 matrix](peers/classic-field161-matrix.md), lines 56 to 59).

### Batch number

A batch number labels a numbered group of retained Ghidra query records. The
groups are the directories `batch-01` to `batch-09` under
`../evidence/gap-remediation/2026-11-12/`. The query files in batch 01 carry
the prefix `B01-`, for example `B01-A-10014df0.json`.

Authoritative source: the batch manifests, for example
`../evidence/gap-remediation/2026-11-12/batch-01/manifest.json`.

Evidence: the retained records do not state what a batch denotes beyond this
grouping.

### C-series label

A C-series label is a `C` followed by a number, such as `C13`, `C32`, `C52` or
`C154`. The retained records attach these labels to preparations, witnesses and
mxd peer runs.

Authoritative source: none of the retained documents defines the letter. The
meaning of the letter is not stated in the retained records.

Evidence: `C52` is the isolated permanent-ban control fixture preparation
([native ban control preparation](native-evidence/native-ban-control-preparation.md#isolated-permanent-ban-control-fixture-c52-preparation),
title). The `C-` prefix on Ghidra query records is a separate series (see
[Ghidra query record](#ghidra-query-record)).

### Packet label

A packet label is the identifier that names a bounded unit of work in a title
or in prose, such as `A26`, `C52` or `B50`. Each label combines a letter and a
number, and the retained records do not state what the letter denotes.

Authoritative source: the documentation plan names its own packets with an
identifier of the form `EP-M5-014`, combining a milestone, a sequence number
and a short name
([plan, sub-agent rules](execplans/documentation-reconcilliation.md)).

Evidence: see Table 5 for the observed label series.

| Series | Examples in the retained records                                                                                        | Stated meaning                        |
| ------ | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| A      | `A7` readback; `A9` density witness; `A11` prepared packet that has not run; `A26` fixture preparation; `A114` audit    | Not stated in the retained records    |
| B      | `B29` to `B31` rehearsal; `B50` to `B52` capture runs and readiness gate; `B82` planned by root; `B95` and `B96` review | Not stated in the retained records    |
| C      | `C14` to `C19` mxd peer runs; `C32` and `C35` stalled transfers; `C52` fixture preparation; `C56` witness               | Not stated in the retained records    |
| Batch  | `batch-01` to `batch-09` directories of Ghidra query records                                                            | Grouping only; nothing further stated |

_Table 5: Work-packet label series observed in the retained records._

## Toolset terms

### AppleDouble

AppleDouble is the sidecar container format that the evidence records beside
the oracle's data fork.

Authoritative source:
[resource inventory](../evidence/gap-remediation/2026-11-12/batch-09/resource-inventory.json),
association field.

Evidence: the sidecar itself is withheld. Its binary delta is retained
([withheld file list](../evidence/withheld.json)).

### Ghidra

Ghidra is the reverse-engineering framework used for the static analysis of the
1.9 binary. The ledger records Ghidra 12.2 PUBLIC.

Authoritative source:
[validity ledger](baseline-validity-ledger.md#provenance-and-authority).

Evidence: all Ghidra access was read-only, and no names, comments, types or
code were changed
([validity ledger](baseline-validity-ledger.md#evidence-method-and-limits)).

### Ghidra MCP bridge

The Ghidra MCP bridge is the Model Context Protocol (MCP) server that exposes a
loaded Ghidra program to read-only queries. The records name the extension
`GhidraMCP`.

Authoritative source: [protocol handoff](provenance/protocol-handoff.md),
opening section.

Evidence: only one tool may serve the MCP endpoint at a time (the same
section). The Classic privilege record names the `GhidraMCP` JAR and its hash
([classic privilege discovery](accounts-and-privileges/classic-privilege-discovery.md),
lines 14 and 15).

### Ghidra query record

A Ghidra query record is the retained JSON of one read-only MCP query, with its
tool name, its arguments, the program identity and the result. The prefix gives
the query kind: `A-` records are disassembly (`disassemble_function`), `C-`
records are caller lists (`get_function_calls`), and `D-` records are
decompilations (`decompile_function_by_address`). Each `D-` record has a `.c`
companion file.

Authoritative source:
[validity ledger](baseline-validity-ledger.md#evidence-method-and-limits).

Evidence: the query records are in `../evidence/hotline-server-1.9/queries/`.
The prefixes are not claim identifiers.

### `mothra`

mothra is the general reverse-engineering and validation toolset that captures
this repository's evidence. It contains nothing specific to Hotline.

Authoritative source:
[AGENTS.md, the mothra toolset](../AGENTS.md#the-mothra-toolset).

Evidence: the documents link to mothra only by its absolute URL,
[github.com/leynos/mothra](https://github.com/leynos/mothra/blob/57aeaac4f12065bfb2de3d47943f4b45622392a9/README.md),
and never by a relative path (the same section).

### PEF

PEF is the Preferred Executable Format, the container format of the Hotline
Server 1.9 binary. The code oracle is the PEF data fork.

Authoritative source: [protocol guide](protocol/protocol.md), opening section.

Evidence: the evidence manifest records the program's executable format as
"Preferred Executable Format (PEF)"
([evidence manifest](../evidence/hotline-server-1.9/manifest.json), `program`
object).

### SheepShaver

SheepShaver is the Mac OS emulator in which the native evidence runs Hotline
Server 1.9.

Authoritative source:
[native diagnostic witness](native-evidence/native-diagnostic-existing-witness.md),
opening section.

Evidence: the records describe a disposable SheepShaver Mac OS 9 guest. The
preflight manifest records the emulator's hash
([preflight manifest](../evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/manifest.json),
`emulator_sha256`).

### Sleuth Kit

Sleuth Kit is the forensic file-system toolkit whose commands the records use
to read HFS images. The records use `fls` and `istat` to list and inspect owned
folders, and `icat` to extract complete data forks for hash comparison.

Authoritative source:
[native settings persistence preparation](native-evidence/native-settings-persistence-preparation.md),
lines 103 to 106.

Evidence: [operation contracts](protocol/operation-contracts.md), line 424,
records a read-only Sleuth Kit `fls -u` and `istat` check of the owned folders.
