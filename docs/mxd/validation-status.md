# mxd validation status

This document records what has been validated for the mxd server against the
Hotline 1.9 protocol documentation, at which revision, with which results, and
what remains. Terms follow the [glossary](../glossary.md). The current state is
set out in [Status of the validation work](#status-of-the-validation-work).

## Status of the validation work

The status is on hold at the user's instruction, dated 13 November 2026. The
primary task is documenting native Hotline Server 1.9, and further mxd
validation, fixes and client trials are deferred.

The record preserves findings already made. It is not a release sign-off or a
claim of full native compatibility.

## Revisions examined

| Identifier                                                         | Type           | Statement in this document                                                          |
| ------------------------------------------------------------------ | -------------- | ----------------------------------------------------------------------------------- |
| `cb907885cc2a61df2d708f38a3cf42da85c2a016`                         | mxd revision   | Canonical mxd remains at this revision. The trial binary was built offline from it. |
| `3da44eac362e1a5433eee4cace8f030e383a9c4a8ea8f587055610299c879375` | Binary SHA-256 | SHA-256 of the trial binary.                                                        |

_Table 1: Revision and binary identifiers on which the recorded results depend._

Unreconciled: `mxd-validation.md` gives canonical mxd as
`cb907885cc2a61df2d708f38a3cf42da85c2a016`. Other records pin accepted
corrections at other revisions. `mxd-direct-ack-correction.md` gives
`20e891a059de7dd9dec5a657d7099570987d860d` as the supervised fast-forward
accepted in canonical mxd, with parent
`481294915b48f4db06943c8af86cf31b7e47597a`. `mxd-limit-contracts.md` pins its
accepted correction at `481294915b48f4db06943c8af86cf31b7e47597a`.
`mxd-login-extras-correction.md` records a fast-forward from
`20e891a059de7dd9dec5a657d7099570987d860d` to
`cb907885cc2a61df2d708f38a3cf42da85c2a016`. This document does not resolve
these statements.

Unreconciled: `mxd-classic-login.md` records that mxd returned a type-0,
reply-marker-1, ID-1 status-1 empty reply in the failed Classic trial.
`mxd-direct-ack-correction.md` states that, at the pinned mxd base, the normal
login route transmitted type 107, not merely an internal dispatch label. The
Classic trial record does not state the mxd revision it ran against. This
document gives the trial binary as built offline from
`cb907885cc2a61df2d708f38a3cf42da85c2a016`. The documents do not decide which
of these describes the trial.

## Gate results for the last correction

The last correction's controlled full gates passed seven nextest profiles and
both doctest groups. PostgreSQL had 565 passing tests, SQLite had 569, and
wireframe-only had 551.

Unreconciled: `mxd-direct-ack-correction.md` gives a different PostgreSQL
figure. It records 557 PostgreSQL cases for an earlier gate, of which 556
passed and one failed during embedded database startup (`pg_ctl` could not
start). The two figures describe different gates, and the gate manifests would
separate them.

The verification profile retained one skip; mxd doctests retained four ignores.

Unreconciled: `mxd-limit-contracts.md` records, for its `make test` gate, seven
nextest profiles with one recorded skip, and both doctest commands with four
recorded ignores. `mxd-login-extras-correction.md` records one verification
skip and four ignored mxd doctests for its corpus. The documents do not say
which gate these counts belong to. The frozen logs linked from those two notes
would decide it.

The
[frozen logs and source snapshots](../../evidence/gap-remediation/2026-11-13/mxd-login-extras-01/manifest.json)
record the exact commands, environment and results of the last correction's
gates.

## Scope of the gate results

Kani was **not run**.

These results establish the tested implementation scope, not historical-client
startup or protocol-wide parity.

## Startup hand-off missing from the current implementation

At the recorded mxd revision:

- `src/login.rs:53–56` grants successful users `NO_AGREEMENT`.
- `src/commands/handlers.rs:101–115` sends the login ACK and updates presence
  for other peers. It sends no agreement notification 109 to the new client.
- `src/commands/parsing.rs:48–76` has no implemented 121 command branch; the
  registered route falls through to the unknown-command result.
- `src/commands/handlers.rs:119–137` builds a roster on explicit request 300.
  The Classic trial sent no 300, so it did not test that writer.

Native 1.9 still sends 109 with field `154=0001` for the agreement-bypass path.
Its
[login-state contract](../presence-and-messaging/presence-messaging-contracts.md#captured-configured-login-states-and-visibility)
distinguishes that notification from becoming online. The source trace is
consistent with the observed Classic wait, and a corrective replay has not been
performed. The
[frozen source review](../../evidence/gap-remediation/2026-11-13/mxd-validation-hold-01/source-reconciliation.as-reviewed.txt)
records the exact anchors.

Current mxd user/developer guides overstate agreement completion.

The roadmap already lists agreement handling as pending. No new agreement
implementation or release scope has been approved by this record.

Unreconciled: `mxd-validation.md` states that the parsing source has no
implemented 121 command branch. `internal-compatibility-matrix.md` (now the
[compatibility matrix](compatibility-matrix.md)) states: "Early completion
still needs no 121, and delayed completion still needs it." Whether the Classic
path needs 121 is not decided in the record.

## Handoff locations

Start with this document when resuming.

The [original assertion review](assertion-reconciliation.md) maps the earlier
55 focused tests. Later correction records supersede the original review's
stale classifier, reply and login-extra findings (see
[corrections](corrections.md)).

Unreconciled: `mxd-reconciliation.md` records, at
`2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131`, that the mxd predicate requires
reply type 107, while the native direct ACK uses type zero and request-ID
correlation. `mxd-direct-ack-correction.md` records that the router still
dispatches on incoming type 107, and that a successful login keeps the
conditional 161/162 behaviour after its wire type becomes 0. The two statements
describe different revisions. This document records the later correction as
superseding the review's reply findings, but it does not decide the predicate
revision by revision beyond that. The direct-reply evidence manifests recorded
in `mxd-direct-ack-correction.md` would settle it.

| Location relative to mothra                    | State at the hold                                                                                                                                                                                                                                                     |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `../mxd`                                       | Canonical accepted source at `cb907885`; no newer mxd changes imported.                                                                                                                                                                                               |
| `state/delegation/workspaces/batch-02-mxd/mxd` | Same source base, with interrupted uncommitted changes to `docs/users-guide.md`, `docs/developers-guide.md` and the doc comment in `src/commands/support.rs`. The interrupted changes are to be preserved and reviewed, and they do not implement agreement handling. |
| `state/native-sessions/mxd-peer-c14`           | Holds the first build, the failed and corrected seed, the supervision anomaly, the accepted C19 daemon and terminal receipts. The private credential, config and SQLite inputs remain there.                                                                          |
| `state/native-sessions/mxd-peer-a22`           | Holds the first failed Classic trial and private raw captures.                                                                                                                                                                                                        |
| `state/native-sessions/mxd-peer-short-01`      | Holds the separate short-password fixture, C21 readiness and terminal receipts.                                                                                                                                                                                       |
| `state/native-sessions/mxd-peer-a24`           | Holds a successful authentication followed by a stalled startup, raw captures and a recorded timing deviation.                                                                                                                                                        |
| `state/delegation/workspaces/batch-02-native`  | Holds A25 partial-login publication work, private Mothra commit `5168b93` and uncommitted protocol notes. Its validators were not imported after the hold.                                                                                                            |

_Table 2: Locations recorded at the hold, relative to the mothra checkout._

Unreconciled: `mxd-reconciliation.md` gives the checkout as
`/data/leynos/Projects/mxd` at `2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131`
before and after testing. The `../mxd` row above is the canonical accepted
source at `cb907885cc2a61df2d708f38a3cf42da85c2a016`. The documents do not say
whether these are one path, and the relative path is not resolved in the text.

Ignored local paths are recovery pointers, not portable evidence links. The
committed redacted witnesses and frozen source and test bundles linked in this
document are the portable handoff. Raw packet replay additionally requires the
private credential-bearing inputs. No live mxd trial daemon remains running.

## Repeatability and deferred validation

The fixture workflow and its repeatability are described in
[Classic client trials](classic-client-trials.md).

Resume mxd work only when requested, starting with these recorded items:

1. Reconcile guide claims and design/test the 109/121 startup sequence,
   including notification IDs, recipient selection and ordering.
2. Complete one identified Classic startup before claiming roster, banner or
   general interoperability; keep authentication-only results separate.
3. Complete the requirement-to-test map and remaining stale-assertion review
   under GAP-085. Passing focused tests are not proof of all operation paths.
4. Resolve native byte-encoding versus mxd's ASCII server-name policy,
   remaining omission/fallback choices, and other explicit compatibility gaps.
5. Obtain the separate release subset, sign-off owner and proof obligations for
   GAP-001/086. Do not infer them from the native 1.9 documentation target.

Unreconciled: `internal-compatibility-matrix.md` (now the
[compatibility matrix](compatibility-matrix.md)) states: "The ASCII 162 trial
reaches login, roster and banner data with all other bytes unchanged." The
24-character Classic trial recorded no 121, 300 or 212 request (see
[Classic client trials](classic-client-trials.md)). That matrix entry names a
separate trial record, `classic-server-name-162.md`, and does not state which
server it used. The record does not settle this.

## Bounded correction proposal

A separate isolated mxd implementation packet should begin with failing tests
for the observed native contract, then change the smallest affected policy and
routing code. The packet should:

1. Replace or retire the “sub-version 2 means SynHX” expectation in
   `compat_policy/mod.rs`, its unit tests, the two login feature suites and
   `compat_policy/kani.rs`. A reported version threshold may remain as a
   version fact; it must not be presented as a verified peer identity.
2. For a native 1.9 compatibility target, expect successful login field 161
   with absent/0/150/151/190 request version, including sub-version 2. Expect
   field 162 when the configured server name is nonempty and no 162 when it is
   empty. Keep failed-login cases without success extras. Exercise the actual
   router boundary as well as the unit augmenter.
3. Review native type-zero ACK versus mxd's type-107 success predicate in
   `compat_policy/mod.rs` and the `compat_layer`/router path. Define an
   explicit mxd wire reply contract before changing the predicate.
4. Update `mxd/docs/internal-compatibility-matrix.md`, the release checklist
   references and any Kani harness whose expected policy changes. Run the
   focused regression commands, relevant full mxd gates and actual peer
   acceptance sessions under a separately approved scope.

This proposal is not a request to copy every native quirk. GAP-001 still needs
an operation-by-profile required/deferred/excluded matrix and unsupported reply
policy. GAP-086 still needs named sign-off owners, the accepted native and
identified-peer corpus, deferred-gap rules, and recorded Kani invocations with
results for any proof claim. The checked-in mxd checklist requires a matrix
link and statement but names no release owner. Roadmap items 1.5.3–6 are
checked; that status cannot validate the new baseline. GAP-085 remains open
until stale expectations are fixed or retired and rerun against the chosen
scope.

## History

Three corrections were accepted before this hold. Their results are recorded in
[corrections](corrections.md).

Private corrections to those guides and one source comment were interrupted and
preserved when this hold was requested. They have not changed canonical mxd.
