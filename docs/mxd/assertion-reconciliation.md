# mxd assertion reconciliation

This document maps mxd test assertions to the corrected Hotline Server 1.9
baseline. It records the assertions reviewed at the revision listed in
[Revisions examined](#revisions-examined) and the protocol requirements that
each is reconciled with. The state of the work after this review, and the point
at which to resume it, is in [validation-status.md](validation-status.md).

## Revisions examined

| Revision                                   | Type                   | Use in this document                                                                                                                                                                      |
| ------------------------------------------ | ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131` | mxd checkout           | Checkout before and after testing. Tracked files were unchanged, and focused tests ran at this revision.                                                                                  |
| `cb907885cc2a61df2d708f38a3cf42da85c2a016` | mxd canonical revision | Named in mxd-validation.md, now [validation-status.md](validation-status.md), as the canonical accepted source at the location `../mxd`. Not the revision of the review in this document. |

_Table 1: Revisions examined in this document._

## Review scope

The checkout was `/data/leynos/Projects/mxd` at
`2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131` before and after testing. Tracked
files were unchanged. The only untracked path in the checkout was
`mxd.worktrees/`, an unrelated directory, which was preserved.

The review was carried out and tested on 12 November 2026 at revision
`2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131`. No mxd source or test was changed
in this review. GAP-085 remains open for implementation and test reconciliation
rather than recording false conformance.

Unreconciled: mxd-reconciliation.md gives the checkout as
`/data/leynos/Projects/mxd` at the revision above. mxd-validation.md, now
[validation-status.md](validation-status.md), says that canonical mxd remains at
`cb907885cc2a61df2d708f38a3cf42da85c2a016`, and that the location `../mxd` is
the canonical accepted source at that revision, with no newer mxd changes
imported. The documents do not say whether these name one checkout.

## Test runs

### Commands and counts

Four focused `cargo test --offline --locked` commands used an external target
directory in `mothra/state/delegation/mxd/target`. All 55 selected tests passed
across the four focused commands, and the corrected runs executed 55 tests.

Unreconciled: mxd-reconciliation.md says that the four focused commands used an
external target directory in `mothra/state/delegation/mxd/target`.
internal-compatibility-matrix.md, now
[compatibility-matrix.md](compatibility-matrix.md), says that build output was
kept under `mothra/state/mxd-target`. Both describe the review at the revision
listed above. This document does not decide which path was used.

All commands used `--offline --locked`, and integration runs enabled
`test-support`.

- The library filter `wireframe::compat` passed 31 tests
  ([log](../../evidence/gap-remediation/2026-11-12/mxd-review/compat-tests.log)).
- The `wireframe_compat_guardrails_bdd` scenario set passed 6 tests
  ([scenario log](../../evidence/gap-remediation/2026-11-12/mxd-review/scenario-tests.log)).
- The `wireframe_login_compat` scenario set passed 9 tests
  ([scenario log](../../evidence/gap-remediation/2026-11-12/mxd-review/scenario-tests.log)).

The results for the `user_name_list`, `wireframe_xor_compat` and
`wireframe_presence_bdd` scopes are stated with their assertions in the
assertion-to-requirement map.

### Evidence records

The
[manifest and logs](../../evidence/gap-remediation/2026-11-13/delegated-mxd-01/manifest.json)
record commands, counts, source hashes and statuses. The manifest and logs
link is
[delegated-mxd-01/manifest.json](../../evidence/gap-remediation/2026-11-13/delegated-mxd-01/manifest.json)
(the run record).

The
[review manifest](../../evidence/gap-remediation/2026-11-12/mxd-review/manifest.json)
records the commands, environment, source hashes and frozen copies.

Unreconciled: mxd-reconciliation.md links the run record under
`2026-11-13/delegated-mxd-01`. internal-compatibility-matrix.md, now
[compatibility-matrix.md](compatibility-matrix.md), links the review manifest
under `2026-11-12/mxd-review` and dates the review 12 November 2026. The
documents do not say whether these are one run or two.

### Verifier

The verifier checks the claims recorded in the manifest and logs against frozen
source snapshots without needing an mxd checkout, and optionally checks the
live pinned checkout with `--mxd ../mxd`. It rejects changed test counts or
source hashes.

The verifier is
[`scripts/verify_mxd_reconciliation.py`](../../scripts/verify_mxd_reconciliation.py).

## Limits of the evidence

Passing tests show that the current policy behaves as its tests demand. They do
not show that the policy matches native 1.9 or an intended client profile.

Kani was not run in this review.

These tests use mxd's own fixtures, not identified historical Hotline/SynHX
client binaries.

This evidence provides an exact starting revision and test map.

## Assertion-to-requirement map

Source locations below refer to the pinned mxd checkout. “Pass” refers only to
the selected test run in the
[run manifest](../../evidence/gap-remediation/2026-11-13/delegated-mxd-01/manifest.json).

### Shared handshake and peer identity

The shared handshake and peer identity rule in
`src/wireframe/compat_policy/mod.rs:82-91` gives sub-version 2 precedence over
field 160. `src/wireframe/compat_policy_tests.rs:39-42,188-193` and
`tests/features/wireframe_login_compat.feature:35-38,53-56` enforce it. Native
1.9 and the actual shx build both use 2. Retire the identity assertion or
replace it with a separately evidenced signal.

`compat_policy/mod.rs::kind` classifies every sub-version-2 connection as
SynHX, before checking field 160. The shared normal handshake is not an
identity discriminator. The existing policy is confirmed, and the
native-conformance claim is rejected.

In particular, the incorrect peer identity must not become a protocol
requirement merely because its current regression test passes.

### Successful login field 161

Successful login field 161 is gated by inferred kind in
`src/wireframe/compat_policy/mod.rs:95-97,119-125`.
`src/wireframe/compat_policy_tests.rs:114-127,188-208` expects omission of
extras for sub-version 2 or old versions. The native corpus includes 161 for
absent/0/150/151/190, and the identified shx build tolerates it. Passing
omission assertions are stale as native-parity tests.

Login extras are enabled only for classified `Hotline85` and `Hotline19`, and
tests enforce omission for SynHX and unknown. Native successful login includes
161/162 without this gate. Passing policy tests do not validate native parity.

Unreconciled: mxd-reconciliation.md records successful login field 161 as gated
by inferred kind at the review revision. mxd-login-extras-correction.md, now
[corrections.md](corrections.md), records that mxd now preserves raw handshake
and reported-version facts without using them to infer peer identity or
suppress success fields. mxd-validation.md, now
[validation-status.md](validation-status.md), records that inferred
client-family gates were removed. The corrections document links the import and
acceptance records for that correction. This document does not decide between
these statements.

### Configured server name 162

`src/wireframe/compat_policy/mod.rs:29-32,125-145` inserts constant `mxd` when
its kind gate passes. `tests/features/wireframe_login_compat.feature:17-30`
expects omission for sub-version 2 or old versions. Native nonempty 162 reached
the actual shx build; empty native name omitted it. Future mxd parity needs a
specified configuration source and empty-name behaviour.

### Failed login and direct reply type

`src/wireframe/compat_policy/mod.rs:152-157`,
`src/wireframe/compat_policy_tests.rs:174-182` and both login feature suites
reject success extras on failure. The distinction agrees with native
observations. The mxd predicate, `is_successful_login_reply`, requires reply
type 107, while the native direct ACK uses type zero and request-ID
correlation. Review the routing context before transplanting this policy to
native replies.

Routing should be reviewed before claiming wire parity for direct replies.

Unreconciled: mxd-reconciliation.md says that the mxd predicate requires reply
type 107, at the review revision. mxd-direct-ack-correction.md, now
[corrections.md](corrections.md), says that the router still dispatches on
incoming type 107, and that its compatibility layer passes the original request
kind to the extras predicate. It also says that a successful login can keep the
conditional 161/162 behaviour after its wire type becomes 0. mxd-validation.md,
now [validation-status.md](validation-status.md), says that later correction
records supersede the original review's stale classifier, reply and login-extra
findings. These statements describe different revisions. This document does not
decide the predicate beyond that statement.

### Version parser and unknown fallback

`src/wireframe/compat_policy/mod.rs:164-175` and
`src/wireframe/compat_policy_tests.rs:57-79,119-127,237-249` enforce a 2/4-byte
`u16` parser and conservative omission. The version parser accepts exactly 2/4
bytes and rejects values outside `u16`.

These are implementation choices, not proof of client identity or native
numeric boundaries.

The native generic numeric helper also accepts 1 byte and has other edge
behaviour. The difference is an explicit acceptance-policy difference, with no
assertion of equivalent boundaries.

### Repeated roster records

`src/presence_tests.rs::user_name_list_reply_contains_repeated_field_300_entries`
passed in the three-test `user_name_list` filter. The library filter
`user_name_list` passed 3 tests
([log](../../evidence/gap-remediation/2026-11-12/mxd-review/roster-tests.log)).

The roster tests assert repeated packed field 300. The repeated roster layout
matches the native roster layout in the reviewed scope, and other repetitions
remain separate. The disposition is verified mxd assertion and result for this
scope.

### Presence routing

`tests/features/wireframe_presence.feature` passed one mxd scenario. The
`wireframe_presence_bdd` scenario set passed 1 test
([log](../../evidence/gap-remediation/2026-11-12/mxd-review/presence-tests.log)).
The presence scenario asserts peer login/update/disconnect delivery, and it
does not establish native 302 teardown order or every peer delivery path.
Native 302 teardown order remains untraced, and the passing scenario does not
close GAP-036.

### XOR compatibility

The `wireframe_xor_compat` scenario set (`tests/wireframe_xor_compat.rs`)
passed five scenarios, including the news body
([scenario log](../../evidence/gap-remediation/2026-11-12/mxd-review/scenario-tests.log)).
The current XOR heuristic is not a negotiated native text mode, and peer
ambiguity and structured news fields remain GAP-080/082 work.

### Exact current text heuristic

`compat.rs` starts a connection with XOR disabled, ignoring handshake metadata.
For a decoded parameter list, it considers these field IDs text: **101, 105,
106, 162, 201, 321, 323, 325, 327, 328, 329, 333**. This includes structured
news fields; it does not include display-name 102, subject 115, quoted text 214
or auto-response 215.

When disabled, it enables XOR if at least one selected field exists, at least
one selected value is invalid UTF-8, and every selected value becomes valid
UTF-8 after complementing. On that request it complements all selected fields.
Once enabled, it complements all selected inbound/outbound values without
redetection; the state has no disable transition in this implementation.
Nonselected values remain unchanged. Invalid TLV decoding returns an error.

This is an observed mxd heuristic, not negotiated native encoding. Plaintext
high bytes can trigger it, and complemented bytes can be valid UTF-8 without
triggering it. The peer ambiguity corpus and decoder policy remain GAP-082. Its
news-field inclusion also needs schema-aware review now that structured layouts
are being recovered.

### Old mxd compatibility matrix

The old
[mxd compatibility matrix](../../evidence/gap-remediation/2026-11-13/delegated-mxd-01/inputs/docs/internal-compatibility-matrix.md.txt),
linked as the `delegated-mxd-01` input `internal-compatibility-matrix.md.txt`,
still lists `sub_version != 2` for Hotline 1.8.5/1.9, calls sub-version 2 a
SynHX identity, and labels unknown/legacy omission “Supported”. Its test
references point to a former `compat_policy.rs` layout; the current tests are in
`src/wireframe/compat_policy_tests.rs`. The old matrix cannot serve as release
acceptance evidence until it is corrected at an identified mxd revision.

## History

An initial filter named the source filename instead of its Rust module and
matched zero tests; its retained log is not counted as coverage.

The content of this document was consolidated from mxd-reconciliation.md and
the review sections of internal-compatibility-matrix.md.
