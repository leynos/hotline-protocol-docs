# mxd compatibility reconciliation at 2e4c9c1

This review maps mxd assertions to the corrected Hotline Server 1.9 baseline.
The checkout was `/data/leynos/Projects/mxd` at
`2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131` before and after testing. Its
only untracked path was `mxd.worktrees/`, which was preserved. Four focused
`cargo test --offline --locked` commands used an external target directory in
`mothra/state/delegation/mxd/target`; all 55 selected tests passed. The
[manifest and logs][run] record commands, counts, source hashes and statuses.
The [verifier][verify] checks those claims against frozen source snapshots
without needing an mxd checkout, and optionally checks the live pinned
checkout with `--mxd ../mxd`. It rejects changed test counts or source hashes.

Passing tests show that the current policy behaves as its tests demand. They
do not show that the policy matches native 1.9 or an intended client profile.
No mxd source or test was changed in this review, and Kani was not run.

## Oracle and identified peer boundary

The [corrected login contract](protocol.md#login-transaction-107--client-initiates)
states that a successful native 1.9 login sends server version 160, numeric
field 161 and, when configured nonempty, server name 162. The [native
configuration corpus](native-wire-details.md#captured-login-extras-configuration-bytes-and-refresh)
observed this with request version 160 absent, 0, 150, 151 and 190 in early and
delayed login paths. Field 161 was `0000`; an empty configured name omitted 162.
The normal handshake's sub-version 2 is shared with the historical shx source
and cannot identify a SynHX peer on its own.

The [identified shx 0.1.48 full-process corpus](identified-client-source.md#full-native-peer-acceptance-matrix)
completed five native sessions with a pinned terminal build. Its ordinary
handshake used sub-version 2, omitted request field 160, and consumed native
login fields 160/161 before roster, chat and file operations. A [second native
corpus](identified-client-source.md#native-configured-name-and-controlled-receiver-matrix)
completed three sessions with configured field 162, including a raw `9a` byte.
The same section's banner 122 and roster-subject 115 cases used a controlled
receiver, not the native server. These are finite observations for that exact
build; they do not identify every SynHX client or set a universal omission
policy.

## Assertion-to-requirement map

The source locations below refer to the pinned mxd checkout. “Pass” refers
only to the selected test run in the [new manifest][run].

- **Shared handshake and peer identity.**
  `src/wireframe/compat_policy/mod.rs:82-91` gives sub-version 2 precedence
  over field 160. `src/wireframe/compat_policy_tests.rs:39-42,188-193` and
  `tests/features/wireframe_login_compat.feature:35-38,53-56` enforce it.
  Native 1.9 and the actual shx build both use 2. Retire the identity
  assertion or replace it with a separately evidenced signal.
- **Successful login field 161.**
  `src/wireframe/compat_policy/mod.rs:95-97,119-125` gates all extras by
  inferred kind. `src/wireframe/compat_policy_tests.rs:114-127,188-208`
  expects omission for sub-version 2 or old versions. The native corpus
  includes 161 for absent/0/150/151/190, and the identified shx build
  tolerates it. Passing omission assertions are stale as native-parity tests.
- **Configured server name 162.**
  `src/wireframe/compat_policy/mod.rs:29-32,125-145` inserts constant `mxd`
  when its kind gate passes. `tests/features/wireframe_login_compat.feature:17-30`
  expects omission for sub-version 2 or old versions. Native nonempty 162
  reached the actual shx build; empty native name omitted it. Future mxd
  parity needs a specified configuration source and empty-name behaviour.
- **Failed login and direct reply type.**
  `src/wireframe/compat_policy/mod.rs:152-157`,
  `src/wireframe/compat_policy_tests.rs:174-182` and both login feature suites
  reject success extras on failure. The distinction agrees with native
  observations. The mxd predicate requires reply type 107, while the native
  direct ACK uses type zero and request-ID correlation. Review routing before
  claiming wire parity.
- **Version parser and unknown fallback.**
  `src/wireframe/compat_policy/mod.rs:164-175` and
  `src/wireframe/compat_policy_tests.rs:57-79,119-127,237-249` enforce a
  2/4-byte `u16` parser and conservative omission. These are implementation
  choices, not proof of client identity or native numeric boundaries.
- **Repeated roster records.**
  `src/presence_tests.rs::user_name_list_reply_contains_repeated_field_300_entries`
  passed in the three-test `user_name_list` filter. This matches the native
  roster layout in the reviewed scope. Other repetitions remain separate.
- **Presence routing.**
  `tests/features/wireframe_presence.feature` passed one mxd scenario. It
  does not establish native 302 teardown order or every peer delivery path.
- **XOR compatibility.**
  `tests/wireframe_xor_compat.rs` passed five scenarios. The current heuristic
  is not a negotiated native text mode; peer ambiguity and structured news
  fields remain GAP-080/082 work.

The old [mxd compatibility matrix][old-mxd-matrix]
still lists `sub_version != 2` for Hotline 1.8.5/1.9, calls sub-version 2 a
SynHX identity, and labels unknown/legacy omission “Supported”. Its test
references point to a former `compat_policy.rs` layout; the current tests are
in `src/wireframe/compat_policy_tests.rs`. The old matrix cannot serve as
release acceptance evidence until it is corrected at an identified mxd
revision.

## Bounded correction proposal

A separate isolated mxd implementation packet should begin with failing tests
for the observed native contract, then change the smallest affected policy
and routing code. The packet should:

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
an operation-by-profile required/deferred/excluded matrix and unsupported
reply policy. GAP-086 still needs named sign-off owners, the accepted native
and identified-peer corpus, deferred-gap rules, and recorded Kani invocations
with results for any proof claim. The checked-in mxd checklist requires a
matrix link and statement but names no release owner. Roadmap items 1.5.3–6
are checked; that status cannot validate the new baseline. GAP-085 remains
open until stale expectations are fixed or retired and rerun against the chosen
scope. This evidence provides an exact starting revision and test map.

[run]: ../mothra/evidence/gap-remediation/2026-11-13/delegated-mxd-01/manifest.json
[verify]: scripts/verify_mxd_reconciliation.py

[old-mxd-matrix]: ../mothra/evidence/gap-remediation/2026-11-13/delegated-mxd-01/inputs/docs/internal-compatibility-matrix.md.txt
