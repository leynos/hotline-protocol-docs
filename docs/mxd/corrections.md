# mxd accepted corrections

This document records the three corrections accepted in canonical mxd during
the validation of the server against the Hotline 1.9 protocol documentation.
They cover framing limits, direct replies and successful login extras. Each
correction is described under the same four headings: native baseline,
behaviour before, correction and acceptance evidence. The state of further mxd
work is recorded in [validation status](validation-status.md). The pinned
revisions for the whole document set are listed in the [README](README.md).

## Revisions examined

The claims in this document depend on the revisions in Table 1.

| Identifier                                 | Type         | What this document records                                                                                                                                                  |
| ------------------------------------------ | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131` | mxd revision | Pins the original finding of the framing limit review (GAP-011).                                                                                                            |
| `481294915b48f4db06943c8af86cf31b7e47597a` | mxd commit   | Accepted framing correction. It fixes the logical/physical framing confusion and adds boundary regressions. It is the parent of `20e891a059de7dd9dec5a657d7099570987d860d`. |
| `50360bebff2c79a54272453ce734251be619c274` | mxd commit   | Makes the watchdog test wait for actual cancellation.                                                                                                                       |
| `20e891a059de7dd9dec5a657d7099570987d860d` | mxd commit   | Accepted direct-reply correction, reached by an exact supervised fast-forward.                                                                                              |
| `cb907885cc2a61df2d708f38a3cf42da85c2a016` | mxd revision | Canonical accepted revision after the successful login extras correction. It was reached by an exact fast-forward from `20e891a059de7dd9dec5a657d7099570987d860d`.          |

_Table 1: mxd revisions and commits on which the accepted corrections depend._

## Framing limits

### Framing limits: native baseline

Native observations remain separate from mxd's configured limits, and these mxd
checks did not contact the native guest.

The [native startup assignment][native] writes 524,288 bytes (512 kibibytes,
KiB) to the receive-limit global. The receiver closes for a zero or
greater-than-524,288 size word, while equality passes. Native request 500
dispatched after two fragments with sizes two and 524,288, an aggregate of
524,290 bytes. That observation does not establish an aggregate allocation cap,
all later writes to the global or mxd's intended interoperability policy.

mxd declares `MAX_FRAME_DATA = 32,768` and `MAX_PAYLOAD_SIZE = 1,048,576` in
`src/transaction/mod.rs`. Its physical decoder rejects a declared frame data
size above 32,768 before reserving payload bytes. Its logical transaction
validator rejects a declared total above 1,048,576; equality is accepted. The
limits are deliberate mxd configuration, not a measured copy of the native 512
KiB comparator. Changing either default requires a separate compatibility
decision.

### Framing limits: behaviour before

The GAP-011 review pins the original finding at mxd
`2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131`.

The original `from_parts` incorrectly re-applied the 32 KiB physical limit to
this normalized logical header. The retained red run passed 32,768 bytes but
rejected 32,769 and 1,048,576 with `InvalidData`/“payload too large”.

### Framing limits: correction

The [validation status](validation-status.md) physical frames and logical
transactions row records separate frame and reassembly limits, with overflow
and boundary controls.

The accepted correction is pinned at mxd
`481294915b48f4db06943c8af86cf31b7e47597a`. Commit
`481294915b48f4db06943c8af86cf31b7e47597a` fixes the logical/physical framing
confusion and adds boundary regressions. The accepted correction removes only
that physical check from `from_parts`. Exact logical length, total/data
consistency and the 1 MiB (mebibyte) total limit remain checked there. The real
physical decoder keeps its 32 KiB rejection.

`src/wireframe/codec/physical_frame.rs::take_hotline_frame` reads the 20-byte
header, calls `validate_header` before `BytesMut::reserve`, then uses
`checked_add` for header plus data length. `validate_header` in
`src/wireframe/codec/mod.rs` uses `>` for both the 1 MiB total and 32 KiB
physical data limit, so equality remains permitted. It rejects data greater
than total and zero data with nonzero total.

`src/wireframe/codec/framed.rs::HotlineCodec` accepts one physical fragment at
a time. Continuation handling uses `checked_sub` for remaining bytes and
rejects data greater than the remainder. It normalizes completed logical
`data_size` to `total_size` before calling `HotlineTransaction::from_parts`.

`src/wireframe/codec/frame.rs::HotlineFrameCodec` is the server's frame
adapter. It reports `HEADER_LEN + MAX_PAYLOAD_SIZE` as the logical message
ceiling, while each inbound physical fragment still passes the physical
decoder. Its series tracker rejects overshoot using a remaining-byte check.
`src/wireframe/message_assembly.rs` carries checked cursor arithmetic.

`src/transaction/reader/mod.rs::TransactionReader` and its streaming variant
default to 1 MiB total and accept a caller-supplied maximum.
`src/transaction/frame.rs::read_frame` checks declared total and 32 KiB
physical data before allocating. Continuations reject zero progress, changed
header fields and data beyond the remaining length.
`TransactionWriter::with_max_frame` clamps to 1..=32 KiB; the buffered and
streaming writer total limit can be configured per instance. These builder
overrides are separate from the current Wireframe server setup.

`src/server/wireframe/mod.rs` explicitly calls
`memory_budgets(explicit_memory_budgets())`. The three configured fields,
`bytes_per_message`, `bytes_per_connection` and `bytes_in_flight`, each equal
1,048,596 bytes (20-byte header plus 1 MiB payload).

The checked `usize` conversion and `checked_add` remain explicit production
guards.

### Framing limits: acceptance evidence

The physical frames row of the [validation status](validation-status.md) links
to the framing limits in this document and to the
[accepted correction manifest][acceptance].

The [original evidence][run] and the [accepted source and gates][acceptance]
preserve both states. The original evidence is linked as
`mxd-limits-01/manifest.json`, and the accepted source and gates as
`mxd-correction-01/manifest.json`.

The [red and green logs][run] exercise the production `HotlineCodec` decoder.
The red run is preserved and is not counted as a passing gate.

- A valid 32,768-byte logical payload decodes as one physical frame.
- A valid 32,769-byte logical payload decodes after two bounded physical frames.
  The red base failed with “payload too large”.
- A valid 1,048,576-byte logical payload decodes after 32 physical frames. The
  red base failed with “payload too large”.
- A declared total of 1,048,577 or `u32::MAX` returns `InvalidData` with “total
  size exceeds maximum” before payload buffering.
- Declared physical data of 32,769 returns `InvalidData` with “data size exceeds
  maximum” before payload buffering.
- A continuation larger than the remaining bytes is rejected by an existing
  codec test with “fragment exceeds remaining payload size”.

The 1 MiB exact and overflow-word controls demonstrate inclusive comparison and
absence of wrap into an accepted length on the tested 64-bit Linux host. No
32-bit executable was tested, and a bounded finite corpus is not an exhaustive
proof. The Kani harness source covers `validate_header` and fragment ranges;
Kani was not run for this packet. No Kani proof was run.

An existing unit test checks those exact values, and an integration test shows
a large fragmented request routes and a 1 MiB+1 declared total disconnects.
Those tests do not measure the maximum aggregate memory across concurrent
connections. Wireframe's documented budget mechanism is an external dependency
assumption until a multi-connection acceptance run verifies it at this mxd
revision.

The [limit corpus run record][run] is linked as `mxd-limits-01/manifest.json`.
The [subsequent recovery record][recovery] is linked as
`mxd-build-recovery-01/manifest.json`. The [controlled diagnostic][watchdog] is
linked as `mxd-watchdog-h1-01/manifest.json`.

Commit `50360bebff2c79a54272453ce734251be619c274` makes the watchdog test wait
for actual cancellation.

Both commits are now in the canonical mxd checkout, and the tested bytes match
those commits and the [supervised import record][import]. The supervised import
record is linked as `mxd-source-import-01/manifest.json`.

Formatting, lint and the complete managed `make test` gate passed: seven
nextest profiles, with one recorded skip, and both doctest commands, with four
recorded ignores.

Unreconciled: This section records the framing correction's managed `make test`
gate as seven nextest profiles with one recorded skip and both doctest commands
with four recorded ignores. The [validation status](validation-status.md)
states that “The verification profile retained one skip and mxd doctests
retained four ignores.” The login extras acceptance evidence states that “The
corpus records one verification skip and four ignored mxd doctests.” Nothing in
the text says which gate a count belongs to. The frozen logs linked from the
two corrections would decide it.

The portable [acceptance verifier][acceptance-verifier] checks the frozen
results without requiring an mxd checkout.

No Kani proof was run.

GAP-011 remains open for a complete native later-write/configuration trace and
independently measured aggregate buffering, plus any release decision about
mxd's distinct defaults. The accepted correction resolves the demonstrated
logical/physical confusion. The broader native/configuration and memory
criterion remains unmet.

## Direct replies

### Direct replies: native baseline

The [native baseline][reply-semantics] requires a direct reply to carry marker
1, type 0 and the request ID, including login success and failure, ordinary
nonlogin ACKs and error ACKs. Numbered server notifications use marker 0 and
retain their notification type.

### Direct replies: behaviour before

At the pinned mxd base, both `header_util::reply_header` and
`HotlineTransaction::reply_from_params` copied the request type into the reply.
The normal login route therefore transmitted type 107, not merely used 107 as
an internal dispatch label. The shared helper also produced nonlogin and
router-error replies, including the legacy writer path.

The first full PostgreSQL gate exposed an additional header-aware validator
assumption: repeated roster field 300 was accepted only when the reply header
echoed request type 300. A native type-0 roster reply therefore failed mxd's
own parser and legacy writer.

Unreconciled: The [classic client trials](classic-client-trials.md) record that
“mxd returned a type-0, reply-marker-1, ID-1 status-1 empty reply.” This
section states that, at the pinned base, the normal login route transmitted
type 107. The classic client trial record does not state the mxd revision it
used. The [validation status](validation-status.md) states that the trial
binary was built offline from `cb907885cc2a61df2d708f38a3cf42da85c2a016`, the
canonical revision after the login extras correction. The redacted corpus
manifest linked from the classic client trials would show the revision.

### Direct replies: correction

The correction makes both direct-reply constructors emit type 0 while
preserving the request ID and status. The
[validation status](validation-status.md) direct replies row records type 0
with reply marker 1 and copied request ID, and states that repeated roster
records remain accepted.

The router retains the original Login107 request kind even though its direct
ACK uses wire type 0. It still dispatches on incoming type 107, and its
compatibility layer passes that original request kind to the extras predicate.
So a successful login can retain the existing conditional 161/162 behaviour
after the reply's wire type becomes 0. A failed login or nonlogin reply cannot
receive those extras through the predicate.

Generic frame serialization still preserves an explicitly supplied header, and
presence notifications still emit types 301/302 with marker 0.

The approved correction permits repeated field 300 for marker-1 direct replies
regardless of wire type. Tested marker-0 Login requests, 301 notifications,
marker 2 and unrelated duplicate fields remain rejected. The pre-existing
marker-0 request type-300 opaque payload bypass is unchanged and outside this
correction.

Unreconciled: The [assertion reconciliation](assertion-reconciliation.md)
states that “The mxd predicate requires reply type 107, while the native direct
ACK uses type zero and request-ID correlation.” The router statement above,
from the direct reply note, says that the router still dispatches on incoming
type 107 and passes the original request kind to the extras predicate. The
assertion reconciliation records its checkout as
`2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131`, and this direct reply note is
pinned at `20e891a059de7dd9dec5a657d7099570987d860d`, so the two describe
different revisions. The [validation status](validation-status.md) states that
later correction records supersede the original review's stale classifier,
reply and login-extra findings. The documents do not decide the predicate
beyond that statement. The direct reply manifests linked in the acceptance
evidence below are the records that bear on it.

Unreconciled: The [compatibility matrix](compatibility-matrix.md) states that
“A global rule allowing repetition only in transaction-300 replies is
incorrect.” It also states that the “global transaction-300-only repetition
restriction should be removed.” The direct reply statements above do not say
whether the corrected mxd rule is still restricted by marker, by transaction or
by both. The frozen source and tests linked in the acceptance evidence below
would show it.

### Direct replies: acceptance evidence

The correction is accepted in canonical mxd after a controlled full gate and an
exact supervised fast-forward at `20e891a059de7dd9dec5a657d7099570987d860d`.
The parent of that commit is `481294915b48f4db06943c8af86cf31b7e47597a`. The
supervised fast-forward import is recorded in the [import manifest][ack-import].

The note supports [GAP-085][gap-analysis], does not change the baseline native
1.9 contract, and does not close that gap.

Four new parser, writer and Tokio tests failed before the correction. All six
new positive and negative controls pass after the correction. The original
multiuser presence behaviour-driven development (BDD) scenario now passes in a
focused SQLite run. Four new router-boundary tests failed at the old type
107/200 and passed after the candidate. Focused wireframe, writer and BDD tests
pass.

The [private evidence package][ack-evidence] is linked as
`mxd-direct-ack-01/manifest.json`.

The [later controlled full gate][controlled] is linked as
`mxd-direct-ack-02/manifest.json`. It passed all seven nextest profiles and
both doctest groups, with a fresh owned PostgreSQL root and two nextest test
threads.

The result does not establish stability at default parallelism or native peer
conformance.

The correction does not validate the existing peer classifier, choose whether
any profile needs omitted extras, set configured server name 162, or resolve
the meaning of field 161. The old passing classifier tests remain
implementation-policy tests.

GAP-085 still needs source/test reconciliation at the final mxd revision;
GAP-001 and GAP-086 need their independent scope and acceptance decisions.

No new native peer test was run in this note.

The direct replies row of the [validation status](validation-status.md) links
to this section.

## Login extras

### Login extras: native baseline

The Mac 1.9 client, identified shx client and historical SynHX source share
handshake sub-version 2. Sub-version 2 is an observed framing fact, not a
unique peer identity. A reported Login field 160 is also an observed value.

The native server's successful Login107 direct ACK includes server version 190
in field 160 and opaque two-byte `0000` in field 161 for absent, 0, 150, 151
and 190 reported versions. A configured nonempty server name appears in 162; an
empty name omits 162. Failed Login ACKs receive no success extras. See the
[native captures][native-captures] and the
[identified client sessions][identified-sessions].

The native 1.9 fixture retains raw byte `9a`. A 32-byte typing attempt stores
its first 31 bytes. Field 161's purpose remains unknown, and its exact two-byte
value does not establish a banner download reference.

Unreconciled: The [compatibility matrix](compatibility-matrix.md) states that
“The Classic 161 matrix establishes tolerance of absent, one-zero-byte and
four-zero-byte values through its recorded stages.” This section records the
native field 161 as the two-byte `0000`, and the
[assertion reconciliation](assertion-reconciliation.md) records the same value.
The behaviour-before section states that the old mxd field 161 was four bytes.
These documents do not reconcile the four-zero-byte width with the native
two-byte value. The Classic 161 matrix linked from the compatibility matrix is
not in this set, so the width cannot be checked here.

### Login extras: behaviour before

Two router tests failed before the production changes, because the old field
161 was four bytes and sub-version 2 suppressed it.

Unreconciled: The [assertion reconciliation](assertion-reconciliation.md)
states that “Successful login field 161 is gated by inferred kind in
compat_policy/mod.rs:95-97,119-125.” The correction described below states that
“mxd now preserves raw handshake and reported-version facts without using them
to infer peer identity or suppress success fields.” The
[validation status](validation-status.md) states that “Inferred client-family
gates were removed.” The documents do not state the revision at which each
statement applies. The linked corrections manifests would let a reader confirm
the change.

### Login extras: correction

mxd now preserves raw handshake and reported-version facts without using them
to infer peer identity or suppress success fields. All peers use the same
default authentication strategy.

Augmentation requires marker 1, type 0 and status zero. mxd emits raw two-byte
field 161 and field 162 when a configured name is nonempty. The existing
outbound exclusive-or (XOR) path transforms field 162 after router augmentation
on connections with XOR enabled, and leaves field 161 unchanged.

Correlated IDs, failed replies and nonlogin ACKs retain the direct reply
correction described above.

The `--server-name` option, `MXD_SERVER_NAME` and the configuration-file value
resolve through OrthoConfig. The resolved product default is `mxd`. Rust's
`AppConfig::default()` retains the repository's derive convention and has an
empty `String` for this field; direct programmatic construction must set it
explicitly.

The wireframe bootstrap validates configured names before the listener starts.
Only American Standard Code for Information Interchange (ASCII) bytes of length
at most 31 are accepted for the configured name. An empty name omits 162, and a
31-byte ASCII name is emitted intact. Non-ASCII and longer names are rejected
rather than transcoded or truncated.

The [validation status](validation-status.md) successful-login extras row
records two opaque zero bytes in 161 and a configured nonempty ASCII 162 of at
most 31 bytes, and states that inferred client-family gates were removed.

The ASCII limit is a declared mxd configuration limitation. Neither raw
high-byte representation nor native local clipping is reproduced by this mxd
setting.

### Login extras: acceptance evidence

The successful Login107 extras correction is accepted in canonical mxd by exact
fast-forward from `20e891a059de7dd9dec5a657d7099570987d860d` to
`cb907885cc2a61df2d708f38a3cf42da85c2a016`.

The [canonical import receipt][lex-import] records a 28-blob comparison and a
passing live verifier. It is linked as
`mxd-login-extras-import-01/manifest.json`.

The [portable C11 acceptance corpus][lex-evidence] is linked as
`mxd-login-extras-01/manifest.json`. It pins the source snapshots, patch, red
witnesses, controlled full gate and retained service exit.

The correction updates the reconciliation record, and does not close GAP-085 or
select a release owner or subset.

The successful-login extras row of the
[validation status](validation-status.md) links to this section.

Final focused router, policy, config, command-line interface (CLI) and BDD
checks passed.

`make check-fmt`, `make lint` and the Markdown gates passed.

A managed, retained `make test` unit passed all seven nextest profiles and both
doctest groups, with a fresh owned PostgreSQL root, `NEXTEST_TEST_THREADS=2`,
offline dependencies, one Cargo build job, and the user interface (UI) target's
layout override.

The corpus records one verification skip and four ignored mxd doctests.

Unreconciled: The login extras acceptance evidence records “a 28-blob
comparison” for the import receipt and “the 28 changed source files” for the
verifier. The History section records “all 19 frozen source hashes checked” for
the direct reply import. The documents do not say that these counts conflict.
The import manifests would show the set that each count covers.

This proves the controlled execution; the cause of an earlier
default-parallelism PostgreSQL startup failure remains unknown.

The Kani source was updated but Kani was not run, so there is no new proof
claim.

From an adjacent two-repository export, run:

```bash
python3 hotline-protocol-docs/scripts/verify_mxd_login_extras.py
python3 -m unittest discover -s hotline-protocol-docs/scripts \
  -p 'test_mxd_login_extras.py'
```

> Record note (2026-11-16): the commands above are quoted as they were run. The
> tests have since moved to `scripts/tests/` and run under pytest; the same
> tests now run with
> `uv run --group dev pytest scripts/tests/test_mxd_login_extras.py`.

The default verifier reads only the exported protocol-docs and mothra
repositories. `--mxd /path/to/mxd` additionally checks exact mxd HEAD, tracked
cleanliness, the 28 changed source files, and the base-to-commit patch. It
tolerates untracked local directories.

Four unittest controls include the baseline and checksum-consistent source,
unit-exit and count forgeries, and each forged corpus fails for its semantic
mismatch.

GAP-018/019/026/080/081/082/085 and the release owner/subset remain subject to
their own acceptance criteria.

No new native client or Ghidra query ran for this correction.

## History

The framing limit attempts came first. The initial full-gate attempts in the
limit corpus failed while linking. Subsequent recovery isolated one truncated
derived archive and retained the separate target-layout, interruption and
watchdog failures. A controlled diagnostic reproduced a sufficient scheduling
mechanism for the watchdog test's finite-sleep assumption, without changing
production timeout semantics or proving the historical cause.

The direct reply gates followed. The private evidence package pins two failed
full-gate outcomes and source hashes. The first failure was the repeated-300
validator dependency, which the candidate now corrects.

The second gate ran 557 PostgreSQL cases: 556 passed, and one failed during
embedded database startup (`pg_ctl` could not start). Later feature profiles
and doctests did not run in that attempt.

Unreconciled: The [validation status](validation-status.md) states that
“PostgreSQL had 565 passing tests” for the last correction's controlled full
gates. The second gate above ran 557 PostgreSQL cases, of which 556 passed. The
two figures are easy to confuse. The documents attribute them to different
gates, and the gate manifests would show which count belongs to which gate.

C8's isolated exact case and an overlapping pair passed with real databases,
but did not reveal the historical startup cause.

The identical tested source was committed privately, then imported into
canonical mxd with all 19 frozen source hashes checked. The original manifest
retains its private status as of capture; the import receipt records subsequent
acceptance.

[native]: ../protocol/session-transport-contracts.md#receive-limit-assignment-at-startup
[run]: ../../evidence/gap-remediation/2026-11-13/mxd-limits-01/manifest.json
[acceptance]: ../../evidence/gap-remediation/2026-11-13/mxd-correction-01/manifest.json
[recovery]: ../../evidence/gap-remediation/2026-11-13/mxd-build-recovery-01/manifest.json
[watchdog]: ../../evidence/gap-remediation/2026-11-13/mxd-watchdog-h1-01/manifest.json
[import]: ../../evidence/gap-remediation/2026-11-13/mxd-source-import-01/manifest.json
[acceptance-verifier]: ../../scripts/verify_mxd_correction.py
[reply-semantics]: ../protocol/protocol.md#4-reply-semantics
[ack-import]: ../../evidence/gap-remediation/2026-11-13/mxd-direct-ack-import-01/manifest.json
[ack-evidence]: ../../evidence/gap-remediation/2026-11-13/mxd-direct-ack-01/manifest.json
[controlled]: ../../evidence/gap-remediation/2026-11-13/mxd-direct-ack-02/manifest.json
[gap-analysis]: ../../gap-analysis.md#gap-085
[native-captures]: ../protocol/native-wire-details.md#captured-login-extras-configuration-bytes-and-refresh
[identified-sessions]: ../peers/identified-client-source.md
[lex-import]: ../../evidence/gap-remediation/2026-11-13/mxd-login-extras-import-01/manifest.json
[lex-evidence]: ../../evidence/gap-remediation/2026-11-13/mxd-login-extras-01/manifest.json
