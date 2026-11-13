# Internal compatibility matrix (Hotline and SynHX)

This matrix separates observed protocol behaviour from mxd compatibility policy
and reported implementation coverage. Its baseline is the
[Hotline 1.9 validity ledger][ledger], captured on 12 November 2026, and the
[corrected protocol guide](protocol.md).

The ledger used the Mac PPC `HLserver19` binary and the supplied historical
SynHX server source. It did not inspect an mxd checkout, run its tests or Kani
proofs, or validate particular Hotline/SynHX client builds. Consequently this
matrix is **not sufficient by itself for release-note QA sign-off**. A subsequent
[revision-specific review](#mxd-review-at-2e4c9c1) now supplies executed test
evidence and identifies policy assertions that conflict with native behaviour.

## Scope and status labels

Protocol evidence and implementation status are separate dimensions:

- **Observed:** established in a named static path of the hashed 1.9 server.
- **Source-observed:** established in a named historical server/client source
  snapshot, not in every client or release. A host fragment test remains a
  different evidence class from executing a full historical peer.
- **Policy requiring validation:** an mxd behaviour or classifier whose peer
  compatibility has not been established.
- **Implementation unverified:** a supplied test/source citation has not been
  checked at an identified mxd revision or executed for this baseline.

The earlier labels `Supported`, `Partial` and `Planned` described reported mxd
implementation progress. They must not be read as binary-validation results.
An implementation-status claim needs a repository revision, checked source
and test/proof output before it can be promoted to verified coverage.

Evidence: M008–M009.

## Compatibility matrix

| Peer or profile | Observed markers and behaviour | Protocol evidence | mxd implementation status |
| --- | --- | --- | --- |
| Hotline 1.9 Mac PPC server | Normal-session magic `TRTPHOTL 00 01 00 02`; successful login reports version 190 and includes 161/162 without a client-kind gate | Observed in the hashed server's handshake/login paths | mxd login policy tests passed; native-parity discrepancies are recorded below |
| Hotline 1.8.5 client profile | No identified client binary or session was validated; field 160 values `151..=189` do not by themselves prove this release | Policy requiring client validation | mxd threshold policy tested; identified-client compatibility unverified |
| SynHX historical server source | Defines the same normal-session magic ending in sub-version 2; its roster writer uses packed field 300 and appends subject 115 | Source-observed in supplied RCS trunk snapshots | Comparison source only; does not establish client behaviour |
| shx 0.1.48 source snapshot | README/version.c identify source at `adb1bf8`; basic login shares sub-version 2, omits 160 and ignores extras 161/162 | Source-observed; seven isolated host callback cases passed | Does not certify mxd or a compiled historical client |
| Other SynHX client profiles | No unique handshake marker, reply-field rejection rule or universal text-XOR mode was established | Policy requiring identified client/session evidence | Classifier/omission tests passed; disputed identity premise remains |
| Unknown or legacy client version | Native 1.9 login has no version/kind gate around reply fields 161/162; a missing/old version is not a proven profile identifier | Native behaviour observed; conservative omission remains a separate mxd policy | Omission-policy tests passed; native reply differs |

**Sub-version 2 is shared, not a SynHX discriminator.** The native 1.9 server
uses it for normal sessions; its sub-version-3 path is transfer-related.
Remove `sub_version != 2` as a Hotline requirement and do not classify every
sub-version-2 peer as SynHX.

The 1.9 server's own login version value 190 does not prove that every client
reporting at least 190 is the same client family. Numeric thresholds and peer
identities must be recorded separately.

Evidence: M001–M004, V003–V004, V023–V027.

## Login reply and banner policy

The inspected native 1.9 successful-login path adds:

- Server version 160 with value **190**.
- Unnamed numeric server value 161; constructor initializes it to zero.
- Server name 162, omitted when empty and copied from the current native
  configuration with a 31-byte destination cap.

It does so without a saved-client-version or SynHX-kind condition in that
handler. The former matrix's “omit 161/162 for SynHX or unknown peers” rule is
therefore an **mxd policy requiring validation**, not native 1.9 behaviour or
proof that including those fields is invalid.

The [configured login-extra corpus][login-extra-fixtures] confirms 161=`0000`
and nonempty 162 for absent/zero/150/151/190 client versions on both completion
paths. It preserves a native high byte and the name-length boundary. Changing
Local/Remote/empty banner configuration does not change 161 in these samples;
its purpose remains unknown. A fresh login sees a saved name change, while the
retained online/waiting clients receive no 161/162 refresh in the bounded trial.
This does not certify historical-client tolerance or restart durability.

The supplied SynHX server's lack of that native augmentation does not establish
that a SynHX **client** rejects those fields. A newly retained
[shx source profile](identified-client-source.md) now supplies
source and isolated callback evidence: its basic-login callback ignores these
extras. Other profiles and full sessions still need peer-specific validation.

Banner advertisement is separate: after agreement acceptance, native
transaction **122** carries type 152 and optional 153, conditional on configured
banner state and saved client version at least 151. Agreement notification
109 is not the combined agreement/banner structure described previously.

Native [agreement configurations][agreements] now distinguish fieldless 109
for missing/empty/unreadable content from bypass field 154. Early completion
still needs no 121; delayed completion still needs it. A loaded agreement above
the field limit can leave early completion online without 109, so a login ACK
alone does not certify agreement delivery.

Evidence: M002–M004, V024–V027, V058; native-agreement-01.

## Credential obfuscation and text compatibility

The native 1.9 login path complements nonempty login-name bytes. The supplied
SynHX server's login parser calls a byte-complement helper for login/password.
That helper implements `~byte`, equivalently XOR with `0xff`.

These observations concern credential fields. They do **not** establish:

- A SynHX-only credential signature.
- A universal XOR mode for chat, messages or news bodies.
- Invalid UTF-8 as a reliable negotiation signal.
- A requirement for a particular client-side `encode` toggle.

If mxd retains heuristic text decoding, document its exact fields and behaviour
as policy, including ambiguous plaintext/encoded inputs and how state changes.
Do not advertise the heuristic as an observed Hotline/SynHX wire guarantee.
The immutable ledger left native nonempty-password encoding unresolved. New
[native-path evidence](native-wire-details.md) establishes bytewise complement
from the native account setter, storage and login comparison; it does not rely
on the SynHX observation to establish that result. The
[native core fixtures](native-capture-workflow.md#recorded-native-core-fixtures)
now demonstrate creation/change of a known nonempty password, successful login
with complemented bytes, and rejection of the old password and plaintext
replacement bytes. General text heuristics and historical peer behaviour remain
separate requirements.

Evidence: M005, V016, V019, V043–V045.

## Repeated fields and presence records

A global rule allowing repetition only in transaction-300 replies is incorrect.
The native server establishes at least these additional cases:

- **115 reply:** repeated field 300, one packed record per listed room member.
- **112/113 request:** repeated target UID field 103, iterated by the handlers.
- **370 reply:** repeated category-list field 323 on the modern-version path.

The guide's file-list schema also describes repeated field 200;
[native wire details](native-wire-details.md) now gives its 20-byte fixed header
and variable name. Use transaction-specific validation and
preserve order/multiplicity until decoding; arbitrary scalar-field duplication
is not validated by these examples.

Field 300's value layout is supported by both the native roster builder and
the supplied historical SynHX roster writer:

```text
BE16 uid | BE16 icon | BE16 colour/status | BE16 name_length | name bytes
```

Its enclosing value length is `8 + name_length`. The native 1.9 roster builder
does not add chat subject 115; the supplied SynHX server writer does. Neither
observation alone certifies every client profile's roster acceptance rules.

Other presence details, particularly native 302 teardown ordering, remain
unresolved. The client-info operation 303 returns generated diagnostics, and
304 must not be assumed to merge only supplied settings fields.

Evidence: M006–M007, V014, V032–V038, V040, V042, V062.

## Historical reported mxd test coverage

The following references are retained from the supplied matrix for follow-up.
At the initial audit they were **reported citations, not executed evidence**.
The review below records subsequent checks. Their presence or names
do not establish protocol correctness; tests encoding the old discriminator or
repetition rule need semantic review before being used as acceptance gates.

| Reported area | Supplied source/test references | Required review |
| --- | --- | --- |
| Hotline 1.8.5 classification | `src/wireframe/compat_policy.rs::classifies_hotline_85_from_login_version` | Treat version-range classification as policy; validate the intended client builds |
| Hotline 1.9 classification | `src/wireframe/compat_policy.rs::classifies_hotline_19_from_login_version` | Separate reported version from conclusive peer identity |
| SynHX classification | `src/wireframe/compat_policy.rs::classifies_synhx_from_handshake` | Replace the shared sub-version-2 discriminator |
| Unknown classification | `src/wireframe/compat_policy.rs::classifies_unknown_for_older_login_versions` | Verify conservative fallback independently of wire-validity claims |
| Login augmentation | `augments_login_reply_when_required`, `does_not_augment_login_reply_for_synhx`, `does_not_augment_login_reply_for_unknown_client_kind` in `src/wireframe/compat_policy.rs` | Compare policy with unconditional native 1.9 success fields and actual client tolerance |
| Login scenarios | `tests/features/wireframe_login_compat.feature`: `Hotline 1.8.5 login reply includes banner fields`, `Hotline 1.9 login reply includes banner fields`, `SynHX login reply omits banner fields`, `Unknown client version omits banner fields` | Check assertions against the corrected login and distinct transaction-122 contracts |
| XOR heuristics | `decode_payload_enables_xor_on_invalid_utf8`, `decode_payload_does_not_enable_xor_for_non_text_fields` in `src/wireframe/compat.rs` | Verify implementation and limit claims to the actual policy and fields |
| XOR scenarios | `tests/features/wireframe_xor_compat.feature`: `XOR-encoded login succeeds`, `XOR-encoded message toggles compatibility`, `Plaintext message keeps XOR compatibility disabled` | Exercise ambiguous inputs; these scenarios do not prove a native universal text mode |
| Packed roster reply | `src/presence_tests.rs::user_name_list_reply_contains_repeated_field_300_entries` | Keep the supported record layout; remove a global transaction-300-only repetition restriction |
| Presence routing | `src/wireframe/routes/tests/presence_routing_cases.rs::process_transaction_bytes_user_name_list_returns_online_snapshot` | Verify at a recorded revision and check other repeated-field contexts |
| Presence scenario | `tests/features/wireframe_presence.feature`: `Login, update, and disconnect notifications reach peers` | Check actual execution and packet semantics, including remaining native teardown gaps |

The original supplied matrix omitted a named news-specific XOR scenario. The
current checkout does contain one, and it passed in the review below. This
verifies an mxd test outcome; it does not establish a native universal XOR mode.

Evidence: M005, M008.

## mxd review at 2e4c9c1

Reviewed and tested on 12 November 2026 at revision
`2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131`. Tracked files were unchanged;
the checkout had an unrelated untracked `mxd.worktrees/` directory. The
[review manifest][mxd-review] records commands, environment, source hashes and
frozen copies. Build output was kept under `mothra/state/mxd-target`.

| Executed scope | Result | Evidence |
| --- | --- | --- |
| Library filter `wireframe::compat` | 31 passed | [Log][compat-log] |
| Library filter `user_name_list` | 3 passed | [Log][roster-log] |
| `wireframe_compat_guardrails_bdd` | 6 passed | [Scenario log][scenario-log] |
| `wireframe_login_compat` | 9 passed | [Scenario log][scenario-log] |
| `wireframe_xor_compat` | 5 passed, including news body | [Scenario log][scenario-log] |
| `wireframe_presence_bdd` | 1 passed | [Log][presence-log] |

All commands used `--offline --locked`; integration runs enabled
`test-support`. An initial filter named the source filename instead of its Rust
module and matched zero tests; its retained log is not counted as coverage.
The corrected runs above executed **55 tests**. Kani was not run. These tests
use mxd's own fixtures, not identified historical Hotline/SynHX client binaries.

### Assertions requiring protocol reconciliation

| Source/test observation | Relationship to native 1.9 | Documentation disposition |
| --- | --- | --- |
| `compat_policy/mod.rs::kind` classifies every sub-version-2 connection as SynHX, before checking field 160 | Shared normal handshake is not an identity discriminator | Existing policy confirmed; native-conformance claim rejected |
| Login extras are enabled only for classified Hotline85/Hotline19; tests explicitly enforce omission for SynHX/unknown | Native successful login includes 161/162 without this gate | Passing policy tests do not validate native parity |
| `is_successful_login_reply` requires reply type 107 | Native direct reply type is zero, correlated by ID | Review routing context before transplanting this policy to native replies |
| Version parser accepts exactly 2/4 bytes and rejects values outside `u16` | Native generic numeric helper also accepts 1 byte and has other edge behaviour | Explicit acceptance-policy difference; no assertion of equivalent boundaries |
| Roster tests assert repeated packed field 300 | Native roster layout agrees | Verified mxd assertion/result for this scope; other repetitions remain separate |
| Presence scenario asserts peer login/update/disconnect delivery | Native 302 teardown order remains untraced | Passing mxd scenario does not close GAP-036 |

No mxd code/tests were changed by this documentation investigation. In
particular, the incorrect peer identity must not become a protocol requirement
merely because its current regression test passes. GAP-085 remains open for
implementation/test reconciliation rather than recording false conformance.

### Exact current text heuristic

`compat.rs` starts a connection with XOR disabled, ignoring handshake metadata.
For a decoded parameter list, it considers these field IDs text:
**101, 105, 106, 162, 201, 321, 323, 325, 327, 328, 329, 333**.
This includes structured news fields; it does not include display-name 102,
subject 115, quoted text 214 or auto-response 215.

When disabled, it enables XOR if at least one selected field exists, at least
one selected value is invalid UTF-8, and every selected value becomes valid
UTF-8 after complementing. On that request it complements all selected fields.
Once enabled, it complements all selected inbound/outbound values without
redetection; the state has no disable transition in this implementation.
Nonselected values remain unchanged. Invalid TLV decoding returns an error.

This is an observed mxd heuristic, not negotiated native encoding. Plaintext
high bytes can trigger it, and complemented bytes can be valid UTF-8 without
triggering it; the peer ambiguity corpus and policy decision remain GAP-080/082.
Its news-field inclusion also needs schema-aware review now that structured
layouts are being recovered.

### Proof and QA limits

The current Kani source contains 8-byte complement round-trip and two-field
4-byte text/numeric vector harnesses, plus symbolic sub-version/login-version
classification and login-extra gates. Those prove internal properties only if
executed successfully; they cannot prove that the classifier's peer premise or
UTF-8 heuristic matches historical clients. No proof result is asserted here.

The checked-in QA checklist requests a compatibility-matrix link, review of
affected rows and a literal sign-off statement. It does not identify a current
release owner or supply native session acceptance fixtures. Roadmap items
1.5.3–1.5.6 are checked, but that status does not resolve these newly identified
conformance discrepancies. Release ownership, supported subset and acceptance
of deliberate deviations remain GAP-001/086 decisions.

## Newly identified client source evidence

The [pinned shx profile](identified-client-source.md) is separate from the
original server-only comparison. Its basic-login callback and TLV iterator were
compiled unchanged with host UI stubs: seven cases passed, including native
extras, unknown fields, UID handling and the low-bit error predicate. These
results narrow field-tolerance uncertainty for this specific path. They do not
validate every SynHX client, optional secure login or a full network session.

The callback tests also show why native wire error 1 must not be conflated with
all internal/native or mxd error values: a synthetic status 2 passes this
callback's low-bit success test. The native setter-call inventory separately
finds 68 explicit direct error calls passing 1. No deliberate mxd status-policy
change has been made by this documentation investigation.

## Historical source lineage and build limits

The [lineage review][lineage] checks all 14 archived server files retained by
the original ledger. Their administrative headers declare trunk head 1.1,
default branch 1.1.1 and vendor revision 1.1.1.1. The retained `rcv.c` archive
records an import on 3 September 2001 by `devinteske`. All 14 vendor delta texts
are empty: for these archives the selected 1.1 content and the imported vendor
revision have no content edit between them. This narrows the old trunk/vendor
ambiguity without asserting a release number or matching client executable.

The [supplementary package record][server-profile] retains six server metadata
archives with the same selected/default revision relationship. Its version file
declares **0.1.48.1**, and README distinguishes the server package from shx. Its
reference to modifications over hxd0.1.41 does not identify a released package.
Configure input/template/runtime defaults document the conditional server
profiles, without establishing a deployed executable. Source comparisons remain
specific to those hashed files and named branches.

The separately identified shx client source is0.1.48, and its full terminal
build has an exact executable/configuration identity. Native sessions establish
160/161/162 and roster/file-record tolerance for that build. Controlled receiver
fixtures show that122is dumped as unknown while later roster/chat still work,
and the subject addition is displayed. These are not a native122session or a
running historical SynHX server. See the
[peer-by-field results](identified-client-source.md#native-configured-name-and-controlled-receiver-matrix)
and [profile applicability](identified-client-source.md#source-package-identities-and-configuration-applicability).
GAP-083 records source identity/applicability; broader target/fallback and peer
coverage remain GAP-080/081.

[server-profile]: ../mothra/evidence/gap-remediation/2026-11-13/synhx-profile-01/manifest.json

## Open compatibility gaps and QA requirements

Before recording support or signing off a release:

1. Use the revision-specific results above as the current implementation
   checkpoint, and rerun them after correcting the disputed expectations.
2. Reconcile classifier, banner, repetition, ACK and privilege semantics with
   the corrected 1.9 guide and its unresolved areas.
3. Identify client binaries/source or sessions for the intended Hotline and
   SynHX profiles. Separate observed native behaviour from deliberate mxd
   differences.
4. Check roadmap and QA references against the actual project. The imported
   document referred to roadmap 1.5.3, Kani item 1.5.4, guardrail items
   1.5.5/1.5.6, later 2.x presence/messaging work, and
   `docs/release-notes-qa-sign-off.md`. Their existence/current status was not
   validated by this baseline; they are retained as historical pointers.
5. Keep unsupported features and unresolved schemas explicit rather than
   promoting them from narrative descriptions to implemented guarantees.

Evidence: M008–M009. See the
[correction map](baseline-correction-map.md) for the disposition of all matrix
and protocol ledger entries, and the [gap analysis](gap-analysis.md) for the
remaining questions and their closure criteria.

[ledger]: ../mothra/docs/baseline-validity-ledger.md

[mxd-review]: ../mothra/evidence/gap-remediation/2026-11-12/mxd-review/manifest.json
[compat-log]: ../mothra/evidence/gap-remediation/2026-11-12/mxd-review/compat-tests.log
[roster-log]: ../mothra/evidence/gap-remediation/2026-11-12/mxd-review/roster-tests.log
[scenario-log]: ../mothra/evidence/gap-remediation/2026-11-12/mxd-review/scenario-tests.log
[presence-log]: ../mothra/evidence/gap-remediation/2026-11-12/mxd-review/presence-tests.log

[lineage]: ../mothra/evidence/gap-remediation/2026-11-12/batch-08/synhx-lineage-review.json

[agreements]: native-wire-details.md#captured-agreement-configurations-and-partial-login-failures

[login-extra-fixtures]: native-wire-details.md#captured-login-extras-configuration-bytes-and-refresh
