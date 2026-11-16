# Native, SynHX and mxd compatibility matrix

This document separates observed protocol behaviour from mxd compatibility
policy and from reported implementation coverage. It sets the native Hotline
Server 1.9 behaviour, the historical SynHX server source and identified client
evidence, and the mxd policy side by side. The matrix is a baseline with a
revision-specific review attached, and its limits are stated first.

## Baseline and limits

The matrix's baseline is the [Hotline 1.9 validity ledger][ledger], captured on
12 November 2026, and the [corrected protocol guide](../protocol/protocol.md).

The ledger used the Mac PPC `HLserver19` binary and the supplied historical
SynHX server source. It did not inspect an mxd checkout, run its tests or Kani
proofs, or validate particular Hotline client builds or clients of the SynHX
family. Consequently this matrix is **not sufficient by itself for release-note
QA sign-off**.

Revision-specific results are set out in the
[assertion reconciliation](assertion-reconciliation.md), and the order in which
the reviews were made is recorded in the [History](#history) section.

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
implementation progress. They must not be read as binary-validation results. An
implementation-status claim needs a repository revision, checked source and
test/proof output before it can be promoted to verified coverage.

Evidence: M008–M009.

## Compatibility matrix

| Peer or profile                  | Observed markers and behaviour                                                                                                    | Protocol evidence                                                                                                                                         | mxd implementation status                                                     |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Hotline 1.9 Mac PPC server       | Normal-session magic `TRTPHOTL 00 01 00 02`; successful login reports version 190 and includes 161/162 without a client-kind gate | Observed in the hashed server's handshake/login paths                                                                                                     | mxd login policy tests passed; native-parity discrepancies are recorded below |
| Hotline 1.8.5 client profile     | No identified client binary or session was validated; field 160 values `151..=189` do not by themselves prove this release        | Policy requiring client validation                                                                                                                        | mxd threshold policy tested; identified-client compatibility unverified       |
| SynHX historical server source   | Defines the same normal-session magic ending in sub-version 2; its roster writer uses packed field 300 and appends subject 115    | Source-observed in supplied RCS trunk snapshots                                                                                                           | Comparison source only; does not establish client behaviour                   |
| shx 0.1.48 source snapshot       | README/version.c identify source at `adb1bf8`; basic login shares sub-version 2, omits 160 and ignores extras 161/162             | Source-observed; seven isolated host callback cases passed                                                                                                | Does not certify mxd or a compiled historical client                          |
| Identified modern shx build      | Source `adb1bf8`, executable `8fbbe56cef43…`; full native sessions and controlled extra-field cases                               | [Build and session evidence](../peers/identified-client-source.md), [controlled matrix](../peers/peer-tolerance-matrix.md)                                | Further mxd validation is on hold                                             |
| Identified Classic PPC candidate | Archive/application label 1.9.2, embedded `vers` 1.9.1.0; DATA `7f286e3f…`, RSRC `f762cfde…`                                      | [Native baseline](../peers/classic-native-baseline.md) and [161 width/omission matrix](../peers/classic-field161-matrix.md) reach 121/300 and banner data | Further mxd validation is on hold; native result does not certify mxd         |
| Other SynHX-family clients       | No unique handshake marker, reply-field rejection rule or universal text-XOR mode was established                                 | Policy requiring identified client/session evidence                                                                                                       | Classifier/omission tests passed; disputed identity premise remains           |
| Unknown or legacy client version | Native 1.9 login has no version/kind gate around reply fields 161/162; a missing/old version is not a proven profile identifier   | Native behaviour observed; conservative omission remains a separate mxd policy                                                                            | Omission-policy tests passed; native reply differs                            |

_Table 1: Peers and profiles with their observed markers, protocol evidence and
mxd implementation status._

In the Hotline 1.9 row, “recorded below” refers to the
[assertion reconciliation](assertion-reconciliation.md).

## Peer identity and sub-version 2

**Sub-version 2 is shared, not a discriminator for the SynHX family.** The
normal handshake's sub-version 2 is shared with the historical shx client
source and cannot identify a peer of the SynHX family on its own.

The native 1.9 server uses it for normal sessions; its sub-version-3 path is
transfer-related. Remove `sub_version != 2` as a Hotline requirement and do not
classify every sub-version-2 peer as a member of the SynHX family.

The 1.9 server's own login version value 190 does not prove that every client
reporting at least 190 is the same client family. Numeric thresholds and peer
identities must be recorded separately.

The
[evaluated-build registry and unknown-peer rule](../peers/peer-profile-rules.md)
name the protocol evidence targets and the native 1.9 fallback. Missing build
provenance remains unknown; this registry does not select an mxd release set.

Evidence: M001–M004, V003–V004, V023–V027.

## Identified client sessions

The
[identified shx 0.1.48 full-process corpus](../peers/identified-client-source.md#full-native-peer-acceptance-matrix)
completed five native sessions with a pinned terminal build. Its ordinary
handshake used sub-version 2, omitted request field 160, and consumed native
login fields 160/161 before roster, chat and file operations.

A
[second native corpus](../peers/identified-client-source.md#native-configured-name-and-controlled-receiver-matrix)
completed three sessions with configured field 162, including a raw `9a` byte.
In that section, the banner 122 and roster-subject 115 cases used a controlled
receiver, not the native server. These are finite observations for that exact
build; they do not identify every client of the SynHX family or set a universal
omission policy.

## Login reply and banner policy

The
[corrected login contract](../protocol/protocol.md#login-transaction-107--client-initiates)
states that a successful native 1.9 login sends server version 160, numeric
field 161 and, when configured nonempty, server name 162.

The inspected native 1.9 successful-login path adds:

- Server version 160 with value **190**.
- Unnamed numeric server value 161; constructor initializes it to zero.
- Server name 162, omitted when empty and copied from the current native
  configuration with a 31-byte destination cap.

It does so without a saved-client-version condition or a condition that the
peer is a client of the SynHX family in that handler. The former matrix's “omit
161/162 for SynHX or unknown peers” rule is therefore an **mxd policy requiring
validation**, not native 1.9 behaviour or proof that including those fields is
invalid.

The [native configuration corpus][login-extra-fixtures] observed this with
request version 160 absent, 0, 150, 151 and 190 in early and delayed login
paths. Field 161 was `0000`; an empty configured name omitted 162.

The [configured login-extra corpus][login-extra-fixtures] confirms 161=`0000`
and nonempty 162 for absent/zero/150/151/190 client versions on both completion
paths. It preserves a native high byte and the name-length boundary. Changing
Local/Remote/empty banner configuration does not change 161 in these samples;
its purpose remains unknown. A fresh login sees a saved name change, while the
retained online/waiting clients receive no 161/162 refresh in the bounded
trial. This does not certify historical-client tolerance or restart durability.

The lack of that native augmentation in the supplied historical SynHX server
source does not establish that a **client** of the SynHX family rejects those
fields. The [shx source profile](../peers/identified-client-source.md) supplies
source and isolated callback evidence: its basic-login callback ignores these
extras. The identified compiled shx and Classic candidate have the finite
native sessions linked in the matrix above. Other profiles still need their own
identified evidence; no reported version alone selects one of these builds. The
Classic 161 matrix establishes tolerance of absent, one-zero-byte and
four-zero-byte values through its recorded stages.

Unreconciled: the Classic 161 matrix statement above (ICM-064) covers absent,
one-zero-byte and four-zero-byte values. The `mxd-login-extras-correction.md`
record gives native field 161 as the two-byte `0000` (LEX-011) and states that
the old mxd field 161 was four bytes (LEX-035). `mxd-reconciliation.md` records
field 161 as `0000` (REC-017). The four-zero-byte width is not reconciled with
the native two-byte value in the source documents. The classic-field161-matrix
record linked at ICM-036 is not among the source documents.

A separate [ASCII 162 trial](../peers/classic-server-name-162.md) appends
`fixture-native` and reaches login, roster and banner data with all other bytes
unchanged. Neither trial establishes nonzero-161 meaning, general 162 encoding,
banner rendering or an mxd omission policy.

Unreconciled: this matrix states that the ASCII 162 trial reaches roster and
banner data (ICM-066). The validation record `mxd-validation.md` states that
one identified Classic startup must be completed before roster, banner or
general interoperability is claimed, and that authentication-only results are
kept separate (VAL-084). The same record states that in the 24-character trial
no 121, 300 or 212 request followed (VAL-036). This matrix names a separate
trial record for the ASCII 162 trial but does not state which server it used
(ICM-065). That record is not among the source documents, so the source
documents do not decide the question.

Banner advertisement is separate: after agreement acceptance, native
transaction **122** carries type 152 and optional 153, conditional on
configured banner state and saved client version at least 151. Agreement
notification 109 is not the combined agreement/banner structure described
previously.

Native [agreement configurations][agreements] distinguish fieldless 109 for
missing/empty/unreadable content from bypass field 154. Early completion still
needs no 121; delayed completion still needs it.

Unreconciled: this matrix states that early completion still needs no 121 and
delayed completion still needs it (ICM-071). The validation record
`mxd-validation.md` states that `src/commands/parsing.rs:48–76` has no
implemented 121 command branch (VAL-050), and lists the 109/121 sequence as an
item to design and test (VAL-083). The source documents do not decide whether
the Classic path needs 121.

A loaded agreement above the field limit can leave early completion online
without 109, so a login ACK alone does not certify agreement delivery.

Evidence: M002–M004, V024–V027, V058; native-agreement-01.

## Credential obfuscation and text compatibility

The native 1.9 login path complements nonempty login-name bytes. The supplied
historical SynHX server source's login parser calls a byte-complement helper
for login/password. That helper implements `~byte`, equivalently XOR with
`0xff`.

These observations concern credential fields. They do **not** establish:

- A credential signature specific to the SynHX family.
- A universal XOR mode for chat, messages or news bodies.
- Invalid UTF-8 as a reliable negotiation signal.
- A requirement for a particular client-side `encode` toggle.

If mxd retains heuristic text decoding, document its exact fields and behaviour
as policy, including ambiguous plaintext/encoded inputs and how state changes.
Do not advertise the heuristic as an observed wire guarantee of Hotline or of
the SynHX family. The immutable ledger left native nonempty-password encoding
unresolved. The [native-path evidence](../protocol/native-wire-details.md)
establishes bytewise complement from the native account setter, storage and
login comparison; it does not rely on the historical SynHX server source
observation to establish that result. The
[native core fixtures](../native-evidence/native-capture-workflow.md#recorded-native-core-fixtures)
demonstrate creation/change of a known nonempty password, successful login
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
[native wire details](../protocol/native-wire-details.md) gives its 20-byte
fixed header and variable name. Use transaction-specific validation and
preserve order/multiplicity until decoding, because arbitrary scalar-field
duplication is not validated by these examples.

Unreconciled: this matrix states that a global rule allowing repetition only in
transaction-300 replies is incorrect (ICM-088), and its historical table asks
for the global transaction-300-only repetition restriction to be removed
(ICM-114). The direct-reply correction record `mxd-direct-ack-correction.md`
states that the approved correction permits repeated field 300 for marker-1
direct replies regardless of wire type (ACK-019), and that tested marker-0
Login requests, 301 notifications, marker 2 and unrelated duplicate fields
remain rejected (ACK-020). The source documents do not state whether the
corrected mxd rule is still restricted by marker, transaction or both. The
frozen ACK source and tests would show it.

Field 300's value layout is supported by both the native roster builder and the
supplied historical SynHX roster writer:

```plaintext
BE16 uid | BE16 icon | BE16 colour/status | BE16 name_length | name bytes
```

Its enclosing value length is `8 + name_length`. The native 1.9 roster builder
does not add chat subject 115; the supplied historical SynHX server writer
does. Neither observation alone certifies every client profile's roster
acceptance rules.

Other presence details, particularly native 302 teardown ordering, remain
unresolved. The client-info operation 303 returns generated diagnostics, and
304 must not be assumed to merge only supplied settings fields.

Evidence: M006–M007, V014, V032–V038, V040, V042, V062.

## Historical reported mxd test coverage

The following references are retained from the supplied matrix for follow-up.
At the initial audit they were **reported citations, not executed evidence**.
The [revision-specific review](assertion-reconciliation.md) records subsequent
checks. Their presence or names do not establish protocol correctness; tests
encoding the old discriminator or repetition rule need semantic review before
being used as acceptance gates.

| Reported area                | Supplied source/test references                                                                                                                                                                                                              | Required review                                                                               |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Hotline 1.8.5 classification | `src/wireframe/compat_policy.rs::classifies_hotline_85_from_login_version`                                                                                                                                                                   | Treat version-range classification as policy; validate the intended client builds             |
| Hotline 1.9 classification   | `src/wireframe/compat_policy.rs::classifies_hotline_19_from_login_version`                                                                                                                                                                   | Separate reported version from conclusive peer identity                                       |
| SynHX classification         | `src/wireframe/compat_policy.rs::classifies_synhx_from_handshake`                                                                                                                                                                            | Replace the shared sub-version-2 discriminator                                                |
| Unknown classification       | `src/wireframe/compat_policy.rs::classifies_unknown_for_older_login_versions`                                                                                                                                                                | Verify conservative fallback independently of wire-validity claims                            |
| Login augmentation           | `augments_login_reply_when_required`, `does_not_augment_login_reply_for_synhx`, `does_not_augment_login_reply_for_unknown_client_kind` in `src/wireframe/compat_policy.rs`                                                                   | Compare policy with unconditional native 1.9 success fields and actual client tolerance       |
| Login scenarios              | `tests/features/wireframe_login_compat.feature`: `Hotline 1.8.5 login reply includes banner fields`, `Hotline 1.9 login reply includes banner fields`, `SynHX login reply omits banner fields`, `Unknown client version omits banner fields` | Check assertions against the corrected login and distinct transaction-122 contracts           |
| XOR heuristics               | `decode_payload_enables_xor_on_invalid_utf8`, `decode_payload_does_not_enable_xor_for_non_text_fields` in `src/wireframe/compat.rs`                                                                                                          | Verify implementation and limit claims to the actual policy and fields                        |
| XOR scenarios                | `tests/features/wireframe_xor_compat.feature`: `XOR-encoded login succeeds`, `XOR-encoded message toggles compatibility`, `Plaintext message keeps XOR compatibility disabled`                                                               | Exercise ambiguous inputs; these scenarios do not prove a native universal text mode          |
| Packed roster reply          | `src/presence_tests.rs::user_name_list_reply_contains_repeated_field_300_entries`                                                                                                                                                            | Keep the supported record layout; remove a global transaction-300-only repetition restriction |
| Presence routing             | `src/wireframe/routes/tests/presence_routing_cases.rs::process_transaction_bytes_user_name_list_returns_online_snapshot`                                                                                                                     | Verify at a recorded revision and check other repeated-field contexts                         |
| Presence scenario            | `tests/features/wireframe_presence.feature`: `Login, update, and disconnect notifications reach peers`                                                                                                                                       | Check actual execution and packet semantics, including remaining native teardown gaps         |

_Table 2: Reported mxd test references and the review each one requires._

The original supplied matrix omitted a named news-specific XOR scenario. The
current checkout does contain one, and it passed in the
[revision-specific review](assertion-reconciliation.md). This verifies an mxd
test outcome; it does not establish a native universal XOR mode.

Evidence: M005, M008.

## Proof and QA limits

The current Kani source contains 8-byte complement round-trip and two-field
4-byte text/numeric vector harnesses, plus symbolic sub-version/login-version
classification and login-extra gates. Those prove internal properties only if
executed successfully; they cannot prove that the classifier's peer premise or
UTF-8 heuristic matches historical clients. No proof result is asserted here.

The checked-in QA checklist requests a compatibility-matrix link, review of
affected rows and a literal sign-off statement. It does not identify a current
release owner or supply native session acceptance fixtures. Roadmap items
1.5.3–1.5.6 are checked, but that status does not resolve the conformance
discrepancies identified in the
[revision-specific review](assertion-reconciliation.md). Release ownership,
supported subset and acceptance of deliberate deviations remain GAP-001/086
decisions.

## Pinned shx profile and callback evidence

The [pinned shx profile](../peers/identified-client-source.md) is separate from
the original server-only comparison. Its basic-login callback and TLV iterator
were compiled unchanged with host UI stubs: seven cases passed, including
native extras, unknown fields, UID handling and the low-bit error predicate.
These results narrow field-tolerance uncertainty for this specific path. They
do not validate every client of the SynHX family, optional secure login or a
full network session.

The callback tests also show why native wire error 1 must not be conflated with
all internal/native or mxd error values: a synthetic status 2 passes this
callback's low-bit success test. The native setter-call inventory separately
finds 68 explicit direct error calls passing 1. No deliberate mxd status-policy
change has been made by this documentation investigation.

## Historical source lineage and build limits

The [lineage review][lineage] checks all 14 archived server files retained by
the original ledger. Their administrative headers declare trunk head 1.1,
default branch 1.1.1 and vendor revision 1.1.1.1. The retained `rcv.c` archive
records an import on 3 September 2001 by `devinteske`. All 14 vendor delta
texts are empty: for these archives the selected 1.1 content and the imported
vendor revision have no content edit between them. This narrows the old
trunk/vendor ambiguity without asserting a release number or matching client
executable.

The [supplementary package record][server-profile] retains six server metadata
archives with the same selected/default revision relationship. Its version file
declares **0.1.48.1**, and README distinguishes the server package from shx.
Its reference to modifications over hxd0.1.41 does not identify a released
package. Configure input/template/runtime defaults document the conditional
server profiles, without establishing a deployed executable. Source comparisons
remain specific to those hashed files and named branches.

The separately identified shx client source is 0.1.48, and its full terminal
build has an exact executable/configuration identity. Native sessions establish
160/161/162 and roster/file-record tolerance for that build. Controlled
receiver fixtures show that 122 is dumped as unknown while later roster/chat
still work, and the subject addition is displayed. These are not a native 122
session or a running historical SynHX server. See the
[peer-by-field results](../peers/identified-client-source.md#native-configured-name-and-controlled-receiver-matrix)
and
[profile applicability](../peers/identified-client-source.md#source-package-identities-and-configuration-applicability).
GAP-083 records source identity/applicability. The
[profile registry](../peers/peer-profile-rules.md) supplies GAP-080's
exact-build targets and unknown-peer rule. The
[cross-peer matrix](../peers/peer-tolerance-matrix.md#cross-peer-acceptance-and-omission-rules)
consolidates GAP-081's finite field coverage; untested builds remain unknown.

## Open compatibility gaps and QA requirements

Before recording support or signing off a release:

1. Use the revision-specific results in the
   [revision-specific review](assertion-reconciliation.md) as the current
   implementation checkpoint, and rerun them after correcting the disputed
   expectations.
2. Reconcile classifier, banner, repetition, ACK and privilege semantics with
   the corrected 1.9 guide and its unresolved areas.
3. Identify client binaries/source or sessions for the intended Hotline
   profiles and the profiles of clients of the SynHX family. Separate observed
   native behaviour from deliberate mxd differences.
4. Check roadmap and QA references against the actual project. The imported
   document referred to roadmap 1.5.3, Kani item 1.5.4, guardrail items
   1.5.5/1.5.6, later 2.x presence/messaging work, and
   `docs/release-notes-qa-sign-off.md`. Their existence/current status was not
   validated by this baseline; they are retained as historical pointers.
5. Keep unsupported features and unresolved schemas explicit rather than
   promoting them from narrative descriptions to implemented guarantees.

Evidence: M008–M009. See the
[correction map](../provenance/baseline-correction-map.md) for the disposition
of all matrix and protocol ledger entries, and the
[gap analysis](../../gap-analysis.md) for the remaining questions and their
closure criteria.

## Revision identifiers

The identifiers below occur in the claims of this matrix. Each is a shx or
archive revision, not an mxd revision.

| Identifier                | Type                                            | Where it occurs                                                                       |
| ------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------- |
| `adb1bf8`                 | shx source revision                             | Compatibility matrix: shx 0.1.48 source snapshot and identified modern shx build rows |
| `1.1`, `1.1.1`, `1.1.1.1` | RCS revision identifiers in the archive headers | Historical source lineage and build limits                                            |

_Table 3: Revision identifiers used in this matrix and where they occur._

## History

The source describes the shx source profile as newly retained. The baseline
itself is described in [Baseline and limits](#baseline-and-limits).

A subsequent revision-specific review supplies executed test evidence and
identifies policy assertions that conflict with native behaviour. Its evidence
is linked as the [assertion reconciliation](assertion-reconciliation.md).

[ledger]: ../baseline-validity-ledger.md
[login-extra-fixtures]: ../protocol/native-wire-details.md#captured-login-extras-configuration-bytes-and-refresh
[agreements]: ../protocol/native-wire-details.md#captured-agreement-configurations-and-partial-login-failures
[lineage]: ../../evidence/gap-remediation/2026-11-12/batch-08/synhx-lineage-review.json
[server-profile]: ../../evidence/gap-remediation/2026-11-13/synhx-profile-01/manifest.json
