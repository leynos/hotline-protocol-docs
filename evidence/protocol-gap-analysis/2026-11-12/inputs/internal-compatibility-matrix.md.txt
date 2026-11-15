# Internal compatibility matrix (Hotline and SynHX)

This matrix separates observed protocol behaviour from mxd compatibility policy
and reported implementation coverage. Its baseline is the
[Hotline 1.9 validity ledger][ledger], captured on 12 November 2026, and the
[corrected protocol guide](protocol.md).

The ledger used the Mac PPC `HLserver19` binary and the supplied historical
SynHX server source. It did not inspect an mxd checkout, run its tests or Kani
proofs, or validate particular Hotline/SynHX client builds. Consequently this
matrix is **not sufficient by itself for release-note QA sign-off**.

## Scope and status labels

Protocol evidence and implementation status are separate dimensions:

- **Observed:** established in a named static path of the hashed 1.9 server.
- **Source-observed:** established in the supplied historical SynHX server
  snapshot, not in every SynHX client or release.
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
| Hotline 1.9 Mac PPC server | Normal-session magic `TRTPHOTL 00 01 00 02`; successful login reports version 190 and includes 161/162 without a client-kind gate | Observed in the hashed server's handshake/login paths | Unverified; imported login tests are listed below |
| Hotline 1.8.5 client profile | No identified client binary or session was validated; field 160 values `151..=189` do not by themselves prove this release | Policy requiring client validation | Unverified |
| SynHX historical server source | Defines the same normal-session magic ending in sub-version 2; its roster writer uses packed field 300 and appends subject 115 | Source-observed in supplied RCS trunk snapshots | Unverified; this source does not establish mxd or client behaviour |
| SynHX client profiles | No unique handshake marker, reply-field rejection rule or universal text-XOR mode was established | Policy requiring identified client/session evidence | Unverified |
| Unknown or legacy client version | Native 1.9 login has no version/kind gate around reply fields 161/162; a missing/old version is not a proven profile identifier | Native behaviour observed; conservative omission remains a separate mxd policy | Unverified |

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
- Community/banner identifier 161.
- Server name 162.

It does so without a saved-client-version or SynHX-kind condition in that
handler. The former matrix's “omit 161/162 for SynHX or unknown peers” rule is
therefore an **mxd policy requiring validation**, not native 1.9 behaviour or
proof that including those fields is invalid.

The supplied SynHX server's lack of that native augmentation does not establish
that a SynHX **client** rejects those fields. Client tolerance needs client
source or session evidence.

Banner advertisement is separate: after agreement acceptance, native
transaction **122** carries type 152 and optional 153, conditional on configured
banner state and saved client version at least 151. Agreement notification
109 is not the combined agreement/banner structure described previously.

Evidence: M002–M004, V024–V027, V058.

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
Native nonempty-password storage/encoding also remains unresolved in the
1.9 ledger; the SynHX source observation cannot fill that gap for another server.

Evidence: M005, V016, V019, V043–V045.

## Repeated fields and presence records

A global rule allowing repetition only in transaction-300 replies is incorrect.
The native server establishes at least these additional cases:

- **115 reply:** repeated field 300, one packed record per listed room member.
- **112/113 request:** repeated target UID field 103, iterated by the handlers.
- **370 reply:** repeated category-list field 323 on the modern-version path.

The guide's file-list schema also describes repeated field 200, while its exact
record layout remains unresolved. Use transaction-specific validation and
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

## Reported mxd test coverage requiring verification

The following references are retained from the supplied matrix for follow-up.
They are **reported citations, not executed evidence**. Their presence or names
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

The earlier claim that XOR-encoded **news** payloads are accepted also remains
unverified. The supplied matrix did not provide a named news-specific scenario
in its table; no additional test result is inferred here.

Evidence: M005, M008.

## Open compatibility gaps and QA requirements

Before recording support or signing off a release:

1. Identify the mxd checkout and revision, inspect the cited tests, and retain
   their execution output. Test names alone are not evidence of passing tests.
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
