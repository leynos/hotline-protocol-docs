# Native 1.9 field presence and defaults

This is a context table for the original
[GAP-016 question](../../gap-analysis.md#gap-016). It extends the
[core field schemas](../protocol/core-field-schemas.md) and
[scalar registry](../protocol/native-wire-details.md#core-scalar-width-registry),
which define types and effective widths. A helper default is not an enclosing
handler's successful reply. `Native` denotes a retained native observation;
`Source` denotes source-derived behaviour only. The final section names the
remaining fixture cells; this document does **not** close GAP-016.

## Four cases are not four distinct wire encodings

<!-- markdownlint-disable MD013 -->

| Notation | Wire distinction                          | Rule                                                                                                                                                                       |
| -------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Ø`      | Field ID not present                      | Lookup returns absent. The enclosing handler chooses its own default or error.                                                                                             |
| `E`      | ID present with BE16 length zero          | This is exactly an empty **B** string on the wire; no separate empty-string encoding exists. The ordinary field writer omits a zero-length output B field.                 |
| `00`     | ID present with length one, byte NUL      | This is **not** `E`: string-copy and password-sentinel paths can see one byte. For generic numeric `N`, its effective value is zero.                                       |
| `N0`     | Numeric ID present with BE16 value `0000` | Generic numeric accessor returns zero, as for `Ø`, `E`, one-byte `00` and a three-byte value, but the indexed TLV still exists. A handler may inspect presence separately. |

An eight-byte all-zero privilege bitmap is another **present value**, not an
empty bitmap. A count-prefixed **empty nested list** has bytes `0000` as its
value and is different from an absent or zero-length outer field.
Duplicate-field selection is not a general first/last rule (GAP-017).

## Credentials and session settings

| Request field              | `Ø` / `E`                                                                                                                                     | `00` or numeric zero                                                                                                                                                                        | Confidence and limit                                                                                                                                                                                                                     |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 107 login **105**          | Both select literal `guest`; a missing guest account still fails.                                                                             | Raw `00` complements to `ff`; decoded NUL requires raw `ff`. Either one-byte input remains nonempty, not guest.                                                                             | **Native:** [guest/auth corpus](../protocol/native-wire-details.md#captured-login-lookup-and-guest-phases) includes absent, empty, explicit guest and decoded-NUL keys. Its retained decoded-NUL controls must not be labelled raw `00`. |
| 107 password **106**       | Both produce a zero-length comparison value; success depends on that account's password.                                                      | Raw `00` complements to `ff`; decoded NUL needs raw `ff`. Neither one-byte login value invokes the 353 password-preservation sentinel; exact login outcomes for these bytes are unmeasured. | **Source+Native:** [authentication fixtures](../protocol/native-wire-details.md#captured-login-lookup-and-guest-phases) prove missing/empty-password guest outcomes.                                                                     |
| 107 version **160**        | Generic `N` reads zero and stores that reported version.                                                                                      | `00` and `N0` also read zero; byte length three likewise reads zero.                                                                                                                        | **Source**, with selected native width/feature controls in [login matrix](../protocol/core-field-schemas.md#login-width-and-feature-condition-matrix); no universal same-session zero-version case is asserted.                          |
| 107 requested name **102** | Missing/empty name prevents early completion even with icon.                                                                                  | `00` is a nonzero byte count, but effective session naming and early-completion outcome for it are unmeasured. Numeric zero is inapplicable to B.                                           | **S+N:** [login presence fixtures](presence-messaging-contracts.md#captured-configured-login-states-and-visibility) show name-only/icon-only and delayed 121.                                                                            |
| 107 icon **104**           | Missing/empty numeric read yields zero, preventing early completion.                                                                          | `00`, `N0` and `00010000` narrowed to zero have the same early-completion condition.                                                                                                        | **S+N:** [login matrix](../protocol/core-field-schemas.md#login-width-and-feature-condition-matrix), [icon widths](../protocol/native-wire-details.md#captured-tlv-and-scalar-boundaries).                                               |
| 121/304 name **102**       | Both request `***`; account naming privilege can replace the effective display name. These are session assignments, not sparse account edits. | `00` has length one, so the absent/empty fallback is not source-proven for it; native output unmeasured.                                                                                    | **S+N:** [eight 304 transitions](../native-evidence/native-settings-transition-witness.md) and [settings helper](presence-messaging-contracts.md#settings-and-login-visibility).                                                         |
| 121/304 icon **104**       | Both replace prior icon with zero.                                                                                                            | `00` and `N0` also store zero; high16 bits are discarded.                                                                                                                                   | **S+N:** native 304 reset and [icon width cases](../protocol/native-wire-details.md#captured-tlv-and-scalar-boundaries). Separate 121 zero-value fixture is unmeasured.                                                                  |
| 121/304 options **113**    | Both clear PM refusal, invitation refusal and automatic response.                                                                             | `00`/`N0` clear; enabled bits 0/1/2 have separate effects.                                                                                                                                  | **S+N:** [ten 304 cases](../native-evidence/native-settings-witness.md) and [transition witness](../native-evidence/native-settings-transition-witness.md). A 121 full width matrix is unmeasured.                                       |
| 121/304 auto text **215**  | When auto response is enabled, both choose the fixed 52-byte default; when disabled, saved text length clears.                                | `00` is distinct nonempty input; its resulting feedback is unmeasured.                                                                                                                      | **S+N:** [304 transitions](../native-evidence/native-settings-transition-witness.md) and [two delayed 121 defaults](../native-evidence/native-121-default-witness.md). This is not an encoding policy.                                   |

## Account replacements and related lookup

Account 350/353 creates a cleared 734-byte replacement record. Missing field
values do not generally preserve an old record. The native
[353 replacement matrix](../protocol/native-wire-details.md#captured-account-replacement-and-password-boundaries)
checks full stored bytes and subsequent login, while
[batch 349](../protocol/operation-contracts.md#captured-batch-account-framing-and-partial-effects)
has nested per-entry rules. The human meaning of attribute 111 stays opaque.

| Context and field                                               | `Ø` / `E`                                                                                                                                                                                      | `00`, `N0` or sentinel                                                                                                                                          | Confidence and limit                                                                                                                                                       |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 353 display **102**, opaque **111**                             | Omitted or empty copied values clear their record lengths. Inspected 352 replies omit empty 102 and do not emit 111, regardless of its stored length.                                          | A one-NUL-byte value has length one; exact native stored result for that byte is unmeasured.                                                                    | **S+N:** sparse 353 and absent/empty/value 111 fixtures.                                                                                                                   |
| 353 access **110**                                              | Both clear all eight bitmap bytes, rather than preserving prior privileges.                                                                                                                    | Present eight zero bytes also stores zero; 1/7/8/9-byte inputs zero-fill or truncate. `N0` is just two bitmap bytes, not a numeric scalar.                      | **S+N:** [six width controls](../protocol/bitmap-boundaries.md#field-110-presence-and-width).                                                                              |
| 353 password **106**                                            | Both clear password length; later empty-password login succeeds and old password fails.                                                                                                        | Exactly one byte `00` preserves up to 31 existing complemented bytes **when the old account is selected**. Literal `78` stores a new one-byte encoded password. | **Native:** [password matrix](../protocol/native-wire-details.md#captured-account-replacement-and-password-boundaries). The one-NUL rule is special to this mutation path. |
| 350/353 account key **105**                                     | Handler lookup/create target and native filesystem errors determine whether an omitted/empty key can succeed; no universal `guest` fallback is established here.                               | One NUL is a byte value, not the password sentinel; observed 31/32-byte filename boundary does not settle it.                                                   | **Source; missing native presence cells.** The 107 guest rule must not be copied here.                                                                                     |
| 349 nested old key **101**, new name **102**, new login **105** | Old 101 absent/empty selects no old account; with nonempty old key, empty new 102/105 can select deletion. An empty outer value, complete empty inner list and incomplete inner record differ. | One-NUL old/new identity outcomes are unmeasured.                                                                                                               | **S+N:** [batch role/default and framing matrix](../protocol/operation-contracts.md#captured-batch-account-framing-and-partial-effects).                                   |
| 349 nested password **106**, bitmap **110**, attribute **111**  | Cleared replacement defaults; absent 110/111 clears. Password sentinel needs a nonempty old 101.                                                                                               | Without old 101, one-NUL password is stored rather than preserving a predecessor; bitmap `0000000000000000` is an explicit zero value.                          | **S+N:** [batch matrix](../protocol/operation-contracts.md#captured-batch-account-framing-and-partial-effects).                                                            |
| 351 delete / 352 read key **105**                               | 352 takes input directly, unlike 350/351/353 complemented mutation keys. Empty/absent/NUL target outcomes are not fully measured.                                                              | No numeric zero interpretation.                                                                                                                                 | **Source** for differing transformations; [account lookup evidence](../protocol/native-wire-details.md#account-lookup-name-encodings).                                     |

## Other core requests and generated fields

| Context and field                                                         | Presence/default distinction                                                                                                                                                                                                               | Confidence and remaining cell                                                                                                                                                                 |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Chat 105 text **101**, option **109**, room **114**                       | Absent/E text copies zero bytes but the formatted notification may still have a sender prefix; one NUL is distinct input. 109 `Ø`/E/zero chooses ordinary rather than action. 114 `Ø`/E/zero selects main chat; nonzero selects a room.    | **Source** from [chat handler](../../evidence/hotline-server-1.9/queries/D-1000fc20.c); native zero-text/one-NUL and 109 width/default cells remain.                                          |
| PM 108 target **103**, option **113**, text **101**, quote **214**        | 103 `Ø`/E/zero has no valid target; 113 `Ø`/E/zero is option zero, not option one. 101 absent/E copies zero and the ordinary recipient delivery branch requires nonempty text. Quote 214 absent/E is not copied; `00` is a one-byte quote. | **Source+Native** [PM variants](../native-evidence/native-pm-witness.md), [routing table](presence-messaging-contracts.md#private-message-routing); exact quote and zero-text matrix remains. |
| Kick 110 target **103**, option **113**, reason **101**                   | Missing target reaches an empty success ACK in the traced branch. Option `Ø`/E/zero means kick without ban; 1 and 2 select other branches. Nonempty reason belongs to option 2 only.                                                       | **Source+Native** [kick cases](presence-messaging-contracts.md#kick-options-and-native-console-messages); option-2 reason `E`/`00` and persisted nonempty outcome remain unmeasured.          |
| Diagnostic 303 target **103**                                             | `Ø` reads zero, does not target caller; the retained admin case returns status1 and missing-client text. `E`/`00`/`N0` also read zero at accessor level.                                                                                   | **Native** absent [partial rate control](../native-evidence/native-rate304-sequence.md); present-zero handler wire outcome remains unmeasured.                                                |
| Rooms 105/113–116/120 room **114**                                        | `Ø`/E/zero selects main chat in 105, but ordinary room operations require a matching nonzero room; do not assign main-chat fallback to them.                                                                                               | **Source+Native** [room cases](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes); per-operation empty/zero error/close matrix incomplete.                    |
| Room 112/113 repeated target **103**                                      | With **no target TLVs**, 112 can create a room for its creator alone. Individual missing/nonmatching targets are skipped rather than a whole-batch default UID. 113 has no normal success ACK.                                             | **Source+Native** [room cases](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes); E/zero/one-NUL each repeated-target element unmeasured.                    |
| Room 120 subject **115**                                                  | `Ø` and E both clear stored subject; writer omits zero-length 119/115 subject. `00` is raw one-byte subject and has no numeric-zero meaning.                                                                                               | **S+N:** [topic clear and 255-byte controls](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes); NUL byte topic unmeasured.                                   |
| Transfer 202/203/210/213 option **204**, size **108**, item count **220** | Generic `N` makes `Ø`/E/`00`/`N0` effective zero. Enclosing handlers assign option-specific preview/resume meaning; zero size/count does not guarantee a successful worker or complete folder stream.                                      | **S+selected N:** [transfer contracts](../files-and-transfers/transfer-contracts.md); full absent/E/zero per-handler matrix remains.                                                          |
| Transfer reference **107** in request 214                                 | Direct-copy four-byte word, unlike `N`: `Ø`/E/zero skips cleanup; shorter values zero-fill, longer values cap at four.                                                                                                                     | **S+selected N:** [reference controls](../files-and-transfers/transfer-contracts.md#reference-allocation-and-request-214); not a default reference to the current transfer.                   |
| News 400/410/411 article **326**, post flags **334**, recursive **337**   | Generic `N` makes `Ø`/E/zero effective zero. Unresolved 326 can select root posting in 410 but errors for read/delete; 334 stores raw zero; 337 zero is nonrecursive, any nonzero recursive.                                               | **Source+Native** [deletion width controls](../news/news-contracts.md#captured-article-deletion-and-index-effects); 326/334 absent/E/zero native cells remain.                                |

<!-- markdownlint-enable MD013 -->

For **outputs**, the sender numeric writer emits zero as BE16 `0000` when the
field is built; it does not convert zero into an omitted TLV. The fixed
reference 107 stays four bytes, bitmap 110 stays eight, and packed roster 300
has its own inner grammar. A byte-string writer omits a zero-length value.
Consequently 107 ACK normally has 160/161 (including observed zero 161), but
empty configured 162 is omitted; 109 can carry nonempty 101, bypass flag
154=`0001`, or no fields; 122 and 153 depend on the configured data source; 354
carries eight bitmap bytes even when zero. A 300 ACK with no rows has a zero
outer field count, not an empty U record.
[Output schemas](../protocol/core-field-schemas.md#login-and-presence-outputs)
and
[agreement/configuration fixtures](../protocol/native-wire-details.md#captured-agreement-configurations-and-partial-login-failures)
support these scoped examples.

Generated 301/302/303, 104/106/111/112/113/115/117/118/119/355, 211 and
news/transfer replies have handler-specific existence gates. A zero numeric
UID/icon/option or an omitted byte string in one variant is not a universal
missing-message rule;
[the output registry](../protocol/core-field-schemas.md#room-and-message-outputs)
and
[notification contract](../protocol/operation-contracts.md#server-notification-catalogue)
give the actual variant/recipient contexts. In particular, PM delivery 104,
refusal feedback 104, console data-only 104 and kick notice 104 cannot share
one 101/103/113 default table (GAP-044).

## Explicitly unmeasured cells

Existing native fixtures cover the high-priority credentials, 304 settings, 353
replacement and bitmap contrasts above; they do **not** constitute a four-case
matrix for every core field. Finite remaining groups are:

1. 107 password and name with one decoded NUL; 107 version absent/E/zero on
   the same account; separate 121 `102/104/113` E/zero width controls and
   one-NUL 215 feedback. 304 one-NUL 102/215 and present one-byte-zero 104/113.
2. 350 create and 353 account-key 105 absent/E/NUL; 351/352 key 105
   absent/E/NUL; 353 name102/attribute111 one-NUL. Nested 349 one-NUL old/new
   key/name and E/zero repeated-value contrasts are not a complete matrix.
3. 105 text101 one-NUL/zero-byte delivery, 108 text101 and quote214 E/NUL,
   108 option113/target103 explicit zeros, and 110 reason101 E/NUL with stored
   option-2 outcome. The exact notification variant must be retained.
4. 112/113 repeated target103 E/zero/NUL, room114 E/zero per 113–116/120,
   and subject115 one-NUL. Source may predict accessor defaults, while native
   missing-object reply/close and recipient effects are distinct observations.
5. Transfer 202/203/210/213 `204/108/220` and request214 reference107
   absent/E/zero per handler; news 400/410/411 `326/334/337` contrasts beyond
   the recorded 337 controls. Output conditional/empty variants beyond the
   named captured 107/109/122/300/354 cases require their own generator and
   recipient fixtures, not a copied generic field rule.

These groups are the remaining GAP-016 fixture obligation; the source rows
already state the known effective values. They do not reopen the completed
GAP-015 wire-width question or prescribe mxd's stricter input policy.
