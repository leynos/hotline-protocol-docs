# Native 1.9 type-104 producer matrix (A28)

This is a source-and-retained-capture inventory for the binary with SHA-256
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`.
Field sets below describe the cited producer branch, **not** a universal 104
schema. A request/reply ID, nearby ACK, exact text or connection lifecycle can
help a capture analyst identify a producer; those are not extra 104 fields.
The [GAP-044 criterion](gap-analysis.md#gap-044) remains open.

| Producer and source | Branch's 104 fields and identity meaning | Native wire evidence | Does this field shape identify origin? |
| --- | --- | --- | --- |
| Routed 108, [1000f4e0][pm] | Original message: 103 sender UID, 102 sender effective name, 113 copied option, 101 nonempty text; optional 214 quoted request text. Empty ordinary text does not enter this send branch. | No direct PM capture yet; [A26 preparation](native-pm-preparation.md) is offline only. | No. Its 103/102/113/101 shape overlaps generated feedback; 214, when present, narrows to this original-message branch in these known producers but is not a global origin tag. |
| 108 refusal/automatic feedback, [1000f4e0][pm] | 103/102 identify the **recipient whose settings triggered feedback**, not the original sender; 113=2 refusal or 4 automatic, 101 generated/nonempty response. No 214 added by this branch. Sender PM refusal suppresses this feedback. | A26 prepared, unrun. | No. 113=4 also occurs in invitation feedback; 113=2 can be a routed option-2 message. |
| Room 113 invitation feedback, [100188e0][invite] | 103/102 identify the refusing or auto-responding **invitee**; 113=3 chat refusal or 4 automatic, 101 generated/nonempty text. Sent to inviter when inviter PM refusal is clear. Room invitation 113 to eligible peers is separate. | [Native rooms refusals][rooms-refusals], action 44: fields 103/102/113=`0003`/101; action 62: 103/102/113=`0004`/101. | No. The same shape/options can arise in PM 108 feedback or routed option 3/4. Room context and request provenance distinguish this capture. |
| Denied 105 chat send, [1000fc20][chat] | 109=`0001` marker and 101 denial text; no 103/102 sender fields. This is sent to the denied sender, not to room recipients. | [Native rooms basics][rooms-basics], actions 67 and 76, fields 109/101. | No. Account 349 collision also has 101/109=`0001`; text and preceding request differ. |
| 110 option-1 or option-2 kick notice, [10015e70][kick] | 101 notice text only, sent to target before closure. Option 113 is read **from the request**; it is not emitted in the 104. Other/absent 110 options close without this 104. No sender UID/name. | No retained native option-1/2 110 notice capture; protected-kick denial and self-delete captures are different branches. | No. Data-only 101 also covers account deletion and console messages. Even kick options 1/2 share the field set. |
| 349 batch existing-login collision, [10015500][batch] | 101 collision text plus 109=`0001`; no 103/102 account or administrator identity. The batch continues and can end in an empty success ACK. | [Native account batch][batch-collision], action 8, fields 101/109=`0001`. | No. The same field set/marker occurs for chat denial; wording and 349 context identify this instance. |
| 350 direct duplicate create, [100146f0][create] | **No 104 on the captured duplicate path.** It returns status 1 with error field 100. This is a negative control against treating every account collision as the 349 notice. | [Native identity duplicate][direct-duplicate], request-10 reply at action 8: status 1/100; no 104. | Not applicable: this branch emits no 104. |
| 351 deletion of a live account, [10005f90][delete] called from [10015500][batch] or the direct account path | 101 fixed logged-out notice only, sent to affected live sessions before transport closure. No field identifies the deleting admin/account. The same helper also runs on account replacement of live sessions where applicable; do not infer all edits send this notice. | [Native live delete][live-delete], actions 29/30 to two sessions; [self/protected delete][identity-delete], action 21 in each. All are 101-only. | No. It shares the data-only shape with kick and console; text/close context identify these captures. |
| Console message dialog [10002dd0][console] through [10005510][fanout] | 101 selected console text only to ready/online recipients. No 103/102 sender identity or option. Client-origin 355 broadcast uses a different notification type. | Frozen oracle only; no native console message delivery capture retained. | No. Another data-only 101 104 can have the same schema; source context is required. |

## Parsing and evidence limits

For the **known captured** shapes, a parser can separate identity-bearing
`103/102/113/101` (sometimes `214`) from `109/101` and `101` alone. It cannot
derive a unique semantic origin from field presence alone. In particular,
`109=0001` is shared by chat denial and account collision; `101` alone does not
identify kick, account deletion or console. Treat 103/102 in a routed original
as sender identity, but in generated feedback as the responding **recipient**.
The same numeric 113 value is an option in a routed message, not a universal
producer code. Text matching is an observed-capture aid, not a protocol-wide
discriminator or an encoding guarantee.

Unmet byte-level producer fixtures are: direct 108 original/quoted/empty and
option-2/3 routes, refusal and automatic feedback with sender-refusal controls
([A26](native-pm-preparation.md) prepared but unrun); native 110 option-1 and
option-2 notice/closure cases; and console 10002dd0 delivery across ready,
offline and refusing sessions. The account 350 duplicate control, 349 collision,
351 live-account deletion, room refusal/auto feedback and denied-chat variants
already have the specific native captures cited above. C26 settings work is
running separately and is **not** counted as PM delivery evidence here. Exact
client rendering and any untraced 104 producers remain unestablished.

[pm]: ../mothra/evidence/hotline-server-1.9/queries/D-1000f4e0.c
[invite]: ../mothra/evidence/hotline-server-1.9/queries/D-100188e0.c
[chat]: ../mothra/evidence/hotline-server-1.9/queries/D-1000fc20.c
[kick]: ../mothra/evidence/hotline-server-1.9/queries/D-10015e70.c
[batch]: ../mothra/evidence/hotline-server-1.9/queries/D-10015500.c
[create]: ../mothra/evidence/hotline-server-1.9/queries/D-100146f0.c
[delete]: ../mothra/evidence/gap-remediation/2026-11-13/native-live-accounts-01/oracle-queries/LA-D-10005f90.c
[console]: ../mothra/evidence/gap-remediation/2026-11-12/batch-06/queries/B06-D-10002dd0.c
[fanout]: ../mothra/evidence/gap-remediation/2026-11-12/batch-06/queries/B06-D-10005510.c
[rooms-refusals]: ../mothra/evidence/gap-remediation/2026-11-13/native-rooms-01/refusals/report.json
[rooms-basics]: ../mothra/evidence/gap-remediation/2026-11-13/native-rooms-01/basics/report.json
[batch-collision]: ../mothra/evidence/gap-remediation/2026-11-13/native-account-batch-01/batch-collision-continues/report.json
[direct-duplicate]: ../mothra/evidence/gap-remediation/2026-11-13/native-account-identity-01/duplicate-exact/report.json
[live-delete]: ../mothra/evidence/gap-remediation/2026-11-13/native-live-accounts-01/delete/report.json
[identity-delete]: ../mothra/evidence/gap-remediation/2026-11-13/native-account-identity-01/self/report.json
