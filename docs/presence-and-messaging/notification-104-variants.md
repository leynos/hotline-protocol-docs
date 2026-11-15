# Native type-104 notification variants

Type 104 is an unsolicited notification with several payload grammars. It has
no universal sender field or option field. The following inventory separates
the traced producer from what a receiver can distinguish on the wire. Field
numbers below are decimal; integers use big-endian bytes.

| Producer and trigger                                                                      | Fields produced                                                                      | Captured evidence                                                                                                                                                     |
| ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `1000f4e0`, ordinary 108 delivery                                                         | 103 sender UID, 102 sender name, 113 request option, 101 text; 214 when supplied     | [Seven PM cases](../native-evidence/native-pm-witness.md)                                                                                                             |
| `1000f4e0`, PM refusal or automatic feedback                                              | 103 recipient UID, 102 recipient name, 113=2 or 4, 101 generated/default/custom text | Same PM corpus                                                                                                                                                        |
| `100188e0` / `10017f30`, 112/113 invitation feedback                                      | 103 invited user's UID, 102 their name, 113=3 or 4, 101 refusal/automatic text       | [Room contract](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes) and `native-rooms-01`                                              |
| `1000fc20`, 105 without send-chat access                                                  | 109=`0001`, 101 denial text                                                          | `native-rooms-01`, denied-chat cases                                                                                                                                  |
| `10015500`, 349 creation collision                                                        | 101 collision text, 109=`0001`                                                       | [Account batch contract](../protocol/operation-contracts.md), `native-account-batch-01`                                                                               |
| `10005f90`, standalone 351 or qualifying nested 349 account deletion with connected users | 101 deletion text only                                                               | `native-live-accounts-01`, two connected targets                                                                                                                      |
| `10015e70`, 110 option 1                                                                  | 101 temporary-ban text only                                                          | [Disposable option-one witness](native-ban-notices.md)                                                                                                                |
| `10015e70`, 110 option 2                                                                  | 101 permanent-ban text only                                                          | [Permanent-ban control witness](../native-evidence/native-ban-control-witness.md)                                                                                     |
| Console message dialog `10002dd0`                                                         | 101 operator-supplied text only                                                      | [Console witness](native-console-broadcast.md)                                                                                                                        |
| `10006590`, applying configured address bans to connected users                           | 101 configured-ban notice only                                                       | [Static bytes and caller](../accounts-and-privileges/native-configured-ban-static.md), [one-Save native witness](../native-evidence/native-configured-ban-witness.md) |

The room and account corpus directories in this table are below
`evidence/gap-remediation/2026-11-13/`. Their semantic verifiers check the
observed fields and participant identities. These are finite fixtures; their
text is not a universal origin discriminator.

## Discrimination and ambiguity

For a known PM or invitation context, 103/102 identify the person represented
by that notification. Feedback identifies the recipient or invited user,
whereas ordinary delivery identifies its sender. Option 113 is the PM enumerant
here; it is not the 121/304 settings bitmap. Field 214 belongs to the
delivered-message variant and is optional.

The `109=0001` shape alone does not distinguish denied chat from an account
creation collision. The data-only shape alone does not distinguish a console
message, deleted account, or ban. Operator-supplied text can match a generated
notice verbatim. A receiver must preserve these ambiguities instead of
inventing an origin, sender UID, or mandatory 113. Known surrounding actions
can provide context, but their absence does not make the payload malformed. The
configured-ban helper's compiled 101 text is the same 42-byte permanent notice
as option 2. The configured-application witness independently records that
exact payload after one Options Save, on both connected clients, followed by
EOF. It sends no request 110. Payload equality still cannot identify which of
those two producers emitted an otherwise context-free notice.

The 349 collision fixture captures the notification before the final success
ACK on the same requesting socket. That ordering does not make 104 a direct
reply: the subsequent ACK is still the numbered transaction result. Ban and
account-deletion notices are followed by target teardown; a data-only console
message does not imply teardown. There is no universal cross-socket arrival
order between a target notice and an administrator's ACK or 302.

## Provenance and remaining acceptance

The pinned oracle is native Server 1.9, DATA SHA-256
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`. The primary
producer decompilations are in
[`queries/`](../../evidence/hotline-server-1.9/queries/). The deletion helper
is separately captured in
[`account-attribute-01`](../../evidence/gap-remediation/2026-11-13/account-attribute-01/queries/AA-D-10005f90.c).
The configured-ban helper is in
[`native-login-extras-01`](../../evidence/gap-remediation/2026-11-13/native-login-extras-01/oracle-queries/LX-D-10006590.c).
Its caller `100023a0` applies configuration and invokes that helper after
refreshing the active ban list; the captured caller is
[`B17-D-100023a0.c`](../../evidence/gap-remediation/2026-11-12/batch-17/queries/B17-D-100023a0.c).
Applying a list and rejecting a later Login107 are separate execution paths.

The positive fixtures now cover every producer listed above and meet GAP-044's
original known-producer criterion. Account deletion reaches `10005f90` through
standalone 351 and the qualifying nested 349 delete branch; 353 and 349 live
updates instead call `10005d30` and must not inherit a deletion-notice claim.
This inventory does not establish that no further producer exists or that every
origin is decidable from its fields. Expiry, rate limits, text boundaries, and
general encoding remain separate requirements; the
[one-restart ban witness](../native-evidence/native-ban-reload-witness.md)
covers only its specified permanent-ban reload case.
