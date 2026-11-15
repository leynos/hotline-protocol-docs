# Native presence, messaging and administration contracts

These observations refine the existing [guide](protocol.md), using baseline
handler captures plus [batch 06][batch]. Static send order means calls enqueue
messages in that order; it does not certify client receipt, filesystem durability
or concurrency behaviour. Runtime closure criteria remain in the gap register.

## Settings and login visibility

Helper `10004d50`, shared by 121 and 304, reads fields whether present or not.
It operates on session state rather than writing the account file:

| Input | Observed assignment |
| --- | --- |
| Name 102 absent/empty | Requested session name becomes `***`, then effective name follows the account naming privilege. |
| Name 102 nonempty | Pascal destination holds at most 31 bytes; classification-table-disallowed bytes become `*`. |
| Account naming privilege (bit 26) clear | Account name is used when an account record is supplied; otherwise the existing effective account name can remain. |
| Account naming privilege set | Requested session name becomes effective display name. |
| Icon 104 absent/zero | Generic numeric result zero replaces the old icon. |
| Options 113 absent/zero | Clears refusal and automatic-response flags; higher option bits are ignored by these assignments. |
| Options bit 0 | Refuse private messages. |
| Options bit 1 | Refuse private-chat invitations. |
| Options bit 2 | Enable automatic response. |
| Auto-response disabled | Clears the saved auto-response text length. |
| Auto-response enabled, 215 absent/empty | Formats `I'm not able to respond right now. Please try later!` as default text. |
| Auto-response enabled, 215 nonempty | Pascal destination has 128-byte capacity, at most 127 content bytes. |

The exact byte classification table is retained in batch 06 at `100945c8`.
It is not a Unicode category rule. The default text bytes are retained at
`1008fd2d`; no peer-wide locale or UTF-8 encoding guarantee follows.

The helper calls the 301 builder after assigning these settings. Fan-out helper
`10005510` selects sessions whose transport is ready and whose online flag is
set, including the sender when already online. Both traced login completion
paths emit their initial 301 **before** setting the new session online, so
existing eligible sessions get that call while the new session is not selected
by this fan-out. The new session is then marked online and receives 354.

For 121, the direct empty ACK precedes settings/301 and online/354. For early
completion in 107, the login ACK precedes identity/301, online/354 and agreement
109. These sequences do not establish a race-free roster snapshot (GAP-035),
restart persistence (GAP-029), or a requirement that every 109 precede online
visibility (GAP-025).

## Agreement and banner condition tables

Login 107's agreement branch checks account privilege bit **27** independently
of whether early completion occurred:

| Condition | Notification 109 contents |
| --- | --- |
| Bit 27 set | Numeric field 154 with value 1. |
| Bit 27 clear and agreement buffer present | Field 101 with configured agreement bytes, subject to zero-length writer omission. |
| Bit 27 clear and agreement buffer absent | Empty field list; no automatic 154 flag is added by this branch. |

Account bit 27 therefore bypasses agreement content; absence of configured text
is not the same branch. The client acceptance interface and all runtime
configuration combinations remain GAP-027.

After 121, banner 122 is considered only when saved client version is at least
151 and the configured type is nonzero. URL type `0x55524c20` requires the configured
153 buffer; if absent, no 122 is sent. Non-URL types require the banner byte
buffer and may also include 153 when configured. Field 152 is four bytes.
These reads use current configuration; lifetime and change fixtures remain
GAP-026/028. This is separate from unconditional login-success fields 161/162.

## Status word, separate from the privilege bitmap

The low 16-bit result of `10005000` is a numeric status word used in 112 and
packed user records. [Assembly evidence][status-asm] confirms the masks below,
including extraction of idle state to **one bit**. It must not be confused
with the MSB-first 64-bit privilege registry.

| Numeric mask | Native condition |
| ---: | --- |
| `0x0001` | Idle flag set in the session. |
| `0x0002` | Session privilege bit 22 set (disconnect-users permission). |
| `0x0004` | Refuse-private-message session flag set. |
| `0x0008` | Refuse-private-chat session flag set. |
| `0x0010` | Every privilege in the aggregate predicate below is set. |
| `0x0020` | Both 32-bit access words are zero. |

The `0x0010` predicate tests bits
`0–11, 14–17, 20–26, 28–40`; it does not test 12/13/18/19/27 or 41–63.
It is an aggregate predicate, not a universal administrator override. The
traced builder sets no other status masks. Auto-response enablement is not
itself another bit in this status builder. Transition fixtures remain GAP-034.

## Disconnect teardown and notification 302

Teardown helper `10004930` first removes the departing session from the server
session list, frees its session object and disposes its transport. It then
walks room membership collections. For each room containing that session it
removes the pointer and sends **118** with room 114 and departing UID 103 to
remaining transport-ready members. Empty rooms are deleted along with their
subject storage. After walking rooms, it broadcasts **302** with numeric
UID field **103**, using the online/transport-ready fan-out above.

This establishes native producer, fields and local send-call order: room-leave
updates precede the general removal notification. The departing session cannot
receive that 302 through the server list because it has already been removed.
This helper does not synchronously walk all transfer collections; their workers
separately check whether the owning session remains present. EOF, kick, timeout,
in-flight transfers and delivered-order fixtures remain GAP-036/064.

## Private-message routing

For 108, handler `1000f4e0` checks PM privilege 40 and resolves a target session
with a ready transport. A denied or unavailable target produces a nonzero
direct reply with error text 100. The ordinary successful path sends an empty
ACK **before** deciding notifications. The table below applies after these
checks and before independent spam/flood interruption.

Let S mean the sender refuses PMs, R the recipient refuses PMs, and A the
recipient has automatic response enabled.

| Request/condition | Feedback to sender | Original message to recipient |
| --- | --- | --- |
| Option 1, S clear, A set | Type 104, recipient UID/name, option 4, automatic-response text when nonempty | Delivered when R clear and original text nonempty. |
| Option 1, S clear, A clear, R set | Type 104, recipient UID/name, option 2, generated refusal text | Suppressed. |
| Option 1, S set | No generated refusal/auto-response feedback | Delivered only when R clear and text nonempty. |
| Option 1, A/R both clear | No generated feedback | Delivered when text nonempty. |
| Any option with R set | Feedback only under the option-1 rules above | Suppressed. |
| Option 2 with R clear | None from the option-1 feedback branch | Type 104 with generated refuse-PM text. |
| Option 3 with R clear | None from that branch | Type 104 with generated refuse-chat text. |
| Other option with R clear | None from that branch | Copies nonempty request text and the numeric option; this handler has no 1–4 whitelist. |

An auto response can therefore accompany successful original-message delivery;
it does not always replace it. Feedback suppression due to S does not prevent
an otherwise permitted original delivery. Native data copying caps the main
request text at 4,096 bytes. Quoted field 214 has separate copying/length code;
its overlong boundary needs a fixture before a safe maximum is asserted.

Delivered user-message 104 includes sender 103/102, option 113, data 101 and
optional quoted 214. Feedback 104 uses the recipient's identity. System notices
can contain only data 101, and chat-denial notices can contain 109/101 instead.
Field presence identifies known variants; no universal sender/option schema
applies to every 104 (GAP-044).

The PM/invitation rate counter permits a request while its previous value is
below 21, increments it, and resets when elapsed seconds exceed 60. The repeat
hash counter is shared with chat; the repeated-hash branch closes/bans when its
previous repeat count is 4. It compares a hash, not proven byte equality. Global
request flooding is a separate dispatcher counter. Bounded native rate/race
fixtures remain GAP-045.

## Rooms, invitations and subjects

The inspected room handlers implement these state-specific operations:

| Operation | Native result / checks in this handler |
| --- | --- |
| 112 create | Checks privilege 11; adds creator immediately, sends eligible 113 invitations in request field order, then ACKs with creator/room data. |
| 113 invite | Looks up room, excludes self and existing members from targets; sends eligible invitations/refusal feedback without a success ACK. No sender-membership or new privilege check appears in this handler. |
| 114 reject | Formats a rejection and routes it as room chat **106** via `10004790`; no independent rejection-state deletion or direct success ACK appears here. |
| 115 join | Existing room required; no invitation/owner/privilege check in this handler. If newly joining, sends 117 to existing ready members before adding the session. Then ACKs with optional subject and a roster including the new member. |
| 115 repeated join | Does not add a duplicate or send another 117; still constructs the roster ACK. |
| 116 leave | Removes member; sends 118 to remaining members, or deletes an empty room. Missing-room/non-member paths have no normal direct success ACK. |
| 120 subject | Existing room required; requester argument is unused, with no membership/privilege check here. Updates subject storage and sends 119 to ready room members. Missing room produces no normal success ACK. |

Invitations are not admission capabilities enforced by these join/subject
handlers. Do not invent an invitation expiry, room owner or administrator bypass
from the UI names. Duplicate targets are iterated; successful sends do not
atomically admit invitees. Refusing-chat suppresses invitation delivery, while
auto-response/refusal feedback follows the settings-based branches, with
sender refusal capable of suppressing feedback. Peer lifecycle/partial-failure
fixtures remain GAP-038/039/040.

Subject 115 is read into a 256-byte Pascal destination, at most 255 content
bytes. Missing/empty subject clears stored subject; zero-length writer omission
means the resulting 119 can contain only room 114. Ordinary room fan-out
`100048b0` checks transport readiness; it does not independently require online
state or receive-chat privilege. Chat-data fan-out `10004790` additionally
checks receive-chat privilege 9. Do not apply one recipient predicate to both.

Chat 105 checks send-chat privilege 10. An absent/zero room ID selects its
main-chat session-list fan-out; nonzero selects the named room. The handler
does not check that the sender belongs to that room before broadcasting to its
members. Option 109 equal to 1 selects the action prefix; every other value
selects the ordinary prefix. Retained format bytes include carriage returns
and Pascal-name formatters; exact multiline/non-ASCII rendering remains GAP-042.

## Kick options and native console messages

Request 110 checks requester privilege 22 and target protection privilege 23.
An absent target still reaches an empty success ACK. A protected existing
target produces an error without performing the ordinary kick branch.

| Option 113 | Native effect on existing unprotected target |
| ---: | --- |
| 1 | Sends type-104 data-only notice; adds the target address as both ends of an in-memory ban range expiring at current seconds plus 1,800. |
| 2 | Sends a different data-only 104 notice; adds the target address range to the persisted ban list, with `ffffffff` expiry in the constructed entry and optional reason bytes capped at 63. |
| Other, including absent/zero | Closes the target without either ban helper or those notices. |

All these normal branches close the target control transport before ACKing the
requester. Option 1 uses `100063c0`; option 2 uses `10006230`, list reader
`1000a070` and writer `10009d10`. The writer rotates the stored ban files and
writes list version 2. These are address bans, not account-name mutations.
Expiry/restart/protection fixtures remain GAP-074.

Console message dialog `10002dd0` sends **104** with field 101 only through
online fan-out. It does not reuse client broadcast type 355 or add a fabricated
sender UID/name. Client request 355 remains its own ACK-plus-355 path.

Shutdown dialog `10001bf0`, when configured to prompt and given nonempty text,
sets the shutdown flag, sends standalone **111** with field **101** through
online/ready fan-out, then proceeds to the shutdown path. Empty/cancel branches
differ and do not establish a mandatory 111. This is a positive producer for
the previously unresolved catalogue entry, not evidence that every kick,
malformed frame or disconnect must send 111. Exact delivered shutdown timing
and notification fixtures remain GAP-084/076.

[batch]: ../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json
[status-asm]: ../mothra/evidence/gap-remediation/2026-11-12/batch-06/queries/B06-A-10005000.json
