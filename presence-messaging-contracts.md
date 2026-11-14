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
It is not a Unicode category rule. The helper uses `1008fd2d` for the
three-byte `***` name fallback and `1008fd31` for the default automatic
response. No peer-wide locale or UTF-8 encoding guarantee follows.

The [eight same-session transitions](native-settings-transition-witness.md)
measure this naming-allowed branch with prior nonzero name/icon and explicit
automatic-response text. Omitted and empty 102/104 reset the observed state to
`***`/0; enabled auto-response with omitted or empty 215 emits the exact
default bytes. Option 8 alone disables feedback, 12 enables it, and absent or
zero 113 disables it before a later re-enable selects the default again.
These are 304 observations. The [two delayed-121 defaults](native-121-default-witness.md)
independently produce the same exact 52-byte ASCII response for absent and
empty 215. Combined review meets GAP-030's unchanged criterion. The
[two-phase persistence witness](native-settings-persistence-witness.md)
adds the bounded storage/restart observation below. Supplied-text encoding
remains GAP-018; the default literal does not establish a general codec.

Settings retain a 16-bit icon. The 301 sender promotes that word as signed
before numeric serialization: high-bit icons use four bytes (`8000` becomes
`ffff8000`, `ffff` becomes `ffffffff`). The [native settings captures](native-wire-details.md#captured-tlv-and-scalar-boundaries)
confirm this exception; the packed roster icon remains BE16.

The helper calls the 301 builder after assigning these settings. Fan-out helper
`10005510` selects sessions whose transport is ready and whose online flag is
set, including the sender when already online. Both traced login completion
paths emit their initial 301 **before** setting the new session online, so
existing eligible sessions get that call while the new session is not selected
by this fan-out. The new session is then marked online and receives 354.

For 121, the direct empty ACK precedes settings/301 and online/354. For early
completion in 107, the login ACK precedes identity/301, online/354 and agreement
109. These sequences do not establish a race-free roster snapshot (GAP-035),
all-storage durability, or a requirement that every 109 precede online
visibility (GAP-025).

## Settings persistence boundary

| Field | Update/default rule | Persistence rule in the inspected settings path |
| --- | --- | --- |
| 102 | Absent/empty requested name becomes `***`; naming privilege determines the effective name. | Helper writes session name buffers, not the account record. With naming disabled, 121 can derive the account name; 304 has no account input and can retain the effective name. |
| 104 | Absent/empty/zero supplies zero; a supplied numeric icon replaces it. | Stored in the session's icon word. |
| 113 | Absent/empty/zero clears the three settings flags; bits 0–2 assign refusal/refusal/automatic response. | The three destination bytes belong to the session; this is distinct from account privilege bitmap 110. |
| 215 | Disabled automatic response clears its length; enabled absent/empty text selects the 52-byte default. | Text and length belong to the session; custom text is observed through PM feedback, not carried in 301. |

In the native 304 witness, explicit name/icon/automatic text changed the
emitted 301 and PM behaviour, survived a disable/re-enable sequence within
that session, and were left enabled before app Quit. Both named 734-byte
UserData records and the complete 175-byte Prefs fork remained unchanged
after that shutdown and after a second boot of the same working image.
The second boot used identical fixed Login107 bytes and returned to its
baseline name/icon and no automatic feedback.

Fresh 107 itself reruns settings, so that result alone does not exclude
stored state. The unchanged named forks and static session-only helper
provide the additional evidence. The 121 handler rereads account data and
calls the same helper without an account-file writer: its session-settings
persistence rule is **inferred from that trace**, not a separately executed
121 restart test. Durable account changes use their account-update paths.

The witness retains its legacy capture-format mismatch, operator-observed
shutdown/FD evidence limits and A48 lock omission. It supports the bounded
GAP-029 rule, with no power-loss, all-storage or general codec guarantee.

## Captured configured login states and visibility

The [authentication corpus][auth] adds eight early/delayed condition cases,
two out-of-state controls and two isolated reauthentication cases. The current
configuration has a TEXT agreement with245 stored bytes and242 loaded bytes
after CRLF conversion, plus the valid Local58-byte GIF. An observer uses300
snapshots to separate authentication from roster visibility; each stream is
reconciled with both packet boundaries. Fourteen read-only Ghidra queries and
positive account/agreement forks retain the configuration provenance.

| Subject path | Subject sequence and observer result |
| --- | --- |
| Nonempty name and nonzero icon, ordinary account | 107 ACK,354,109; observer sees301 and the subject in its next roster. No121 is needed to become visible; no122 is sent by this early path. |
| Name absent, icon absent, name without icon, icon without name, or icon`00010000` narrowing to zero | 107 ACK,109; subject absent from observer roster. After a three-second wait,121 yields ACK,354,122 and the subject becomes visible. |
| Icon`8000` with a name | Early completion; the roster retains BE16 icon`8000`. Nonzero does not mean strictly positive signed16. |
| Bit27 bypass account, early completion | Same early readiness sequence, but109 contains154=`0001` instead of agreement101. |
| Bit27 bypass account, delayed completion | 109 contains154, but the subject remains absent until121. Bypass changes content, not this readiness condition. |
| 107 or121 repeated after online | Status1, field100 `Unknown transaction type!`; subsequent500 still ACKs. |
| 121 before107 | Status1 with `Cannot read account` plus native quoted empty-name text. No301 or roster entry. A later valid107 produces no ACK during the accepted three-second observation; the original30-second failed recovery hypothesis is retained. No universal recovery deadline is inferred. |
| 121 after an incorrect password | No response during three seconds; observer confirms no roster entry. |
| 107 repeated while waiting for acceptance | Second107 with name/icon succeeds and completes early, producing ACK,354,109. The initial109 remains a separate earlier notification. |

Both successful completion paths produce one301 for the existing observer;
the joining subject does not receive that initial fan-out. On the subject's
connection, early354 precedes109; delayed121 ACK precedes354 and122. Static
calls enqueue301 before setting online. Cross-connection packet delivery is not
promised to follow a single global order, and a roster request is a separate
snapshot rather than an atomic subscription boundary.

After failed or premature sessions close, the observer receives302 for a UID
that was never listed in its rosters and had no301 update. After ordinary
successful paths, the captured post-close snapshot excludes the subject.
The isolated repeated107 case differs: its three-second post-close snapshot
still lists the subject, then a native302 for that UID arrives unread. The
literal28-byte tail is retained separately and reconciles in both packet
views; the original report is unchanged. This is a bounded delayed-cleanup
observation, not evidence of a permanent ghost or a guaranteed three-second
cleanup deadline (GAP-035/036).

One exploratory reauthentication trial overlapped account cleanup and includes
another peer's301. It remains separate from the isolated repeat. The temporary
guest and other owned accounts are removed and read back as missing; existing
account records were not edited. These authentication cases originally left
the absent, empty and unreadable agreement configurations open. Those are now
covered by the separate [agreement corpus][agreements]. Login
field161 remains an unnamed zero in these observations; no banner-identity
meaning or constant-zero guarantee is inferred (GAP-026).

[auth]: ../mothra/evidence/gap-remediation/2026-11-13/native-auth-01/manifest.json

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

### Early completion and metadata changes

The early-completion branch in 107 does not invoke the 122 builder. Its session
is already online, and the dispatcher sends a replayed 121 to the
unknown-operation error handler. Request 212 obtains a banner data reference;
its inspected success reply does not substitute a 122 metadata notification.
The catalogue therefore supplies no validated request that an early-completed
client can use to demand the delayed path's metadata. Clients must tolerate
that absence; an invented mandatory 122 sequence would contradict these paths.

The content loader changes current type/buffers without emitting 122 itself.
Subsequent eligible 121 processing reads the new values. An already advertised
reference does not snapshot banner data: the worker reads the current buffer
at send time. No automatic metadata refresh for existing clients is established
by these inspected producers. This completes GAP-028's type/field/ordering
matrix. [Captured banner streams](transfer-contracts.md#captured-banner-formats-and-recovery)
now cover loaded type selection, current-buffer replacement and recovery after
absence. Actual historical-client image decoding remains GAP-080/084.

## Login extras and configured content

### Fields 160, 161 and 162

Login success reads the current server object, rather than a saved per-client
copy, for these values:

| Field | Native source | Established representation / scope |
| ---: | --- | --- |
| 160 | Literal 190 | Generic numeric writer emits two bytes `00 be`. |
| 161 | Server word at `+0x41c` | Numeric writer emits two bytes for values at most 65,535, four otherwise. Constructor initializes this word to zero. Meaning and any later assignment remain unknown. |
| 162 | Pascal string at server `+0xcc` | Configuration/UI readers copy at most 31 bytes. Captured 31-byte names and a 32-byte typing attempt corroborate this destination cap. Empty omits the field; native byte `9a` is preserved. |

[Constructor assembly][constructor] confirms the zero assignment for 161.
The original [word-store scan][store-scan] found only that constructor store.
The new [expanded direct-store scan][expanded-store-scan] also checks byte,
halfword, floating-point/doubleword and multiple-register stores whose constant
ranges intersect the slot; Ghidra confirms the same single constructor store.
Indexed writes, split base derivations and aliases remain outside that discovery
scan. Neither a constant-zero guarantee nor a persistent community/banner
identifier is established. The earlier community/banner label remains withdrawn.

The configuration reader loads 162 from the fourth Pascal string following
its version-5 fixed prefix and clears it on the fallback path. Options handling
passes this string to/from the Info pane's Name field; its getter limits the
copy to 31 bytes. The [login-extra corpus][login-extras] confirms exact stored
and wire bytes, omission when empty and emission without a client-version gate.
A native Mac keyboard high byte `9a` survives unchanged; no Unicode conversion is
established by that fixture.

Changing the saved name from A to B leaves existing online and waiting login
ACKs as A. A fresh login returns B; subsequent 121 and 500 replies carry no 161/162
refresh in the accepted 20-second trial. Its separate 90-second hypothesis lost
the waiting session before 121: that late request reached the host proxy after
the guest had closed and never reached the native application. It is not a
native rejection of a delivered 121 or a universal configuration/timer rule.

Local GIF, Remote URL and empty Remote URL configurations all retain 161=`0000`
in these samples. Two successful 212 downloads use different nonzero four-byte
references while the login value stays zero. That excludes interpreting 161 as
those observed transfer references; its purpose and full change/lifetime rules
remain GAP-026. A zero 161 is present data, distinct from omitted 162. These
observations do not establish an automatic existing-client refresh protocol or
restart durability.

### Agreement and banner loading

[Content loader `10003940`][content-loader] first reloads `Agreement.txt` into
the agreement buffer. It then clears the banner type and chooses between URL
metadata and file-backed image content using option-word bit `0x80`:

| Configuration branch | Loader effects |
| --- | --- |
| `0x80` clear | Dispose old image buffer; copy the configured URL byte string to metadata buffer. Nonempty URL selects type `URL` + ASCII space (`55 52 4c 20`); empty URL leaves type zero. |
| `0x80` set | Dispose old metadata buffer; load the configured banner file, infer its type, then copy an optional configured link byte string into metadata. Failed file loading leaves type zero. |

The URL/link helper copies the Pascal-string content as bytes, with no NUL
terminator in the resulting buffer. No URL fetch, transcoding or syntax
validation appears in that helper. File-backed type selection examines the
last four filename bytes after native case conversion, plus the file's native
type value:

| Suffix / native file type | Selected four-byte value |
| --- | --- |
| `.jpg`, or native `JPEG` / `JFIF` | `JPEG` |
| `.gif`, or native `GIFf` | `GIFf` |
| `.pct`, or native `PICT` | `PICT` |
| `.bmp` / `.dib`, or native `BMP` + ASCII space | `BMP` + ASCII space |
| None of those matches | Native file type unchanged, including zero if supplied |

These are loader selection rules, not proof of image validation or successful
decoding by every client. The earlier version/type/buffer table still controls
whether 122 is sent. Neither this table nor field 152 assigns a meaning to 161.

### Content byte limits and reload effects

[File loader `10003bd0`][file-loader] disposes the previous destination buffer
before resolving/reading its replacement. It accepts sizes equal to the limit
and rejects larger values:

| Native file type | Pre-conversion data-fork limit | Byte transformation |
| --- | ---: | --- |
| `TEXT` | 65,535 | Replace CRLF (`0d 0a`) pairs with CR (`0d`). |
| Other types | 262,140 (`0x3fffc`) | No TEXT newline conversion in this branch. |

The same helper loads agreement and image buffers; its limit depends on native
file type, not solely on their intended role. It does not establish a character
encoding, universal LF-to-CR conversion or a safe single-TLV grammar for a
non-TEXT agreement larger than 65,535 bytes. The agreement corpus now confirms
that the writer rejects a loaded 65,536-byte value before sending 109, with
different early/delayed partial-login outcomes. Broader field validation, text
policy and peer acceptance remain GAP-011/018/019/028.

Empty paths, missing files or size rejection do not preserve the old buffer
in this helper. Options handling has an explicit content-reload call when its
selected settings change; startup also loads content. This does not establish
a filesystem watcher or atomic replacement across advertisement and data send.
Native agreement changed/missing/empty/unreadable/over-limit cases now have
paired network and positive-file evidence. Concurrent-transfer and broader
content-refresh requirements remain separate. A successful configuration load
alone does not establish a native network outcome.

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
itself another bit in this status builder. The following **code-derived**
transitions hold with other inputs fixed; they are not captured native events:

| Before / change | Calculated status after change |
| --- | --- |
| No access bits, no settings flags; become idle | `0x0020` to `0x0021` |
| No access bits; enable PM refusal | `0x0020` to `0x0024` |
| Then also enable chat refusal | `0x0024` to `0x002c` |
| Only access bit 22 becomes set; no settings flags | `0x0020` to `0x0002` |
| Every bit in the aggregate predicate set; no settings flags | `0x0012` (aggregate plus bit-22 status) |
| Clear only access bit 27 from that aggregate case | Remains `0x0012`; bit 27 is outside that predicate. |
| Only access bit 63 set; no settings flags | `0x0000`; access is nonzero, but none of the positive status predicates apply. |
| Toggle automatic response alone | No status-bit change from that setting alone. |

This satisfies GAP-034's traced registry and transition-example criterion.
Settings rules are specified above, and the live-account and identified-peer
fixtures cover their measured notification paths. Concurrent snapshot and
delivery ordering remain GAP-035.

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
The [producer inventory](notification-104-variants.md) records the overlapping
schemas, contextual distinctions and known-producer fixtures.

The [bounded native PM witness](native-pm-witness.md) now confirms seven 108
cases with six delivered 104 frames: direct quoted text, recipient refusal,
automatic feedback alongside original delivery, sender-refusal suppression,
generated option-2/3 text and empty-text silence. The request's empty success
ACK precedes feedback on the **same sender TCP stream** in the captured
refusal/automatic cases. Separate recipient-stream delivery timing is not
established by the sequential Recorder reads. These bytes do not supply a
universal 104 origin discriminator or settle spam and text limits.

GAP-043's routing-table criterion is satisfied by the sender/recipient/options
matrix and the ACK/identity/field rules above. It covers feedback suppression,
original delivery alongside auto response, empty ordinary text and non-whitelisted
options. Text boundaries, independent spam interruption, other 104 producers
and delivered native cases remain GAP-019/044/045/084; no native session is
claimed by that documentation closure.

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

These normal branches invoke the target-close helper before constructing the
requester's ACK; this is not a cross-socket arrival-order guarantee.
Option 1 uses `100063c0`; option 2 uses `10006230`, list reader
`1000a070` and writer `10009d10`. The writer rotates the stored ban files and
writes list version 2. These are address bans, not account-name mutations.
Expiry/restart/protection fixtures remain GAP-074.

The [owned lab fixture](native-ban-notices.md) captures option 1 with an
unprotected target: data-only 104, target close, then the administrator's
success ACK before 302 on its own stream. Its single fresh probe completed
TRTP but attempted no 107; the failed pre-login EOF expectation is preserved.
This does not establish later login acceptance or rejection.

The [separate option-two witness](native-ban-control-witness.md) captures a
42-byte data-only permanent-ban notice, target EOF, requester ACK/302 and a
fresh Login107 rejection with the same text in error field 100. The existing
admin connection remains usable for the exact account and Files readback.
Its readiness profile covers control operations; it makes no full-transfer
baseline claim. The stopped image contains a 49-byte `Banned` data fork.
Expiry and behaviour after reload remain untested.

The [fresh read-only oracle trace][ban-oracle] finds direct callers of both
ban predicates only in login 107. `10011960` checks the permanent list first,
then the temporary list, before reading login/password TLVs. A matching branch
constructs status 1 with field 100: the compiled Pascal strings are
You are permanently banned on this server. and
You are temporarily banned on this server. This is code-derived error text;
C32 did not request login after its ban. Direct-call coverage does not exclude
all indirect or alternative paths.

Temporary lookup calls `100064d0` to purge deadlines no later than current
GetDateTime, then matches the address. The deadline is the native 32-bit
GetDateTime word plus 1800; range matcher `10009960` includes both endpoints.
This is a lazy lookup-time cleanup path, not a proved background timer.
Actual expiry, multiple-expired-entry behaviour, rollover and restart cases
remain untested. The permanent writer refreshes its active list after writing;
its full persisted reason/layout contract still needs a native fixture.

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

[constructor]: ../mothra/evidence/gap-remediation/2026-11-12/batch-17/queries/B17-A-10000160.json
[content-loader]: ../mothra/evidence/gap-remediation/2026-11-12/batch-17/queries/B17-D-10003940.c
[file-loader]: ../mothra/evidence/gap-remediation/2026-11-12/batch-17/queries/B17-D-10003bd0.c

[store-scan]: ../mothra/evidence/gap-remediation/2026-11-12/batch-17/discovery-offset-41c-stores.json

[agreements]: native-wire-details.md#captured-agreement-configurations-and-partial-login-failures

[expanded-store-scan]: ../mothra/evidence/gap-remediation/2026-11-13/native-login-extras-01/all-direct-store-candidates.json
[login-extras]: ../mothra/evidence/gap-remediation/2026-11-13/native-login-extras-01/manifest.json

## Captured private rooms, invitations and chat bytes

The [native room corpus][rooms-corpus] retains thirteen completed captures,
two failed recorder expectations, 45 host/guest TCP lifetimes and sixteen
identity-checked oracle queries. Three newly owned accounts have only receive
chat (bit 9), send/receive chat (bits 9/10), or no privileges. The creator is
the existing administrator. Room IDs are captured as four-byte values; subject
UIDs are two bytes. No ID is copied from a previous connection or room.

| Action / state | Native result |
| --- | --- |
| Zero-privilege 112 create | Status 1, field 100: `You are not allowed to create a new chat.` |
| 115 join existing room without invitation, zero privileges | Success; returned packed roster includes creator and joining subject |
| 115 repeated join | Same membership roster; no additional 117 |
| 115 absent/zero or missing room | Status 1: `Cannot join private chat because it has been closed already.` |
| 113 invite from zero-privilege non-member | Delivers invitations; neither room membership nor creation bit 11 is required |
| 120 topic from zero-privilege non-member | Changes subject and sends 119 to room members; no direct ACK |
| 105 room chat from send-enabled non-member | Reaches members with receive bit 9; sender membership is not required |
| 105 from a member without send bit 10 | Data-only 104, option 109=`0001`, text `You are not allowed to participate in chat.` |
| Receive-disabled member | Receives membership/topic notifications, but not room chat 106 |
| 105 absent or zero room | Main-chat fan-out to eligible sessions, including sender; no explicit main-room join |

The owner/administrator label supplies no universal room bypass or ownership
ACL. Creation requires bit 11, sending requires bit 10, and chat reception
requires bit 9; the observed join/invite/subject handlers impose their separate
state checks. A topic-denial rule based on membership or privileges would be
incorrect: the negative controls are missing-room silence and denied creation,
while the zero-privilege non-member topic update succeeds.

Topic 115 accepts raw bytes. Omitted and present-empty inputs clear it; 119
and later join replies then omit 115 entirely. Seven-byte text and a nine-byte
value containing NUL, CR, LF, `80` and `ff` survive exactly. Inputs of 255, 256
and 65,535 bytes yield 255 stored/output bytes. The 119 fan-out reaches the
creator and receive-only member, not the outsider who changed the subject.
Repeated join returns the current subject without another membership event.
No Unicode interpretation is established by these byte fixtures.

A new join emits 117 to existing ready members before the handler adds the
subject, then returns its post-add roster. Leave 116 removes the member and
sends 118 to remaining members. Non-member leave adds no event; last-member
leave deletes the room, and a later join reports the missing-room error.
There is no normal direct leave ACK. Paired outstanding joins from two sockets
return a two-member snapshot and a three-member snapshot, each including its
own requester. Paired leaves produce each departure exactly once for the
remaining creator and one cross-member departure notification. The trace
establishes local enqueue order; these observations do not promise a universal
receipt order across sockets or an atomic global snapshot.

Mixed-target 112 and 113 requests retain valid invitations while skipping a
missing UID. Repeated target UIDs produce repeated 113 notifications. Existing
members and the inviting session are excluded by 113. A disconnected target
is skipped and a later valid target still receives its invitation. Retrying
113 can therefore repeat delivery. Invitations notify; they do not admit all
targets, reserve membership, or supply a capability consumed by join.

Two 114 rejections from the receive-only, unjoined invitee send this exact 106
data to eligible room members, with room 114 and no separate sender field:

```text
\r<<< "Room30-reader" declined invitation to chat >>>
```

Here `\r` denotes one byte `0d`. The invitee joins successfully afterward.
No pending-invitation deletion or expiry gate exists in the traced join path;
uninvited and previously rejecting subjects both join. These results do not
invent an invitation timer. A refusing target gets no invitation: the inviter
receives 104 option 113=`0003` with refusal text, or `0004` with enabled
automatic-response bytes. Other valid targets still receive 113. The inviter's
PM-refusal setting suppresses that feedback, independently of invitation
fan-out. The final refusing invitee can still join without receiving 113.

Chat formatting uses these byte prefixes before applying the 8,192-byte
handler output cap. Name formatting is byte-oriented:

| Option 109 | Prefix |
| --- | --- |
| Exactly 1 | CR, ASCII space, `***`, ASCII space, full effective Pascal-name bytes, ASCII space |
| Absent, 0, 2 or 65,535 | CR, first 13 name bytes right-justified to width 13, colon, two ASCII spaces |

The formatter prepends the prefix, then replaces each CR in the input with
that same prefix. LF remains LF, CRLF becomes prefix-plus-LF, and embedded NUL,
`80` and `ff` remain bytes. Empty and absent text each yield the prefix alone.
The captured short-name result is `\r       Talk30:  short-name30`; the long
ordinary name becomes `Room30-speake`, while action text keeps `Room30-speaker`.
The temporary short account name is restored before account cleanup. These
ordinary/action/system and denied-send examples establish formatting and
recipient rules; they do not choose a cross-client text-decoding policy.

The failed width fixture substituted a four-byte room ID into a declared
two-byte field and received EOF. Its corrected request succeeds in the same
application epoch. Another recorder waited thirty seconds for a nonexistent
304 ACK; the corrected version uses a later 500 liveness reply. Both failures
remain failed, rather than becoming successful room examples or crash claims.

Closing clients produces additional 118/301/302 bytes beyond recorded read
prefixes. Both packet views agree on recorded application bytes; their late
tails can differ because the guest queues further output after host closure.
The corpus retains and verifies each view separately, with known participant
and room identities. It does not trim the guest stream to make them identical.
Cleanup restores the exact original `admin`/`fixture-low` enumeration and
41-entry Files listing. No guest/application restart or original-account
mutation is performed.

[rooms-corpus]: ../mothra/evidence/gap-remediation/2026-11-13/native-rooms-01/manifest.json

## Captured console and client broadcast recipients

The [D1 witness](native-console-broadcast.md) confirms the traced console
104/data-only path and client 355 identity/data path with four session states.
The console message reaches both online sessions; client 355 excludes its
sender. The peer requesting refusal options still receives both forms. A
waiting login receives the later 355 after 121 activation; the unauthenticated
connection receives neither. Exact fields, finite silence windows, teardown
tails and the missing first host handshake are retained. The complete guest
view and three complete host views are distinguished from that partial view.
The full A7 account/file/metadata/download postflight matches the baseline.

[ban-oracle]: ../mothra/evidence/gap-remediation/2026-11-13/native-ban-oracle-01/manifest.json
