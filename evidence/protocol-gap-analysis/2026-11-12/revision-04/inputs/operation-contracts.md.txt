# Native operation and session dispatch contracts

This catalogue covers all 45 explicit client-request handlers in the hashed
1.9 dispatcher `1000acf0`. The immutable [dispatcher map][map] and
[handler captures][queries] provide the source references below. Directions
are client-to-server for every request row and server-to-client for its direct
reply. Server notifications have a separate namespace and are listed below.

## Session eligibility and invalid transitions

The dispatcher uses its online flag and failure timestamp, rather than a
separate state enum for every login step. This table describes dispatch
eligibility; handler configuration/account checks can still reject a request.
It closes the dispatch question in GAP-007, while GAP-025 retains the complete
login/agreement sequence and fixture work.

| Native connection condition | Requests dispatched | Other input / transition |
| --- | --- | --- |
| Handshake incomplete | No numbered requests yet | Twelve-byte handshake parser waits for availability; successful normal negotiation creates a session. |
| Session not online, failure timestamp zero | 107 and 121 only | Any other numbered request takes the close path, including 500. Dispatch of 121 alone does not prove successful authentication. |
| Session online, failure timestamp zero | Catalogue rows except 107/121 | Replayed 107 or 121 takes the unknown-operation error handler, as does an unrecognized type. |
| Authentication-failure timestamp nonzero | Normal request loop bypassed | Dispatcher closes once failure age is greater than 30 seconds. |
| Transport no longer connected | No request dispatch | Teardown helper `10004930` runs; its full event/cleanup order remains GAP-036. |

The [unknown-operation handler][unknown] sets reply status 1 and error-text
field 100, then logs the failure. It does not turn an unknown online request
into a mandatory standalone transaction 111. This differs from the pre-online
close path. Flood checks can close before the operation handler runs.

## Request catalogue

ACK denotes a visible direct normal-path reply, with the request ID and native
type zero. Push denotes no direct normal success ACK at the inspected handler.
Neither label guarantees successful delivery, persistence, atomicity or retry
safety. The field column identifies helper reads, not a declaration that every
listed field is mandatory or unique. Feature-specific open constraints remain
in [the gap analysis](gap-analysis.md).

| Request | Operation | Entry/evidence | Directly read field IDs | Success path |
| ---: | --- | --- | --- | --- |
| 101 | Get old message board | [1000f130](../mothra/evidence/hotline-server-1.9/queries/D-1000f130.c) | None identified directly | ACK |
| 103 | Post old message board | [1000f260](../mothra/evidence/hotline-server-1.9/queries/D-1000f260.c) | 101 | ACK |
| 105 | Send chat | [1000fc20](../mothra/evidence/hotline-server-1.9/queries/D-1000fc20.c) | 101, 109, 114 | Push |
| 107 | Login | [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c) | 102, 104, 105, 106, 160 | ACK |
| 108 | Send private message | [1000f4e0](../mothra/evidence/hotline-server-1.9/queries/D-1000f4e0.c) | 101, 103, 113, 214 | ACK |
| 110 | Disconnect user | [10015e70](../mothra/evidence/hotline-server-1.9/queries/D-10015e70.c) | 101, 103, 113 | ACK |
| 112 | Create private chat | [10017f30](../mothra/evidence/hotline-server-1.9/queries/D-10017f30.c) | 103, iterated by index | ACK |
| 113 | Invite to existing chat | [100188e0](../mothra/evidence/hotline-server-1.9/queries/D-100188e0.c) | 114; target UID via field iteration | Push |
| 114 | Reject chat invitation | [10018340](../mothra/evidence/hotline-server-1.9/queries/D-10018340.c) | 114 | Push |
| 115 | Join chat | [100183c0](../mothra/evidence/hotline-server-1.9/queries/D-100183c0.c) | 114 | ACK |
| 116 | Leave chat | [10018620](../mothra/evidence/hotline-server-1.9/queries/D-10018620.c) | 114 | Push |
| 120 | Set chat subject | [10018760](../mothra/evidence/hotline-server-1.9/queries/D-10018760.c) | 114, 115 | Push |
| 121 | Accept agreement | [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c) | 102/104/113/215 through helper | ACK |
| 200 | List files | [100100a0](../mothra/evidence/hotline-server-1.9/queries/D-100100a0.c) | 202 | ACK |
| 202 | Download file | [100121a0](../mothra/evidence/hotline-server-1.9/queries/D-100121a0.c) | 201, 202, 203, 204 | ACK |
| 203 | Upload file | [100130f0](../mothra/evidence/hotline-server-1.9/queries/D-100130f0.c) | 108, 201, 202, 204 | ACK |
| 204 | Delete file/folder | [100140e0](../mothra/evidence/hotline-server-1.9/queries/D-100140e0.c) | 201, 202 | ACK |
| 205 | Create folder | [100143f0](../mothra/evidence/hotline-server-1.9/queries/D-100143f0.c) | 201, 202 | ACK |
| 206 | Get file info | [10016ba0](../mothra/evidence/hotline-server-1.9/queries/D-10016ba0.c) | 201, 202 | ACK |
| 207 | Set file info | [100170c0](../mothra/evidence/hotline-server-1.9/queries/D-100170c0.c) | 201, 202, 210, 211 | ACK |
| 208 | Move file/folder | [100177d0](../mothra/evidence/hotline-server-1.9/queries/D-100177d0.c) | 201, 202, 212 | ACK |
| 209 | Make alias | [10017c10](../mothra/evidence/hotline-server-1.9/queries/D-10017c10.c) | 201, 202, 212 | ACK |
| 210 | Download folder | [10012850](../mothra/evidence/hotline-server-1.9/queries/D-10012850.c) | 201, 202, 203, 204 | ACK |
| 212 | Download banner | [10012f40](../mothra/evidence/hotline-server-1.9/queries/D-10012f40.c) | None identified directly | ACK |
| 213 | Upload folder | [10013930](../mothra/evidence/hotline-server-1.9/queries/D-10013930.c) | 108, 201, 202, 204, 220 | ACK |
| 214 | Reference cleanup (cancellation inferred) | [10013040](../mothra/evidence/hotline-server-1.9/queries/D-10013040.c) | 107 | ACK |
| 300 | Get user roster | [10011870](../mothra/evidence/hotline-server-1.9/queries/D-10011870.c) | None identified directly | ACK |
| 303 | Get client diagnostic info | [10016150](../mothra/evidence/hotline-server-1.9/queries/D-10016150.c) | 103 | ACK |
| 304 | Set client info | [10016ad0](../mothra/evidence/hotline-server-1.9/queries/D-10016ad0.c) | 102/104/113/215 through helper | Push |
| 348 | Enumerate accounts | [10015160](../mothra/evidence/hotline-server-1.9/queries/D-10015160.c) | Transitive/indexed; not enumerated | ACK |
| 349 | Batch account mutations | [10015500](../mothra/evidence/hotline-server-1.9/queries/D-10015500.c) | Transitive/indexed; not enumerated | ACK |
| 350 | Create account | [100146f0](../mothra/evidence/hotline-server-1.9/queries/D-100146f0.c) | 102, 105, 106, 110, 111 | ACK |
| 351 | Delete account | [100149e0](../mothra/evidence/hotline-server-1.9/queries/D-100149e0.c) | 105 | ACK |
| 352 | Get account | [10014bc0](../mothra/evidence/hotline-server-1.9/queries/D-10014bc0.c) | 105 | ACK |
| 353 | Update account | [10014df0](../mothra/evidence/hotline-server-1.9/queries/D-10014df0.c) | 102, 105, 106, 110, 111 | ACK |
| 355 | Broadcast | [1000f990](../mothra/evidence/hotline-server-1.9/queries/D-1000f990.c) | 101 | ACK |
| 370 | List news categories | [100102c0](../mothra/evidence/hotline-server-1.9/queries/D-100102c0.c) | 325 | ACK |
| 371 | List news articles | [10011370](../mothra/evidence/hotline-server-1.9/queries/D-10011370.c) | 325 | ACK |
| 380 | Delete news item | [10010b70](../mothra/evidence/hotline-server-1.9/queries/D-10010b70.c) | 325 | ACK |
| 381 | Create news folder | [10010ee0](../mothra/evidence/hotline-server-1.9/queries/D-10010ee0.c) | 201, 325 | ACK |
| 382 | Create news category | [10011110](../mothra/evidence/hotline-server-1.9/queries/D-10011110.c) | 322, 325 | ACK |
| 400 | Read news article | [10011580](../mothra/evidence/hotline-server-1.9/queries/D-10011580.c) | 325, 326, 327 | ACK |
| 410 | Post news article | [10010470](../mothra/evidence/hotline-server-1.9/queries/D-10010470.c) | 325, 326, 327, 328, 333, 334 | ACK |
| 411 | Delete news article | [100108a0](../mothra/evidence/hotline-server-1.9/queries/D-100108a0.c) | 325, 326, 337 | ACK |
| 500 | Undocumented empty ACK operation | [10018c00](../mothra/evidence/hotline-server-1.9/queries/D-10018c00.c) | None identified directly | ACK |

## Server notification catalogue

| Type | Producer / role | Known value fields | Remaining contract |
| ---: | --- | --- | --- |
| 102 | Old-board post | 101 | GAP-046: serialization and recipient/order rules |
| 104 | Routed PM, refusal/automatic response, denial, kick notices | Variant-specific 101/102/103/113/214 | GAP-043/044: variant discriminator and routing table |
| 106 | Chat fan-out | 101; room path also 114 | GAP-042: formatted text rules |
| 109 | Login agreement | 101 or no-agreement flag 154 | GAP-027: complete condition matrix |
| 113 | Chat invitation | 114, inviter 103/102 | GAP-039: lifecycle and partial failures |
| 117 | Room member joins | 114, 103, 104, 112, 102 | GAP-040: races and recipient order |
| 118 | Room member leaves | 114, 103 | GAP-036/040: disconnect cleanup |
| 119 | Subject update | 114, 115 | GAP-041: input and permission cases |
| 122 | Configured banner metadata | Four-byte 152; conditional 153 | GAP-028/063: metadata lifetime and stream |
| 301 | Presence update | 103, 104, 112, 102 | GAP-034/035: status and event ordering |
| 354 | Login completion or changed live account privileges | Eight-byte 110 | GAP-073: delivered sequence and persistence |
| 355 | Client-originated broadcast fan-out | 103, 102, 101 | GAP-076: console-originated path |
| 211 | Download queue advancement or changed position | Four-byte 107, numeric 116 | [Transfer contracts](transfer-contracts.md#queue-notification-211); GAP-061 runtime queue behaviour |
| 111 / 302 | Independently unresolved producer or schema | Unestablished here | GAP-075 / GAP-036 respectively |

Error-text field 100 is not a proven notification type 100. A notification
usually uses a newly generated server ID, while a direct reply copies its
request's ID. Do not match notifications as completion of an unrelated request
merely because a numeric identifier collides.

## Frame acceptance and reassembly boundaries

The frame receiver `100590e0` rejects either size word equal to zero or greater
than the current global `10094a50`. Equality with that limit passes these
comparisons. The retained initial value is 2 MiB; runtime configuration remains
GAP-011. These are per-frame word checks, not a demonstrated bound on the sum
of interleaved or accumulated fragments.

The receiver uses the is-reply byte as a zero/nonzero discriminator. The traced
path does not validate the flags byte against a whitelist. Requests are grouped
by ID; incoming replies are matched to an existing reply-waiting record, with
an unmatched complete reply discarded by this path. Existing records have
stored type and total overwritten by later frames. Completion uses accumulated
length **at least** total, so overshoot is not rejected by that comparison.
No type/total consistency, aggregate-memory or fragment-expiry guarantee should
be inferred. GAP-012/013 retain boundary packets and transport outcomes.

The server ID generator `10058d70` increments a connection object's 32-bit
counter and replaces wrapped zero with 1. It performs no outstanding-ID scan in
that helper. Client zero-ID rejection, reuse and late replies remain GAP-004.
Do not substitute this counter for independent room/user/article/ref lifetimes.

## Administrative account list and batch mutation

Request **348**, handler `10015160`, enumerates accounts when the requester's
account-view privilege check succeeds. Its reply repeats outer field **101**;
each value is itself a count-prefixed TLV stream with 102 (name), 105
(complemented login), 106 (literal `x` if a password exists, otherwise omitted),
and eight-byte 110. It does not expose the real encoded password. No input
fields are read directly by this handler. GAP-077 retains representative
success/error fixtures and source-independent historical naming.

Request **349**, handler `10015500`, iterates outer fields in wire order and
interprets each value as an account TLV stream. It does not filter outer IDs in
this loop. Indexed copying caps each nested value at **512 bytes**. Inside,
101 is the complemented old account name (up to 31 bytes), while
102/111/105/106/110 build the new record as described in
[native wire details](native-wire-details.md). Empty new display/login with an
old name selects deletion; otherwise the path can rename, create or update.
The existing-password NUL sentinel requires a nonempty old name in this path.

Processing is **sequential and not atomic**: earlier records can be written or
deleted before a later permission/error branch returns. Some malformed records
set a flag and processing continues, followed by an error reply after the loop.
An existing-account collision on the no-old-name path sends a type-104 notice
and continues, so a final empty ACK does not certify that every requested
mutation happened. Retries require checking actual account state; no rollback
or idempotency guarantee is established. GAP-078 retains mixed-outcome fixtures,
rename/conflict helper validation and complete permissions.

[map]: ../mothra/evidence/hotline-server-1.9/dispatcher-map.json
[queries]: ../mothra/evidence/hotline-server-1.9/queries/
[unknown]: ../mothra/evidence/gap-remediation/2026-11-12/batch-03/queries/B03-D-10014640.c
