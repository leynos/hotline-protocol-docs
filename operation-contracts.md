# Native operation and session dispatch contracts

This catalogue covers all 45 explicit client-request handlers in the hashed 1.9
dispatcher `1000acf0`. The immutable [dispatcher map][map] and
[handler captures][queries] provide the source references below. Directions are
client-to-server for every request row and server-to-client for its direct
reply. Server notifications have a separate namespace and are listed below.

## Session eligibility and invalid transitions

The dispatcher uses its online flag and failure timestamp, rather than a
separate state enum for every login step. This table describes dispatch
eligibility; handler configuration/account checks can still reject a request.
It closes the dispatch question in GAP-007, while GAP-025 retains the complete
login/agreement sequence and fixture work.

| Native connection condition                | Requests dispatched           | Other input / transition                                                                                                        |
| ------------------------------------------ | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Handshake incomplete                       | No numbered requests yet      | Twelve-byte handshake parser waits for availability; successful normal negotiation creates a session.                           |
| Session not online, failure timestamp zero | 107 and 121 only              | Any other numbered request takes the close path, including 500. Dispatch of 121 alone does not prove successful authentication. |
| Session online, failure timestamp zero     | Catalogue rows except 107/121 | Replayed 107 or 121 takes the unknown-operation error handler, as does an unrecognized type.                                    |
| Authentication-failure timestamp nonzero   | Normal request loop bypassed  | Dispatcher closes once failure age is greater than 30 seconds.                                                                  |
| Transport no longer connected              | No request dispatch           | Teardown helper `10004930` runs; its full event/cleanup order remains GAP-036.                                                  |

The [unknown-operation handler][unknown] sets reply status 1 and error-text
field 100, then logs the failure. It does not turn an unknown online request
into a mandatory standalone transaction 111. This differs from the pre-online
close path. Flood checks can close before the operation handler runs.

## Request catalogue

ACK denotes a visible direct normal-path reply, with the request ID and native
type zero. Push denotes no direct normal success ACK at the inspected handler.
Neither label guarantees successful delivery, persistence, atomicity or retry
safety. The field column identifies helper reads, not a declaration that every
listed field is mandatory or unique. Feature-specific open constraints remain in
[the gap analysis](gap-analysis.md).

| Request | Operation                                 | Entry/evidence                                                         | Directly read field IDs                                        | Success path            |
| ------: | ----------------------------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------------- | ----------------------- |
| 101     | Get old message board                     | [1000f130](../mothra/evidence/hotline-server-1.9/queries/D-1000f130.c) | None identified directly                                       | ACK                     |
| 103     | Post old message board                    | [1000f260](../mothra/evidence/hotline-server-1.9/queries/D-1000f260.c) | 101                                                            | ACK                     |
| 105     | Send chat                                 | [1000fc20](../mothra/evidence/hotline-server-1.9/queries/D-1000fc20.c) | 101, 109, 114                                                  | Push                    |
| 107     | Login                                     | [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c) | 102, 104, 105, 106, 160                                        | ACK                     |
| 108     | Send private message                      | [1000f4e0](../mothra/evidence/hotline-server-1.9/queries/D-1000f4e0.c) | 101, 103, 113, 214                                             | ACK                     |
| 110     | Disconnect user                           | [10015e70](../mothra/evidence/hotline-server-1.9/queries/D-10015e70.c) | 101, 103, 113                                                  | ACK                     |
| 112     | Create private chat                       | [10017f30](../mothra/evidence/hotline-server-1.9/queries/D-10017f30.c) | 103, iterated by index                                         | ACK                     |
| 113     | Invite to existing chat                   | [100188e0](../mothra/evidence/hotline-server-1.9/queries/D-100188e0.c) | 114; target UID via field iteration                            | Push                    |
| 114     | Reject chat invitation                    | [10018340](../mothra/evidence/hotline-server-1.9/queries/D-10018340.c) | 114                                                            | Push                    |
| 115     | Join chat                                 | [100183c0](../mothra/evidence/hotline-server-1.9/queries/D-100183c0.c) | 114                                                            | ACK                     |
| 116     | Leave chat                                | [10018620](../mothra/evidence/hotline-server-1.9/queries/D-10018620.c) | 114                                                            | Push                    |
| 120     | Set chat subject                          | [10018760](../mothra/evidence/hotline-server-1.9/queries/D-10018760.c) | 114, 115                                                       | Push                    |
| 121     | Accept agreement                          | [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c) | 102/104/113/215 through helper                                 | ACK                     |
| 200     | List files                                | [100100a0](../mothra/evidence/hotline-server-1.9/queries/D-100100a0.c) | 202                                                            | ACK                     |
| 202     | Download file                             | [100121a0](../mothra/evidence/hotline-server-1.9/queries/D-100121a0.c) | 201, 202, 203, 204                                             | ACK                     |
| 203     | Upload file                               | [100130f0](../mothra/evidence/hotline-server-1.9/queries/D-100130f0.c) | 108, 201, 202, 204                                             | ACK                     |
| 204     | Delete file/folder                        | [100140e0](../mothra/evidence/hotline-server-1.9/queries/D-100140e0.c) | 201, 202                                                       | ACK                     |
| 205     | Create folder                             | [100143f0](../mothra/evidence/hotline-server-1.9/queries/D-100143f0.c) | 201, 202                                                       | ACK                     |
| 206     | Get file info                             | [10016ba0](../mothra/evidence/hotline-server-1.9/queries/D-10016ba0.c) | 201, 202                                                       | ACK                     |
| 207     | Set file info                             | [100170c0](../mothra/evidence/hotline-server-1.9/queries/D-100170c0.c) | 201, 202, 210, 211                                             | ACK                     |
| 208     | Move file/folder                          | [100177d0](../mothra/evidence/hotline-server-1.9/queries/D-100177d0.c) | 201, 202, 212                                                  | ACK                     |
| 209     | Make alias                                | [10017c10](../mothra/evidence/hotline-server-1.9/queries/D-10017c10.c) | 201, 202, 212                                                  | ACK                     |
| 210     | Download folder                           | [10012850](../mothra/evidence/hotline-server-1.9/queries/D-10012850.c) | 201, 202, 203, 204                                             | ACK                     |
| 212     | Download banner                           | [10012f40](../mothra/evidence/hotline-server-1.9/queries/D-10012f40.c) | None identified directly                                       | ACK                     |
| 213     | Upload folder                             | [10013930](../mothra/evidence/hotline-server-1.9/queries/D-10013930.c) | 108, 201, 202, 204, 220                                        | ACK                     |
| 214     | Reference cleanup (cancellation inferred) | [10013040](../mothra/evidence/hotline-server-1.9/queries/D-10013040.c) | 107                                                            | ACK                     |
| 300     | Get user roster                           | [10011870](../mothra/evidence/hotline-server-1.9/queries/D-10011870.c) | None identified directly                                       | ACK                     |
| 303     | Get client diagnostic info                | [10016150](../mothra/evidence/hotline-server-1.9/queries/D-10016150.c) | 103                                                            | ACK                     |
| 304     | Set client info                           | [10016ad0](../mothra/evidence/hotline-server-1.9/queries/D-10016ad0.c) | 102/104/113/215 through helper                                 | Push                    |
| 348     | Enumerate accounts                        | [10015160](../mothra/evidence/hotline-server-1.9/queries/D-10015160.c) | None identified directly                                       | ACK                     |
| 349     | Batch account mutations                   | [10015500](../mothra/evidence/hotline-server-1.9/queries/D-10015500.c) | Ordered outer values containing nested 101/102/105/106/110/111 | ACK/error; possible 104 |
| 350     | Create account                            | [100146f0](../mothra/evidence/hotline-server-1.9/queries/D-100146f0.c) | 102, 105, 106, 110, 111                                        | ACK                     |
| 351     | Delete account                            | [100149e0](../mothra/evidence/hotline-server-1.9/queries/D-100149e0.c) | 105                                                            | ACK                     |
| 352     | Get account                               | [10014bc0](../mothra/evidence/hotline-server-1.9/queries/D-10014bc0.c) | 105                                                            | ACK                     |
| 353     | Update account                            | [10014df0](../mothra/evidence/hotline-server-1.9/queries/D-10014df0.c) | 102, 105, 106, 110, 111                                        | ACK                     |
| 355     | Broadcast                                 | [1000f990](../mothra/evidence/hotline-server-1.9/queries/D-1000f990.c) | 101                                                            | ACK                     |
| 370     | List news categories                      | [100102c0](../mothra/evidence/hotline-server-1.9/queries/D-100102c0.c) | 325                                                            | ACK                     |
| 371     | List news articles                        | [10011370](../mothra/evidence/hotline-server-1.9/queries/D-10011370.c) | 325                                                            | ACK                     |
| 380     | Delete news item                          | [10010b70](../mothra/evidence/hotline-server-1.9/queries/D-10010b70.c) | 325                                                            | ACK                     |
| 381     | Create news folder                        | [10010ee0](../mothra/evidence/hotline-server-1.9/queries/D-10010ee0.c) | 201, 325                                                       | ACK                     |
| 382     | Create news category                      | [10011110](../mothra/evidence/hotline-server-1.9/queries/D-10011110.c) | 322, 325                                                       | ACK                     |
| 400     | Read news article                         | [10011580](../mothra/evidence/hotline-server-1.9/queries/D-10011580.c) | 325, 326, 327                                                  | ACK                     |
| 410     | Post news article                         | [10010470](../mothra/evidence/hotline-server-1.9/queries/D-10010470.c) | 325, 326, 327, 328, 333, 334                                   | ACK                     |
| 411     | Delete news article                       | [100108a0](../mothra/evidence/hotline-server-1.9/queries/D-100108a0.c) | 325, 326, 337                                                  | ACK                     |
| 500     | Undocumented empty ACK operation          | [10018c00](../mothra/evidence/hotline-server-1.9/queries/D-10018c00.c) | None identified directly                                       | ACK                     |

## Per-operation reply and fan-out map

Every request below is client-to-server; ACK/error and numbered notifications
are server-to-client. Session eligibility is the state table above. **E** means
an explicit status-1 direct-error branch or call to formatted-error helper
`1000ef30` appears in the retained handler. A dash means no such direct branch
was identified there; thrown exceptions still require GAP-003's translation
work. These labels are not a claim that every failure has a numbered reply.

| Request | Direct normal reply                         | E   | Subsequent or associated native effects                                                                                                                  |
| ------: | ------------------------------------------- | :-: | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 101     | Board-data ACK                              | E   | Retrieval only; no board update push.                                                                                                                    |
| 103     | Empty ACK after board write                 | E   | Conditional 102 to eligible readers after repeated-hash check.                                                                                           |
| 105     | None                                        | —   | Formatted 106 to eligible main/room recipients; denied chat can produce data/option 104 to sender.                                                       |
| 107     | Login fields ACK                            | E   | Early path: identity/301 then online/354 then 109; delayed path sends 109 and waits for 121.                                                             |
| 108     | Empty ACK before routing                    | E   | Conditional 104 original/refusal/automatic response according to routing table; ACK is not delivery.                                                     |
| 110     | Empty ACK, including missing target         | E   | Conditional target 104, close request, later room 118/general 302 teardown. No mandatory 111.                                                            |
| 112     | Room/creator ACK                            | E   | Creator added and eligible 113 invitations sent before ACK; refusal/automatic feedback can use 104.                                                      |
| 113     | None                                        | —   | Eligible target 113 and conditional 104 feedback; no atomic admission.                                                                                   |
| 114     | None                                        | —   | Rejection text routed as room 106.                                                                                                                       |
| 115     | Subject/roster ACK                          | E   | Newly joining: 117 before membership insertion; ACK roster includes joiner. Repeated join omits duplicate insertion/push.                                |
| 116     | None                                        | —   | 118 to remaining members or empty-room deletion.                                                                                                         |
| 120     | None                                        | —   | Subject update and 119 to ready members; empty subject field can be omitted.                                                                             |
| 121     | Empty ACK before settings                   | —   | Settings/301, online/354, then eligible 122. Online replay takes dispatcher error path instead.                                                          |
| 200     | Repeated file-list 200 ACK                  | E   | Snapshot builder; no completion push.                                                                                                                    |
| 202     | Size/reference/queue ACK                    | E   | Entry created before ACK; later data stream and possible 211. Empty raw preview can ACK size zero without a reference.                                   |
| 203     | Upload-reference/resume ACK                 | E   | Entry created before ACK; later HTXF/FILP worker completion/close, not a second numbered completion ACK.                                                 |
| 204     | Empty ACK after Trash move                  | E   | No automatic file-list refresh at normal success site.                                                                                                   |
| 205     | Empty ACK after directory create            | E   | Activity log follows success reply.                                                                                                                      |
| 206     | File-info ACK                               | E   | Target-kind metadata matrix; no update push.                                                                                                             |
| 207     | Empty ACK after requested effects           | E   | Comment may change before rename later fails; no rollback implied.                                                                                       |
| 208     | Empty ACK after move                        | E   | Activity log follows success reply.                                                                                                                      |
| 209     | Empty ACK after alias create                | E   | Activity log follows success reply.                                                                                                                      |
| 210     | Folder reference/size/item-count ACK        | E   | Later bidirectional folder stream and possible 211; empty traversal may produce no live entry.                                                           |
| 212     | Banner reference/size ACK                   | —   | Later raw current-banner bytes; not a metadata-122 request.                                                                                              |
| 213     | Folder-upload reference ACK                 | E   | Later per-item controls/streams; completion closes data transport without final numbered ACK.                                                            |
| 214     | Empty ACK even on lookup miss               | —   | Owner-matched download cleanup; no proof of cancellation delivery from ACK alone.                                                                        |
| 300     | Repeated packed-user 300 ACK                | —   | Snapshot only; later changes use 301/302.                                                                                                                |
| 303     | Name/diagnostic-text ACK                    | E   | Generated diagnostics; no state-change push.                                                                                                             |
| 304     | None                                        | —   | Apply settings then 301 fan-out; spam paths can interrupt.                                                                                               |
| 348     | Nested repeated-account ACK                 | E   | Enumeration, with password-presence placeholders.                                                                                                        |
| 349     | Empty final ACK on ordinary loop completion | E   | Sequential writes/deletes; collision can use 104 and continue; live edits/deletes use 354/301 or 104/close. Earlier mutations can precede a final error. |
| 350     | Empty ACK after create                      | E   | Account activity/log callbacks after ACK.                                                                                                                |
| 351     | Empty ACK after account Trash move          | E   | Matching sessions get 104 and disconnect request after ACK, followed later by teardown.                                                                  |
| 352     | Single-account fields ACK                   | E   | Password-presence placeholder, not actual password.                                                                                                      |
| 353     | Empty ACK after write                       | E   | Matching live sessions can get 354 and roster propagation after ACK.                                                                                     |
| 355     | Empty ACK before recipient loop             | E   | 355 to eligible ready/online recipients, distinct from console data-only 104.                                                                            |
| 370     | Repeated category 320/323 ACK               | E   | Version-selective builder; no list-change push at success site.                                                                                          |
| 371     | One serialized list-321 ACK                 | E   | Cached or rebuilt list; no subscription established.                                                                                                     |
| 380     | Empty ACK after Trash move                  | E   | No structure-refresh push at success site.                                                                                                               |
| 381     | Empty ACK after directory create            | E   | Activity log follows success reply.                                                                                                                      |
| 382     | Empty ACK after HLNZ create/write           | E   | Activity log follows success reply; failed write may follow file creation.                                                                               |
| 400     | Article/body/navigation ACK                 | E   | Requested flavour lookup; no read receipt.                                                                                                               |
| 410     | Empty ACK after create/body write           | E   | No returned new ID or article push at success site; metadata creation precedes body validation.                                                          |
| 411     | Empty ACK after graph/index rewrite         | E   | No article-list refresh push at success site.                                                                                                            |
| 500     | Empty ACK                                   | —   | Processed request refreshes activity; one modern client’s optional schedule is scoped in the [request-500 contract](request-500-contract.md).            |

This completes GAP-006's operation/direction/state and reply/effect catalogue.
All rows link to entry captures through the request catalogue. Associated
notifications are conditional; silence is not success, and ACK does not certify
transport delivery, durability, idempotency or all-or-nothing mutation.
Internal exception translation remains GAP-003; request-specific runtime
ordering, partial failure and conformance fixtures retain their existing gap
IDs.

## Server notification catalogue

| Type | Producer / role                                             | Known value fields                   | Remaining contract                                                                                                        |
| ---: | ----------------------------------------------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| 102  | Old-board post                                              | 101                                  | GAP-046: serialization and recipient/order rules                                                                          |
| 104  | Routed PM, refusal/automatic response, denial, kick notices | Variant-specific 101/102/103/113/214 | GAP-043/044: variant discriminator and routing table                                                                      |
| 106  | Chat fan-out                                                | 101; room path also 114              | GAP-042: formatted text rules                                                                                             |
| 109  | Login agreement                                             | 101 or no-agreement flag 154         | GAP-027: complete condition matrix                                                                                        |
| 113  | Chat invitation                                             | 114, inviter 103/102                 | GAP-039: lifecycle and partial failures                                                                                   |
| 117  | Room member joins                                           | 114, 103, 104, 112, 102              | GAP-040: races and recipient order                                                                                        |
| 118  | Room member leaves                                          | 114, 103                             | GAP-036/040: disconnect cleanup                                                                                           |
| 119  | Subject update                                              | 114, 115                             | GAP-041: input and permission cases                                                                                       |
| 122  | Configured banner metadata                                  | Four-byte 152; conditional 153       | GAP-028/063: metadata lifetime and stream                                                                                 |
| 301  | Presence update                                             | 103, 104, 112, 102                   | GAP-034/035: status and event ordering                                                                                    |
| 354  | Login completion or changed live account privileges         | Eight-byte 110                       | GAP-073: delivered sequence and persistence                                                                               |
| 355  | Client-originated broadcast fan-out                         | 103, 102, 101                        | GAP-076: console-originated path                                                                                          |
| 211  | Download queue advancement or changed position              | Four-byte 107, numeric 116           | [Transfer contracts](transfer-contracts.md#queue-notification-211); GAP-061 runtime queue behaviour                       |
| 111  | Native shutdown dialog with nonempty text                   | 101                                  | [Presence contracts](presence-messaging-contracts.md#kick-options-and-native-console-messages); GAP-075 shutdown fixtures |
| 302  | Session teardown after room-leave calls                     | Numeric 103                          | [Presence contracts](presence-messaging-contracts.md#disconnect-teardown-and-notification-302); GAP-036 runtime ordering  |

Error-text field 100 is not a proven notification type 100. A notification
usually uses a newly generated server ID, while a direct reply copies its
request's ID. Do not match notifications as completion of an unrelated request
merely because a numeric identifier collides.

## Field and aggregate byte limits (GAP-019)

This is a **contextual limit inventory** for the 1.9 native server. All sizes
below count raw bytes unless a row names another unit. A handler's copy bound,
the native filesystem's returned value, and the outer TLV ceiling are separate
limits. “Source” identifies a retained handler/helper comparison; “native”
identifies a controlled packet or stored-fork outcome. A source-only maximum
does not assert a network result at maximum plus one. No row sets mxd policy:
its distinct framing/memory limits are in
[mxd limit contracts](mxd-limit-contracts.md).

| Operation and field                                                 | Native limit and unit                                                                                                                | Boundary evidence and confidence                                                                                                                                                                                                                                                                                                                                 |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| All outer TLVs                                                      | 65,535 value bytes per BE16 length; no global semantic character count                                                               | Wire layout, not a promise a handler accepts that much. [Parser and scalar captures](native-wire-details.md#parameter-parsing-and-scalar-access).                                                                                                                                                                                                                |
| 107 input 105 login; 106 password                                   | 32 copied bytes each; login lookup then uses the native filename backend                                                             | Source; 31-byte owned account succeeds, 32-byte create/read/login reports `badfilename`, and over-32 login names clip to 32. This does not establish a valid 32-byte account. [Identity captures](native-wire-details.md#account-lookup-name-encodings).                                                                                                         |
| 350/351/352/353 input 105 account key                               | Tested native filesystem key accepts 31 bytes and rejects 32; request encodings differ                                               | Native create, 352 readback and 107 login establish the 31/32 outcome. The 352 input is uncomplemented, whereas 350/351/353 complement theirs before lookup; a shared wire transform would be wrong. [Account lookup captures](native-wire-details.md#account-lookup-name-encodings).                                                                            |
| 107 input 102 display name                                          | 32 copied bytes; later session effective name uses 31                                                                                | Source and native 65,535-byte settings input clipped to 31; keep the login copy and session assignment distinct. [Login/settings](core-field-schemas.md#login-and-settings-requests).                                                                                                                                                                            |
| 121/304 input 102, 215                                              | 31 requested-name bytes; 127 automatic-response content bytes                                                                        | Source and framing native name clip; 215 is conditional on automatic response. [Settings schema](core-field-schemas.md#login-and-settings-requests). Exact 127/128 native output is still unmeasured.                                                                                                                                                            |
| 350/353 fields 102, 111, 105, 106                                   | Account record copies 64, 64, 32, 32 bytes respectively                                                                              | Source; native 65-byte 111 stores first 64; 32-byte 106 replacement/login succeeds; preserve-sentinel branch clips old password to 31. [Account update corpus](native-wire-details.md#captured-account-replacement-and-password-boundaries).                                                                                                                     |
| 349 outer value                                                     | At most 512 copied bytes **per nested record**, not whole request                                                                    | Source; native 513-byte outer entry retains its complete prefix, with unavailable identity beyond an incomplete field. [Batch rules](operation-contracts.md#administrative-account-list-and-batch-mutation). Aggregate number/bytes of records is not established by this copy cap.                                                                              |
| 105 field 101                                                       | Chat text copied toward an 8,192-byte formatted output buffer; CR expansion and sender prefix consume capacity                       | Source plus native formatting controls, not a universal 8,192-byte accepted input. [Chat contract](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes). Exact output-cap-plus-one outcome remains unmeasured.                                                                                                                     |
| 108 field 101; optional quoted 214                                  | Main PM text 4,096-byte cap; quote has separate bounded copy path                                                                    | Source. Quote maximum and its max-plus-one behaviour are still open. [PM contract](presence-messaging-contracts.md#private-message-routing).                                                                                                                                                                                                                     |
| 115/120 field 115 subject                                           | 255 stored/output bytes                                                                                                              | Native 255, 256 and 65,535 inputs produce 255 bytes, including repeated-join readback. [Room corpus](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes).                                                                                                                                                                         |
| 205 field 201 folder name                                           | 255-byte Pascal input staging, then tested pre-OS-X path normalization clips to 31 name bytes                                        | Native 32/255/256/65,535 input and `.txt` example; the alternate platform branch remains unexecuted. [Folder matrix](filesystem-and-board-contracts.md#captured-native-folder-creation-and-field-202-paths).                                                                                                                                                     |
| 207 field 210 comment and 211 rename                                | Each staged in a 256-byte Pascal destination (up to 255 content bytes); lower comment setter passes at most 200                      | Native 198/199 read back exactly and 200 through 65,535 read back 199 for file and folder. This is observed readback, not a portable capacity. [Comment matrix](filesystem-and-board-contracts.md#captured-rename-and-comment-mutation-matrix). Rename max-plus-one is unmeasured.                                                                               |
| 103 field 101 board post                                            | 8,192 post bytes, separate from formatted segment and stored aggregate                                                               | Native 8,191/8,192 accepted, 8,193 status 1 with no 102/storage change. [Board captures](filesystem-and-board-contracts.md#captured-legacy-board-boundaries-and-updates).                                                                                                                                                                                        |
| 101 board reply / board file                                        | Reply is newest 65,535-byte prefix; stored DATA may exceed it                                                                        | Native exact 65,535 aggregate and 65,629 stored bytes after one more post, with reply clipped to 65,535. [Board captures](filesystem-and-board-contracts.md#captured-legacy-board-boundaries-and-updates).                                                                                                                                                       |
| 410 field 328 title; 333 body                                       | Title 31 stored content bytes on tested native path; body 65,535-byte stored flavour                                                 | Native 64-byte title clips to 31; body 65,535 round-trips. Serializer has separate 63-byte title/31-byte poster/63-byte flavour caps. [News captures](news-contracts.md#captured-category-versions-and-header-metadata). Body 65,536 outcome is not captured here.                                                                                               |
| Configured agreement/banner 109/212                                 | Loader: `TEXT` 65,535 source bytes; other types 262,140. A non-TEXT loaded value above BE16 TLV capacity fails the writer before 109 | Native TEXT 65,535 emits complete 101; TEXT 65,536 and non-TEXT 262,141 omit it after loader warning; non-TEXT 65,536 triggers writer failure. [Content captures](presence-messaging-contracts.md#content-byte-limits-and-reload-effects).                                                                                                                       |
| 107 ACK field 162 server name                                       | Native configuration stores at most 31 bytes; empty omits field                                                                      | Native 31-byte exact and 32-byte typing attempt clipped to first 31. This is a GUI/Pprefs destination limit, not account-name policy. [Login extras](native-wire-details.md#captured-login-extras-configuration-bytes-and-refresh).                                                                                                                              |
| 355 field 101 broadcast text                                        | At most 4,096 copied input bytes                                                                                                     | Handler `1000f990` passes `0x1000` to its field copier, then forwards that copied length. This is **source only**; 4,096/4,097 native delivery is untested. [Handler](../mothra/evidence/hotline-server-1.9/queries/D-1000f990.c). Console-originated 104 has a different source path.                                                                           |
| 303 reply field 101 generated diagnostic                            | Final formatter cap 1,024 output bytes, with no reserved/appended NUL; length is returned as TLV length                              | [Formatter trace](diagnostic-formatting-trace.md) and [native examples](diagnostic-replies.md#contract-boundary) reach 995 bytes. The 1,024/1,025 formatted-output case is **not** a native observation; GAP-037's descriptive-text decision does not establish it. The [exact boundary proposal](native-diagnostic-boundary-preparation.md) remains unexecuted. |
| 110 option-2 field 101 reason                                       | At most 63 request payload bytes staged; constructed/stored reason length at most 63                                                 | [Instruction trace](native-ban-file-format.md#request-110-reason-copy-path) predicts a length-prefix copy for nonempty reason, but all retained stored ban reasons are empty. No nonempty 63/64 native write is claimed.                                                                                                                                         |
| 202 field 203 resume descriptor                                     | At most 512 copied bytes; helper requires a 42-byte RFLT minimum                                                                     | [Transfer trace](transfer-contracts.md#resume-data-rflt) establishes source copy and format; it does not make 512/513 bytes a successful transfer or validate arbitrary larger descriptors.                                                                                                                                                                      |
| 208/209 field 212 Files destination; 370 field 325 News path        | 2,048 copied path bytes per handler                                                                                                  | Both 2,048 and 2,049 submitted values with a valid prefix plus padding select the same owned destination; parsing of byte 2,049 is unproved. [Structured-path captures](native-wire-details.md#field-212-files-destinations). Path component and depth limits are separate.                                                                                      |
| 410 field 325 path; 326 parent ID; 327 flavour; 328 title; 333 body | 2,048 copied path bytes; separate stored title/flavour/body and list serialization bounds                                            | Handler `10010470` uses `0x800` for 325. [News schema](news-contracts.md#posting-partial-effects-and-deletion) distinguishes a 31-byte created title from a 63-byte serialized title, and a 65,535-byte body round trip. A single generic “news string” cap would be false.                                                                                      |
| 300/301/303 user-name outputs; 348/352 account-name outputs         | Session effective name is a separate 31-byte destination; account record 102 is a separate 64-byte destination                       | [Session-name assignment](core-field-schemas.md#login-and-settings-requests) and [account record](native-wire-details.md#account-record-and-field-schema). A returned roster/diagnostic or account-list name inherits the relevant stored source; its outer TLV width does not widen that source.                                                                |
| 200/206 file names and 370/371/400 news names                       | Native filesystem/catalogue name and serializer capacities differ by operation                                                       | [File path/list grammar](native-wire-details.md#structured-file-paths-and-file-list-entries) and [news list](news-contracts.md#article-list-field-321) give the observed layout. There is no source-backed universal 31-byte bound for all output names or all platforms.                                                                                        |

### Remaining boundary cells and aggregate scope

The [45-handler catalogue](#request-catalogue) bounds the operation inventory,
but not every field has an independently proven value limit. The narrow cells
below are the outstanding ones for the original name/password/message/subject/
comment/body question. A bounded native fixture must preserve the exact request
bytes, reply/status, subsequent output and any stored value; a static copy
constant alone is marked as such above.

| Context                              | Exact unresolved boundary or aggregate question                                                                                                                                     | Smallest next evidence using existing tooling                                                                                                                                                                                                                                            |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 303 generated 101                    | Source final 1,024 bytes; native positive 995 only. Does the formatted 1,024/1,025 case clip, reject or lose a field?                                                               | Reuse the existing diagnostic transfer/density fixture with one owned additional long-name/queue state, capture the exact formatter input/output and retained cleanup. No general presentation-parity promise follows.                                                                   |
| 110 option-2 reason 101              | Source stages at most 63 and predicts prefix-copy; no nonempty persisted reason at 63/64.                                                                                           | One isolated owned zero-ACL target, exact option-2 63/64 inputs, native Banned record bytes and postflight; the existing ban fixture tools and [reason trace](native-ban-file-format.md#request-110-reason-copy-path) provide the shape. Never use the original administrator as victim. |
| 105/108/355 text and 108 quote 214   | 8,192 formatted chat output, 4,096 PM/broadcast copies, quoted value's separate bound; native exact cap-plus-one delivery/storage not shown.                                        | Three isolated owned senders/recipients with existing chat/PM/broadcast plans, one at-cap and one plus-one raw value per operation; inspect source quote copier before choosing its numeric bound. No broad spam/flood inference.                                                        |
| 207 rename 211 and 381/382/410 names | Native comment readback is bounded, but these other names have separate 31/63/255 paths and no complete max-plus-one matrix.                                                        | Use the existing owned file/news fixture builders for 31/32 and 255/256 byte names, with before/after list and stored-fork checks; keep the Mac filesystem branch explicit.                                                                                                              |
| Aggregate request/reassembly         | BE16 TLV values, per-record 349 copy512 and native per-frame startup comparator512 KiB are not a cross-field/fragment allocation cap.                                               | A bounded multi-field/fragment plan with current `protocol_capture.py` and host/guest parity, including equality and one-over each declared size; report close versus ACK, not an inferred heap ceiling. GAP-011/012 retain the broader receiver question.                               |
| Stored/list aggregates               | Board store may exceed its65,535-byte reply prefix; news list321 stores unsigned 65,535 flavour length; transfer advertised size/reference/queue bounds depend on their own fields. | Keep the existing board and news at-cap-plus-one witnesses as separate aggregates. Any additional transfer-size claim needs a transfer-specific native fixture, not reuse of the TLV cap.                                                                                                |

The table is a finite status map, not a claim that all unlisted fields are
unlimited. No complete GAP-019 certificate follows while the named source-only
and native-unmeasured cells above remain. mxd currently has its own 32-KiB
physical-frame and 1-MiB logical-total checks and explicit memory budgets;
those are [implementation policy](mxd-limit-contracts.md), not the native field
limits in this registry.

A 65,536-byte **single** TLV value is not representable with BE16 length; it
cannot be used as a well-formed max-plus-one field fixture. Where a smaller
semantic cap is 65,535, the meaningful next question is whether a larger
aggregate or malformed declared length is accepted, rejected or closed, with
that different input class stated explicitly.

## Frame acceptance and reassembly boundaries

The frame receiver `100590e0` rejects either size word equal to zero or greater
than the current global `10094a50`. Equality with that limit passes these
comparisons. The retained data-image value is 2 MiB, but
[startup assigns 512 KiB](session-transport-contracts.md#receive-limit-assignment-at-startup);
Later configuration and boundary fixtures remain GAP-011. These are per-frame
word checks, not a bound on the sum of accumulated or interleaved fragments.

The receiver uses the is-reply byte as a zero/nonzero discriminator. The traced
path does not validate the flags byte against a whitelist. Requests are grouped
by ID; incoming replies are matched to an existing reply-waiting record, with
an unmatched complete reply discarded by this path. Existing records have
stored type and total overwritten by later frames. Completion uses accumulated
length **at least** total, so overshoot is not rejected by that comparison. No
type/total consistency, aggregate-memory or fragment-expiry guarantee should be
inferred. GAP-012/013 retain boundary packets and transport outcomes.

The server ID generator `10058d70` increments a connection object's 32-bit
counter and replaces wrapped zero with 1. It performs no outstanding-ID scan in
that helper. Client zero-ID rejection, reuse and late replies remain GAP-004.
Do not substitute this counter for independent room/user/article/ref lifetimes.

## Administrative account list and batch mutation

Request **348**, handler `10015160`, enumerates accounts when the requester's
account-view privilege check succeeds. Its reply repeats outer field **101**;
each value is itself a count-prefixed TLV stream with 102 (name), 105
(complemented login), 106 (literal `x` if a password exists, otherwise
omitted), and eight-byte 110. It does not expose the real encoded password. No
input fields are read directly by this handler. The
[native core fixtures][native-core] include a successful two-account response
and a status-1 permission denial from a zero-privilege account. The executable
verifier checks the nested grammar, password placeholders, account membership
and denied reply. This satisfies GAP-077's unchanged
semantics/grammar/representative-fixture criterion; it does not identify a
historical client brand or establish snapshot atomicity.

Request **349**, handler `10015500`, iterates outer fields in wire order and
interprets each value as an account TLV stream. It does not filter outer IDs in
this loop. Indexed copying caps each nested value at **512 bytes**. Inside, 101
is the complemented old account name (up to 31 bytes), while
102/111/105/106/110 build the new record as described in
[native wire details](native-wire-details.md). Empty new display/login with an
old name selects deletion; otherwise the path can rename, create or update. The
existing-password NUL sentinel requires a nonempty old name in this path.

Processing is **sequential and not atomic**: earlier records can be written or
deleted before a later permission/error branch returns. Some malformed records
set a flag and processing continues, followed by an error reply after the loop.
An existing-account collision on the no-old-name path sends a type-104 notice
and continues, so a final empty ACK does not certify that every requested
mutation happened. Retries require checking actual account state; no rollback
or idempotency guarantee is established. The captured matrix below supplies
framing, role/default and mixed-outcome fixtures, including a rename collision
that changes the destination record and continues before returning an error.

## Captured batch account framing and partial effects

The [batch-account corpus][batch-accounts] retains 70 completed reports and 75
paired host/guest connections. Eighteen primary batches and a separate
distinct-password collision are surrounded by administrator reads and complete
enumerations. Four owned actors have only create bit 14, delete bit 15, update
bit 17 or no account-mutation rights. Twelve identity-checked queries include
the complete 555-instruction handler assembly and the rename/copy helpers.

The outer request is the ordinary count-prefixed TLV stream. **Each outer
value** is another count-prefixed account TLV stream; outer field IDs do not
select the operation. One batch uses IDs `0,65000,0`: it creates A, renames A
to B and updates B. Only B remains, with the last name and preserved password.
This captures position-based processing, including repeated and unknown IDs.

| Nested field | Input rule in this handler                                                                              |
| -----------: | ------------------------------------------------------------------------------------------------------- |
| 101          | Complemented old login, copied up to 31 bytes; absent/empty means no old account                        |
| 102          | New display-name bytes, copied up to 64 bytes                                                           |
| 105          | Complemented new login, copied up to 32 bytes; presence also distinguishes update from deletion         |
| 106          | Encoded password, copied up to 32 bytes; one NUL preserves up to 31 old bytes only when 101 is nonempty |
| 110          | Eight-byte access bitmap copied into the cleared replacement record                                     |
| 111          | Opaque attribute, copied up to 64 bytes; human meaning remains unresolved                               |

Every nested value is copied through a **512-byte** buffer. The recorded
512-byte value and a 513-byte value with known fields first both create their
accounts. In the latter, the final unknown field is truncated and ignored. A
separate value puts a 507-byte unknown field first: that record alone needs 513
bytes including count/header, so the copied prefix has no complete field. Its
later identity is not found, its account is not created, a following valid
record is processed, and the batch ends with an error. This is a per-entry copy
boundary, not a 512-byte maximum for the entire request.

| Gate / branch                             | Observed outcome                                                                                       |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| None of bits 14/15/17                     | Initial status 1: `You are not allowed to modify account information.`                                 |
| Create-only actor: create, update, create | First create persists; update returns that modify error; last create is skipped                        |
| Delete-only actor: delete, create, delete | First account moves to Trash; `You are not allowed to create new accounts.`; last account survives     |
| Update-only actor: update, delete, update | First replacement persists; `You are not allowed to delete accounts.`; last replacement is skipped     |
| Create-only actor grants download bit 2   | `Cannot create account with more access than yourself.`; neither that nor the later account is created |
| Create-only actor grants bit 27           | Creation succeeds and stored/retrieved bitmap retains `0000001000000000`                               |

Admission through one account-mutation bit does not grant every item operation.
The create subset comparison exempts bit 27; the native fixture confirms that
exception without turning it into a general grant rule for other bits.

With no old name, an existing-account collision sends type 104 with text in 101
and marker 109=`0001`, then continues to a later successful creation and an
**empty final success ACK**. The existing target stays unchanged. The text is:

```text
Cannot create account “m-b28-collision” because there is already an
account with that login.
```

The example wraps the single captured line for readability. The raw message
uses Mac bytes `d2/d3` for those quotes; retain the captured bytes rather than
UTF-8-encoding this rendered example for an exact comparison. This 104 schema
differs from the data-only account-deletion notice.

An empty outer value, a complete empty nested TLV stream, and a record whose
identity falls beyond the copied prefix each permit a following valid creation
but produce final status 1, field 100 `Error saving list of accounts.` An empty
batch produces that same error. Permission failures above instead return
immediately and skip the remaining records. The final text does not identify an
item number or certify that no earlier/later effects occurred.

Normal rename preserves the source directory and UserData catalogue identities
under the destination path and writes the new record with its preserved
password. A replacement with old and new login but omitted display name,
attribute and bitmap clears those values while the NUL sentinel retains the
password. Without an old login, a new account with encoded NUL password stores
one `00` byte; plaintext `ff` login succeeds. Do not apply 353's unconditional
NUL-preservation branch to a new 349 account.

### Rename collision does not preserve the destination account

The two rename-collision batches return status 1 and the coarse saving-list
error, but leave both source and destination directories present, **replace the
destination UserData**, and process the following creation. Native helper
`1002bc30` calls `FSpRename` and maps a nonzero result through the exception
wrapper. The retained assembly and native outcomes prevent treating the
decompiled success path as a complete exception/rollback contract.

The second case begins with different source and destination passwords. After
the failed rename, the source still accepts its original password; the
destination now accepts that source password and rejects its own previous
password. Full native records retain the destination's new display/login,
source password and submitted replacement fields. Both original catalogue
identities remain unchanged. The following creation also exists despite the
error. A client must inspect resulting state before retrying this operation;
neither error nor success ACK means all-or-nothing application.

The final state contains 29 owned accounts. Complete native records, metadata
and rename identities are checked across seed, main-final, distinct-seed and
distinct-final snapshots. Cleanup restores the original two-account enumeration
and exact 41-entry Files baseline. All 64 original objects, including a prior
deletion, four flush helpers and their forks, are positively identified in
Trash. A separate publisher corroborates them and is removed with wire
controls. No restart/power-loss or arbitrary write-failure guarantee is
inferred. This closes GAP-078's original batch framing/permission/default/
partial-error/mixed-fixture criterion; protected/self-delete remains GAP-072,
attribute meaning remains GAP-071, and general exception translation remains
GAP-003.

[batch-accounts]: ../mothra/evidence/gap-remediation/2026-11-13/native-account-batch-01/manifest.json

[map]: ../mothra/evidence/hotline-server-1.9/dispatcher-map.json
[queries]: ../mothra/evidence/hotline-server-1.9/queries/
[unknown]: ../mothra/evidence/gap-remediation/2026-11-12/batch-03/queries/B03-D-10014640.c

[native-core]: ../mothra/evidence/gap-remediation/2026-11-12/native-core-01/manifest.json

## Account deletion and allocated Trash records

The [later ban fixture](native-ban-expiry-later-witness.md) removed its two
owned accounts with 351. Both 352 lookups then reported missing, and 348
returned the original two accounts. The original account/Prefs data forks
matched preflight after the native app quit and the emulator was terminated.

Read-only TSK `fls -u` and `istat` found the owned folders and 734-byte
UserData files still **allocated in Trash**. They were not unallocated
recovered records. This corroborates the traced account Trash move; active
account removal does not imply physical erasure. The fixture did not empty
Trash or restart this post-deletion image. Other owned-account persistence
examples remain separately scoped. This does not establish single-operation
write failure atomicity for 350 or 353 (GAP-072/021).
