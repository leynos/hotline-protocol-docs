# Hotline 1.9 baseline validity ledger

Captured on 12 November 2026 from the Mac PowerPC `HLserver19` program open in
Ghidra. This is the first static validation baseline for updating the protocol
documents used by mxd. The intended specification is **Hotline 1.9**, as
confirmed by the document owner; the supplied guide's 1.8.5 title is stale.

The input documents have **not** been edited. This ledger identifies corrections,
supported claims, and unresolved questions before those edits are made.

The first pass records **83 ledger entries**: 16 supported, 26 contradicted,
18 partial, 15 unverified, and 8 document defects. These are grouped claims,
not a count of every assertion in the input prose. The evidence contains
154 captured MCP queries and all 45 identified request handlers in the
dispatcher. A [machine-readable claim index][claim-index] accompanies this file.

## Provenance and authority

| Item | Recorded identity |
| --- | --- |
| Primary oracle | User-supplied Mac PPC server data fork, `HLserver19` |
| SHA-256 | `ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b` |
| Preserved binary | [HLserver19.pef][binary] |
| Ghidra program | `/HLserver19`, `PowerPC:BE:32:default`, PEF, 32-bit pointers |
| Analysis inventory | 1,840 functions; 392 imports; 238 defined strings |
| Loaded addresses | Code `10000000..10088717`; data/imports through `1009734f` |
| Toolchain | Ghidra 12.2 PUBLIC; Temurin JDK 25.0.5+8 |
| GhidraMCP checkout | `1e980252087b2479a21b9ca6d82d5829538651a7`, clean |
| Protocol-docs Git HEAD | `6ebdec87c04abee9b822b22b169898404dab969b` |
| Input worktree caveat | `internal-compatibility-matrix.md` was untracked |
| Source comparison | Supplied `../synhxd/server/` RCS archives; not a Git checkout |
| Full provenance | [Manifest][manifest], including input, lockfile, and extension hashes |

The binary name and the successful-login constant `160 = 190` support its
identification as the requested 1.9 oracle. No independent vendor signature or
release archive authenticity claim is made. The hash covers the PEF data fork,
not a complete Mac distribution or its resource fork.

Document references below use the frozen snapshots:

- **P** = [protocol.md input][protocol], SHA-256
  `7a5a4dd969f0c0d98e8021eec664275203b8edb19a2aa18160732862391114b2`.
- **M** = [compatibility-matrix input][matrix], SHA-256
  `12041e2cf2d84d8cac709476fd670e8c80942d5c9806909733d555f19c8526aa`.
- Line numbers refer to these snapshots, not to future edited versions.

The 1.9 binary is authoritative for behaviour of this build. SynHX source is
independent comparison evidence, not evidence of what this binary does. Neither
can establish the state of mxd's implementation, tests, proofs, or release gates.

### Evidence method and limits

All Ghidra access was read-only through MCP: program metadata, lists, memory,
callers, disassembly, and decompilation. No names, comments, types, or code were
changed in the Ghidra program. No Hotline network session was executed.

Each [query record][queries] contains its UTC capture time, exact tool name and
arguments, loaded program identity/hash, and complete MCP result. `D-<address>`
records have a neighbouring `.c` file containing the decompiler output;
`A-<address>` records retain instruction addresses and bytes. The query address
can lie inside a function: use the function identity returned by Ghidra rather
than assuming every filename denotes a distinct entry point.

The [capture plans][plans] replay the recorded queries. The collector verifies
the expected binary hash before querying and unchanged program metadata after
each plan. Assembly was retained for the dispatcher, handshake reader, frame
reader/writer, TLV writer, integer writer, login, agreement acceptance, roster,
chat join, privilege accessor, and reply-object allocation.

Decompiler output contains inferred signatures, missing inferred arguments,
overlapping-global warnings, and some rejected/unreachable blocks. Treat
constant stores, offsets, direct calls, and checked branches as evidence;
do not turn a guessed C prototype into a wire contract. Absence of a string
cross-reference is not negative evidence: the initial string-anchor queries
returned no references despite the same strings appearing in decompiled code.

### Status meanings

| Status | Meaning |
| --- | --- |
| Supported | The named static path establishes the narrowly stated claim for this build. |
| Contradicted | An inspected path provides a concrete counterexample to the document claim. |
| Partial | Some named parts are established; the rest remain open. |
| Unverified | The necessary binary path, runtime observation, client, or implementation evidence is absent. |
| Doc defect | Arithmetic, internal inconsistency, missing required detail, or scope wording needs correction independently of runtime testing. |

These statuses do not mean that every configuration or error path was tested.
Transaction dispatch coverage is not complete semantic validation of a handler.

## Immediate blockers for using the guide as an mxd wire contract

1. Replace the client-kind rule based on handshake sub-version 2. Both this
   Hotline server's normal session path and the supplied SynHX source use it.
2. Correct the handshake tag, empty-payload representation, credential example,
   repeated-field rule, and reply expectations before generating fixtures.
3. Separate agreement 109 from banner notification 122, and document the
   actual successful-login fields without the matrix's unsupported gating.
4. Extend and define the privilege bitmap, including bit ordering and bits
   38–40. Do not implement private-message permission using documented bit 19.
5. Preserve unresolved layouts and compatibility policies as open claims;
   do not convert narrative guesses into normative requirements.

## Envelope, parameters, dates, and examples

| ID | Source and claim | Status | Oracle observation and documentation action |
| --- | --- | --- | --- |
| V001 | P:1–15 describes the target as 1.8.5 and claims every transaction. | Doc defect | Intended target is 1.9. Retitle and revise version wording; the dispatcher and send paths contain undocumented transactions. See the coverage inventory below. |
| V002 | P:17–19, 44–59: big-endian integers and a 20-byte envelope. | Supported | [Frame writer][frame-write] stores byte flags, byte reply marker, BE16 type, then four BE32 values at offsets 4, 8, 12, 16; it sends `0x14` header bytes. |
| V003 | P:23–28: handshake sub-protocol can be `CHAT`, `FILE`, or zero. | Contradicted | [Handshake reader][handshake] reads 12 bytes and checks `TRTP`, version 1; [session dispatcher][dispatch] additionally requires `0x484f544c` (`HOTL`). Arbitrary tags are rejected. |
| V004 | P:28: sub-version is an application-defined revision/build number. | Contradicted | [Dispatcher][dispatch] accepts 2 or 3, creates a normal session for 2, and redirects 3 into the transfer-connection handling path. These are operationally distinct modes here, not an unconstrained build number. |
| V005 | P:32–39: eight-byte server handshake reply, `TRTP` plus BE32 status. | Supported | [Success writer][handshake-ok] sends `TRTP` and zero; [failure writer][handshake-error] sends `TRTP` and a nonzero status, normalizing zero to 1. A complete reply is eight bytes. |
| V006 | P:37–39: client simply waits for the four-byte error code. | Doc defect | State explicitly that the client consumes/checks the preceding four-byte `TRTP` too; otherwise the described read can interpret magic as status. V005 establishes the layout. |
| V007 | P:50, 146–147: reply marker and request-ID correlation. | Supported | [Reply construction][reply-build] copies the incoming ID into the reply object; [reply send][reply-send] supplies that ID and a true reply marker to [frame writer][frame-write]. |
| V008 | P:51, 187–188: client IDs must be nonzero; never reuse before reply. | Partial | [Server ID generator][id-generator] skips zero for its own generated IDs. [Frame reader][frame-read] groups incoming fragments by ID but does not establish a rejection of incoming ID zero. Outstanding-ID uniqueness is a sound implementation policy, not a proven peer requirement from this path. |
| V009 | P:53–59, 133–140: total/current lengths and fragment accumulation. | Partial | [Frame reader][frame-read] reads each 20-byte frame, accumulates payload bytes into a transaction object by ID and request/reply state; [ready lookup][ready] waits for accumulated bytes to reach total length. This supports reassembly, not every stated invariant. |
| V010 | P:137–140: identical type/ID/header invariants across fragments are enforced. | Unverified | ID grouping is visible, but the reader updates stored type and total on later frames. Do not claim checked type/total consistency or exact-equality completion without adversarial packet tests. |
| V011 | P:148–152: zero-size or absent parameter blocks are normal empty replies. | Contradicted | [Field-buffer accessor][field-buffer] materializes two zero bytes for an empty list; [reply send][reply-send] therefore emits a two-byte zero count. [Frame reader][frame-read] rejects either size equal to zero. Use payload `00 00`, sizes 2, for this baseline. |
| V012 | P:49, 183–190: flags are emitted zero and invalid framing causes disconnect transaction 111. | Partial | [Writer][frame-write] emits zero flags. [Reader][frame-read] sets a connection-error flag and closes its transport on invalid sizes; this does not establish a transaction-111 notice. Separate emitted format, receiver policy, and optional graceful-close advice. |
| V013 | P:65–75: count followed by unpadded BE16 ID/BE16 length/value records. | Supported | [TLV writer][tlv-write] stores count 1 and the first record in six bytes plus value, then increments count and appends four bytes plus each subsequent value. Field length is bounded to 65,535. |
| V014 | P:77–81; P:413–424: only field 300 in transaction 300 may repeat. | Contradicted | [Chat join][chat-join] also repeats field 300 in reply 115; [new-chat handler][chat-create] iterates repeated input field 103. File/news list builders repeat their own list fields. A global uniqueness validator would reject valid traffic. The guide also contradicts itself at P:657–662 and 754–757. |
| V015 | P:80–81: numeric values use two or four bytes. | Partial | [Numeric writer][integer-write] uses two bytes through `0xffff`, otherwise four. [Numeric reader][integer-read] also accepts one-byte integers; a three-byte value returns zero. Document writer convention separately from receiver acceptance. |
| V016 | P:75: strings are ASCII, or otherwise opaque. | Unverified | The inspected field readers copy raw bytes into Pascal or NUL-terminated local strings. No text-encoding negotiation or blanket UTF-8 rule was established. Retain bytes and define per-field encoding in a later pass. |
| V017 | P:83–129: eight-byte date layout and annual conversion algorithm. | Partial | [File-info handler][file-info] writes eight-byte fields 208/209. [File date builder][file-date] stores BE16 year **1904**, BE16 zero, then the supplied 32-bit filesystem time. Layout is supported; nonzero milliseconds, generic annual conversion, timezone, and all timestamp consumers are not validated. Document the observed 1904 form without rejecting other years based only on this path. |
| V018 | P:155–175: login example has 20 parameter bytes, total frame 40. | Doc defect | Including the missing BE16 count, the listed records require `2 + (4+5) + (4+0) + (4+2) = 21` bytes and a 41-byte frame. If empty password is omitted as the native writer does, count/lengths change again. Replace the example with explicitly counted bytes. |
| V019 | P:171: literal ASCII `admin` is a working login-name example. | Contradicted | [Login handler][login] complements every nonempty login-name byte before account lookup. The wire form of `admin` is `9e 9b 92 96 91`. Do not label plaintext bytes as a valid authenticated login example. |
| V020 | P:191–192: many clients send dozens of fragments for folder uploads. | Unverified | Fragment reception exists, but client frequency/size and folder-upload fragmentation behaviour require client or trace evidence. Keep this out of a normative baseline. |
| V021 | P:181–195: no concrete maximum transaction size is given. | Doc defect | [Reader][frame-read] compares both size words to global `10094a50`; the captured [initial image bytes][frame-limit] contain `0x00200000` (2 MiB). Record this build's image value and comparison, not a guaranteed immutable runtime cap. |
| V022 | P:46–59: reply transaction type is unspecified. | Doc defect | [Reply allocation][reply-allocate] uses a [zeroing allocator][zero-allocator]; [reply construction][reply-build] sets reply state and copies ID while leaving type zero. [Reply send][reply-send] serializes that zero type. Add the observed reply-type rule rather than requiring request type to be echoed. |

## Login, agreement, privileges, and presence

| ID | Source and claim | Status | Oracle observation and documentation action |
| --- | --- | --- | --- |
| V023 | P:217–225: login fields 105/106/160; server version in field 160. | Supported | [Login][login] reads these fields and also reads optional display name 102 and icon 104. On success it writes `160 = 0xbe` (**190**). Add the optional legacy/early-completion inputs. |
| V024 | P:222–229 and M:19–25, 40–42: fields 161/162 depend on client class/version. | Partial | [Successful login][login] unconditionally adds 160, 161, 162 before replying; no comparison of the saved client version guards these additions in this handler. The documented positive case is supported, but the matrix's omission policy is not native 1.9 behaviour. Its implementation status remains unverified. |
| V025 | P:248–278: transaction 109 includes banner type/URL/image fields 152/153/151. | Contradicted | [Login][login] builds 109 with agreement text 101 or no-agreement flag 154. [Agreed][agreed] later builds separate **122** with type 152 and optional URL 153 for client version at least 151 when a banner is configured. No inline image 151 is added by these inspected send paths. |
| V026 | P:299–300: transaction 121 receives no direct reply. | Contradicted | [Agreed][agreed] immediately sends an empty field-list reply before applying settings and sending access privileges. This is a 22-byte frame, not a header-only packet; see V011. |
| V027 | P:281–317: all sessions must wait for transaction 121 to become online. | Contradicted | [Login][login] can complete early when nonempty name 102 and nonzero icon 104 are supplied; it marks the session active and sends 354 before 109. The later-121 path also exists. Document both paths and their conditions. |
| V028 | P:287–297, 530–538: options 1/2/4 and automatic-response field 215. | Supported | [Settings helper][settings] maps bits 0/1/2 of field 113 to refusal/auto-response state and reads field 215; it supplies default response text when that field is absent. |
| V029 | P:319–343: access notification 354 contains bitmap field 110. | Supported | [Login][login] and [Agreed][agreed] serialize eight bytes from the session privilege bitmap as field 110 and send type `0x162` (354). The eight-byte width needs adding to the guide. |
| V030 | P:345–391: privilege table is complete and Send Private Message is bit 19. | Contradicted | [PM handler][pm] checks bit **40** using [MSB-first accessor][privilege]. [Folder upload][folder-upload] checks bit **38**, and [folder download][folder-download] bit **39**. The table ends at 37 and assigns PM to 19; it is incomplete/wrong for this build. Bits 18/19 and all other unused entries are not certified by this pass. |
| V031 | P:345–391: bit numbering can be used without a byte-order rule. | Doc defect | [Accessor][privilege] computes byte `bit >> 3`, then bit `7 - (bit & 7)`. Define bit 0 as byte 0's MSB, over eight transmitted bytes; do not implement an LSB-first host integer bitmap. |
| V032 | P:400–413: roster field 300 has UID/icon/colour/name-length/name. | Supported | [Roster builder][roster] writes four BE16 values, name bytes, and field length `8 + name_length`, once per active named session. Name length zero is skipped. This agrees with [SynHX roster source][syn-roster]. |
| V033 | P:419–421: main-chat subject field 115 in transaction 300. | Partial | [Supplied SynHX server][syn-roster] appends subject 115 to its roster reply. [Native 1.9 roster][roster] does not add 115. This is a source-observed server difference, not proof of what every SynHX client accepts. |
| V034 | P:403–408: roster reply contains one or more entries. | Partial | [Roster][roster] appends only eligible nonempty names; the builder has no minimum-entry check and can emit a zero count if none qualify. A normally logged-in requester may itself supply an entry. Prefer zero-or-more in the structural grammar; this pass does not prove an empty-roster session is reachable. |
| V035 | P:445–492: notifications 301/302 describe online-state changes. | Partial | [Update builder][presence-update] writes fields 103/104/112/102 and broadcasts 301. Roster entry status construction is [captured][status]. Exact self-exclusion, all disconnect-302 paths, and client UI effects remain unverified. |
| V036 | P:495–522: transaction 303 returns an admin-configured short profile. | Contradicted | [Client-info handler][client-info] assembles operational diagnostic text with nickname, account, address and transfer summaries; replies contain data 101 and name 102. Replace the invented profile/real-name semantics with observed content and its privilege-24 gate. |
| V037 | P:530–547: transaction 304 updates only supplied fields. | Contradicted | [304 handler][settings-handler] calls [settings helper][settings] unconditionally. That helper reads name/icon/options regardless of presence, supplies a fallback name for empty input, and assigns icon/options from the reader's returned value. Missing fields do not implement an established patch/merge contract here. |
| V038 | P:539–547: transaction 304 has no direct reply. | Supported | [304 handler][settings-handler] calls the settings/update path without invoking the direct reply helper. Flood handling can close the connection. |

## Chat, private messages, and legacy message board

| ID | Source and claim | Status | Oracle observation and documentation action |
| --- | --- | --- | --- |
| V039 | P:578–641: 105 takes text/options/chat ID and generates 106 without an ACK. | Supported | [Chat-send handler][chat-send] reads 101/109/114, formats the text, and sends 106 to eligible recipients; a room-specific send adds field 114. No direct success reply call appears. Permission and flood branches are configuration-dependent. |
| V040 | P:643–678: join 115 returns subject and packed user-list records. | Supported | [Join][chat-join] optionally adds subject 115 and appends repeated packed field-300 records; success and missing-chat error both use direct replies. It sends 117 to existing room members when adding a new member. |
| V041 | P:700–743, 847–885: notifications 117/118/119 carry chat-scoped state. | Partial | Join, leave, and subject handlers establish send sites for 117/118/119 and relevant chat/user fields. All leave/disconnect cleanup and client rendering semantics are not established. See the handler inventory and retained decompilations. |
| V042 | P:749–785: create 112 accepts repeated target UID field 103. | Supported | [Create-chat handler][chat-create] iterates every field by index and processes each 103. It creates a room containing the inviter, sends invites, then replies with room 114 and the inviter's 103/104/112/102; it does not return all invitees as already-joined participants. |
| V043 | P:901–920: PM input fields 103/113/101 and optional quoted text 214. | Supported | [PM handler][pm] reads those four fields, interpreting option values 1–4 as distinct cases rather than proving a freely combinable bitmap. Retain numeric enumerants; do not infer additional bit combinations. |
| V044 | P:922–923, 959–971: sending transaction 108 has no direct reply. | Contradicted | [PM handler][pm] sends a direct empty success reply before routing; permission/offline errors return status 1 and field 100 text. It then emits type 104 to recipients as applicable. |
| V045 | P:942–957: the client probably handles automatic response/refusal. | Contradicted | [PM handler][pm] itself generates type-104 refusal/auto-response messages using recipient session state for normal-message option 1. It suppresses delivery to a refusing recipient. This behaviour is visible server-side and should not be left as a client-only guess. |
| V046 | P:1000–1018, 2119–2151: broadcast probably becomes type 104 or possibly 355. | Contradicted | [Broadcast handler][broadcast] ACKs the initiator, builds fields 103/102/101, and sends **355** to other active connected users. Preserve this observed path, separately from server/admin type-104 notices. |
| V047 | P:1036–1045, 1895–1905: legacy 101/102/103 are mostly ignorable. | Contradicted | [Get-board 101][old-get] reads the configured old message-board buffer and replies with data 101. [Post-board 103][old-post] updates it, ACKs, and emits 102. They remain implemented alongside threaded news in this 1.9 build; deprecation is an mxd scope decision. |
| V048 | P:613–641, 974–1034: exact client windows, styling, sender attribution. | Unverified | The server establishes emitted text/fields, not Mac/SynHX client presentation. Keep UI expectations descriptive until a client or trace is checked. |

## File services and transfers

| ID | Source and claim | Status | Oracle observation and documentation action |
| --- | --- | --- | --- |
| V049 | P:1055–1092: list 200 accepts path 202 and repeats file record 200. | Partial | [List handler][file-list] reads path 202 and calls the list builder. Its exact record layout is not validated in this pass; the guide's vague record description is insufficient for mxd. Repeated-list fields are also documented here, contradicting V014's global prohibition. |
| V050 | P:1064–1068: a path can be treated as unspecified opaque data or folder IDs. | Unverified | [Path resolver entry][path-resolver] passes the bytes into a filesystem resolver; it treats lengths below six as no path. Exact counted path-component layout, reserved fields, and name encoding still need tracing before implementation. |
| V051 | P:1094–1170: download request fields and reply size/reference/queue. | Partial | [Download handler][file-download] reads 201/202/203/204, uses a fixed four-byte reference 107, and writes 108/207 plus 116 only when queued. Preview option 2 has a separate path; an empty preview can reply with size zero and no reference. Whole transfer-stream semantics remain open. |
| V052 | P:1172–1227: upload initiation and resume direction. | Partial | [Upload handler][file-upload] reads 201/202/204/108, takes a resume path when options equals 1, and may return resume data 203 plus four-byte reference 107. Confirm these fields; remove the guide's guess that this option may be unused. Full resume-stream format remains open. |
| V053 | P:1229–1282, 1330–1434: delete/create/rename/move/alias have no reply. | Contradicted | Handlers 204, 205, 207, 208, and 209 all contain direct reply calls, including success paths. Their per-handler evidence is linked in the dispatch inventory. Use ACK/error semantics rather than implicit refresh-only success. |
| V054 | P:1284–1328: file-info fields and type/creator meanings. | Partial | [File info][file-info] writes name 201, size 207 on file paths, dates 208/209, comment 210, and fields 205/206/213. Fields 205/206 can contain descriptive strings, not always four-character codes; raw file type is placed in 213 on the ordinary file branch. Document branch-specific representations. |
| V055 | P:1436–1494: folder-download permission is ordinary Download File bit 2. | Contradicted | [Folder download][folder-download] checks bit **39** through the folder privilege helper, not only bit 2; field inputs also include 203/204. Its initiation reply includes 220/108, plus reference/queue when applicable. |
| V056 | P:1496–1539: folder-upload permission is ordinary Upload File bit 1. | Contradicted | [Folder upload][folder-upload] checks bit **38**, takes 201/202/204/108/220, and can return an empty success reply without a transfer reference when there is nothing to transfer. |
| V057 | P:1458–1478, 1510–1532: exact folder stream actions 1/2/3 and resume exchanges. | Unverified | Captured initiation handlers and the HTXF acceptor do not establish the complete per-file state machine. Trace the download/upload stream workers and retain byte layouts before treating these descriptions as normative. |
| V058 | P:1541–1574: banner 212 replies with transfer reference and size; HTXF type 2. | Supported | [Banner handler][banner-download] writes reference 107 as four bytes and size 108. [HTXF acceptor][transfer-accept] routes odd reference + type 2 to its banner-transfer lookup. Banner advertisement comes from 122, not 109; see V025. |
| V059 | P:1129–1147, 1190–1205: client connects to data endpoint using `HTXF` and reference. | Partial | [Transfer acceptor][transfer-accept] accepts an incoming connection, waits for **16 bytes**, checks `HTXF`, and uses the reference, a later size word, and a type halfword to choose a worker. A complete offset table and reserved-byte interpretation are not yet established. |
| V060 | P:1049–1053: data port is base port + 1; queued server initiates connection. | Partial | The acceptor establishes a client-initiated connection for the inspected path, contradicting the later statement at P:1140–1141 that the server initiates it. The base-port arithmetic itself was not traced; verify listener setup separately. |
| V061 | P:all file services: reference cancellation is absent. | Doc defect | [Dispatcher][dispatch] accepts **214**, whose [handler][transfer-cancel] reads four-byte reference 107, calls transfer cleanup if nonzero, and ACKs. Name and document the operation after tracing the cleanup helper; cancellation is the current behavioural interpretation. |

## Threaded news and administration

| ID | Source and claim | Status | Oracle observation and documentation action |
| --- | --- | --- | --- |
| V062 | P:1600–1645: 370 returns repeated 323; only pre-1.5 uses 320. | Partial | [Category builder][news-categories] repeats 323 when saved client version is at least **15**, otherwise 320. The numeric comparison is `0xf`, not 150 or 151. Name the numeric threshold explicitly; don't infer a display-version conversion. |
| V063 | P:1647–1677: 371 returns one field 321 per article. | Contradicted | [Article-list builder][news-article-list] adds **one field 321 containing the entire serialized list** returned by its database helper. The nested record format still needs decoding; do not model it as repeated per-article TLVs from this description. |
| V064 | P:1679–1726: 400 input 325/326/327 and metadata/body output. | Supported | [400 handler][news-read] reads path/article ID/flavour. [Data builder][news-data] writes 333 when nonempty, 331/332/335/336, title 328, poster 329, flavour 327, and eight-byte date 330. Exact thread-navigation meanings and non-text flavours remain to be validated. |
| V065 | P:1728–1905: 410/411/380/381/382 succeed without replies. | Contradicted | Each captured handler invokes the shared direct reply helper on success and error paths. Do not omit ACKs for posting, deleting, or changing news structure. |
| V066 | P:1588–1598, 1789–1818: fixed four-tier hierarchy and recursive-delete side effects. | Unverified | Dispatch and field extraction establish relevant operations, not all hierarchy constraints, orphan handling, notifications, or rollback. These claims need database-helper analysis and runtime fixtures. |
| V067 | P:1915–2054: account 350/351/353 have no direct success reply. | Contradicted | [Create][account-create], [delete][account-delete], and [update][account-update] handlers send direct ACK/error replies. They include permission gates and should be documented as request/reply transactions. |
| V068 | P:1980–2005: account 352 returns the password or an encoded copy. | Contradicted | [Get-account handler][account-get] returns field 106 containing the one-byte literal **`x`** when a password exists; when empty, the zero-length-field writer omits it. It complements the login-name bytes for field 105. This is a presence placeholder, not password disclosure or recoverable obfuscation. |
| V069 | P:1924–1936, 2013–2022: account input fields are only 102/105/106/110. | Partial | Create/update additionally read field **111**. Its semantics are not established here. The eight-byte privilege width is established elsewhere. Do not silently discard this field from a complete 1.9 account schema. |
| V070 | P:2025–2049: live account edits update permissions and preserve sessions. | Unverified | Captured account handlers show mutation paths, but this pass does not certify every active-session propagation, account-renaming, password-storage, or disconnect consequence. Narrative guesses need deeper helper/runtime evidence. |
| V071 | P:2056–2091: kick 110 has no reply; ban options are probably a bitmap. | Contradicted | [Kick handler][kick] ACKs success, checks privileges 22/23, treats option **1** and **2** as distinct branches, and reads optional field 101 on the latter path. Do not invent independently combinable ban bits or account/IP meanings without tracing the two ban helpers. |
| V072 | P:2093–2117: admin kick always sends disconnect type 111 with required text. | Contradicted | [Kick handler][kick] emits type **104** on its option-1/2 notice branches, then closes the transport; a plain kick can close without that notice. No type-111 send is visible in this inspected kick path. Other 111 paths, if any, remain unverified. |
| V073 | P:2162–2174: privileges 11/12 imply entering/closing any private chat. | Unverified | The create-chat handler checks 11, but this does not establish all asserted admin overrides. Avoid implementing broad bypasses from this prose. |
| V074 | P:2178–2185: the catalogue completely enumerates relevant server operations. | Doc defect | The captured dispatcher also handles 348/349 and 500; the login path sends 122. These require explicit catalogue/scope decisions. The ledger does not assign names to 348/349/500 solely from their numbers. |

## Compatibility-matrix ledger

The supplied source tree contains CVS/RCS `*,v` archives, not checked-out C
files or a Git revision. Fourteen relevant archives and decoded source snapshots
are preserved with individual hashes in the [SynHX manifest][syn-manifest].
For each, the selected full-text **trunk revision is 1.1**; the archive declares
default vendor branch **1.1.1**. The extraction does not claim to check out that
default branch or identify a current SynHX release. Archive dates identify this
as historical source evidence, not proof about all later clients.

| ID | Matrix claim | Status | Evidence and action |
| --- | --- | --- | --- |
| M001 | M:19–21: Hotline 1.8.5/1.9 use `sub_version != 2`; SynHX alone uses 2. | Contradicted | Native [1.9 dispatcher][dispatch] uses 2 for normal sessions. Supplied [SynHX constants][syn-wire] define the same 12-byte magic and [receiver][syn-login] compares it. This marker cannot distinguish those peers. |
| M002 | M:19–25: login version 151–189 versus at least 190 proves client profile. | Unverified | Native [login][login] stores version 160, replies with 190, and uses at least 151 for later banner delivery. It does not establish the matrix's client classifier, nor identify every 151–189 client as 1.8.5. Preserve this as mxd policy pending client evidence. |
| M003 | M:21–22, 41: SynHX replies must omit 161/162. | Unverified | Supplied SynHX source lacks the inspected native 1.9 augmentation, but source omission is not proof that a SynHX client rejects these fields. Native [login][login] adds them without a peer-kind gate. Separate client tolerance from mxd response policy. |
| M004 | M:25, 42: old/unknown clients omit 161/162 as conservative safety behaviour. | Unverified | Native [successful login][login] has no such version/kind gate. The matrix records an mxd policy; it does not itself establish that inclusion is invalid or that omission is necessary. Verify that policy against the intended client builds and mxd tests. |
| M005 | M:19–22, 43–44: arbitrary text may use heuristic XOR mode. | Unverified | [SynHX `hl_code`][syn-code] complements bytes; [login parser][syn-login] applies it specifically to login/password. [Native login][login] complements login bytes too. This is not evidence for invalid-UTF-8-driven global XOR mode on chat/news/text, and credential obfuscation is not a SynHX fingerprint. |
| M006 | M:29–36: only transaction 300 may repeat a field ID. | Contradicted | Native [join 115][chat-join] repeats field 300; [create 112][chat-create] iterates repeated 103. The protocol guide also documents repeated file/news fields. A global allowlist restricted to transaction 300 is incompatible with the observed paths. |
| M007 | M:29–36: packed field-300 roster layout is SynHX-compatible. | Supported | Native [roster builder][roster] and supplied [SynHX roster writer][syn-roster] agree on BE16 UID/icon/colour/name length followed by name bytes. This validates the structure in these two implementations, not every client profile. |
| M008 | M:3–15, 19–25, 38–44: listed mxd tests prove implementation status. | Unverified | The supplied documents cite tests but no mxd checkout/revision or test execution is part of this evidence set. Ghidra cannot certify those Rust tests. Keep implementation status and protocol validity as separate columns. |
| M009 | M:46–53: roadmap, Kani, sign-off, and future-work status. | Unverified | These are project-management assertions, not binary properties. Required evidence is the exact mxd revision, cited test/proof outputs, roadmap and QA documents. |

## Transaction coverage and evidence index

The [dispatcher map][dispatch-map] is a manual reading of the captured dispatcher
decision tree, cross-checked against each handler's field operations. It is not
an automatically proven control-flow extraction. The table records direct
reads, not all transitive helpers; a blank direct-read list does not mean the
request cannot contain parameters.

Every handler below was decompiled and retained. **ACK** means a normal-path
direct reply is visible; it does not mean every branch replies or succeeds.
**Push** means no normal direct success ACK was identified in that handler.
Unknown-transaction handling, privilege failures, floods, filesystem errors,
and configuration branches can change behaviour.

<!-- The handler table is generated from the preserved manual dispatcher map. -->

| Request | Operation | Entry/evidence | Directly read field IDs | Success path |
| ---: | --- | --- | --- | --- |
| 101 | Get old message board | [1000f130](../evidence/hotline-server-1.9/queries/D-1000f130.c) | None identified directly | ACK |
| 103 | Post old message board | [1000f260](../evidence/hotline-server-1.9/queries/D-1000f260.c) | 101 | ACK |
| 105 | Send chat | [1000fc20](../evidence/hotline-server-1.9/queries/D-1000fc20.c) | 101, 109, 114 | Push |
| 107 | Login | [10011960](../evidence/hotline-server-1.9/queries/D-10011960.c) | 102, 104, 105, 106, 160 | ACK |
| 108 | Send private message | [1000f4e0](../evidence/hotline-server-1.9/queries/D-1000f4e0.c) | 101, 103, 113, 214 | ACK |
| 110 | Disconnect user | [10015e70](../evidence/hotline-server-1.9/queries/D-10015e70.c) | 101, 103, 113 | ACK |
| 112 | Create private chat | [10017f30](../evidence/hotline-server-1.9/queries/D-10017f30.c) | 103, iterated by index | ACK |
| 113 | Invite to existing chat | [100188e0](../evidence/hotline-server-1.9/queries/D-100188e0.c) | 114; target UID via field iteration | Push |
| 114 | Reject chat invitation | [10018340](../evidence/hotline-server-1.9/queries/D-10018340.c) | 114 | Push |
| 115 | Join chat | [100183c0](../evidence/hotline-server-1.9/queries/D-100183c0.c) | 114 | ACK |
| 116 | Leave chat | [10018620](../evidence/hotline-server-1.9/queries/D-10018620.c) | 114 | Push |
| 120 | Set chat subject | [10018760](../evidence/hotline-server-1.9/queries/D-10018760.c) | 114, 115 | Push |
| 121 | Accept agreement | [10011ee0](../evidence/hotline-server-1.9/queries/D-10011ee0.c) | 102/104/113/215 through helper | ACK |
| 200 | List files | [100100a0](../evidence/hotline-server-1.9/queries/D-100100a0.c) | 202 | ACK |
| 202 | Download file | [100121a0](../evidence/hotline-server-1.9/queries/D-100121a0.c) | 201, 202, 203, 204 | ACK |
| 203 | Upload file | [100130f0](../evidence/hotline-server-1.9/queries/D-100130f0.c) | 108, 201, 202, 204 | ACK |
| 204 | Delete file/folder | [100140e0](../evidence/hotline-server-1.9/queries/D-100140e0.c) | 201, 202 | ACK |
| 205 | Create folder | [100143f0](../evidence/hotline-server-1.9/queries/D-100143f0.c) | 201, 202 | ACK |
| 206 | Get file info | [10016ba0](../evidence/hotline-server-1.9/queries/D-10016ba0.c) | 201, 202 | ACK |
| 207 | Set file info | [100170c0](../evidence/hotline-server-1.9/queries/D-100170c0.c) | 201, 202, 210, 211 | ACK |
| 208 | Move file/folder | [100177d0](../evidence/hotline-server-1.9/queries/D-100177d0.c) | 201, 202, 212 | ACK |
| 209 | Make alias | [10017c10](../evidence/hotline-server-1.9/queries/D-10017c10.c) | 201, 202, 212 | ACK |
| 210 | Download folder | [10012850](../evidence/hotline-server-1.9/queries/D-10012850.c) | 201, 202, 203, 204 | ACK |
| 212 | Download banner | [10012f40](../evidence/hotline-server-1.9/queries/D-10012f40.c) | None identified directly | ACK |
| 213 | Upload folder | [10013930](../evidence/hotline-server-1.9/queries/D-10013930.c) | 108, 201, 202, 204, 220 | ACK |
| 214 | Reference cleanup (cancellation inferred) | [10013040](../evidence/hotline-server-1.9/queries/D-10013040.c) | 107 | ACK |
| 300 | Get user roster | [10011870](../evidence/hotline-server-1.9/queries/D-10011870.c) | None identified directly | ACK |
| 303 | Get client diagnostic info | [10016150](../evidence/hotline-server-1.9/queries/D-10016150.c) | 103 | ACK |
| 304 | Set client info | [10016ad0](../evidence/hotline-server-1.9/queries/D-10016ad0.c) | 102/104/113/215 through helper | Push |
| 348 | Undocumented account operation | [10015160](../evidence/hotline-server-1.9/queries/D-10015160.c) | Transitive/indexed; not enumerated | ACK |
| 349 | Undocumented account operation | [10015500](../evidence/hotline-server-1.9/queries/D-10015500.c) | Transitive/indexed; not enumerated | ACK |
| 350 | Create account | [100146f0](../evidence/hotline-server-1.9/queries/D-100146f0.c) | 102, 105, 106, 110, 111 | ACK |
| 351 | Delete account | [100149e0](../evidence/hotline-server-1.9/queries/D-100149e0.c) | 105 | ACK |
| 352 | Get account | [10014bc0](../evidence/hotline-server-1.9/queries/D-10014bc0.c) | 105 | ACK |
| 353 | Update account | [10014df0](../evidence/hotline-server-1.9/queries/D-10014df0.c) | 102, 105, 106, 110, 111 | ACK |
| 355 | Broadcast | [1000f990](../evidence/hotline-server-1.9/queries/D-1000f990.c) | 101 | ACK |
| 370 | List news categories | [100102c0](../evidence/hotline-server-1.9/queries/D-100102c0.c) | 325 | ACK |
| 371 | List news articles | [10011370](../evidence/hotline-server-1.9/queries/D-10011370.c) | 325 | ACK |
| 380 | Delete news item | [10010b70](../evidence/hotline-server-1.9/queries/D-10010b70.c) | 325 | ACK |
| 381 | Create news folder | [10010ee0](../evidence/hotline-server-1.9/queries/D-10010ee0.c) | 201, 325 | ACK |
| 382 | Create news category | [10011110](../evidence/hotline-server-1.9/queries/D-10011110.c) | 322, 325 | ACK |
| 400 | Read news article | [10011580](../evidence/hotline-server-1.9/queries/D-10011580.c) | 325, 326, 327 | ACK |
| 410 | Post news article | [10010470](../evidence/hotline-server-1.9/queries/D-10010470.c) | 325, 326, 327, 328, 333, 334 | ACK |
| 411 | Delete news article | [100108a0](../evidence/hotline-server-1.9/queries/D-100108a0.c) | 325, 326, 337 | ACK |
| 500 | Undocumented empty ACK operation | [10018c00](../evidence/hotline-server-1.9/queries/D-10018c00.c) | None identified directly | ACK |

Server-originated messages need separate send-path evidence; their absence from
a client-request dispatcher is not evidence that they are unsupported:

| Type | Evidence in this baseline | Remaining scope |
| --- | --- | --- |
| 100 | Field **100** contains error text in many replies. | Do not confuse this field ID with a proven standalone error transaction type 100. |
| 102 | [Old-board post][old-post] sends 102. | Full old-board history/update ordering. |
| 104 | [PM][pm], [chat-denial][chat-send], and [kick][kick] send 104. | Every server/admin notice form and client rendering. |
| 106 | [Chat send][chat-send] sends 106. | Full formatting and encoding rules. |
| 109 | [Login][login] sends agreement 109. | All configured agreement content sources. |
| 111 | Not established as a send type by the kick path. | Locate any real 111 producer; do not infer absence globally. |
| 113 | [Chat creation][chat-create] and existing-chat invite send 113. | All refusal and invitation-expiry behaviour. |
| 117/118/119 | Join/leave/subject handlers contain send sites. | Disconnect-driven room cleanup and recipient filtering. |
| 122 | [Agreed][agreed] sends banner metadata. | Add missing transaction to the guide. |
| 211 | Queue semantics are not fully traced here. | Follow queue-advance worker and record emitted fields. |
| 301 | [Settings update][presence-update] constructs 301. | Self-recipient policy and ordering. |
| 302 | Not independently traced here. | Follow teardown producer and its field serialization. |
| 354 | [Login][login] and [Agreed][agreed] send eight-byte field 110. | Live account-edit propagation. |
| 355 | [Broadcast][broadcast] sends 355 to other active users. | Server-console-originated broadcast path. |

### Selected instruction anchors

These anchors allow the most consequential conclusions to be checked without
trusting only the decompiler's inferred C. Consult the whole captured function
to establish control flow; a single immediate value alone is not a protocol
finding.

| Conclusion | Instruction address and observation | Raw assembly evidence |
| --- | --- | --- |
| Required `HOTL` tag | `1000ae80` subtracts high half `484f`; `1000ae84` compares low half `544c`. | [Dispatcher assembly][asm-dispatch] |
| Normal mode 2; additional mode 3 | `1000ae90`/`1000ae9c` compare 2/3; `1000aeb4` branches on 2. | [Dispatcher assembly][asm-dispatch] |
| Server version 190 | `10011c30`: `li r5,0xbe`. | [Login assembly][asm-login] |
| Login extras 161/162 | `10011c44`: `li r4,0xa1`; `10011c54`: `li r4,0xa2`. | [Login assembly][asm-login] |
| Banner threshold 151 and send type 122 | `10012044`: compare `0x97`; `10012174`: `li r4,0x7a`. | [Agreed assembly][asm-agreed] |
| PM privilege bit 40 | `1000f668`: `li r5,0x28`; `1000f66c` calls the bit accessor. | [PM assembly][asm-pm] |
| Folder upload/download bits 38/39 | `1001397c`: `li r5,0x26`; `1001289c`: `li r5,0x27`. | [Upload][asm-folder-upload], [download][asm-folder-download] |
| Password placeholder `x` | `10014d4c`: `li r0,0x78`; surrounding stores set length 1 before field 106 serialization. | [Account-get assembly][asm-account-get] |
| Observed date year 1904 | `10058070`: `li r0,0x770`, followed by year/millisecond/seconds stores. | [Date assembly][asm-date] |
| News-list threshold 15 | `1000575c`: `cmplwi r27,0xf`. | [Category assembly][asm-news-categories] |
| Broadcast send type 355 | `1000fbe4`: `li r4,0x163`, on the per-recipient send path. | [Broadcast assembly][asm-broadcast] |

## Required follow-up before a complete 1.9 specification

This is a baseline ledger, not a blanket endorsement of the 2,193-line guide.
Untested narrative details remain unverified, including claims phrased as
“likely”, “possibly”, “IIRC”, and descriptions of client windows. In particular:

1. Trace exact binary layouts for paths, file-list records, resume data,
   flattened forks, HTXF fields, folder control messages, and nested news lists.
2. Establish encoding per field, text conversion, maximum sizes, and behaviour
   for unknown/duplicate fields, truncated TLVs, count mismatch, and overflow.
3. Exercise both login paths with native wire fixtures, including failed auth,
   no agreement, banner/no banner, missing fields, and different version codes.
4. Test fragmentation with interleaved IDs, changed type/total, overrun,
   underflow, zero lengths, nonzero flags, duplicate IDs, and zero IDs. Static
   recognition of a reassembly mechanism does not settle its full contract.
5. Complete the privilege table and its enforcement at account, folder, news,
   and private-chat boundaries; inspect unused/extra bits and field 111.
6. Trace 302, 111 if present, queue notification 211, and omitted requests
   214/348/349/500 through all relevant helper paths.
7. Validate cross-version and SynHX-client claims against identified client
   builds or recorded sessions. This historical server snapshot cannot supply
   those observations.
8. Validate the matrix's implementation/test/proof statements against an exact
   mxd checkout and execution evidence.

For each documentation edit, cite one or more ledger IDs, keep wire fact
separate from mxd policy, and retain any unclosed uncertainty. Convert the
corrected bytes into interoperability fixtures rather than copying native
implementation quirks without an explicit compatibility decision.

## Reproduce and check the evidence

With the same hashed program open in CodeBrowser and its plugin enabled:

```sh
tools/ghidramcp/.venv/bin/python scripts/capture-ghidra-evidence.py \
  evidence/hotline-server-1.9/plans/03-handshake.json \
  state/ledger-replay/queries
```

The collector refuses to overwrite existing query records. Replay other plans
into the same new output directory; plans use distinct IDs. Replays will have
different timestamps and may reflect changed Ghidra analysis, so compare
program hashes, tool arguments, and results rather than whole-file hashes.

Verify the recorded historical SynHX trunk snapshots without needing an RCS
installation:

```sh
python3 scripts/extract-synhxd-evidence.py
```

The complete retained evidence file inventory and hashes are in
`evidence/hotline-server-1.9/SHA256SUMS`, relative to the repository root:

```sh
sha256sum -c evidence/hotline-server-1.9/SHA256SUMS
make ledger-check
make markdownlint nixie
```

[binary]: ../evidence/hotline-server-1.9/inputs/HLserver19.pef
[manifest]: ../evidence/hotline-server-1.9/manifest.json
[claim-index]: ../evidence/hotline-server-1.9/claims.json
[protocol]: ../evidence/hotline-server-1.9/inputs/protocol.md.txt
[matrix]: ../evidence/hotline-server-1.9/inputs/internal-compatibility-matrix.md.txt
[queries]: ../evidence/hotline-server-1.9/queries/
[plans]: ../evidence/hotline-server-1.9/plans/
[dispatch-map]: ../evidence/hotline-server-1.9/dispatcher-map.json
[syn-manifest]: ../evidence/hotline-server-1.9/synhxd-source/manifest.json
[dispatch]: ../evidence/hotline-server-1.9/queries/D-1000acf0.c
[handshake]: ../evidence/hotline-server-1.9/queries/D-10058650.c
[handshake-ok]: ../evidence/hotline-server-1.9/queries/D-10058770.c
[handshake-error]: ../evidence/hotline-server-1.9/queries/D-100587f0.c
[frame-write]: ../evidence/hotline-server-1.9/queries/D-10058fd0.c
[frame-read]: ../evidence/hotline-server-1.9/queries/D-100590e0.c
[frame-limit]: ../evidence/hotline-server-1.9/queries/M-frame-limit.json
[reply-build]: ../evidence/hotline-server-1.9/queries/D-10058880.c
[reply-send]: ../evidence/hotline-server-1.9/queries/D-10058a70.c
[reply-allocate]: ../evidence/hotline-server-1.9/queries/D-10058d90.c
[zero-allocator]: ../evidence/hotline-server-1.9/queries/D-10079e30.c
[id-generator]: ../evidence/hotline-server-1.9/queries/D-10058d70.c
[ready]: ../evidence/hotline-server-1.9/queries/D-10058e80.c
[field-buffer]: ../evidence/hotline-server-1.9/queries/D-10056d00.c
[tlv-write]: ../evidence/hotline-server-1.9/queries/D-100568b0.c
[integer-write]: ../evidence/hotline-server-1.9/queries/D-10056a90.c
[integer-read]: ../evidence/hotline-server-1.9/queries/D-10056b90.c
[login]: ../evidence/hotline-server-1.9/queries/D-10011960.c
[agreed]: ../evidence/hotline-server-1.9/queries/D-10011ee0.c
[settings]: ../evidence/hotline-server-1.9/queries/D-10004d50.c
[settings-handler]: ../evidence/hotline-server-1.9/queries/D-10016ad0.c
[privilege]: ../evidence/hotline-server-1.9/queries/D-10008a90.c
[roster]: ../evidence/hotline-server-1.9/queries/D-10011870.c
[presence-update]: ../evidence/hotline-server-1.9/queries/D-10004f30.c
[status]: ../evidence/hotline-server-1.9/queries/D-10005000.c
[client-info]: ../evidence/hotline-server-1.9/queries/D-10016150.c
[chat-send]: ../evidence/hotline-server-1.9/queries/D-1000fc20.c
[chat-join]: ../evidence/hotline-server-1.9/queries/D-100183c0.c
[chat-create]: ../evidence/hotline-server-1.9/queries/D-10017f30.c
[pm]: ../evidence/hotline-server-1.9/queries/D-1000f4e0.c
[broadcast]: ../evidence/hotline-server-1.9/queries/D-1000f990.c
[old-get]: ../evidence/hotline-server-1.9/queries/D-1000f130.c
[old-post]: ../evidence/hotline-server-1.9/queries/D-1000f260.c
[file-list]: ../evidence/hotline-server-1.9/queries/D-100100a0.c
[path-resolver]: ../evidence/hotline-server-1.9/queries/D-1002b0e0.c
[file-download]: ../evidence/hotline-server-1.9/queries/D-100121a0.c
[file-upload]: ../evidence/hotline-server-1.9/queries/D-100130f0.c
[file-info]: ../evidence/hotline-server-1.9/queries/D-10016ba0.c
[file-date]: ../evidence/hotline-server-1.9/queries/D-10058070.c
[folder-download]: ../evidence/hotline-server-1.9/queries/D-10012850.c
[folder-upload]: ../evidence/hotline-server-1.9/queries/D-10013930.c
[banner-download]: ../evidence/hotline-server-1.9/queries/D-10012f40.c
[transfer-accept]: ../evidence/hotline-server-1.9/queries/D-1000bd20.c
[transfer-cancel]: ../evidence/hotline-server-1.9/queries/D-10013040.c
[news-categories]: ../evidence/hotline-server-1.9/queries/D-10005710.c
[news-article-list]: ../evidence/hotline-server-1.9/queries/D-100059e0.c
[news-read]: ../evidence/hotline-server-1.9/queries/D-10011580.c
[news-data]: ../evidence/hotline-server-1.9/queries/D-10005ac0.c
[account-create]: ../evidence/hotline-server-1.9/queries/D-100146f0.c
[account-delete]: ../evidence/hotline-server-1.9/queries/D-100149e0.c
[account-update]: ../evidence/hotline-server-1.9/queries/D-10014df0.c
[account-get]: ../evidence/hotline-server-1.9/queries/D-10014bc0.c
[kick]: ../evidence/hotline-server-1.9/queries/D-10015e70.c
[syn-wire]: ../evidence/hotline-server-1.9/synhxd-source/hotline.h
[syn-login]: ../evidence/hotline-server-1.9/synhxd-source/rcv.c
[syn-code]: ../evidence/hotline-server-1.9/synhxd-source/hlwrite.c
[syn-roster]: ../evidence/hotline-server-1.9/synhxd-source/rcv.c
[asm-dispatch]: ../evidence/hotline-server-1.9/queries/A-1000acf0.json
[asm-login]: ../evidence/hotline-server-1.9/queries/A-10011960.json
[asm-agreed]: ../evidence/hotline-server-1.9/queries/A-10011ee0.json
[asm-pm]: ../evidence/hotline-server-1.9/queries/A-1000f4e0.json
[asm-folder-upload]: ../evidence/hotline-server-1.9/queries/A-10013930.json
[asm-folder-download]: ../evidence/hotline-server-1.9/queries/A-10012850.json
[asm-account-get]: ../evidence/hotline-server-1.9/queries/A-10014bc0.json
[asm-date]: ../evidence/hotline-server-1.9/queries/A-10058070.json
[asm-news-categories]: ../evidence/hotline-server-1.9/queries/A-10005710.json
[asm-broadcast]: ../evidence/hotline-server-1.9/queries/A-1000f990.json
