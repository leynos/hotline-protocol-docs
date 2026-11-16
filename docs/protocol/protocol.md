# Hotline Server Protocol 1.9: transactions and functionality guide

This is the baseline protocol guide for [mxd](../glossary.md#mxd)'s intended
Hotline **1.9** compatibility. It describes observed behaviour of the Mac
PowerPC `HLserver19` server, with explicit gaps where the available evidence
does not establish a complete wire contract. It does not claim to enumerate
every protocol extension or certify compatibility with every Hotline client or
client of the [SynHX](../glossary.md#synhx) family.

This document belongs to the [Hotline 1.9 wire protocol](README.md) set; the
[glossary](../glossary.md) defines the terms it uses.

The authority for this revision is the
[Hotline 1.9 baseline validity ledger][ledger], captured on 12 November 2026.
The [oracle](../glossary.md#oracle) is a PEF data fork with SHA-256:

```text
ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
```

The
[paired resource-fork inventory](../../evidence/gap-remediation/2026-11-12/batch-09/resource-inventory.json)
advertises `Hotline Connect Server 1.9.1.0` in both version resources. This
identifies the labelled build within the intended 1.9 family; the data-fork
hash above remains the code oracle, and its login wire version is still 190.

The ledger preserves the original documents, exact Ghidra MCP queries,
decompilations, assembly and comparison-source hashes. References such as
**V003** identify ledger entries. **[Observed](../glossary.md#observed)** means
supported by static analysis of that build; it does not mean exercised in a
live network test. **[Unresolved](../glossary.md#unresolved)** means that an
implementer must obtain further evidence rather than treat the previous guide's
guesses as requirements.

Client interface details and project implementation status are outside this
wire specification. The [compatibility matrix](../mxd/compatibility-matrix.md)
separates protocol observations from mxd policy and reported test coverage.
Tracker and HTTP tunnelling details remain outside this guide's scope.

## Binary message formats (Hotline Protocol 1.9)

Multi-byte envelope and parameter integers are big-endian. The following
structures have no implicit alignment padding. Text fields carry bytes; this
baseline does not establish a universal ASCII or UTF-8 encoding rule.

Evidence: V002, V013, V016.

### 1 Session-initialization handshake

The normal session handshake is twelve bytes:

| Offset | Size | Field           | Observed value               |
| -----: | ---: | --------------- | ---------------------------- |
| 0      | 4    | Protocol ID     | ASCII `TRTP`, `54 52 54 50`  |
| 4      | 4    | Sub-protocol ID | ASCII `HOTL`, `48 4f 54 4c`  |
| 8      | 2    | Version         | `00 01`                      |
| 10     | 2    | Sub-version     | `00 02` for a normal session |

_Table 1: Fields of the normal session handshake, with the observed value for
each._

The native server rejects a different sub-protocol tag. `CHAT`, `FILE` and zero
are not interchangeable with `HOTL`. It also recognizes sub-version 3, which
enters a transfer-related handling path rather than creating a normal session.
[Session transport details](session-transport-contracts.md#sub-version-3-versus-the-data-endpoint)
now establish its same-connection handover to HTXF after the success response.
It does not create a normal user session or identify an application build.

The supplied historical SynHX server source uses the same normal-session magic,
`TRTPHOTL 00 01 00 02`. **Sub-version 2 cannot uniquely identify a peer of the
SynHX family.**

The server's handshake reply is eight bytes:

| Offset | Size | Field       | Meaning                               |
| -----: | ---: | ----------- | ------------------------------------- |
| 0      | 4    | Protocol ID | `TRTP`                                |
| 4      | 4    | Status      | Zero for success; nonzero for failure |

_Table 2: Fields of the server's eight-byte handshake reply, with the meaning
of each._

A canonical client should consume and check both magic and status. The
[identified shx source](../peers/identified-client-source.md#other-receiver-observations-and-negative-scope)
advances its receive state without inspecting those response bytes, so this is
not a proven behaviour of every historical peer. The reply is unnumbered and
does not contain a general transaction header.

Admission does not establish an unconditional wall-clock timeout. The native
dispatcher refreshes activity after selecting a complete logical request;
partial TCP input is a different event. The
[activity table and finite native liveness capture](session-transport-contracts.md#captured-selected-request-and-partial-input-timing)
distinguish the compiled age checks, guest TCP resets, relay EOF and the
remaining scheduling and clock uncertainties.

Evidence: V003–V006, M001; Ghidra `10058650`, `10058770`, `100587f0`,
`1000acf0`.

### 2 General transaction frame

After the handshake, transactions use a twenty-byte envelope:

| Offset | Size | Field      | Meaning                                                      |
| -----: | ---: | ---------- | ------------------------------------------------------------ |
| 0      | 1    | Flags      | Emitted as zero by this server                               |
| 1      | 1    | Is-reply   | Zero for a request/notification; one for a reply             |
| 2      | 2    | Type       | Request/notification type; native direct replies use zero    |
| 4      | 4    | ID         | Correlation identifier; a direct reply copies the request ID |
| 8      | 4    | Error code | Reply status; zero for success                               |
| 12     | 4    | Total size | Total parameter-stream length for the transaction            |
| 16     | 4    | Data size  | Parameter-stream length in this frame                        |

_Table 3: Fields of the general transaction frame, with the meaning of each._

Request and server-notification types are described in the catalogue below. A
direct reply does **not** need to echo the request's type: the inspected native
reply construction leaves type zero and copies the request ID.

The server's own notification-ID generator increments a 32-bit counter and
skips wrapped zero. Direct replies instead echo client IDs: native captures
accept zero, high-bit values and completed reuse. Equal IDs can collide while
an assembly still exists. See the
[ID/reassembly contract](session-transport-contracts.md#transaction-ids-reassembly-and-correlation)
for native collisions, late replies and notification correlation. mxd resource
and retry policies remain separate implementation choices.

Evidence: V002, V007–V010, V022; `10058fd0`, `10058880`, `10058a70`.

#### 2.1 Parameter list (payload block)

A transaction's parameter stream starts with a two-byte field count, followed
by that many records:

| Offset within record | Size         | Field                 |
| -------------------: | -----------: | --------------------- |
| 0                    | 2            | Field ID              |
| 2                    | 2            | Value length in bytes |
| 4                    | Value length | Value bytes           |

_Table 4: Layout of each record in a transaction parameter list._

The count is outside the first record. There is no padding between records. A
field value is limited to 65,535 bytes by the native writer.

An empty native field list is **`00 00`**, not an absent payload. Accordingly,
an empty direct reply has `Total size = Data size = 2` and a complete length of
**22 bytes**. The inspected receive path rejects either size word equal to
zero. Do not use header-only transactions as the normal empty-message form for
this baseline.

Field IDs may repeat when the transaction's schema permits it. Observed
examples include:

- Repeated field 300 for roster entries in replies to **300 and 115**.
- Repeated target-user field 103 in private-chat requests **112 and 113**.
- Repeated category-list field 323 in the modern reply to **370**.

File-list replies also use repeated field 200; the fixed header and name layout
are recorded in [native wire details](native-wire-details.md). Do not apply a
global uniqueness rule or allow repetition only in transaction 300. Preserve
field order and multiplicity until the transaction-specific decoder handles
them. Scalar lookup sorts an ID index and uses binary search; arbitrary
duplicates have no general first/last-wins guarantee. See the supplement for
malformed-TLV prefix handling and numeric-copy edge cases. The
[transaction-specific multiplicity table](parameter-multiplicity.md) separates
scalar fields, repeated TLVs and packed lists with native reorder and
interleaving fixtures.

The numeric writer emits two bytes for values through `0xffff`, otherwise four.
The numeric reader also accepts one byte; its inspected three-byte case returns
zero. This does not make every field variable-width: for example, transfer
references are explicitly serialized as four bytes, and access bitmaps as
eight. Use the field's schema where its width is established. Field-specific
narrowing, signedness and invalid-width effects are in the
[core scalar registry](native-wire-details.md#core-scalar-width-registry). The
[presence/default registry](../presence-and-messaging/presence-defaults.md)
distinguishes omission, empty values, NUL bytes and numeric zero in each
operation context.

Evidence: V011, V013–V016, V032, V040, V042, V062; `100568b0`, `10056a90`,
`10056b90`, `10056d00`.

#### 2.2 Date parameters

The observed file-date representation is eight bytes:

| Offset | Size | Observed file-date value                                   |
| -----: | ---: | ---------------------------------------------------------- |
| 0      | 2    | Fixed base-year word 1904 (`07 70`), not the calendar year |
| 2      | 2    | Milliseconds slot, set to zero                             |
| 4      | 4    | Supplied filesystem timestamp value                        |

_Table 5: Observed file-date value fields, with their offsets, sizes and
meanings._

The file-info handler emits eight-byte creation/modification values in fields
208/209. The observed builder writes a fixed year of 1904; it does not perform
the previous guide's conversion to a timestamp's calendar year and seconds
within that year.

The [date producer/consumer registry](date-contracts.md) traces file-info,
transfer INFO and news dates. The native clock/catalogue APIs use seconds since
1 January 1904; the traced builders copy that word unchanged.

**Unresolved:** nonzero millisecond/other-year consumer behaviour, the guest
timezone basis and native rollover. A copied date is not verified UTC. This
observation does not require receivers to reject other years or certify a
general annual-conversion algorithm.

Evidence: V017; `10016ba0`, `1002c910`, `10058070`.

### 3 Fragmentation rules

The receive path accumulates payloads by transaction ID and request/reply
state. A transaction becomes available to the complete-request lookup when its
accumulated payload length reaches its recorded total length. A single frame
normally has equal total and data sizes; fragments carry successive parts of
the transaction parameter stream.

The count belongs at the start of the reassembled parameter stream, not before
every arbitrary fragment. Do not confuse application frames with separate TCP
reads: the receiver also handles partial delivery of a frame's bytes.

The native receiver appends matching-ID/request-class payloads, updates stored
type/total from later frames and dispatches when accumulated bytes reach or
exceed that total. The
[captured reassembly matrix](session-transport-contracts.md#transaction-ids-reassembly-and-correlation)
covers interleaving, collisions, changed totals/types, overshoot, underfilled
EOF and partial TCP delivery. The
[parameter parser](native-wire-details.md#parameter-parsing-and-scalar-access)
separately specifies malformed counts and truncated records. A conservative mxd
encoder should keep type, ID and total stable; this is its own writer policy.
No evidence establishes the old assertion that clients routinely fragment
folder-upload requests into dozens of frames.

The reader compares both size words against global `10094a50`. The preserved
program image initializes it to 2 MiB, but the newly traced startup assigns
**512 KiB**. See
[startup limit details](session-transport-contracts.md#receive-limit-assignment-at-startup).
Captured boundaries include equality and overshoot. Later
writes/configurability and aggregate-memory limits remain separate unresolved
requirements.

Evidence: V009–V012, V020–V021; `100590e0`, `10058e80`.

### 4 Reply semantics

Direct replies copy the request ID, set the reply marker, use type zero, and
carry a status plus a parameter stream. Empty success replies contain the zero
field count described above. Inspected error paths commonly set status 1 and
include error-text **field 100**.

A field ID and transaction type are separate namespaces. Error-text field 100
is not evidence for a standalone error transaction type 100. Likewise, a
successful operation can send an ACK and then additional notifications; these
are separate messages with different roles.

The catalogue's **ACK** label means a normal-path direct reply is visible, not
that every branch replies. **Push** means the inspected handler routes a
notification/update without a normal direct success reply. Permission failures,
flood limits and connection closure can change the outcome.

The
[native envelope table](session-transport-contracts.md#native-envelope-acceptance-and-emission)
specifies flags, reply-marker, type, status and size handling. Valid unmatched
replies are silent; invalid zero-size replies close before correlation.
Malformed framing can close the transport. There is no established universal
rule requiring transaction 111 before closing a malformed connection.

Evidence: V007, V011–V012, V022, V044, V053, V065, V067, V071–V072.

### 5 Worked example (login)

This framing example uses login `admin`, an empty password, and client-version
value 190. It deliberately includes a zero-length password field so every
record can be counted. A nonempty login name is sent bytewise complemented:
`admin` becomes `9e 9b 92 96 91`.

| Header field         | Hex bytes     |
| -------------------- | ------------- |
| Flags / reply / type | `00 00 00 6b` |
| ID                   | `00 00 01 27` |
| Error                | `00 00 00 00` |
| Total size           | `00 00 00 15` |
| Data size            | `00 00 00 15` |

_Table 6: Header fields of the worked login example, with their hex bytes._

| Parameter component    | Hex bytes                    |
| ---------------------- | ---------------------------- |
| Field count = 3        | `00 03`                      |
| Login 105, length 5    | `00 69 00 05 9e 9b 92 96 91` |
| Password 106, length 0 | `00 6a 00 00`                |
| Version 160, length 2  | `00 a0 00 02 00 be`          |

_Table 7: Parameter components of the worked login example, with their hex
bytes._

The payload length is `2 + 9 + 4 + 6 = 21` bytes, giving a **41-byte frame**.
The native writer omits zero-length fields. Omitting the empty password field
would instead give count 2, payload length 17 and frame length 37; the header
size words must change accordingly.

This is an illustrative byte layout, not a captured successful login or a claim
that an `admin` account accepts an empty password. The native credential paths
establish bytewise complement for nonempty passwords too;
[native wire details](native-wire-details.md) records the storage, comparison,
normalization and update-sentinel evidence.

Evidence: V018–V019, V023; `10011960`, `100568b0`.

### 6 Implementation checklist

1. Emit the established handshake, envelope and count-prefixed parameter stream.
2. Distinguish direct replies from notifications and retain correlation IDs.
3. Keep repeated fields and decode them according to each transaction schema.
4. Preserve text bytes until their field-specific encoding is established.
5. Exercise malformed sizes, fragmentation and error paths with wire fixtures.
6. Keep mxd's acceptance limits and defensive checks explicit as policy where
   the native behaviour remains unresolved.

These are implementation recommendations, not a claim that the native server
performs each defensive check. See the ledger's follow-up list for the
validation required before this becomes a complete interoperable specification.

## User login and presence

### Session handshake (before transactions begin)

Use the twelve-byte normal-session handshake and eight-byte response above. A
successful transport handshake does not itself authenticate the user.
Sub-version 2 is shared with the supplied historical SynHX server source.

Evidence: V003–V006, M001.

### Login (Transaction 107) – client initiates

**Request:** login name105, password106 and client version160; optional
settings102/104 control early completion. Clients send complemented login and
password bytes. The server complements the nonempty login, applies its byte
table and CR replacement, then looks up the account. It compares incoming
encoded password bytes directly against the stored encoded value. Absent/empty
105 selects the actual guest account; unknown nonempty names do not fall back
to guest. The
[captured lookup contract](native-wire-details.md#captured-login-lookup-and-guest-phases)
specifies case/high-byte/NUL handling, native account-length failures and
guest permissions with configuration provenance.

**ACK:** on success, the inspected handler writes server version **190** in
160, unnamed numeric value 161 and server name 162. These additions are not
gated by client kind or saved client version in this handler. Do not infer that
clients of the SynHX family or unknown clients require their omission. Failure
paths reply with nonzero status and field 100 text; delayed closure can follow.
The
[login extras and content sources](../presence-and-messaging/presence-messaging-contracts.md#login-extras-and-configured-content)
separate field 161's unknown meaning from banner types and server-name
loading. The [configured login-extra fixtures][login-extra-fixtures] confirm
that a nonempty 162 is emitted even for absent/zero client version. Empty name
omits 162; the native configuration destination retains at most 31 bytes,
including the tested high byte `9a`. A saved name change affects a fresh login;
no new 161/162 refresh is observed for the existing online/waiting sessions in
the accepted 20-second sequence. Field 161 stays two zero bytes across these
name and banner modes, but its purpose remains unresolved.

The [pinned Classic client baseline](../peers/classic-native-baseline.md)
accepted the unchanged two-zero-byte 161, completed 121 and roster 300, and
received 58 banner bytes. A separate
[three-case matrix](../peers/classic-field161-matrix.md) reached those stages
with 161 omitted, one zero byte, or four zero bytes. These finite observations
do not establish 161's meaning or nonzero values. The
[one ASCII server-name case](../peers/classic-server-name-162.md) also reaches
those stages after appending 162=`fixture-native` to the unchanged native login
ACK. It establishes tolerance of that value, not its UI rendering or a general
text codec.

There are two observed login-completion paths:

- With nonempty name 102 and nonzero icon 104, the handler can mark the session
  active and send access notification 354 before agreement notification 109.
- Otherwise, completion is handled through transaction 121.

Account bans, connection limits and configuration can affect admission. This
baseline does not establish every account-storage or authentication edge case.
The
[configured state fixtures](../presence-and-messaging/presence-messaging-contracts.md#captured-configured-login-states-and-visibility)
separate readiness, agreement bypass, duplicate/out-of-state requests and
observer visibility. The
[agreement configuration corpus](native-wire-details.md#captured-agreement-configurations-and-partial-login-failures)
adds missing, empty, unreadable, typed-content and size-boundary paths.

Evidence: V023–V027; `10011960`.

### Server agreement (Transaction 109) – server initiates

**Notification:** account privilege 27 selects flag 154 with value 1. With that
bit clear, the handler adds configured agreement text 101 when available; an
absent buffer can instead produce an empty 109, without 154. The inspected
sender does not add banner fields 151/152/153 to this notification.

Agreement delivery is part of the login path, but it does not imply that every
session remains inactive until transaction 121: the early-completion path above
also exists. Client prompts and acceptance interface are not established by
this server analysis.

Native configuration fixtures confirm that missing, zero-byte and unreadable
(directory) agreements produce type109 with **zero fields**, rather than an
empty value101 or a154 bypass flag. Bit27 still produces154=`0001` for each
configuration. These outcomes leave the early/delayed readiness distinction
intact: early completion needs no121; a delayed login still needs121, including
when109 has no fields or carries154.

TEXT data converts CRLF to CR; a lone LF, byte80 and embedded NUL survive. A
recognized non-TEXT Finder type preserves those bytes unchanged. TEXT65535
bytes serialize intact; TEXT65536 and non-TEXT262141 fail the loader's
respective 65535/262140 checks and subsequently yield a fieldless109.
Oversized-file warning dialogs were acknowledged before those wire observations.

A non-TEXT65536-byte agreement loads but cannot fit field101. In the retained
partial-failure fixtures, early107 sends ACK and354, stays roster-visible and
answers500, but sends no109 during three seconds. Online107/121 replay still
fails. Delayed107 sends its ACK without109, stays unlisted during three
seconds, then closes when500 is sent. A separate30-second no-trigger hypothesis
timed out; no immediate-close or universal timeout rule follows. See the
[condition and sequence evidence](native-wire-details.md#captured-agreement-configurations-and-partial-login-failures).

Evidence: V025, V027; `10011960`, `10003bd0`, `100568b0`; native-agreement-01.

### Agreement acceptance (Transaction 121) – client initiates

**Request settings:** name 102, icon 104, options 113 and automatic-response
text 215, read through the shared settings helper.

**ACK:** an empty field-list success reply is sent before settings are applied.
The handler then marks the session active, sends access notification 354 and
can send banner notification 122.

Options 113 is a bitmap in this settings context:

| Value | Meaning                         |
| ----: | ------------------------------- |
| 1     | Refuse private messages         |
| 2     | Refuse private-chat invitations |
| 4     | Enable automatic response       |

_Table 8: Values of field 113 in the settings context, with their meanings._

With bit 2 (value 4) enabled and 215 absent or empty, the default response is
exactly 52 ASCII bytes: `I'm not able to respond right now. Please try later!`.
The [two delayed-121 cases](../native-evidence/native-121-default-witness.md)
and
[eight 304 transitions](../native-evidence/native-settings-transition-witness.md)
capture these defaults and the enable/disable/update rules. Only bits 0–2
participate in the helper's three flag assignments; measured values 8 and 12
agree with that mask. This establishes the default's bytes, not a general
supplied-text codec. Transaction 108 uses 113 as an enumerated PM option, a
separate grammar.

The [settings rate-path trace](../presence-and-messaging/rate304-contract.md)
predicts a separate 26-update counter within a native-time window and a
close/temporary-ban path on the next update. The later
[captured sequence](../native-evidence/native-rate304-sequence.md) has 26
admitted updates, each followed by numbered 500, with matching 301 on subject
and observer. After a request-free interval of at least 70.103 host seconds on
the paced subject, one further update was admitted. A fresh session's 26
updates were followed by a 27th update without 500; its relay reported EOF and
the guest capture retained a reset diagnostic. One new login received the
temporary-ban error. This is a finite sequence, with no calibrated native
60-second boundary or measured ban expiry. The run failed at its final
fieldless 303 control, whose missing-target error is documented below; the
earlier paired packet observations remain independently checked.

Evidence: V026–V029; `10011ee0`, `10004d50`.

### Banner metadata (Transaction 122) – server initiates

This notification is distinct from agreement 109 and download request 212.
After transaction 121, the inspected path sends 122 when the saved client
version is at least **151** and the current loaded banner type is nonzero.

It includes four-byte banner type 152. For type `0x55524c20` (ASCII URL
followed by a space), field 153 carries the configured URL. The inspected
image-banner path can also add a configured 153 value; it does not append
inline image field 151 here. Fetching banner bytes uses transaction 212. The
earlier guide's combined agreement/banner message is not the observed 1.9
sequence.

Evidence: V025, V058; `10011ee0`.

### User access privileges (Transaction 354) – server initiates

**Notification:** field 110 contains the session's **eight-byte** access
bitmap. The inspected login-completion paths send it without waiting for a
separate request. Changed account access bytes also trigger 354 for matching
live sessions; see [native wire details](native-wire-details.md).

Evidence: V029, V070; `10011960`, `10011ee0`.

#### Access privilege bits (Field 110)

The [64-row evidence index](../accounts-and-privileges/privilege-bits.md)
records exact bitmap bytes, native update/readback IDs, known uses and
explicitly unknown positions.

Number bits in transmitted byte order: bit 0 is the most significant bit of
byte 0. The native accessor uses byte `bit >> 3` and bit position
`7 - (bit & 7)`. Do not cast the bitmap to a host integer and assume
least-significant-bit-first numbering.

The following checks are explicitly recorded in the ledger:

| Bit     | Observed use                                                   |
| ------: | -------------------------------------------------------------- |
| 0 / 6   | Delete file / folder in transaction 204                        |
| 1 / 2   | Upload / download a file                                       |
| 9 / 10  | Receive / send chat                                            |
| 11      | Create a private chat                                          |
| 20 / 21 | Read / post news                                               |
| 22 / 23 | Disconnect users / protection from disconnection               |
| 24      | Get client diagnostic information                              |
| 26      | Use requested session display name instead of the account name |
| 27      | Bypass configured agreement content (109 carries 154 = 1)      |
| 32      | Broadcast                                                      |
| 33      | Delete news article                                            |
| 34 / 35 | Create / delete news category                                  |
| 36 / 37 | Create / delete news folder                                    |
| **38**  | **Upload folder**                                              |
| **39**  | **Download folder**                                            |
| **40**  | **Send private message**                                       |

_Table 9: Privilege bits recorded explicitly in the ledger, with their observed
uses._

The
[full numbering registry](../accounts-and-privileges/privilege-contracts.md#bitmap-numbering-and-known-uses)
adds file mutation, account, upload-destination and drop-box gates, while
explicitly retaining unknown bits 12–13, 18–19 and 41–63. Account creation and
update enforce different grant rules; see
[account composition](../accounts-and-privileges/privilege-contracts.md#account-creation-update-and-batch-rules).
Private messaging uses bit 40 in this build. Do not infer private-chat owner
or administrator overrides from historical privilege names.

Evidence: V030–V031, V055–V056, V073; `10008a90`, `1000f4e0`, `10012850`,
`10013930`.

### Retrieving the user list (Transaction 300) – client initiates

**Request:** no directly required fields were identified.

**ACK:** repeated field 300 values, each containing:

| Offset within value | Size        | Field         |
| ------------------: | ----------: | ------------- |
| 0                   | 2           | User ID       |
| 2                   | 2           | Icon ID       |
| 4                   | 2           | Colour/status |
| 6                   | 2           | Name length   |
| 8                   | Name length | Name bytes    |

_Table 10: Fields of each packed user record in field 300, with their offsets
and sizes._

The enclosing field length is `8 + name_length`. The native builder includes
sessions with the online-state byte set and nonempty names. It has no
minimum-entry check. Use a zero-or-more structural grammar; this pass does not
prove that a zero-entry snapshot is reachable during an ordinary logged-in
session.

The
[ordering contract](../presence-and-messaging/presence-messaging-contracts.md#roster-snapshots-and-concurrent-updates)
records initial-login eligibility, rename recipients and a measured overlap:
one outstanding snapshot showed the old name/icon, then a later snapshot after
the recorded barriers showed the complete new pair. This is one finite
schedule, not a global atomic-snapshot guarantee.

The native 1.9 roster builder does not add subject field 115. The supplied
historical SynHX **server** roster writer does append 115, and uses the same
packed field-300 layout. This source difference does not establish what every
client of the SynHX family accepts or requires.

Evidence: V032–V034, M007; `10011870` and the preserved historical SynHX server
source `rcv.c`.

### User appearance and updates (Transaction 301 & 302) – server initiates

**301:** the inspected settings-update builder sends fields user ID 103, icon
104, colour/status 112 and name 102. Recipient filtering, self-inclusion and
ordering have not all been validated.

**302:** new teardown analysis identifies field 103 (departing UID), sent to
remaining online/ready sessions after room-leave 118 calls and deletion of
empty rooms. The departing session is removed before fan-out. Transfer workers
clean up separately when their owner is absent. See
[presence contracts](../presence-and-messaging/presence-messaging-contracts.md#disconnect-teardown-and-notification-302)
for exact static order and remaining runtime criteria.

Client list rendering and private-room UI updates are outside the server-only
evidence. The six masks produced by the status builder, including idle and
refusal flags, are now assembly-checked in the presence supplement.

Evidence: V035, V048; `10004f30`, `10005000`.

### Viewing user info (Transaction 303) – client initiates

**Request:** target user ID 103. The handler checks privilege bit 24.

**ACK:** name 102 and data 101. The data is generated operational diagnostic
text containing nickname, account, address and transfer summaries. It is not
established as an administrator-configured short profile or real-name field.
Permission and missing-user failures produce error replies.

The
[captured settings-rate sequence](../native-evidence/native-rate304-sequence.md)
ended with an administrator's fieldless 303. It returned error 1 and field 100
stating that the specified client did not exist. Omission did not select the
caller; a self-information request still needs the caller's current UID in
field 103.

Evidence: V036; `10016150`.

### Changing user settings (Transaction 304) – client initiates

The handler uses the same settings helper as transaction 121, reading
102/104/113/215. It does not implement an established “update only the supplied
fields” contract: the helper reads name/icon/options regardless of presence,
uses fallback name handling, and assigns values returned by the field reader.
Do not rely on omission to preserve every old setting.

**Push:** no direct normal success reply is visible. The settings path emits
301 updates. Flood handling can close the connection. The inspected helper
updates session name, icon, flags and text; durable account edits use the
account-update paths.

The
[ten captured field-113 cases](../native-evidence/native-settings-witness.md)
confirm absent, empty and zero clearing, three-byte defaulting, first-four-byte
handling of a five-byte value, and two measured duplicate selections. These are
operation-specific results, not a universal duplicate rule. Here 113 is a
settings bitmask; the same field in PM 108/104 is an option enumerant.

The
[same-session transition witness](../native-evidence/native-settings-transition-witness.md)
adds eight before/after cases: on the naming-allowed admin session,
omitted/empty name and icon become `***` and zero, while omitted/empty 215 with
auto-response enabled selects the exact default text. Unknown-only 8, mixed 12,
disable and re-enable cases retain their measured PM outcomes. The separate
[121 default cases](../native-evidence/native-121-default-witness.md) match the
same default bytes. The
[two-phase persistence witness](../native-evidence/native-settings-persistence-witness.md)
records the 304 transitions, unchanged named account/Prefs forks and a fresh
login on the same restarted image. The
[persistence boundary](../presence-and-messaging/presence-messaging-contracts.md#settings-persistence-boundary)
distinguishes that native observation from the shared-helper inference for 121
and from broader durability or encoding requirements.

Evidence: V028, V037–V038; `10016ad0`, `10004d50`, `10004f30`.

## Chat (public and private chat rooms)

### Sending a chat message (Transaction 105) – client initiates

**Request:** text 101, optional chat ID 114 and chat option 109.

**Push:** the handler formats text and sends 106 to eligible recipients; it
checks send-chat permission and applies flood handling. An absent or zero room
ID selects the main-chat path; a nonzero ID selects the room-specific path,
which adds field 114. There is no normal direct success ACK in the inspected
handler. A denied send can produce a type-104 notice instead of an error ACK.

Evidence: V039; `1000fc20`.

### Receiving a chat message (Transaction 106) – server initiates

**Notification:** formatted data 101 and, on the room-specific path, chat ID
114. Do not assume a separate sender UID exists in every chat message or infer
how a client renders the formatted text. The
[native room/chat matrix](../presence-and-messaging/presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes)
records exact formatting and recipient rules. Cross-client decoding policy
remains separate.

Evidence: V039, V048; `1000fc20`.

### Joining a chat room (Transaction 115) – client initiates

**Request:** chat ID 114.

**ACK:** optional subject 115 and repeated packed user records in field 300,
using the same value layout as roster replies. When adding a member, the
handler first notifies existing members with 117. Missing-chat errors use a
direct error reply. This is an explicit second context where field 300 repeats.

Evidence: V014, V040; `100183c0`.

### Leaving a chat room (Transaction 116) – client initiates

**Request:** chat ID 114.

**Push:** the inspected handler removes the member. If members remain it sends
118; if none remain, it removes the room. No direct normal success ACK was
identified. Disconnect-driven cleanup beyond this request path is unresolved.

Evidence: V041 and the captured handler `10018620`.

### Chat room notifications (Transactions 117 & 118) – server initiates

The inspected join/leave send sites construct:

- **117:** chat ID 114, user ID 103, icon 104, status 112 and name 102.
- **118:** chat ID 114 and user ID 103.

These establish the explicit request-driven paths, not every disconnect,
profile-change or client-rendering case.

Evidence: V040–V041; `100183c0`, `10018620`.

### Chat invitations (Transactions 112, 113, 114) – private chats

**112 — create chat:** reads repeated target-user field 103. It checks
private-chat creation permission, creates a room containing the inviter, sends
113 invitations to eligible targets, and ACKs with room 114 plus the inviter's
103/104/112/102. Invited users are not all reported as already joined.

**113 — invite to an existing chat:** request includes room 114 and target UID
fields 103, iterated by index. The sender builds notification 113 with room 114
and inviter UID/name 103/102. No normal direct success ACK was identified.
Refusal/automatic-response branches can send type 104.

**114 — reject invitation:** the inspected request handler reads chat ID 114.
Rejection is a formatted room-chat 106 notification; repeated rejection does
not prevent a later join. No direct normal success ACK was identified. The
[native room matrix](../presence-and-messaging/presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes)
records mixed/duplicate targets, disconnect, refusal and retry outcomes.

None of these paths establishes a universal XOR text mode specific to the SynHX
family.

Evidence: V042–V043, M005; `10017f30`, `100188e0`, `10018340`.

### Chat subject management (Transactions 119 & 120)

**120 — set subject:** request fields chat ID 114 and subject 115. The handler
updates room state and sends notification **119** with fields 114/115. No
normal direct success ACK was identified. Empty-subject handling exists; all
authorization and client presentation semantics remain unresolved.

Evidence: V041; `10018760`.

## Private messaging (instant messages)

### Sending an instant message (Transaction 108) – client initiates

**Request:** recipient user ID 103, option 113, text 101 and optional quoted
text 214. In this message context, option values are enumerants:

| Value | Interpreted case      |
| ----: | --------------------- |
| 1     | Normal user message   |
| 2     | Refuse-message notice |
| 3     | Refuse-chat notice    |
| 4     | Automatic response    |

_Table 11: Option values of the transaction 108 instant message, with their
interpreted cases._

Do not infer that arbitrary bit combinations have meaningful semantics. The
handler checks **private-message privilege bit 40**.

**ACK and delivery:** the normal path sends an empty direct success reply, then
routes type 104 as appropriate. Permission and unavailable-recipient failures
return nonzero status and error-text field 100.

For normal-message option 1, the server itself can generate refusal or
automatic-response type-104 messages using the recipient's session settings. It
suppresses delivery to a refusing recipient. Automatic response is not solely a
speculative client responsibility. Flood/spam handling can disconnect.

[Seven native PM cases](../native-evidence/native-pm-witness.md) retain quoted
delivery, refusal, automatic feedback alongside original delivery,
sender-refusal suppression, options 2/3 and empty-text suppression. The direct
ACK precedes feedback on the same sender stream. This is not a delivery receipt
or a universal cross-socket arrival-order guarantee.

Evidence: V030, V043–V045; `1000f4e0`.

### Receiving a private message (Transaction 104) – server initiates

The inspected routed-message path builds sender UID 103, name 102, option 113,
text 101 and optional quoted text 214. Refusal/auto-response paths construct
related 104 messages. Other type-104 send sites include chat-denial notices and
some kick/ban notices, so not every 104 has the same field set.

The [producer matrix](../presence-and-messaging/native-104-variants.md) defines
the known field sets and their overlaps. Field presence cannot uniquely
distinguish routed from generated feedback, chat denial from account collision,
or console from other data-only notices. Direct PM, room, account and console
fixtures are retained; native 110 ban-option notices still need a
disposable-server trial. Client rendering remains a separate question. A client
broadcast request 355 has its own captured type-355 fan-out, as
[console/broadcast evidence]( ../presence-and-messaging/native-console-broadcast.md)
confirms.

> Status note (2026-11-16):
> [`native-ban-notices.md`](../presence-and-messaging/native-ban-notices.md)
> records a disposable option-one witness, in which the target received the
> option-one type-104 notice with field 101 and then reached EOF. That
> document says that option two and post-ban Login 107 were measured in a
> separate control-only witness, and that the 1,800-second expiry and reload
> persistence remain open. The register now lists
> [GAP-074](../../gap-analysis.md#gap-074) as Resolved; its closure text
> records the kick-only and both ban-branch fixtures as documented.

Evidence: V043–V048, V071–V072.

### Legacy message board (Transactions 101, 102, 103)

These operations remain implemented in the 1.9 binary alongside threaded news:

- **101:** requires read-news privilege20. Its reply carries at most65,535
  bytes in field101; an empty board omits that field.
- **103:** requires post-news privilege21. Field101 accepts zero through8,192
  bytes inclusive; the8,193-byte fixture returns an error without changing the
  stored board. The normal path prepends a formatted segment, writes the whole
  board, ACKs and sends102 updates to eligible users.
- **102:** carries the new formatted segment in field101, rather than the
  whole retained board. It is an unsolicited server notification.

mxd may explicitly defer support, but that is an implementation scope choice,
not evidence that these operations are absent or obsolete in the oracle. The
[finite native board witness](../native-evidence/native-board-witness.md)
pairs12 successful posts with read prefixes, recipient observations and an
exact65,629-byte stopped file. Sender ACK precedes its own102 in every
successful case; no cross-socket total order or crash-durability guarantee
follows. The
[board contract](../files-and-transfers/filesystem-and-board-contracts.md#captured-legacy-board-boundaries-and-updates)
gives the measured boundaries and remaining limits.

Evidence: V047; `1000f130`, `1000f260`.

## File services (files and folders)

The control transactions below negotiate operations and transfers. Exact path,
file-list, resume and flattened-fork formats remain incomplete. The native
transfer acceptor handles client-initiated incoming connections; the assertion
that the queued server itself initiates the data connection is unsupported. The
[traced listener map](session-transport-contracts.md#configured-endpoints)
uses ordinary base/base+1 and alternative-wrapper base+2/base+3 pairs. Port
fields narrow to 16 bits; this does not guarantee usable adjacent ports at
every boundary configuration or plain-protocol operation on the alternative
pair. Captured ordinary control/data examples and alternative no-response
observations are retained separately.

Evidence: V049–V060.

### Listing files in a folder (Transaction 200) – client initiates

**Request:** path 202. The handler treats paths shorter than six bytes as the
root/no-path case and delegates listing construction.

**ACK:** repeated field 200 records use the 20-byte fixed header and name
layout in [native wire details](native-wire-details.md). That supplement also
records the structured file-path grammar. Name encoding, complete filtering and
malformed-path outcomes still require fixtures; do not substitute plain path
strings or guessed folder IDs.

Evidence: V049–V050; `100100a0`, `1002b0e0`.

### Downloading a file (Transaction 202) – client initiates

**Request:** file name 201, path 202, optional resume data 203 and transfer
options 204. The handler checks file-download permission.

**ACK:** transfer size 108, file size 207, four-byte transfer reference 107
when a transfer is created, and waiting count 116 when queued. Options value 2
follows a separate preview path; an empty preview can return size zero without
a reference. Do not require a reference in every successful response.

The field schemas do not establish that file size always equals transfer size,
that preview mode is the default for all clients, or the full resume-stream
format. Queue advancement and notification 211 are now traced in
[transfer contracts](../files-and-transfers/transfer-contracts.md). The
[controlled queue cases](../files-and-transfers/transfer-contracts.md#captured-controlled-queues)
cover response sizes, position changes and admission ordering; they do not
establish a universal FIFO or starvation guarantee.

For a nonqueued ordinary download, read the advertised transfer count rather
than waiting for server EOF. The
[native fork captures](../files-and-transfers/transfer-contracts.md#captured-completion-and-eof-behaviour)
show full delivery followed by an open data connection; owner request 214 then
ACKs and closes that connection. Buffered bytes can still be read after the
ACK; the
[cleanup race captures](../files-and-transfers/transfer-contracts.md#buffered-receipt-and-packet-ordering)
distinguish application reads from packet ordering across the two connections.
This is distinct from native upload completion, which closes the data
connection without an additional numbered control ACK.

Evidence: V051; `100121a0`.

### Uploading a file (Transaction 203) – client initiates

**Request:** file name 201, path 202, transfer options 204 and transfer size
108. The handler checks file-upload permission. Options value **1** selects
its resume path; this field is not merely unused/default upload metadata.

**ACK:** four-byte reference 107 and, on a resume path, resume data 203. The
[RFLT resume format](../files-and-transfers/transfer-contracts.md#resume-data-rflt)
is now traced, including DATA/MACR offsets and
[native continuation fixtures](../files-and-transfers/transfer-contracts.md#captured-upload-continuation-and-inconsistent-state).
Resume uses existing incomplete-file fork EOFs; replaying full forks appends
at those offsets rather than replacing them. No separate upload-queue protocol
is established by this baseline.

Evidence: V052; `100130f0`.

### Deleting a file (Transaction 204) – client initiates

**Request:** name 201 and path 202.

**ACK:** the success path replies after the native helper moves the object to
Trash; this is not a recursive erase. The handler checks separate file/folder
delete privileges 0/6. The
[captured Trash matrix](../files-and-transfers/filesystem-and-board-contracts.md#captured-move-and-trash-outcomes)
supplies ordinary/nonempty, missing-source, permission, path-derived and
Trash-name collision fixtures. Protected/root targets, interrupted failures and
broader refresh coverage remain open;
[filesystem contracts](../files-and-transfers/filesystem-and-board-contracts.md)
trace the calls.

Evidence: V053; `100140e0`.

### Creating a new folder (Transaction 205) – client initiates

**Request:** optional name 201 and structured path 202. Missing/empty name can
select the last path component as the new leaf; an existing root/target is not
an idempotent success. Native bit 5 controls creation.

**ACK:** empty success reply after creation, or status 1 with field 100 for the
captured permission, conflict and parent-resolution failures. Explicit
before/after listings prove the effects. On the recorded Mac OS 9.0.4 profile,
name handling includes a 31-byte limit, tested extension preservation and
opaque NUL/high-byte names. Short or incomplete paths can select root/a valid
prefix rather than fail strict validation. See the
[captured creation matrix](../files-and-transfers/filesystem-and-board-contracts.md#captured-native-folder-creation-and-field-202-paths)
for exact inputs, platform boundaries and cleanup. Fields 212/325 have
[separate path contracts](native-wire-details.md#field-212-files-destinations);
alias containment and general filesystem failures remain separate requirements.

Evidence: V053; `100143f0`.

### Getting file/folder info (Transaction 206) – client initiates

**Request:** name 201 and path 202.

**ACK:** the inspected branches build name 201, fields 205/206/213, file size
207 where applicable, dates 208/209 and comment 210. Some values depend on
whether the target is a file, folder, alias or other special item.

Fields 205/206 can be descriptive strings; they are not always raw
four-character type/creator codes. The ordinary file branch places a raw type
value in field 213. Do not impose a universal four-byte schema on 205/206. For
the captured file aliases, 207 is the resolved target's DATA-plus-resource
aggregate; it is not a DATA-only length or the alias file's own fork size.
Dates follow the observed eight-byte representation described above. The
[native metadata matrix](../files-and-transfers/filesystem-and-board-contracts.md#file-info-presence-and-values)
supplies exact file, folder, alias, unattached, empty and zero/unknown-tag
field-presence examples.

Evidence: V017, V054; `10016ba0`.

### Setting file/folder info (Transaction 207) – client initiates

**Request:** current name 201, path 202, new name 211 and/or comment 210.

The
[captured presence/permission matrix](../files-and-transfers/filesystem-and-board-contracts.md#captured-rename-and-comment-mutation-matrix)
distinguishes absent, empty and nonempty updates for files and folders.
Comment mutation precedes rename: a rename error can leave an applied comment.
Re-read metadata after a combined-operation error; the reply does not promise
rollback.

**ACK:** normal success and error reply paths are present. Absent comment 210
skips comment mutation; present empty/single-NUL clears it. Empty new name
skips rename. Comment mutation occurs before later rename validation, so a
rename error can follow a changed comment. See
[filesystem contracts](../files-and-transfers/filesystem-and-board-contracts.md#request-207-presence-and-mutation-order).
The captured matrix supplies permission/conflict and partial-failure fixtures;
its bounded quiet windows do not establish every later refresh.

Evidence: V053 and the captured handler `100170c0`.

### Moving files/folders (Transaction 208) – client initiates

**Request:** name 201, source path 202 and destination path 212. The
[field-specific path contracts](native-wire-details.md#field-212-files-destinations)
distinguish canonical component records from native prefix acceptance and the
reader's copied-width cap.

**ACK:** direct success/error replies are present. The
[captured move matrix](../files-and-transfers/filesystem-and-board-contracts.md#captured-move-and-trash-outcomes)
shows same-parent success, rejection of existing-name collisions, preserved
ordinary forks and native alias source/destination handling. Cross-volume,
protected-object and interrupted-filesystem behaviour require further
validation rather than guessed defaults.

Evidence: V053 and the captured handler `100177d0`.

### Creating an alias (shortcut) (Transaction 209) – client initiates

**Request:** source name 201, source path 202 and destination path 212.

**ACK:** direct success/error replies are present. Exact alias resolution and
transfer examples are documented in the
[captured alias matrix](../files-and-transfers/filesystem-and-board-contracts.md#captured-alias-and-metadata-matrix).
Nonempty 201 keeps the source basename; absent/empty 201 can derive a new leaf
from 212. An ordinary destination file can become an alias successfully. Live
aliases and chains resolve in listing/info/download; a cyclic self-alias is
classified unattached. Genuine deleted-target behaviour remains unresolved.

Evidence: V053 and the captured handler `10017c10`.

### Downloading an entire folder (Transaction 210) – client initiates

**Request:** name 201, path 202; the handler also reads resume data 203 and
options 204.

**Permission:** folder-download bit **39**, not simply file-download bit 2.

**ACK:** item count 220 and transfer size 108, with four-byte reference 107 and
queue count 116 when applicable. A no-transfer result can omit the reference.
The
[folder-download states](../files-and-transfers/transfer-contracts.md#folder-download-control-states)
establish the state-dependent controls 1/2/3, per-file lengths and resume
exchange.
[Native nested/empty/skip/resume fixtures](../files-and-transfers/transfer-contracts.md#captured-folder-downloads)
now verify the descriptor bytes and root-excluded count. The observed
aggregate is the sum of DATA/MACR lengths, excluding flattened-file and control
overhead; it is not the enclosing protocol's byte length. Upload uses a
distinct contract.

Evidence: V055, V057; `10012850`.

### Uploading an entire folder (Transaction 213) – client initiates

**Request:** name 201, path 202, options 204, transfer size 108 and item count
220.

**Permission:** folder-upload bit **38**, not simply file-upload bit 1.

**ACK:** reference 107 when a transfer is created. If there is nothing to
transfer, a successful empty field-list reply can omit it. The
[folder-upload states](../files-and-transfers/transfer-contracts.md#folder-upload-control-states)
distinguish descriptor parsing, fresh/resumed file responses, directory/skip
handling, lengths and completion.
[Native upload fixtures](../files-and-transfers/transfer-contracts.md#captured-folder-uploads)
verify nested, zero-item, partial, resumed and conflict outcomes. A final
directory/skip sends control 3 before EOF; a final file does not.
Malformed-path, descriptor-safety and durable failure outcomes remain open;
upload is not a symmetric inverse of folder download.

Evidence: V056–V057; `10013930`.

### Banner download (Transaction 212) – client initiates

**Request:** no directly required fields were identified.

**ACK when a buffer is present:** four-byte reference 107 and transfer size108.
The HTXF acceptor routes an odd reference with type2 to the banner lookup.
Metadata is advertised by122, without adding image metadata to109. The
[captured banner contracts](../files-and-transfers/transfer-contracts.md#captured-banner-formats-and-recovery)
validate raw loaded-buffer bytes, TEXT normalization and configuration
lifetime. A43-byte advertisement can deliver58 replacement bytes on the same
reference; a waiting connection can recover after failed loading and
restoration. A missing buffer raises an internal exception before ACK
construction, with bounded silence retained. A present empty GIF instead
returns size0 and a reference, then the captured attachment triggers native
service-reset RSTs on data, owner and observer. This is a native failure
observation; general reset and mxd policy remain open.

Evidence: V025, V058; `10012f40`, `1000bd20`.

### Transfer connection and reference cleanup

The inspected incoming-transfer acceptor waits for a **16-byte** header, checks
`HTXF`, then uses reference parity and a selector halfword to choose a transfer
collection. The
[transfer supplement](../files-and-transfers/transfer-contracts.md) gives the
exact offset/dispatch tables, RFLT resume records, FILP/fork grammar, queue 211
fields and worker timers. Its captured header/reference cases establish nonzero
trailing-word tolerance, ordinary-upload size replacement, collection
rejection, owner cleanup and bounded duplicate/reuse outcomes. Bytes14–15 are
consumed but unexamined; general identifier lifetimes remain separate.

The request dispatcher also accepts **214**. Its handler reads a four-byte
reference 107, invokes transfer cleanup when nonzero and ACKs. The helper
searches queued/active downloads and checks session ownership; it does not
search uploads or banners. The ACK is also sent for an absent/unknown/unowned
reference and does not certify cancellation. Race fixtures and the historical
operation name remain open.

Evidence: V059–V061; `1000bd20`, `10013040`.

## News (bulletin board system)

### News hierarchy

The server implements category/folder listing, article listing, article data,
posting and deletion. A fixed four-tier hierarchy, all parent/child
constraints, flavour support and orphan handling have not been established. The
old 101/102/103 board remains separate and implemented.

Evidence: V047, V062–V066.

### Listing news categories (Transaction 370) – client initiates

**Request:** news path 325. The handler uses its top-level listing path when
fewer than six path bytes are supplied. The
[field-325 contract](native-wire-details.md#field-325-news-paths) records its
News root, high-byte and malformed-component outcomes separately from Files
paths.

**ACK:** the native builder emits repeated category-list fields **323** when
the saved client-version value is at least **15**, and **320** otherwise. The
comparison is literally `0x000f`; mapping it to a displayed release such as
“1.5” is not established. See the
[category layouts](../news/news-contracts.md#category-list-variants) for the
distinct folder/category grammars and their opaque trailing bytes. The
[captured category matrix](../news/news-contracts.md#captured-category-versions-and-header-metadata)
verifies the 14/15 boundary through native login requests, mixed kinds,
count/valence values and nonzero opaque tails. Controlled version values and
identified historical-peer evidence are distinguished explicitly.

Evidence: V062; `100102c0`, `10005710`.

### Listing news articles (Transaction 371) – client initiates

**Request:** category path 325.

**ACK:** a **single field 321 containing the serialized article list** returned
by the database helper. It is not one repeated top-level field 321 per article.
The [nested list grammar](../news/news-contracts.md#article-list-field-321)
describes its header, article and flavour records. The
[threaded native fixtures](../news/news-contracts.md#captured-threaded-article-lists-and-partial-posts)
validate empty/multiple/branching lists, depth-first ordering, raw flags,
unsigned flavour lengths and exact cached/rebuilt bytes.

Evidence: V063; `10011370`, `100059e0`.

### Reading a news article (Transaction 400) – client initiates

**Request:** path 325, article ID 326 and flavour 327.

**ACK:** the inspected builder emits these fields:

| Field     | Observed role                      |
| --------: | ---------------------------------- |
| 328       | Title                              |
| 329       | Poster                             |
| 330       | Eight-byte date                    |
| 331 / 332 | Previous / next sibling public IDs |
| 335 / 336 | Parent / first-child public IDs    |
| 327       | Flavour                            |
| 333       | Body, when nonempty                |

_Table 12: Fields of the transaction 400 reply, with their observed roles._

Absent links map to zero. Navigation follows same-level sibling links, while
list serialization traverses children before the next sibling. Native-created
news dates use the fixed-1904-year representation. See
[body lookup and navigation](../news/news-contracts.md#reading-bodies-and-navigation).
No particular Markdown, HTML or attachment implementation follows from the
existence of a flavour field. The
[captured graph and body cases](../news/news-contracts.md#captured-threaded-article-lists-and-partial-posts)
verify these links and exact bytes, including a 65,535-byte body. Unknown or
case-changed flavours, a zero-flavour record and an unknown article share a
coarse invalid-category error; it does not prove the category is absent.

Evidence: V064; `10011580`, `10005ac0`.

### Posting a news article (Transaction 410) – client initiates

**Request:** path 325, article/parent-related ID 326, title 328, flags 334,
flavour 327 and body 333.

**ACK:** normal success is an empty reply. The handler checks post-news
privilege 21. A resolved 326 selects the parent; zero/unresolved lookup inserts
at root level. Flags 334 are stored as a raw word with unnamed bit meanings.
Creation precedes body validation. A captured missing-body request returns an
error while leaving a listed zero-flavour article, so failure does not imply
rollback. The success site sends neither a new ID nor an article notification;
discovery requires further client evidence. See
[posting effects](../news/news-contracts.md#posting-partial-effects-and-deletion).

Evidence: V064–V066 and the captured handler `10010470`.

The captured
[child append boundary](../news/news-contracts.md#captured-child-append-boundary-and-indexed-orphan)
shows that posting a 102nd child can return success while bypassing the 101st
child in list traversal. The bypassed article remains indexed and directly
readable. Category counts and article-list cardinalities can therefore differ.

### Deleting a news article (Transaction 411) – client initiates

**Request:** path 325, article ID 326 and optional recursive boolean 337.

**ACK:** direct success/error replies are present. The handler checks privilege
33. Scalar widths one, two and four are accepted; three bytes default to zero,
and longer values use their leading four bytes. Nonzero 337 requests descendant
deletion. Without recursion, the first child replaces the deleted article and
adopts its former siblings after its existing children. See the
[captured deletion contract](../news/news-contracts.md#captured-article-deletion-and-index-effects)
for parent, leaf, root-endpoint and rejected-request fixtures, exact errors,
body navigation and stored index/cache counts. Repeated deletion is an error.
Forced interrupted-storage atomicity and restart durability remain unproved.

Evidence: V065–V066; `100108a0`.

### Managing news structure (Transactions 380, 381, 382) – client initiates (admin/mods)

| Request                   | Directly read fields | Observed result                                     |
| ------------------------: | -------------------- | --------------------------------------------------- |
| 380: delete news item     | Path 325             | Success/error ACK; folder/category permission paths |
| 381: create news folder   | Name 201, path 325   | Success/error ACK; privilege 36                     |
| 382: create news category | Name 322, path 325   | Success/error ACK; privilege 34                     |

_Table 13: Transactions 380, 381 and 382, with their directly read fields and
observed results._

Deletion rejects the configured root, checks bit 37 for native directories and
bit 35 for ordinary files, then moves the object to native Trash. Creation
rejects an existing target; category creation initializes an HLNZ version-2
file. See
[structure effects and conflicts](../news/news-contracts.md#structure-operation-effects-and-conflicts)
for alias-kind limits, partial writes and remaining fixtures. No fixed
two-level hierarchy or permanent recursive erase is established.

Evidence: V065–V066; `10010b70`, `10010ee0`, `10011110`.

## Administrative functions

### User account management – client initiates (admin) (Tx 350–353)

These are request/reply operations with permission checks:

| Request             | Input fields identified                                        | Reply behaviour               |
| ------------------: | -------------------------------------------------------------- | ----------------------------- |
| 350: create account | Name 102, login 105, password 106, bitmap 110, extra field 111 | Success/error ACK             |
| 351: delete account | Login 105                                                      | Success/error ACK             |
| 352: get account    | Uncomplemented lookup name 105                                 | Account fields or error reply |
| 353: update account | Name 102, login 105, password 106, bitmap 110, extra field 111 | Success/error ACK             |

_Table 14: Input fields of account transactions 350 to 353, with the reply
behaviour of each._

The meaning of extra field **111** is unresolved. The inspected
[Classic account constructors](../accounts-and-privileges/classic-account-constructors.md)
omit it; that bounded client trace does not establish a reserved or unused
field. Account credentials, copy limits and update defaults are now traced in
[native wire details](native-wire-details.md). Changed privilege bytes
propagate to matching active sessions through 354; effective identity/access
changes can also emit roster updates. The
[live-account fixtures](native-wire-details.md#captured-live-account-changes-and-server-restart)
record two-session updates/deletion, late 302 removal and persistence across
normal server application restart. Rename/protection variants, interrupted
writes and broader durability guarantees still need further evidence.

Request **352** uses uncomplemented lookup bytes in 105, unlike the
complemented inputs of 350/351/353. This asymmetry is established by the
[account lookup fixtures](native-wire-details.md#account-lookup-name-encodings).
For **352**, the observed response includes name 102, complemented lookup
bytes in 105, an eight-byte privilege bitmap 110, and password-presence
handling:

- If a password exists, field 106 contains the single literal byte **`x`**
  (`78`). It is a placeholder, not the stored password or a recoverable
  encoding.
- For an empty password, the zero-length writer omits field 106.

For update **353**, exactly one NUL byte (`00`) in field 106 selects
preservation of the existing encoded password, clipped to 31 bytes. Literal `x`
does not preserve it. Missing/empty 106 clears the newly built password value.
Other missing fields are not general sparse-update instructions; see the
[captured account-update matrix](native-wire-details.md#captured-account-replacement-and-password-boundaries).
It verifies full 32-byte network password replacement/login, sentinel
clipping, literal-`x` replacement, and clearing of omitted
name/attribute/privilege fields. The
[identity contrasts](native-wire-details.md#captured-account-identity-and-protection-contrasts)
add exact/ASCII-case duplicate rejection, lookup-case echo in 352, bit-23 kick
protection versus account deletion, and self-deletion with ACK before notice.
The original accounts are not used as deletion targets.

Evidence: V067–V070; `100146f0`, `100149e0`, `10014bc0`, `10014df0`.

### Disconnecting a user (Transaction 110 & 111) – admin/server use

**110 request:** target UID 103, option 113 and optional data 101. The handler
checks requester privilege 22 and target protection privilege 23.

**ACK:** direct success/error paths are present. Options **1** and **2** select
distinct branches; do not model them as independently combinable guessed IP/
account ban bits. The option-2 path reads optional field 101. A separate
[configured-address ban witness](../native-evidence/native-configured-ban-witness.md)
observes Options > Ban > Save sending the permanent data-only 104 to both
connected clients and then closing them; that case sends no request 110.

Option 1 adds an in-memory address ban with a GetDateTime-plus-1800 seconds
deadline. Option 2 writes the persisted address-ban list. A
[one-restart witness](../native-evidence/native-ban-reload-witness.md)
preserves the stored row and observes fresh Login107 rejection. The later
temporary-ban observation covers immediate rejection and post-deadline
acceptance; it does not measure the exact cutoff. Other restart, range and
clock-boundary combinations remain untested.

The
[later first-epoch witness](../native-evidence/native-ban-expiry-first-witness.md)
records kick-only/reconnect, a protected target's error and bounded continued
operation, and immediate valid Login107 rejection after a temporary ban. The
[later witness](../native-evidence/native-ban-expiry-later-witness.md) accepts
the same valid login after 2,032 host-relative seconds. The missed pre-window
control and unmeasured exact cutoff remain explicit; 1,800 seconds is
source-derived.

The [captured option-1 fixture](../presence-and-messaging/native-ban-notices.md)
delivered the data-only temporary-ban 104 and disconnected its target; the
administrator's ACK preceded 302 in both packet views. A later probe completed
the handshake but sent no login. The
[Ghidra trace](../presence-and-messaging/presence-messaging-contracts.md#kick-options-and-native-console-messages)
places the two list checks at the start of 107, before credentials. A ban does
not imply refusal of the initial handshake in this captured case.

The inspected option-1/2 notice branches send **104** before closing the target
transport. A plain kick can close without such a notice. Do not require an
emitted transaction 111 for every kick or every malformed connection.

**111:** a native shutdown-dialog producer is now established: nonempty
shutdown text is sent as field 101 to online/ready sessions before the shutdown
path. It is conditional, not mandatory for every kick or malformed connection.
[Presence/admin contracts](../presence-and-messaging/presence-messaging-contracts.md#kick-options-and-native-console-messages)
record the producer and the distinct temporary/persisted address-ban branches.

Evidence: V071–V072; `10015e70`.

### Broadcasting a message (Transaction 355) – admin/server initiated

**Client request:** data 101. The handler checks broadcast privilege 32.

**ACK and delivery:** it ACKs the initiator and sends **355**, with sender UID
103, name 102 and data 101, to other active connected users. This inspected
path is not a universal conversion to type 104. Spam/flood branches can
interrupt processing.

The newly traced console message dialog uses type **104** with data 101 only,
through online/ready fan-out. It does not reuse this client-originated 355
schema. Client presentation and delivered sequences still require fixtures.

Evidence: V046, V048; `1000f990`.

### Additional admin privileges note

A named privilege or an available transaction is not evidence of an
unrestricted admin override. In particular, entering or closing arbitrary
private chats, complete account-change propagation and every protected-user
interaction remain unresolved beyond the explicit checks recorded above.

Evidence: V070, V073.

## Additional observed requests and scope gaps

The inspected dispatcher contains **45 request handlers**, including operations
omitted from the previous guide:

| Type | Established observation                                                                                        | Remaining uncertainty                                      |
| ---: | -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| 214  | Reads reference 107, invokes cleanup and ACKs                                                                  | Complete cancellation effects and historical name          |
| 348  | Account enumeration; repeated 101 values contain account TLVs, with native fixtures                            | Historical name and wider snapshot atomicity               |
| 349  | Captured sequential nested account mutations, permission/default rules and partial effects                     | Protected identity variants and arbitrary storage failures |
| 500  | Handler sends an empty direct ACK; [one modern client](request-500-contract.md) uses it after a quiet interval | Historical-client behaviour and universal scheduling       |

_Table 15: Established observations and remaining uncertainty for each
additional request, by type._

The [operation contracts](operation-contracts.md) catalogue all 45 handlers,
normal reply directions, session-state eligibility and the recovered 348/349
nested account grammar.

The
[captured batch matrix](operation-contracts.md#captured-batch-account-framing-and-partial-effects)
includes type-104 collision notices followed by success, permission failures
after earlier mutations, per-entry 512-byte clipping and rename collisions that
overwrite the destination and continue before a final error. Inspect resulting
account state before retrying; final ACK status is not an atomicity guarantee.

Transaction 122 is an additional server-originated banner notification. Neither
missing documentation nor lack of a client-request handler proves a server
notification is unsupported. The ledger's dispatcher map and send-path table
are the coverage inventory for this revision.

The following are still needed before this guide is a complete wire contract:

- Remaining path/name/collision/alias cases, transfer interruption/durability
  and configured endpoint boundaries beyond the retained native fixtures.
- Per-field encoding, scalar, multiplicity, presence, length and date rules,
  remaining privilege bits and failure/partial-effect boundaries.
- Presence, room/invitation/topic, broadcast, old-board and remaining news
  flag/flavour/date/hierarchy cases.
- Wider timer and teardown/queue ordering, including room and concurrent
  transfer cleanup beyond the captured 302/211 and account cases.
- Remaining account identity/protection and opaque field meanings.
- Wider identified-peer coverage, extra-field/text tolerance, and separate
  mxd revision/test/release acceptance evidence.

Unresolved details are not permission to reproduce the old speculative
behaviour in mxd. Record any chosen implementation policy separately and
validate it against the intended peers.

Evidence: V001, V048–V074, M002–M009.

## References and correction traceability

- [Baseline validity ledger][ledger]: immutable pre-correction claims,
  addresses, input snapshots and remaining validation work.
- [Captured evidence][evidence]: query plans, raw MCP replies, assembly and
  decompilations tied to the binary hash above.
- [Correction map](../provenance/baseline-correction-map.md): disposition of
  every ledger entry in this revision.
- [Internal compatibility matrix](../mxd/compatibility-matrix.md):
  observed peer behaviour, mxd policies and unverified implementation/test
  claims.
- [Error outcomes](error-outcomes.md): explicit wire failures, derived reply
  bytes and the separate native internal exception/message domains.
- [Identified client source](../peers/identified-client-source.md): pinned shx
  0.1.48 source observations and bounded host callback tests.
- [Filesystem and board contracts](../files-and-transfers/filesystem-and-board-contracts.md):
  target variants, Trash deletion, metadata mutation order, moves/aliases and
  old news.
- [Core field schemas](core-field-schemas.md): types, cardinalities, defaults
  and conditions for core requests, replies and notifications.
- [Session transport contracts](session-transport-contracts.md): endpoints,
  handshake failure paths, sub-version-3 handover and startup limits.
- [Presence and messaging contracts](../presence-and-messaging/presence-messaging-contracts.md):
  settings, status masks, teardown, PM/room routing, shutdown and console
  messages.
- [News contracts](../news/news-contracts.md): category/article record
  boundaries, flavour selection, native dates and mutation ordering.
- [Transfer contracts](../files-and-transfers/transfer-contracts.md): HTXF
  dispatch, fork streams, resume records, queue notifications, cleanup scope
  and worker timers.
- [Operation contracts](operation-contracts.md): complete dispatcher inventory,
  session-state dispatch, frame edge cases and batch account operations.
- [Native wire details](native-wire-details.md): traced parser, credential,
  account, path, file-list, privilege and timer details.
- [Gap analysis](../../gap-analysis.md): open questions, implementation impact
  and evidence required to complete the specification.

The historical SynHX server source comparison is the supplied
`../synhxd/server/` archive set, with selected trunk revision 1.1 and declared
default branch 1.1.1. It is not a claim about every client of the SynHX family
or a currently released server.

[ledger]: ../baseline-validity-ledger.md
[evidence]: ../../evidence/hotline-server-1.9/

[login-extra-fixtures]: native-wire-details.md#captured-login-extras-configuration-bytes-and-refresh
