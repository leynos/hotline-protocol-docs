# Hotline 1.9 native wire details

This supplement records further static analysis of the exact `HLserver19`
binary identified in [the guide](protocol.md). It refines the baseline without
rewriting the immutable validity ledger. Receiver/serializer analysis is
distinguished from the native captures cited below. Malformed-input tolerance
does not prescribe mxd policy. Open requirements remain in [the gap register][gaps].

## Parameter parsing and scalar access

Evidence: [index construction][index], [ID lookup][lookup],
[indexed copying][copy], and the baseline numeric reader `10056b90`.
Related: GAP-014–GAP-019.

| Input or operation | Observed helper behaviour |
| --- | --- |
| Fewer than three remaining payload bytes | Indexes zero fields, including the canonical two-byte zero count. |
| Declared count with incomplete next four-byte record header | Stops indexing; retains preceding complete records. |
| Record value extends beyond payload end | Stops indexing before that record; retains the valid prefix. |
| Bytes after the declared records | Not indexed as further fields. |
| Unknown field ID | Indexed; a handler ignores it unless it requests or iterates it. |
| Scalar lookup of ID zero | Returns absent. |
| Duplicate scalar IDs | Lookup sorts an index by ID and uses binary search plus a cached match; no general first/last-wins guarantee. |
| Indexed iteration | Uses original record positions, preserving wire order and repetition. |
| Numeric value length 1 / 2 / 4 | Reads an unsigned big-endian value of that width. |
| Numeric value length 3 | Returns zero. |
| Numeric value longer than 4 | Copies the first four bytes into the generic numeric reader. |
| Absent or zero-length numeric field | Returns zero through this accessor. |

These are helper outcomes. They do not establish that every enclosing request
succeeds: a handler can reject the resulting missing/default value. Preserve
order and duplicates in the codec, then apply the operation's cardinality.
An implementation may reject malformed TLVs more strictly, but must identify
that as its own acceptance policy.

### Captured TLV and scalar boundaries

The [native framing corpus](../mothra/evidence/gap-remediation/2026-11-12/native-framing-01/manifest.json)
checks 62 cases against both host and guest packet captures. Settings requests
304 expose the indexed values through notification 301; request 500 is used
only to observe dispatch/ACK behaviour, not to prove another handler's parsing.

| Captured payload class | Settings outcome |
| --- | --- |
| One count byte; canonical zero count; count one without any record | No indexed settings: name `***`, icon zero. |
| Count zero followed by a complete name/icon record stream | Trailing records ignored; same defaults. |
| Next record header has zero, one, two or three bytes | Stops before the incomplete record. |
| Declared value length three but only two bytes remain | Incomplete value ignored; defaults when no earlier complete record exists. |
| Complete name before truncated header or missing second record | Complete name retained, missing icon defaults to zero. |
| Count one but two complete records; count three but two complete records | First case applies only name; second applies both complete name and icon. |
| Complete declared stream followed by five garbage bytes | Complete indexed fields used; trailing garbage ignored. |
| Unknown field 65000, field zero, or empty unknown field before known settings | Known settings remain accessible. |
| Count 65,535 with 65,534 empty field-zero records then name | Final complete name is found. |
| Name value length 65,535 | Handler clips effective name to 31 bytes. |

The settings icon tests cover zero through five input bytes and high-bit
boundaries. They confirm zero for three bytes and the first-four-byte rule for
five bytes. Assignment retains the low 16 bits, but **301 emits the stored icon
through a signed-short promotion**: `7fff` emits `7fff`, `8000` emits
`ffff8000`, and `ffff`, `0000ffff` and `ffffffff` emit `ffffffff`.
Input `00018000` emits `ffff8000`; `00010000` emits `0000`.
Builder [10004f30](../mothra/evidence/gap-remediation/2026-11-12/batch-02/queries/B02-D-10004f30.c)
independently shows that promotion. This is specific to this icon sender; its
UID load is unsigned, and packed roster records retain a two-byte icon.

Duplicate icon sequences `[1,2]`, `[2,1]`, `[1,2,3]` and `[3,2,1]` emitted
2, 1, 3 and 1 respectively in these four cases. These observations do not
replace the sorted-lookup analysis with a universal last-wins rule (GAP-017).
The initial all-ones test incorrectly expected a two-byte output; that
disproven expectation and its unchanged transcript are retained separately.
Other handlers' missing-value errors and field-specific widths remain separately
tracked; structural tolerance is not universal transaction success.

## Credential bytes, lookup and account updates

Evidence: login `10011960`, account create `100146f0`, update `10014df0`,
retrieval `10014bc0`, [account reader][account-read],
[account writer][account-write], [native password setter][password-set],
[native password recovery][password-recover], and [byte comparison][compare].
Related: GAP-016, GAP-018, GAP-019, GAP-022, GAP-023, GAP-071–GAP-073.

A nonempty password is represented by **bytewise complement**, as is a
nonempty login name. For plaintext bytes `secret`, field 106 is
`8c 9a 9c 8d 9a 8b`. This example is derived from the code, not a successful
network capture. It makes no claim about an account named `admin` existing.

The native setter complements the password before storing it. Account files
are read and written verbatim; login compares the incoming field-106 bytes
against those stored bytes with an exact-length equality check. A separate
native consumer complements the stored bytes to recover the password. There
is no password hashing in these traced paths. mxd's internal storage scheme
is a separate implementation choice.

### Account record and field schema

The account reader requests a 734-byte (`0x2de`) record and checks its leading
big-endian 16-bit version against 1. The offsets below describe the internal
account record, **not** a new on-wire struct. Wire values remain ordinary TLVs.

| Wire field | Stored length offset | Stored bytes offset | Handler copy cap | Meaning |
| ---: | ---: | ---: | ---: | --- |
| 102 | `0x210` | `0x212` | 64 bytes | Account display name |
| 111 | `0x254` | `0x256` | 64 bytes | Opaque account attribute; its human meaning remains GAP-071 |
| 105 | `0x298` | `0x29a` | 32 bytes | Login; complemented on input before storage |
| 106 | `0x2bc` | `0x2be` | 32 bytes | Password in complemented representation |
| 110 | None | `0x004` | 8 bytes | MSB-first access bitmap |

Create/update handlers start with a cleared record, set its version to 1 and
copy these fields. A missing field is therefore not generally a partial-update
instruction. Missing/empty name, attribute or bitmap can clear their values;
permission and account-identity checks can still reject the operation. Do not
invent sparse-update semantics for 353.

| Field 106 in request 353 | Observed password result |
| --- | --- |
| Absent or zero length | Empty password in the newly built record. |
| Exactly one byte `00` | Reads the existing account and preserves its encoded password, clipped to at most 31 bytes. |
| Literal byte `78` (`x`) | Stores `78`; it is not the preservation sentinel. |
| Other nonempty bytes | Stores the copied encoded value, up to the handler's 32-byte cap. |

Reply 352 uses literal `x` to indicate that a password exists, and omits 106
for an empty password. That output is a **presence placeholder**, not an input
value to echo when preserving the password. The one-byte NUL update sentinel
corresponds to complemented plaintext byte `ff`; that byte cannot be treated
as an ordinary one-byte replacement password through this branch.

The native local setter caps passwords at 31 bytes, while the network account
handlers copy up to 32. Preserve this distinction rather than declaring a
single universal limit. The captured update matrix below verifies the full
32-byte network replacement/login round trip and the sentinel's 31-byte clip.
Restart persistence and failed writes still need runtime checks.

Field 111 is stored by create/update handlers but is not included in the
inspected 352 retrieval or 348 enumeration output. The newly inspected native
UI range `10018c60`–`10019690` concerns ban editing and does not supply an account
label. The identified shx account constants also do not name 111. Its meaning
remains opaque; these bounded negatives are not proof of no use anywhere.

### Account lookup name encodings

Field 105 is operation-specific. Login 107 and mutation requests 350/351/353
complement incoming login bytes before their lookup/storage use. **352 instead
passes its input name directly to the account reader, then complements it for
the reply.** Handler `10014bc0` performs the read before its complement loop.
Do not apply the output encoding to that request automatically.

The [native core fixtures][native-core] demonstrate both outcomes: complemented
`fixture-low` in 352 receives status 1 with a missing-account message;
uncomplemented `fixture-low` succeeds, returning complemented 105, literal `x`
in 106 and an eight-byte zero bitmap. The known nonempty password itself is
never returned by 352. Account create/change/login fixtures independently prove
the complemented password representation against the native stored record.

The same corpus records 111 absent, empty and `opaque-c` in update requests.
The first two store length zero; the value case stores eight bytes at `0x256`.
All three 352 replies omit 111. This establishes those storage/output cases,
not the attribute's human meaning or absence of every later consumer.

### Login lookup transformations

Absent/empty field 105 selects the literal account name `guest`. A nonempty
105 is copied into a Pascal-string destination (up to 32 content bytes),
complemented, transformed through the 256-byte table at `100946c8`, and has
carriage return byte `0d` replaced with hyphen `2d` before lookup.

The table maps ASCII `A`–`Z` to `a`–`z`, but also transforms high bytes; it is
not equivalent to ASCII-only lowercasing or Unicode case folding. The exact
[table bytes][normalization] are retained as evidence. For example,
`80 → 8a`, `ae → be`, `cb → 88`, and `e5 → 89`. The table and transformation
order are authoritative for this binary; the character encoding of each peer
remains a separate evidence question. Unknown nonempty accounts do not become
`guest` merely because lookup fails.

### Captured login lookup and guest phases

The [native authentication corpus][auth-corpus] retains missing-guest,
configured-guest and verified cleanup phases. The original guest account is
absent: admin352 returns status1. Three login107 probes with absent105,
zero-length105 and explicit complemented `guest` each return status1 with
field100 `Incorrect login.`. After creating an owned guest with an empty
password and zero privileges, the same three inputs succeed and354 contains
that zero bitmap. An unknown nonempty account with the same empty-password
input still fails. Thus missing/empty login selects the guest account; it does
not synthesize guest permissions or redirect every failed lookup to guest.

| Input/control | Captured result |
| --- | --- |
| Complemented `AdMiN` or `ADMIN`, correct fixture password | Login succeeds; matches the lowercase account. |
| Complemented `m-auth` + CR + `cr` | Succeeds against stored key `m-auth-cr`. |
| Complemented key ending in byte`80` | Succeeds against the separately created/stored key ending in`8a`. This corroborates the native table, not Unicode folding. |
| Decoded NUL at the start, middle or end of `admin`; decoded NUL alone | Status1 `Incorrect login.` even while empty-password guest login succeeds. A NUL-containing value is distinct from absent/zero-length105. |
| Owned 31-byte account name | Account creation,352 readback and107 login succeed. |
| Owned 32-byte account name | Creation and352 readback fail with status1 and native bad-file/folder-name diagnostics. Login also returns status1 with that diagnostic, rather than `Incorrect login.`. |
| More than32 login bytes with the same32-byte prefix | Same diagnostic naming the clipped32-byte key. The helper copy cap is32; this does not establish a valid32-byte account on this guest. |

For nonempty105, clipping precedes complement, table conversion and CR-to-hyphen
replacement. Table byte0 maps to0; these operations do not interpret it as a
C-string terminator or turn its nonzero Pascal length into an empty login.
The raw request bytes,14 identity-checked Ghidra queries and five positive native
734-byte account records retain the transformations' provenance. Native
UserData keys, display names, encoded fixture passwords and privilege bitmaps
are checked independently of successful ACKs. The high-byte catalogue path is
rendered by SleuthKit in decomposed Unicode; that display is not a wire-encoding
rule. The 32-byte filename failure is scoped to the retained native filesystem
path; it is not a general claim that every Hotline account backend has that cap.
The session's later stored-key copy cap31 remains distinct from the lookup cap32.

All five temporary accounts are removed with351, followed by status1 readbacks;
the original missing-guest outcome is restored. Positive live snapshots do not
prove restart durability or exhaustive filesystem absence. Password rejection,
malformed lookup errors and configured account privileges remain distinct.

[auth-corpus]: ../mothra/evidence/gap-remediation/2026-11-13/native-auth-01/manifest.json

### Changes to connected accounts

[The propagation helper][propagation] walks sessions matching the original
account login. It copies changed access bytes and sends **354** with field 110
when the bitmap changes. It refreshes stored account/display identity with a
31-byte cap. Display-name selection also depends on the account's naming
privilege, and a changed effective identity/access state triggers the roster
update helper `10004f30`. This demonstrates live propagation for the traced
update path; exact queue delivery and restart behaviour remain untested.

## Structured file paths and file-list entries

Evidence: [last-component parser][path-last], [directory traversal][path-walk],
[path resolver][path-resolve], and [file-list builder][file-list].
Related: GAP-047, GAP-048. News field 325 uses this structured resolver under
its own root; [news structure contracts](news-contracts.md#structure-operation-effects-and-conflicts)
record its distinct operation checks and alias uncertainty.

The structured file path begins with a big-endian 16-bit component count.
Each component contains a two-byte word followed by a Pascal byte string:

| Relative offset | Size | Component value |
| ---: | ---: | --- |
| 0 | 2 | Component word; do not assign unsupported semantics |
| 2 | 1 | Name length `n` |
| 3 | `n` | Name bytes |

Directory traversal skips the word and uses the byte string. Last-component
extraction can return that word to its caller. A one-component path `foo` with
a zero word is `00 01 00 00 03 66 6f 6f`. An empty root is conventionally a
zero count, but these helpers' short-buffer handling must not be mistaken for
a complete canonical-root or malformed-path validation contract. In particular,
the last-component helper requires at least six bytes and traversal can stop
at an invalid component rather than reject the entire value. Alias resolution
and name sanitization are separate helper steps.

Each field **200** in a file-list reply contains this unpadded record:

| Offset | Size | Value |
| ---: | ---: | --- |
| 0 | 4 | File type |
| 4 | 4 | Creator |
| 8 | 4 | File aggregate fork size, immediate folder valence, or zero for unresolved alias |
| 12 | 4 | Zero |
| 16 | 2 | Zero |
| 18 | 2 | Name length `n` |
| 20 | `n` | Name bytes |

Thus the value length is `20 + n`; the outer TLV length excludes its own
four-byte header. Records repeat as field 200. The builder skips entries with
its enumerator flag bit zero set and has an additional conditional type filter.
It does not itself sort entries. The native alias matrix below supplies exact
file/folder/alias, non-ASCII, empty and multi-entry examples. The conditional
filter is a static branch; these captures do not prove every filter mode.

### Captured listing kinds and enumeration order

The [alias corpus](../mothra/evidence/gap-remediation/2026-11-13/native-alias-01/manifest.json)
checks exact field-200 grammar and ordered records against paired TCP streams.
An empty directory returns no 200 fields. Each repeated record has its own
20-byte header and exact name bytes, with no alignment padding. Names include
high byte `9a`; earlier directory fixtures supply NUL/control-byte names.

Ordinary files expose raw type/creator and DATA plus resource-fork length:
the 16-byte DATA/317-byte resource example has value 333. Folders expose `fldr`,
zero creator and immediate child count. Live aliases expose the corresponding
resolved file/folder metadata and value, with their own entry names. No separate
wire alias flag is emitted. Unattached `self` exposes `alis`, zero creator and
value zero, despite nonempty physical forks.

The owned root's recorded sequence is `A`, `B`, `C`, `D`, `dir`, `empty`, `file`,
`hi-9a` (the last byte is binary `9a`), `m-al20-absent`, `m-al20-empty`,
`m-al20-zero`, `same`, `self`, `unknown-tags`, `zero-tags`. Both alias directories
A/B return `dir`, `file`. D returns `derived-dir`, `derived-empty`,
`derived-link`, then the high-byte name. This is the captured native order;
do not infer a Unicode or host-filesystem comparator from these examples.

`1002cb20` obtains records using `PBGetCatInfoSync` with positive indices from
one upward. It appends each result to a cache. `1002ce00` walks that cache;
`100055a0` emits records in that order without a further sort. The cache uses
four-byte alignment internally, but the emitter copies exactly `20 + n` bytes.
Native catalogue enumeration therefore determines wire order on this profile.
The invisible-entry bit and conditional `HTft` filter can remove entries without
changing the remaining sequence. Other OS/filesystem orders and unexecuted
filter modes are not established by this corpus.

### Captured field 202 directory-creation boundaries

The [native create/path matrix](filesystem-and-board-contracts.md#captured-native-folder-creation-and-field-202-paths)
checks root/nested/non-ASCII and invalid-prefix cases against real before/after
listings. It includes absent/short root paths, count/length truncation,
zero-length components, nonzero component words, unused trailing bytes and
literal dot/dot-dot traversal. These field-202 outcomes do not establish
field-212/325 equivalence or alias containment. Name 201 handling is separate:
absent/empty can derive a leaf from 202; one NUL byte can remain a nonempty
native name. Native path/name bytes are not interchangeable with rendered TSK
paths, POSIX components or C strings.

## Privilege access and connection timers

Evidence: [general accessor][priv-general], [file accessor][priv-file],
[news accessor][priv-news], baseline dispatcher `1000acf0`, and
[clock helper][clock]. Related: GAP-005, GAP-031, GAP-032, GAP-045.

All three privilege accessors in this binary have the same body: read byte
`session + 8 + (bit >> 3)`, shift by `7 - (bit & 7)`, and mask to one bit.
Their first argument is unused. These helpers do not perform inheritance,
filesystem lookup, or an administrator bypass. The
[privilege registry and composition](privilege-contracts.md) now cover all 64
numbered positions, separating known checks from unknown meanings. Account
creation, update and batch paths have distinct grant rules; identical accessors
alone do not prove that every operation has identical policy.

The dispatcher clock calls Mac `GetDateTime`; these comparisons use seconds:

| Condition | Observed dispatcher action |
| --- | --- |
| Not online, last activity age at least 61 seconds | Close path. |
| Recorded authentication-failure time nonzero and age greater than 30 seconds | Close path. |
| Active session, last activity age greater than 600 seconds | Calls idle-state setter `10005400` with 1; this branch does not itself disconnect. |
| More than 120 processed requests in the 60-second flood window | Flood/close path with a 1,800-second ban argument. |

A selected complete logical request refreshes activity; TCP byte arrival and
incomplete fragments do not update that slot in the traced receive/dispatch
paths. Request 500 has an empty-ACK handler, which makes it usable as a probe
without establishing a client's intended schedule. See the
[activity boundary table](session-transport-contracts.md#activity-clocks-and-incomplete-input)
and [distinct flood counters](session-transport-contracts.md#flood-and-connection-burst-counters)
for exact comparisons, bounded negative findings and remaining timer fixtures.

[gaps]: gap-analysis.md
[index]: ../mothra/evidence/gap-remediation/2026-11-12/batch-01/queries/B01-D-10056e20.c
[lookup]: ../mothra/evidence/gap-remediation/2026-11-12/batch-01/queries/B01-D-10057180.c
[copy]: ../mothra/evidence/gap-remediation/2026-11-12/batch-01/queries/B01-D-100565b0.c
[account-read]: ../mothra/evidence/gap-remediation/2026-11-12/batch-01/queries/B01-D-100073c0.c
[account-write]: ../mothra/evidence/gap-remediation/2026-11-12/batch-01/queries/B01-D-100075e0.c
[password-set]: ../mothra/evidence/gap-remediation/2026-11-12/batch-01/queries/B01-D-10007780.c
[password-recover]: ../mothra/evidence/gap-remediation/2026-11-12/batch-01/queries/B01-D-10003170.c
[compare]: ../mothra/evidence/gap-remediation/2026-11-12/batch-01/queries/B01-D-1006cd80.c
[normalization]: ../mothra/evidence/gap-remediation/2026-11-12/batch-01/queries/B01-M-login-normalization.json
[propagation]: ../mothra/evidence/gap-remediation/2026-11-12/batch-02/queries/B02-D-10005d30.c
[path-last]: ../mothra/evidence/gap-remediation/2026-11-12/batch-01/queries/B01-D-1006e820.c
[path-walk]: ../mothra/evidence/gap-remediation/2026-11-12/batch-01/queries/B01-D-1002e3d0.c
[path-resolve]: ../mothra/evidence/gap-remediation/2026-11-12/batch-01/queries/B01-D-1002e8b0.c
[file-list]: ../mothra/evidence/gap-remediation/2026-11-12/batch-01/queries/B01-D-100055a0.c
[priv-general]: ../mothra/evidence/gap-remediation/2026-11-12/batch-02/queries/B02-D-10008a90.c
[priv-file]: ../mothra/evidence/gap-remediation/2026-11-12/batch-02/queries/B02-D-10008ab0.c
[priv-news]: ../mothra/evidence/gap-remediation/2026-11-12/batch-02/queries/B02-D-10008ad0.c
[clock]: ../mothra/evidence/gap-remediation/2026-11-12/batch-01/queries/B01-D-10057d00.c

[native-core]: ../mothra/evidence/gap-remediation/2026-11-12/native-core-01/manifest.json

## Captured agreement configurations and partial login failures

The [agreement corpus](../mothra/evidence/gap-remediation/2026-11-13/native-agreement-01/manifest.json)
retains 42 accepted cases:40 ordinary/bypass state cases across 10 configurations
and two oversized-field cases. It also retains 28 setup/control reports,
12 exploratory reports and 16 identity-checked read-only Ghidra queries. The
server remains the same Mac PPC oracle and live emulator PID used by the
preceding authentication corpus. The original 245-byte TEXT agreement is backed
up, then restored and independently read at the application path. The temporary
bit 26/27 account is deleted and 352 subsequently fails to read it.

For each ordinary configuration, both admin and the bypass account take both
early and delayed completion paths. Every case includes observer rosters,
duplicate online 107/121 errors, a successful 500 and post-close observations.
Delayed cases wait three seconds before 121, then receive its ACK,354 and 122;
early cases receive ACK,354,109 and are visible before any 121. Existing observer
301 and subject 354/109 observations span different TCP connections; they do not
establish a total delivery order or atomic roster subscription.

| Configuration at application-relative Agreement.txt | Ordinary 109 | Bypass 109 |
| --- | --- | --- |
| Original/restored 245-byte TEXT | Field 101 with 242 bytes after CRLF conversion | 154=`0001` |
| Missing path, with native missing-file reload diagnostic | Zero fields | 154=`0001` |
| Present zero-byte TEXT | Zero fields | 154=`0001` |
| Directory at the exact path, positively verified in HFS+ | Zero fields | 154=`0001` |
| 34-byte TEXT containing CRLF, loneLF,80 andNUL | 32 bytes; only CRLF changes | 154=`0001` |
| Same 34 raw bytes, native typeBMP | All 34 bytes unchanged | 154=`0001` |
| TEXT 65535 bytes | Field 101 with 65535 bytes | 154=`0001` |
| TEXT 65536 bytes | Warning at 65535, then zero fields | 154=`0001` |
| BMP 262141 bytes | Warning at 262140, then zero fields | 154=`0001` |

For empty files, zero-length field omission follows the writer; a fieldless 109
alone does not distinguish a null buffer from a zero-size loaded handle.
The loader releases the previous buffer before its replacement attempt. The
nonempty-to-empty sequence proves that old text is not retained in the notice.
BMP is a Finder type control here, not a valid image or an agreement encoding.

A separate BMP 65536 fixture passes the loader but exceeds the 65535-byte TLV
field cap. The writer asserts its maximum and raises internalSError 1/10 before
constructing field 101; this does not wrap the length or emit a truncated field.
The two final probes use a bypass observer so its own login can complete:

| Subject path | Captured partial outcome |
| --- | --- |
| Early name/icon completion | ACK,354; no 109 in three seconds.500 ACKs; observer 301 and rosters show the subject online. Subsequent 121/107 return status 1, field 100 `Unknown transaction type!`. After client close,302 and a subject-free roster follow. |
| Delayed completion | ACK without 109; three seconds of silence and no roster visibility. Sending 500 then yields EOF, corroborated by the guest close trace. The observer receives 302 for a UID never introduced by 301. |

These are failed agreement serialization outcomes after an ACK. They are not a
successful ordinary login contract, a complete session rollback, or evidence
that the native writer permits arbitrary field lengths. The separate no-trigger
30-second EOF hypothesis failed; retain it alongside the original pipelined
liveness hypothesis and early-survival hypothesis. Do not replace those reports
with the final plans.

Every ordinary/overflow input and output reconciles exactly with both host and
guest TCP lifetimes. All 28 setup and 11 non-stalled exploratory reports also
reconcile. Two unread notification tails are pinned explicitly, in setup and
exploratory streams; no accepted case needs an unread-tail allowance. Host
capture statistics report 4337 packets and zero kernel drops.

The remaining exploratory report hit the diagnosed host timer deadlock. During
its 0.770-second failed observation the host proxy accepted 12 handshake bytes;
the guest sent no response and consumed no application bytes. A late SYN-ACK
286.213 seconds after the first SYN and the resulting reset are retained in the
full lifetime. They do not turn that failed observation into a native rejection.
The [timer diagnosis and patch](../mothra/evidence/gap-remediation/2026-11-13/timer-suspension-01/manifest.json)
records host-only recovery. The patched executable was built and regression
tested but is not the binary running these captures.

A proposed BINA control became TEXT/ttxt during GUI setup and returned normalized
text. Its four completed reports remain exploratory. Native Finder metadata,
not the upload plan's intended type, selects the accepted non-TEXT control.
Failed moves/renames and zero-record native scans are retained as setup history;
a scan with no matching records does not establish path absence. No ROM,
operating-system image, working disk or restart-durability claim is included.

## Captured login extras, configuration bytes and refresh

The [login-extra corpus][login-extras] retains 34 accepted cases,11 setup/control
reports, five exploratory reports and 14 identity-checked read-only Ghidra
queries. Positive HFS+ Prefs data corroborates the Info Name and banner settings.
The server remains the same identified oracle and live emulator; no host resume,
restart, guest memory/register modification or new account is used here.

| Controlled condition | Captured result |
| --- | --- |
| Client version field 160 absent,0,150,151 or 190; early and delayed paths | Successful 107 replies include 160=`00be`,161=`0000` and the configured nonempty 162, without a version gate. |
| The same version/path matrix after restoring an empty server name | 160/161 remain present;162 is omitted. |
| 31-byte configured name | All 31 bytes appear in 162. |
| 32-byte typing attempt with a distinct 31-byte prefix | Native Prefs and 162 contain the first 31 bytes. This is the native configuration destination boundary, not a universal Unicode character limit. |
| Native keyboard input producing hex `6d6f746872612d9a` | The stored and wire suffix is byte `9a`, not its UTF-8 transcription. |
| Local GIF versus Remote URL versus empty Remote URL | 161 remains two zero bytes. Delayed completion advertises 122 for 151/190 when content is configured, with GIFf/URL tags and their configured 153. No 122 for absent/0/150 versions or empty URL; early completion emits none. |
| Two 212/raw-selector 2 downloads | Each has a nonzero four-byte 107 reference and 58 delivered GIF bytes. Those references differ from login 161's two zero bytes. The banner data channel has a three-second quiet tail, then client close. |

The accepted name-change case establishes online and waiting sessions under
`mothra-name-a`, then pauses 20 host seconds while the operator saves
`mothra-name-b`. A fresh connection receives B. The waiting session completes
with 121 ACK/354/122; neither it nor the existing online session receives a new
161/162 value in the subsequent recorded replies. The earlier A ACKs remain
separate observations. This proves the bounded change sequence, not a total
cross-connection delivery order, polling API or universal notification policy.

The original 90-second hypothesis ended before the waiting 121 could be read.
The guest closed at 90.851866 seconds from report start; the client sent 121 at
92.727286 seconds. The host proxy accepted that write, but the guest stream ends
before it. A final 28-byte observer 302 exists only at the guest boundary after
host observer cleanup. The diagnostic verifier keeps these asymmetric prefixes
separate; it never rewrites the report or treats late 121 as native consumption.
The other 49 reports reconcile exactly across both packet boundaries. Literal
unread 301/302 bytes in the exploratory stream are pinned; accepted cases need
no unread-tail allowance. Host capture reports 1101 packets with zero kernel
drops. No universal waiting deadline or causal claim about the options save
follows from this trial; GAP-005 retains those requirements.

One early click only woke the screen saver, leaving the name empty. That
completed control is retained as failed configuration setup. The first URL
controls also completed, but the immediate HFS+ snapshot retained a stale
188-byte fork length and truncated the new URL. It remains an intentionally
rejected snapshot. An independent owned 203 upload finalization invokes the
native volume flush; the subsequent 222-byte Prefs fork contains the complete
URL. Fresh accepted URL cases follow that positive observation. No zero-record
scan or completed GUI script substitutes for native configuration verification.

The saved name, Local GIF, link and empty Remote URL are restored. The final
175-byte Prefs data matches the first retained empty-name sample byte for byte;
that first sample was captured after the unsuccessful empty-name GUI save,
not independently before all GUI work or before launch. General 100/10/5 and
control port 5500 are checked in every accepted configuration snapshot. The
original 245-byte agreement still yields 242 loaded bytes. Owned flush files
remain in Files; no accounts are added. Neither the snapshot nor a save/flush
proves restart durability.

The source scan checks all D-form scalar store widths and `stmw` ranges that
intersect server+`041c..041f` in the uncompressed code section. Its only candidate
is constructor store`1000035c`; the login load is`10011c3c`. Ghidra confirms both.
The scan excludes indexed writes and derived/aliased bases, so field 161's
purpose and exhaustive lifetime semantics remain unresolved. GAP-026 stays
Investigating despite the new 162 and configured-banner evidence.

[login-extras]: ../mothra/evidence/gap-remediation/2026-11-13/native-login-extras-01/manifest.json

## Captured account replacement and password boundaries

The [account-update corpus][account-updates] retains 31 completed reports,
34 paired host/guest connections and eleven fresh identity-checked queries.
Eight new owned accounts are absent at preflight, then created with display
name, opaque attribute `opaque26` and access bitmap `2000000000000000`
(download-file bit 2). Seven start with 15-byte password `account-base-26`;
the preservation-boundary account starts with 32 `q` bytes. A successful login
with those 32 bytes is recorded before its update.

Each 353 has an empty success ACK, retains control liveness, and is followed
by 352, positive/negative login probes and independent final retrieval. Every
before/after native UserData file is checked as a complete 734-byte record,
including version, field lengths, raw bytes, bitmap and cleared unused bytes.
The account files retain their catalogue identities through replacement.

| 353 password field 106 | Stored result | Login controls |
| --- | --- | --- |
| One byte `00`, existing 15-byte password | Original 15 complemented bytes | Original succeeds; unrelated password fails |
| Omitted | Length zero | Empty succeeds; old 15-byte password fails |
| Present, empty | Length zero | Empty succeeds; old 15-byte password fails |
| Literal byte `78` (`x`) | Length 1, byte `78` | Plaintext byte `87` succeeds; old password fails |
| Complemented 32-byte replacement | All 32 complemented bytes | New 32-byte password succeeds; old password fails |
| One byte `00`, existing 32-byte password | First 31 complemented bytes | New 31-byte password succeeds; original 32 bytes fail |

The same literal `x` can therefore appear as a password-presence placeholder
in 352 and as actual encoded replacement input in 353. The receiving operation
determines its meaning. Echoing the placeholder does not preserve a password.
The successful 32-byte login and replacement distinguish the network handler
from the separately traced local setter's 31-byte cap.

A sparse 353 containing only login 105 and the NUL password sentinel retains
the 15-byte password but clears the account name, attribute 111 and privilege
bitmap. Its subsequent 352 omits 102 and 111, includes complemented 105 and
the `x` password placeholder, and emits eight zero privilege bytes. Its fresh
login succeeds with a zero-mask 354. This is replacement with a special
password branch, not a general sparse-update operation.

Another 353 submits 65 `X` bytes in 111: stored length is 64 with exactly those
64 bytes at `0x256`; 352 still omits 111. In combination with the earlier
absent/empty/value fixtures, this establishes copy/default/output boundaries.
It does not identify the attribute's human meaning or every later consumer.

The nine positive logins complete ACK/354/agreement and answer request 500.
The eight wrong/old-password probes return status 1, field 100
`Incorrect login.`. Their three quiet seconds are bounded observations, not a
universal authentication-disconnect deadline. The positive and negative
credential bytes are retained exactly in both packet views.

Cleanup deletes only the eight new accounts and two flush helpers. Account
enumeration returns exactly to its two-account baseline, and Files returns
to its original 41 entries. Positive native Trash observations preserve all
18 original objects with catalogue identities, paths and complete forks,
including the replacement UserData contents. A separate owned publisher
corroborates those objects and is then removed with wire controls. No
post-removal disk or restart-durability claim is made for that publisher.

This replacement corpus alone does not establish rename/conflict,
protected/self-deletion, live propagation, interrupted writes or restart
persistence. The separate live-account corpus below supplies propagation and
normal server-restart evidence. Other identity/protection/write-failure cases
remain GAP-072, and field 111's meaning remains GAP-071. These replacement
fixtures change no existing account, server configuration or application and
do not claim historical-client parity.

[account-updates]: ../mothra/evidence/gap-remediation/2026-11-13/native-account-update-01/manifest.json

## Captured live account changes and server restart

The [live-account corpus][live-accounts] retains 18 completed reports and one
deliberately failed stopped-listener observation. Its 25 host socket lifetimes
correspond to 24 established guest connections and one rejected guest SYN.
Sixteen identity-checked queries trace replacement, session propagation,
deletion, roster fan-out and transport close helpers. Two separate owned
accounts distinguish replacement from deletion; two sessions use each account.

Helper `10005d30` matches connected sessions by account login, copies changed
privileges and sends 354, then updates stored identity and effective display
name. When the new bitmap does not permit choosing a name, the account's
display name supplies the effective name; when it permits that choice, the
session's requested name is used instead. A privilege or effective-name change
causes roster propagation through `10004f30`. Password and opaque attribute
bytes are not read by this propagation helper. This trace does not identify
every other consumer of attribute 111.

The captured sessions start as `Stored Alpha27` with download-file bit 2,
icons 7/8 and no permission to choose their own names. A single 353 changes
their account to `Stored Beta27`, replaces its password and clears its bitmap:

| Recipient / request | Delivered sequence or result |
| --- | --- |
| Administrator making the update | Empty ACK, two 301 updates, then the requested 300 snapshot showing both renamed subjects |
| Each matching subject | New zero-mask 354 before its own 301; both subjects' 301 records are delivered |
| Either existing subject's next 202 | Status 1, field 100 `You are not allowed to download files.` |
| Existing subjects after password replacement | Request 500 still ACKs; neither session reauthenticates in this trial |
| Password-only replacement | Empty ACK; no additional 354/301 during the measured windows |
| Attribute-only update with NUL password sentinel | Empty ACK; no additional 354/301 during the measured windows |

The two 301 records retain their subject UIDs and icons, use the new name and
raw status word `0020`. Each subject can receive its peer's 301 before its own
354; the established ordering is per socket and per subject, not a global
notification-ID sequence. Each quiet window is three measured seconds.
After the subjects close, the observer receives their two 302 records and
later snapshots exclude them.

The deletion account's two sessions instead receive type 104, status zero,
with only field 101 containing:

```text
You are logged in with an account which was deleted.
```

Handler 351 deletes the account and sends its ACK before invoking matching
session teardown. Helper `10058400` delegates through `1006db60`; the traced
Open Transport backend `10070700` calls `OTSndOrderlyDisconnect`. Both subject
connections show **guest-initiated FIN** before the controlled client closes.
Nevertheless, the observer's two snapshots during the following bounded
interval still contain both subjects. Account deletion and orderly send-side
close do not make roster removal atomic.

The observer's final recorded read does not include the eventual removals.
Two exact 28-byte 302 messages, each containing only its subject UID in 103,
follow the recorded receive prefix in both packet captures. They are retained
as explicit unread tails and verified separately. Do not discard them, invent
notification 111, or rewrite the earlier snapshots as already empty. This
does not establish a universal teardown deadline or room/transfer ordering.

Fresh reconnects reject the original password, the intermediate password and
the deleted login; the final password succeeds with zero-mask 354. The server
is then quit normally with zero connected users. A retained handshake attempt
while it is stopped resets: the guest rejects SYN with a TCP RST carrying
diagnostic bytes `No listener`, not an application frame. The same application
is reopened in Finder and the known Sound Manager alert dismissed. Startup
screenshots and the timed input journal retain this application boundary.

After that normal server restart, retrieval, enumeration and the same four
reconnect probes reproduce the stored replacement/deletion results. Complete
734-byte account records and all five owned catalogue objects/forks match
their pre-restart observations. Application data/resource identities and all
Prefs bytes also match. This is **server application restart in the same
running emulator**, not an OS restart, power-loss test or interrupted-write
atomicity guarantee.

The host execution tool returned exit 143 for one post-restart stage after all
five complete transcripts were present. Its cause is not inferred. That
observation remains separate from the native reports; an independent complete
retrieval/enumeration confirmation followed before cleanup. It is not presented
as a native-server crash or silently converted into a successful host exit.

Cleanup restores the original two-account enumeration and exact 41-entry Files
view. All five original owned objects are positively retained in Trash with
unchanged identities, paths and forks; a separate upload corroborates them
and its helper is removed with wire controls. Normal restart persistence and
this captured live-edit/delete criterion close GAP-073. Protected/self-delete,
rename/conflict and forced write failures remain GAP-072; broader teardown and
snapshot races remain GAP-035/036, and field 111's meaning remains GAP-071.

[live-accounts]: ../mothra/evidence/gap-remediation/2026-11-13/native-live-accounts-01/manifest.json

## Captured account identity and protection contrasts

The [identity corpus][account-identity] retains fourteen completed reports,
sixteen paired host/guest TCP connections and ten identity-checked oracle
queries. Three owned accounts are absent before creation. The original
`admin` and `fixture-low` enumeration and complete 41-entry Files listing are
restored after cleanup. An inherited as-run environment sentence calls the
second account guest; the actual enumeration identifies `fixture-low`.

An exact duplicate 350 and an ASCII-uppercase duplicate both return status 1,
field 100, with the supplied login in this message:

```text
Cannot create account “m-id29-duplicate” because there is already an
account with that login.
```

This display wraps one native line, whose quotes are Mac bytes `d2/d3`.
Both attempts retain the original name, access mask, password and lowercase
account enumeration. The original password succeeds; the attempted replacement
password fails. Lowercase and uppercase 352 lookups retrieve the same record,
but reply field 105 complements the **supplied lookup spelling**. It is not a
canonical stored-login response. This ASCII observation does not settle the
full native case-folding table, non-ASCII collisions or cross-platform rules.

| Owned target | Effective bitmap | Request 110 | Request 351 |
| --- | --- | --- | --- |
| Protected subject | `0000010000000000` (bit 23) | Administrator kick rejected; subject still answers 500 | Administrator deletes account successfully |
| Protected self-delete subject | `0001010000000000` (bits 15, 23) | Administrator kick rejected; subject still answers 500 | Subject successfully deletes its own account |

Kick errors use status 1 and field 100, naming the protected display name:
`You are not allowed to disconnect user … (user is protected).`
The target UID is captured from that live subject's 301, rather than reused
from another session. Bit 23 protects request-110 disconnection, not the
account from request 351. A guessed blanket protected-account rule would
contradict these captures. The configured head administrator is not deleted;
these fixtures establish only the stated owned bit-23 and self-delete cases.

Each deletion has an empty success ACK, a data-only 104 with field 101
`You are logged in with an account which was deleted.`, and guest-first FIN.
For self-deletion, ACK and notice are on the same target stream and ACK comes
first. Readback and fresh login fail afterward. The administrator's roster
snapshot three seconds after the notice still contains the target; an exact
28-byte 302 naming that target follows the recorded receive prefix in both
packet views. The unrelated earlier 302 already read in the protected case
is retained and is not relabelled as the deleted target's removal.

Full enumeration proves the three-account, two-account, one-account and
restored baseline states. Cleanup here is verified on the wire; this corpus
adds no native Trash-fork, forced-write, restart or power-loss claim. GAP-072
remains Investigating for the remaining identity/storage-failure scope, while
GAP-074 still requires plain kick and both ban-option/expiry fixtures.

[account-identity]: ../mothra/evidence/gap-remediation/2026-11-13/native-account-identity-01/manifest.json
