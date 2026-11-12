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
single universal limit. Restart persistence, failed writes, and full 32-byte
round trips still need runtime checks.

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
| 8 | 4 | Size from the native enumerator |
| 12 | 4 | Zero |
| 16 | 2 | Zero |
| 18 | 2 | Name length `n` |
| 20 | `n` | Name bytes |

Thus the value length is `20 + n`; the outer TLV length excludes its own
four-byte header. Records repeat as field 200. The builder skips entries with
its enumerator flag bit zero set and has an additional conditional type filter.
It does not itself sort entries; filesystem enumeration, folder sizes, aliases,
and exact filtering still need their own verified examples.

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
