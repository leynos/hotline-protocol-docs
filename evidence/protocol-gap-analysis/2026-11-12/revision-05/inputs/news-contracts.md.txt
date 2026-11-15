# Native nested news contracts

These static findings refine GAP-020 and GAP-065–GAP-070 for the hashed native
1.9 server. The [baseline guide](protocol.md), its preserved handler captures,
and [batch 05][batch] identify the oracle. A serialized example inferred from
these builders is not a captured client exchange. Unknown words remain opaque.

## Category-list variants

Builder `10005710` compares the saved numeric client version with **15**,
not 151 or 190. Values below 15 select repeated field **320**; values at least
15 select repeated field **323**. These are numeric wire branches, not proof
of a particular client identity. Entries with enumerator flag bit zero set
are skipped.

For legacy field 320, the first byte is a kind marker followed immediately by
name bytes. The builder replaces the original Pascal-string length byte with
the marker and emits `1 + name_length` bytes; the TLV length supplies the name
boundary. Kind values are 1 for native folders, 10 for HLNZ category files and
255 for other enumerated types.

For modern field 323, folders and HLNZ categories have different layouts.
Other enumerated types are omitted. The following offsets are checked against
[the actual store/call instructions][category-asm], not just inferred from a
padded C struct.

| Folder offset | Size | Emitted value |
| ---: | ---: | --- |
| 0 | 2 | Kind 2 |
| 2 | 2 | Low 16 bits of the enumerator's supplied size/auxiliary value |
| 4 | 1 | Name length `n` |
| 5 | `n` | Name bytes |
| `5 + n` | 1 | Additional emitted byte, not assigned by this branch |

The native call emits `n + 6` bytes. Do not silently shorten it to `n + 5`
or declare the final byte zero. Its observed stack source is not a semantic
field definition; native capture fixtures remain necessary.

| Category offset | Size | Emitted value |
| ---: | ---: | --- |
| 0 | 2 | Kind 3 |
| 2 | 2 | Low 16 bits from category information at offset 18 |
| 4 | 16 | Packed category metadata copied by `1006f350` |
| 20 | 4 | Category-information word at offset 20 |
| 24 | 4 | Category-information word at offset 24 |
| 28 | 1 | Name length `n` |
| 29 | `n` | Name bytes |
| `29 + n` | 3 | Additional emitted bytes, not assigned by this branch |

The emitted category length is `n + 32`. Metadata helper `10022830` reads the
HLNZ file header; its packed fields are not all semantically named by this
investigation. Auxiliary/count interpretations and mixed-category fixtures
remain GAP-065. Tail bytes must remain opaque rather than becoming invented
required padding or a zero-filled interoperability assertion.

## Article-list field 321

Reply 371 contains one field **321** holding a serialized list; it is not one
outer TLV per article. Builder `100059e0` calls `10023180` with optional-extra
mode zero. That routine either returns a cached list from the HLNZ file or
rebuilds it through `10025900`, `100248a0`, `10025a60`, `10025c60` and
`10025d80`.

| List-header offset | Size | Rebuilt value |
| ---: | ---: | --- |
| 0 | 4 | Zero |
| 4 | 4 | Number of serialized article records |
| 8 | 2 | Two zero bytes |
| 10 | Variable | Article records |

The base article record is:

| Record offset | Size | Value |
| ---: | ---: | --- |
| 0 | 4 | Article's public identifier |
| 4 | 8 | Stored date bytes copied without annual conversion |
| 12 | 4 | Related article ID mapped from a native record link |
| 16 | 4 | Stored article word at native offset `0x40` |
| 20 | 2 | Flavour count `f` |
| 22 | `1 + t` | One-byte title length `t`, followed by title bytes |
| `23 + t` | `1 + p` | One-byte poster length `p`, followed by poster bytes |
| `24 + t + p` | Variable | `f` flavour entries |

Title bytes are capped at 63 and poster bytes at 31 by this serializer. Each
flavour entry is a one-byte length, at most 63 flavour-name bytes, and a
big-endian **16-bit** size derived from its stored 32-bit body length. Values
above 65,535 therefore cannot be reconstructed from this narrowed list size
alone. The base record has `24 + t + p` bytes before flavour entries.

An internal optional-extra mode inserts another Pascal byte string (maximum
63 bytes) after the poster, but the traced 371 reply uses mode zero. Do not
insert that extra string unconditionally into the network reply grammar.

Traversal emits a record and its flavour chain, then recursively visits its
child link before continuing its sibling chain. Its flavour-chain walk is
bounded to 32 iterations; the read-body helper has its own separate bound.
The ID-mapping helper returns zero for an absent/unmapped related link. This
establishes byte boundaries and traversal shape, not every previous/next/thread
label or a promise that corrupt storage cannot produce malformed output.
Empty/multiple/branching list fixtures and cached-versus-rebuilt equivalence
remain GAP-066.

## Reading bodies and navigation

Handler 400 reads path 325, numeric article ID 326 and a NUL-terminated flavour
string from 327. Helper `100233e0` locates the article, then searches at most
30 flavour links. Flavour matching compares length and exact bytes; no
case-insensitive, MIME-alias or automatic fallback rule appears in this lookup.
Failure to find the requested article/flavour reaches the native exception
path. Its final wire error/close outcome must be checked through the enclosing
exception machinery rather than invented from that helper alone.

Reply builder `10005ac0` emits title 328, poster 329, eight-byte date 330,
flavour 327, navigation fields 331/332/335/336, and body 333 when nonempty.
The four navigation outputs map stored record links at native offsets
`0x28`, `0x2c`, `0x30` and `0x34` to public article IDs. Create/delete analysis
identifies `0x30` as the parent record and `0x34` as the child-list head;
previous/next traversal and post-deletion graph fixtures remain GAP-067/069.
Do not confuse native record numbers with the public IDs transmitted here.

## News dates

Create helper `100229b0` calls `10057de0` when no explicit stored date is
supplied. That producer calls Mac `GetDateTime`, writes year 1904 (`07 70`),
zero milliseconds and the returned 32-bit seconds word. Article-list and body
reply paths copy those eight bytes. This confirms the fixed-year form for
native-created news too; timezone and rollover fixtures remain GAP-020.

## Posting, partial effects and deletion

Handler 410 checks post-news privilege 21 and resolves path 325. It reads
326, title 328, flags 334, flavour 327 and body 333. The handler's Pascal title
buffer has a 32-byte capacity (31 content bytes), narrower than the stored
article title and list serializer's 63-byte cap. It takes the poster from the
session display name, not a client-supplied field 329.

The handler calls `100229b0` to create the article **before** checking that body
333 is nonempty or writing the flavour body through `10022ea0`. A subsequent
body failure can therefore follow earlier metadata/index mutation; no rollback
is visible in this path. The new public ID is returned internally by the create
helper, but the normal handler's success reply is an empty ACK. It does not
return that ID in the success payload or send an article notification at its
own success site. How clients discover it requires polling/client evidence;
no push-discovery guarantee is assigned.

The create helper treats 326 as a possible parent ID: a resolved parent record
is attached through native link `0x30`; an unresolved/zero lookup takes the
root-list insertion path. Flags 334 are stored as a raw word at native `0x40`;
no locked/announcement bit interpretation is established here. It invalidates
the stored serialized-list cache after changing the index.

Handler 411 converts field 337 to a zero/nonzero boolean, not an independent
bitmap of deletion options. Helper `10023830` uses that boolean to select
recursive descendant deletion through `100249f0`. Without recursion, its
child-present branch rewires surviving child/sibling/parent links rather than
simply orphaning them. Both paths update the article index/count and invalidate
the serialized-list cache. Exact resulting navigation graphs, storage-write
failures and atomicity still require parent/leaf/branch fixtures (GAP-069).

## Scope of hierarchy evidence

These wire handlers resolve field 325 through the structured filesystem-path
resolver used elsewhere in this binary, with an operation-specific news root.
That is evidence for shared framing, not proof of identical allowed names,
permissions, alias resolution or maximum depth. Operations 380/381/382 remain
subject to GAP-070's hierarchy/conflict/recursive-effect tables and fixtures.
The existence of native folder enumeration does not establish a fixed four-tier
news hierarchy.

[batch]: ../mothra/evidence/gap-remediation/2026-11-12/batch-05/manifest.json
[category-asm]: ../mothra/evidence/gap-remediation/2026-11-12/batch-05/queries/B05-A-10005710.json
