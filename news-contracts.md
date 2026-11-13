# Native nested news contracts

These static and captured findings refine GAP-020 and GAP-065–GAP-070 for the
hashed native 1.9 server. The [baseline guide](protocol.md), preserved handler
captures and [batch 05][batch] identify the oracle. The native fixture sections
below distinguish captured exchanges from static branches and identified peers.
Unknown words remain opaque.

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
field definition; the captured category matrix below preserves actual tails.

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
investigation. The captured matrix below ties the auxiliary values to immediate
folder valence and the category header's article count. Tail bytes remain
opaque rather than becoming invented
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
| 12 | 4 | Parent public ID mapped from native link `0x30` |
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
The captured threaded matrix below supplies empty/multiple/branching lists and
cached-versus-rebuilt equivalence for the observed native storage profile.

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
The four navigation outputs map stored record links to public article IDs:

| Reply field | Native record offset | Meaning |
| ---: | ---: | --- |
| 331 | `0x28` | Previous sibling |
| 332 | `0x2c` | Next sibling |
| 335 | `0x30` | Parent |
| 336 | `0x34` | First child |

Create [assembly][create-asm] stores the parent at `0x30`, finds the last child
through `0x2c`, stores that sibling at the new record's `0x28` and updates its
`0x2c` to the new record. Root insertion uses the same sibling links, with
first/last root pointers in the HLNZ header. These are same-level links; 331/332
do not promise adjacent entries in the flattened depth-first article list.
The list record's offset-12 ID is the mapped parent, not its previous sibling.
Do not confuse native record numbers with the public IDs transmitted here.

The append search `100247f0` stops after at most 100 link reads, returning the
last visited record. This is not proof that categories with more than 100
siblings append correctly. Native navigation fixtures, including that boundary,
remain GAP-067/068.

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

### Deletion graph rewrite

Handler 411 converts field 337 to a zero/nonzero boolean, not an independent
bitmap of deletion options. Helper `10023830` uses that boolean to select
recursive descendant deletion through `100249f0`. For a leaf, or after recursive
removal, it connects the deleted record's previous and next siblings and updates
the parent child-head or root-list endpoints as needed.

For non-recursive deletion with children, [the assembly][delete-asm] and helper
`10025120` establish this rewrite:

1. Promote the first child into the deleted article's position, inheriting its
   previous sibling, next sibling and parent links.
2. Reparent the other former children to the promoted article.
3. Append those articles after the promoted article's existing children, or use
   them as its child list if it previously had none.

For example, suppose `A.children = [B, C, F]` and `B.children = [D, E]`.
Deleting A without recursion places B where A was, with
`B.children = [D, E, C, F]`. C and F now have parent B. The independent native
fixtures below capture this exact rewrite, including body navigation links.

Both paths update the article index/count and invalidate the serialized-list
cache. The non-recursive path decrements the count by one. Storage writes occur
in sequence without an established rollback guarantee. The parent/leaf/branch
fixtures below establish the ordinary and rejected-request outcomes; forced
interrupted-storage behaviour remains unproved.

## Scope of hierarchy evidence

These wire handlers resolve field 325 through the structured filesystem-path
resolver used elsewhere in this binary, with an operation-specific news root.
That is evidence for shared framing, not proof of identical allowed names,
permissions, alias resolution or maximum depth. Operations 380/381/382 remain
subject to GAP-070's hierarchy/conflict/recursive-effect tables and fixtures.
The existence of native folder enumeration does not establish a fixed four-tier
news hierarchy.

### Structure operation effects and conflicts

Evidence: preserved handlers [380][delete-structure], [381][create-folder] and
[382][create-category], shared [resolver classifier][classify], and the native
[Trash mover][trash-move].

The handlers distinguish native directories (news bundles) from ordinary files
(category storage). Deletion's resolver does not test an HLNZ signature before
moving an ordinary file. Creation of a category does initialize HLNZ version 2
storage through [helper `10022670`][category-create], which creates an `HLNZ`
file with creator `HTLS`, opens it and writes a 1,024-byte initial buffer.

| Request | Target and permission checks | Normal effect / reply |
| ---: | --- | --- |
| 380 | Path 325 resolves an existing object; reject missing target or target equal to the configured news root. Kind 3 (directory) requires bit 37; kind 2 (ordinary file) requires bit 35 and nonzero path byte length. | Move target to native Trash via `1002ba20`, then empty ACK. No explicit recursive erase walk in the handler. |
| 381 | Name 201 and parent path 325; require bit 36. Resolve proposed child in mode 5, which admits a missing leaf under an existing parent and rejects an existing item. | `FSpDirCreate`, release resolver objects, empty ACK, then native activity-log helper. |
| 382 | Name 322 and parent path 325; require bit 34. Same mode-5 conflict check. | Create/write HLNZ file, empty ACK, then native activity-log helper. |

Resolver `1002f800` reports kind 0 for an unavailable enclosing location and
kind 1 for a missing leaf with an existing parent. The creation handlers format
different direct status-1/field-100 errors for kind 0 and for an existing item.
Errors thrown inside resolution or Toolbox calls remain subject to the
untraced enclosing exception translation; do not replace them with a guessed
wire status or presume that a failed creation leaves no file behind.

Root protection uses [FSSpec comparison `1002cac0`][spec-equal]: volume,
parent-directory value and the native string comparison must match. The 380
resolver's mode 2 does not include the alias-replacement flag `0x200`. Its
classifier can report alias kinds 4/5 or unresolved kind 6, while the handler's
explicit type-specific privilege branches test only 2 and 3. This bounded
observation does not establish safe alias containment or equivalent alias
permissions; native alias/root variants remain essential fixtures.

Trash movement can preserve a directory's descendants as part of moving the
whole object; it is not proof of permanent recursive deletion. The shared
helper has collision-renaming fallback paths. Failed moves, collisions, partial
category writes and eventual activity-log failure after an ACK still need
native fixtures (GAP-021/047/070). No news-list refresh broadcast is sent at
these three normal success sites.

Names pass through the same resolver sanitization as file operations. The
[sanitizer `1002f0c0`][sanitize] replaces `:` with `-` when its platform selector
is below `0x0a00`; the other branch also replaces `/`, changes a leading `.`,
and applies additional single-byte-name rules. The resolver has a long-name
fallback to a generated 32-byte name. These are transformations, not a blanket
rejection or UTF-8 normalization contract. Which platform branch runs and
collision effects require environment-specific fixtures.

[batch]: ../mothra/evidence/gap-remediation/2026-11-12/batch-05/manifest.json
[category-asm]: ../mothra/evidence/gap-remediation/2026-11-12/batch-05/queries/B05-A-10005710.json

[create-asm]: ../mothra/evidence/gap-remediation/2026-11-12/batch-13/queries/B13-A-100229b0.json
[delete-asm]: ../mothra/evidence/gap-remediation/2026-11-12/batch-13/queries/B13-A-10023830.json

[category-create]: ../mothra/evidence/gap-remediation/2026-11-12/batch-14/queries/B14-D-10022670.c
[spec-equal]: ../mothra/evidence/gap-remediation/2026-11-12/batch-14/queries/B14-D-1002cac0.c
[sanitize]: ../mothra/evidence/gap-remediation/2026-11-12/batch-14/queries/B14-D-1002f0c0.c

[delete-structure]: ../mothra/evidence/hotline-server-1.9/queries/D-10010b70.c
[create-folder]: ../mothra/evidence/hotline-server-1.9/queries/D-10010ee0.c
[create-category]: ../mothra/evidence/hotline-server-1.9/queries/D-10011110.c
[classify]: ../mothra/evidence/gap-remediation/2026-11-12/batch-14/queries/B14-D-1002f800.c
[trash-move]: ../mothra/evidence/gap-remediation/2026-11-12/batch-08/queries/B08-D-1002ba20.c

## Captured category versions and header metadata

The [native news corpus][native-news] retains 43 reports/45 paired socket
lifetimes and 29 fresh identity-checked oracle queries. Its nine controlled
107 requests advertise two-byte values 0, 1, 14, 15, 16, 149, 150, 190 and
`ffff`. Values 0/1/14 select field 320; 15 and the remaining tested values select
323. These are decoder fixtures, not historical-client identities or release
labels. In particular, the literal threshold 15 is not proof of “version 1.5”.

The separately [identified shx 0.1.48 peer](identified-client-source.md#full-native-peer-acceptance-matrix)
omits 160 in its basic login request. Its source and captured execution
establish that absence, rather than transmission of 15. The native scalar
accessor defaults an absent value to zero; inferring its legacy category branch
is distinct from capturing a category exchange from that peer. No identified historical
peer in this new corpus supplies the 14/15/16 boundary cases. Historical modern
peer classification and wider interoperability remain separate open evidence
requirements; do not relabel this controlled driver as an actual client release.

The owned root contains folder `bundle`, category `category`, empty folder
`empty`, folder `hi-9a` (final byte is binary `9a`) and category `zero-articles`,
in that native enumeration order. `bundle` contains folder `child` and category
`nested`; `child` contains empty category `deep`. Empty-folder listing returns
no 320/323 fields. The same names and kind distinctions survive both formats.

| Record | Legacy 320 | Modern 323 |
| --- | --- | --- |
| Folder | Marker 1, then exact name bytes | Kind 2; auxiliary is immediate child count; Pascal name at offset 4; total `n + 6` |
| HLNZ category | Marker 10, then exact name bytes | Kind 3; auxiliary is low 16 bits of stored article count; Pascal name at offset 28; total `n + 32` |
| Other native types | Static branch emits marker 255 | Static branch omits them; no foreign-type runtime fixture here |

Captured modern tails are nonzero and can vary between otherwise unchanged
listings. Folder examples include `10`, `61` and `79`; category examples include
`5186a0` and `b5f000`. They are retained raw, excluded from semantic equality
checks and given no required value. Their positions and emitted lengths remain
part of the grammar. Removing them or demanding zero padding changes native
bytes.

Positive `HLNZ`/`HTLS` file observations tie category records to native storage:
wire metadata bytes 4–19 equal file-header bytes 8–23; wire words at 20/24 copy
header words at 24/28. The auxiliary copies the low half of the 32-bit article
count at header offset 44. That count progresses through 0, 1, 2 and 3 during
initial posting and reaches 6 after the thread fixtures. A missing-body post
contributes to the count. The nested category has count 1 and empty categories
have 0. Remaining metadata words are preserved by source offset; this does not
assign a standard UUID or a guessed application meaning to them.

## Captured threaded article lists and partial posts

The initial 371 reply contains field 321 with exactly ten zero bytes. Three
valid initial posts create two root articles in `category` and one independent
root in `nested`. A fourth request omits body 333 and receives status 1,
`Cannot post article because invalid data was specified.` Its title/date/index
record nevertheless appears as public ID 3 with zero flavours. This is an
observed partial mutation, not a rollback or a successful body post.

Two children of ID 1 and a grandchild of the first child produce this list:

| Serialized public ID | Parent | Title | Raw flags | Flavours and unsigned 16-bit body length |
| ---: | ---: | --- | --- | --- |
| 1 | 0 | `First root` | 0 | `text/plain`, 14 |
| 4 | 1 | `long-` followed by 26 `x` bytes | 0 | `text/plain`, 65,535 |
| 6 | 4 | `Grandchild` | 0 | `text/plain`, 15 |
| 5 | 1 | `Second child` | 0 | `text/plain`, 9 |
| 2 | 0 | `Second root` | `11223344` | `text/plain`, 11 |
| 3 | 0 | `Missing body` | 0 | No flavours |

This is depth-first child-before-sibling order, neither numeric-ID nor creation
order. The offset-12 link is the parent public ID. Raw flags occupy four bytes;
no named flag bits are inferred from `11223344`. Dates retain the eight-byte
native representation with `0770` year, zero milliseconds and copied seconds.
Each poster is the session name `framing-fixture`; a client-supplied poster is
not used by this producer.

The 64-byte submitted child title becomes 31 bytes through the post handler,
while the serializer's separate static cap remains 63. Poster serialization's
static cap is 31. The list stores a 65,535-byte flavour length as unsigned
`ffff`; it must not pass through a signed outer-scalar interpretation. Bodies
above that size can exist only through paths not exercised here; the static
serializer narrows a stored 32-bit body length to 16 bits. These captures do not
prove behaviour for every flavour-chain or sibling-count boundary.

All nine version sessions return identical field-321 bytes for the populated,
empty and nested categories. The first list after the final post matches the
later cached replies. Positive HLNZ data independently retains those exact
bytes at `512 + (cache_index - 1) * block_size`, using header offsets 32/36/40
for block size, cache index and serialized byte length. The populated cache is
395 bytes, the empty cache 10 and the independent nested list 73. This supports
cached/rebuilt equivalence for these fixtures, without inventing an optional
extra Pascal string in network mode zero.

Five successful 400 reads return exact body bytes, including CR/LF/NUL/high-byte
content and the 65,535-byte body. Their title/poster/date agree with 321. The
four navigation outputs are present two-byte scalars for these small IDs:

| Article | 331 previous sibling | 332 next sibling | 335 parent | 336 first child |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 0 | 2 | 0 | 4 |
| 4 | 0 | 5 | 1 | 6 |
| 6 | 0 | 0 | 4 | 0 |
| 5 | 4 | 0 | 1 | 0 |
| 2 | 1 | 3 | 0 | 0 |

The zero-flavour record, unknown flavour, case-changed `TEXT/PLAIN` and unknown
article each receive status 1 with the same literal: `Cannot get article data
because an invalid category was specified.` That coarse message does not prove
the category itself is missing. Subsequent 500 replies and measured quiet
windows retain liveness. Broader navigation/date/flavour limits remain GAP-067;
post flag meanings, discovery/push and other partial failures remain GAP-068.

## Captured hierarchy failures and owned cleanup

Fourteen structure requests return exact errors without changing known listing
semantics: folder/category name conflicts against both kinds, missing and
category-as-parent locations, zero-privilege creation/deletion, missing target
and protected configured news root. Protection and missing-target errors share
`Cannot delete news item because it could not be found.` Before/after semantic
comparisons preserve every name, kind, count and header value while allowing
opaque tail bytes to vary.

The successful seed creates a nested owned hierarchy; final 380 moves the
whole owned root to Trash. Both native roots return to baseline: News empty,
Files with its original 41 entries. The first disk probe after cleanup has no
positive matching records and is retained as inconclusive. A separate owned
upload then exercises the known native flush path: all ten original objects
are positively identified in Trash with catalogue IDs, subtree paths, file
forks and HLNZ caches preserved. Its separate publication file is subsequently
removed with ACK and complete wire-listing controls. No post-removal disk or
restart-persistence claim is made for that helper file.

No account is changed and no historical client runs in this corpus. Article
recursive deletion is covered by the separate corpus below. Alias/root
variants, interrupted category writes and broader hierarchy failure effects
remain GAP-070. One-second quiet windows do not establish every later
notification or durable completion.

[native-news]: ../mothra/evidence/gap-remediation/2026-11-13/native-news-01/manifest.json

## Captured article deletion and index effects

The [article-deletion corpus][article-delete] retains 58 reports: 56 completed
and two failed, reconciled against 60 host/guest TCP connections. Each of 25
independent categories starts with roots `L(1), A(2), R(3)`, A's children
`B(4), C(5), F(6)` and B's children `D(7), E(8)`. Initial depth-first order is
`1,2,4,7,8,5,6,3`. Every article has its letter as title, poster
`framing-fixture`, zero flags and six-byte `text/plain` body `body-X`.

| Deleted article and mode | Result | Stored count |
| --- | --- | --- |
| A, nonrecursive | Roots L,B,R; B's children D,E,C,F | 7 |
| A, recursive | Roots L,R; all A descendants removed | 2 |
| B, nonrecursive | A's children D,C,F; D's child E | 7 |
| B, recursive | A's children C,F | 5 |
| D, either mode | B's only child E | 7 |
| L, nonrecursive | Roots A,R, with A's subtree intact | 7 |
| R, nonrecursive | Roots L,A, with A's subtree intact | 7 |

All survivors retain their original IDs, dates, bodies and flavour metadata.
Every surviving 400 reply checks previous/next sibling, parent and first-child
fields 331/332/335/336, including explicit two-byte zeros. Deleted IDs fail body
reads with `Cannot get article data because an invalid category was specified.`
The text is coarse: the category still exists.

Field 337 uses the generic scalar-width reader, then a zero/nonzero test:

| Input bytes | Observed deletion of A |
| --- | --- |
| Absent; empty; `00`; `0000`; `00000000` | Nonrecursive |
| `01`; `02`; `ff`; `0001`; `8000`; `00010000` | Recursive |
| `000001` (three bytes) | Nonrecursive: unsupported width defaults to zero |
| `00000001ff` (five bytes) | Recursive: leading four bytes are nonzero |
| `00000000ff` (five bytes) | Nonrecursive: trailing byte is ignored |

Twenty-one primary requests succeed with empty ACKs. Four fail with status 1
and field 100; a repeated successful deletion adds a fifth error:

| Request | Exact field 100 text |
| --- | --- |
| Missing ID 99, omitted 326, repeated deletion | `Cannot delete article because an invalid category or item was specified.` |
| Missing category | `Cannot delete article because the specified category could not be found.` |
| Zero-privilege account | `You are not allowed to delete articles.` |

Rejected requests preserve the complete list. The zero-privilege account can
obtain 371 metadata but 400 returns `You are not allowed to read articles.`
An independent administrator session subsequently reads its unchanged eight
bodies. The observed 371 path therefore does not enforce the same permission
gate as 400 or 411. Each deletion session remains live for request 500 and
records three quiet seconds; this bounds the observation, not all later events.

Before/after 371 reads, a repeated cached read and independent final reads
agree exactly. Positive native HLNZ files have header count at offset 44
matching each resulting tree, with the exact wire list in the stored cache
selected by block size/index/length at offsets 32/36/40. The fresh
`10023830`/`100249f0`/`10025060`/`10024620`/`10025120` queries trace descendant
removal, target record/block release, index removal, link rewriting, cache
invalidation and header/index writes. Their sequence supplies no transactional
rollback guarantee for forced I/O interruption.

The initial unpaced seed was interrupted after 121 ACKs including login,
before the reply to request 219. A fresh login returned an explicit temporary
ban, and the native GUI logged `Autobanned for flooding`. A later host display
exit caused the emulator's XIO exit; the cause of the display exit is unknown.
These are separate observations, with no supported native-server-crash claim.
Recovery used a new managed runtime from a preserved, stopped unclean disk
copy, followed by Disk First Aid completion and positive application fork
identity checks. Successful access in that new process does not prove natural
ban expiry or in-place unbanning.

Recovery inventory found thirteen full categories, one containing only L, and
eleven missing categories. Bounded per-category sessions retained the existing
IDs and appended only the verified missing suffix. Three-second pauses pace
these sessions. Owned cleanup restores empty News and the full 41-entry Files
baseline. A first zero-positive disk probe remains inconclusive; a subsequent
independent upload publishes all 27 original objects positively in Trash,
preserving catalogue identities, paths, forks and caches. Its separate helper
is then removed with wire controls. No restart-durability claim follows.

[article-delete]: ../mothra/evidence/gap-remediation/2026-11-13/native-article-delete-01/manifest.json
