# Native filesystem, diagnostics and legacy-board contracts

This supplement refines GAP-037, GAP-046 and GAP-049–GAP-054 from preserved
native handlers and [batch 08][batch]. Native Toolbox calls are identified
explicitly so implementations do not inherit guessed portable filesystem
semantics. The captured 205 matrix below now supplies creation/path fixtures;
other operation-specific object/conflict/failure requirements remain active.

## File-info target kinds and field presence

Classifier `1002f600` distinguishes ordinary files (2), directories (3), file
aliases (4), directory aliases (5) and unattached aliases (6). It resolves
aliases through native resolution helpers/`ResolveAliasFile`, retaining whether
the source was an alias. Handler 206 builds these variants:

| Target kind | 205 | 206 | 213 | 207 size | 208/209 dates and 210 comment |
| --- | --- | --- | --- | --- | --- |
| Ordinary file (2) | Known native type description or raw four type bytes | Known creator description or raw four creator bytes | Four raw type bytes | Numeric value | Included, subject to empty-comment omission |
| File alias (4) | Four type bytes, space and `(alias)` | Creator description/raw bytes | Four raw type bytes | Resolved target DATA-plus-resource aggregate in the captured cases | Included from resolved object |
| Directory (3) | `Folder` | `n/a` | `fldr` | Not added in this branch | Included |
| Directory alias (5) | `Folder Alias` | `n/a` | `fldr` | Not added in this branch | Included from resolved object |
| Unattached alias (6) | `Unattached Alias` | `n/a` | `alis` | Not added | Not added |

Successful branches add name 201. The literals and Pascal lengths are retained
in batch 08 at `10091cfd`. A descriptive 205/206 is a byte string, not a fixed
four-byte integer. Known type descriptions include application, StuffIt archive,
text, incomplete file and Hotline bookmark; unknown types preserve the raw
four bytes. The captured matrix below supplies alias, zero and unknown-value
fixtures for this native profile.

## Delete, create, rename, comment, move and alias

All paths use operation-specific file roots and the structured resolver;
the top-level handler's checks are not evidence of unrestricted admin override.
Relevant privilege bits are:

| Operation | Native check |
| --- | --- |
| 204 delete file / directory | 0 / 6 |
| 205 create directory | 5 |
| 207 rename file / directory | 3 / 7 |
| 207 change file / directory comment | 28 / 29 |
| 208 move file / directory | 4 / 8 |
| 209 create alias | 31 |

**204 delete:** helper `1002ba20` finds the native Trash folder and calls
`FSpCatMove`. A duplicate-name outcome enters collision/name handling before
retrying the move. This path does not recursively erase a directory's contents.
A successful handler ACK follows the helper; there is no file-list refresh
notification constructed at this success site. Filesystem errors route through
the native exception machinery, not a promised all-or-nothing portable delete.
The captured matrix below supplies Trash placement and name-conflict outcomes.
Protected/root targets and interrupted failures remain GAP-050.

**205 create:** the handler caps Pascal name input at 255 bytes, normalizes the
name and resolves a creation target. Helper `1002b670` calls `FSpDirCreate`,
then updates its native spec. The empty success ACK follows creation/closing.
The handler distinguishes resolver failure conditions; it does not promise
idempotent success on existing names, automatic parent creation or overwrite.
The captured matrix below supplies permission, conflict, root, empty and
boundary fixtures for this handler (GAP-051).

### Request 207 presence and mutation order

Comment processing uses a field-presence accessor, separately from its content
length. An absent 210 skips comment mutation. Present empty 210, or exactly one
NUL byte, selects an empty comment. Other values are read through a 256-byte
Pascal destination (at most 255 content bytes). Unattached alias kind 6 skips
this comment branch. File/directory comment permission is checked first.

New name 211 is then read into its own 256-byte Pascal destination. Absent/empty
name skips rename; an equal existing name also skips the changed-name branch.
A changed nonempty name requires its separate file/directory rename permission
and applicable path/name policy before native normalization and `FSpRename`.

| Request case | Observed order/result |
| --- | --- |
| Name only | Comment absent: skip it, then validate/rename changed name. |
| Comment only | Apply permitted comment; empty new name skips rename. |
| Both supplied | Apply permitted comment first, then validate/rename name. |
| Comment succeeds, later rename denied/fails | Error can follow an already changed comment; no rollback is visible here. |
| Both absent | No mutation from these branches; normal empty ACK remains possible. |

The helper wrappers flush/prepare native file state and invoke platform comment
or rename operations. The captured mutation matrix below supplies round-trip,
permission and partial-failure fixtures. Its bounded quiet windows do not
establish every later refresh; a nonzero reply does not prove unchanged metadata.

### Move and alias distinctions

Move handler 208 resolves source 201/202 and destination directory 212, then
calls `1002c130`. That helper rejects a different volume reference, verifies
the destination is a directory and calls `FSpCatMove`. It does not implement a
cross-volume copy/delete fallback or an explicit overwrite policy. Captured
same-place, collision and same-volume failures are documented below. Other
volumes and interrupted-operation outcomes remain GAP-053.

Alias handler 209 uses source 201/202 and destination path 212. With nonempty
201 it constructs the destination with that source name. With absent/empty 201,
202 and 212 can supply complete source and destination paths, including a new
destination leaf. It does not read a separate new-name 211. Helper `1002fb00`
calls `NewAlias`, creates a resource file, stores an
`alis` resource with ID zero and sets Finder alias flags. Directories use native
folder-alias type/creator values; files use their native metadata. Error cleanup
can delete a partially created alias resource file.

This is a classic Mac alias. The captured cases below cover live targets,
alias-to-alias sources, destination conflicts and resolved transfers. Genuine
deleted-target resolution remains GAP-054; a cyclic self-alias does not supply
that missing fixture.

## Legacy board 101/102/103

101 checks read-news privilege 20 and returns field 101 from the in-memory board,
clipped to 65,535 bytes. An empty value is omitted by the writer. It is not a
nested article list and does not use modern-news field 321.

103 checks post-news privilege 21 and accepts request field 101 only when its
length is at most 8,192 bytes, including zero. Helper `10004110` prepends a
formatted `From` header using the session display name and native date/time,
then the raw post and the native separator to the existing board buffer. It
writes the whole updated buffer to the board file before returning. The handler
then sends an empty ACK and performs its repeated-hash spam check.

The [static format-byte trace](legacy-board-format.md) identifies the Pascal
filename `MessageBoard.txt` and the separator's 60 emitted bytes: CR, 58
underscores, CR. Its leading stored byte `3c` supplies that length and is not
an emitted `<`. The immutable fixture base has an allocated empty board file;
that stopped-image fact does not substitute for a live101 empty-board reply.
The retained format string alone does not establish a timezone or full text
encoding rule.

On the normal fan-out path, 102 contains field 101 holding the **new formatted
post segment**, not the whole retained board. It is sent to transport-ready
sessions with read-news privilege 20; this loop does not independently require
the online flag. The post already exists and has been ACKed before the spam
branch can suppress fan-out and close/temporarily ban the sender.

The old board and new hierarchical articles therefore have different framing,
discovery and mutation order. Exact header/separator bytes are retained through
`10004110` and its referenced data. The captured matrix below supplies
multi-post, empty, boundary and recipient examples. Crash/failure persistence
remains GAP-021; no UTF-8 or CR/LF normalization rule is invented here.

### Captured legacy-board boundaries and updates

The [native board witness](native-board-witness.md) records one isolated run
with an initially empty `MessageBoard.txt`, four case sockets and separate
18-action control checks before and after. The file's empty starting state
is proved both by stopped HFS inspection and the live101 reply, which omits
field101. The account without read privilege receives a101 error.

| Post case | Native result |
| --- | --- |
| Explicit empty101, then two distinct seven-byte posts | Success; each creates a segment, prepended newest first. |
| 8,191 bytes and six distinct8,192-byte posts | Success; sender and eligible reader each receive the complete new segment in102. |
| Measured7,155-byte filler | Stored/retrieved aggregate reaches exactly65,535 bytes. |
| One additional byte | Stored aggregate grows to65,629 bytes;101 returns its newest65,535-byte prefix. |
| 8,193 bytes | Status1/field100 error; no new102 or change to the reconstructed or stopped board. |

Each observed segment has a33-byte header ending in CR CR, the raw post,
then the60-byte separator. In this run the header is
`From BoardSender (Nov14 09:14):` followed by those two CR bytes. Its rendered
overhead is measured, not a promise that every name, locale or date has the
same length. The twelve exact102 segments, reversed into newest-first order,
equal the complete65,629-byte stopped file, including the94 bytes beyond
the retrieved prefix. Resource size remains zero and Finder type/creator
remain `TEXT`/`ttxt`; the five original account/preferences/application forks
remain byte-identical.

The sender and eligible online reader each receive all12 updates. The denied
reader receives none. The waiting account receives none during the first
three posts before its client closes. That last absence does not establish
an online-flag check: its active session ACL and Open Transport predicate are
not independently measured. The traced fan-out condition still governs.

Within the sender's stream, each success ACK precedes its matching102.
Arrival order on another socket is not a global execution order. All six
TCP lifetimes have exact namespace/guest/runner application-byte equality,
including tails. The full stopped-file comparison proves normal completed
storage effects in this case; power-loss atomicity, write-failure recovery,
universal recipient states, date/timezone and text-encoding rules remain
separate questions. The repeated-hash suppression branch is source-derived;
this unique-post fixture does not exercise its threshold.

## Diagnostic text 303

303 requires privilege 24 and reads numeric target UID 103. Its normal reply
contains name 102 and generated data 101. Handler `10016150` assembles
nickname/account/address and active transfer/queue summaries into bounded local
buffers, with final diagnostic formatting capped at 1,024 bytes. This is
operational diagnostic text derived from session/server state, not an editable
real-name profile or a stable structured record.

The protocol documents the field roles and native generation path. It does not
choose a new mxd release requirement for exact prose, spacing or localized
textual parity. That decision, representative native outputs and encoding/
boundary fixtures remain GAP-037/086.

[batch]: ../mothra/evidence/gap-remediation/2026-11-12/batch-08/manifest.json

## Captured native folder creation and field 202 paths

The [directory/path corpus][mkdir] retains 47 creation/path cases, six additional
absent/empty-name root combinations, setup/finalization/cleanup and ten
identity-checked Ghidra queries. All 51 reports complete, and all 53 socket
lifetimes reconcile at both host and guest packet boundaries. The two literal
host recorder files contain 1,374 and 43 packets, each with zero kernel drops;
the merged capture preserves their 1,417 records. The target is the continuing
Mac OS 9.0.4 native executable, not a claim about the unexecuted OS X branch.

### Create inputs, permissions and replies

Field 201 is optional. The handler reads at most 255 content bytes into a
Pascal destination, then applies platform normalization. On this pre-OS-X
profile, ordinary 32-, 255-, 256- and 65,535-byte inputs yield the first 31 bytes.
A tested 44-byte name ending in `.txt` yields its first 27 bytes plus `.txt`.
The separate `1002c070` branch for system version at least `0a00` has a different
limit; these captures do not execute it. The 31-byte outcome is not the TLV
field-width limit.

A missing/empty 201 can use the final component of 202 as the new leaf name:
`ROOT/nest/via-path` and `ROOT/nest/via-empty` create those leaves. If that path
instead names an existing directory, the operation fails. All six combinations
of absent/empty 201 and absent/empty/zero-count 202 fail against the existing
Files root; they do not mean successful idempotent creation.

| Case | Captured outcome |
| --- | --- |
| New name at root or nested parent | Empty success ACK; exactly one new directory record in the explicit after-listing. |
| Existing directory, existing ordinary file or ASCII case collision | Status 1, field 100: `Cannot create folder` followed by the quoted requested name and the existing-file-or-folder explanation. Existing listing records are unchanged. |
| Missing parent or ordinary file used as parent | Status 1 with the enclosing-folder-could-not-be-found explanation; listing unchanged. |
| Account with zero field-110 privileges | Status 1, field 100: `You are not allowed to create folders.` Both a new target and an existing-name target get this result. |
| Absent/empty name with existing root | Status 1 with the existing-file-or-folder explanation and empty quoted name; root listing unchanged. |

The native handler checks bit 5 before resolving the target. The tested
administrator has bitmap `fff3cfefff800000`; the denied account has eight zero
bytes. No account is changed for these controls. Successful creates and expected
failures all complete request 500 afterward. Each ordinary case then observes
one measured second of silence. That bounds the no-unsolicited-refresh
observation; it is not a universal guarantee about all later notifications.

### Name bytes and structured-path acceptance

A one-byte NUL name creates a record whose native name is exactly `00`.
Leading, trailing and interior NUL names remain distinct from an empty name.
Colon becomes hyphen in the tested name and traversal components. Slash, CR,
LF and high byte `9a` survive in returned native name bytes on this host.
Directory records for literal `.` and `..` are created; subsequent structured
paths address those empty child directories and create their own children.
They are not interpreted as POSIX current/parent components in these fixtures.
Traversal through the created high-byte and NUL-leading directories also
completes. This does not establish alias containment or another platform's rules.

| Field-202 input | Captured creation location |
| --- | --- |
| Absent, empty, zero count, one byte, count-only or five-byte input | Files root for the tested nonempty name. The wrappers ignore the tested values shorter than six bytes. |
| Valid root component followed by truncated or zero-length component | Last complete directory, rather than blanket rejection of the entire path. |
| Count two with only one complete component | The one complete directory. |
| Component word `ffff` | Same tested directory as the zero-word control. |
| Trailing bytes beyond the declared component count | Ignored by this tested traversal. |
| Zero count followed by a complete unused record | Files root. |

The before/create/after listings prove each claimed location and raw name.
These are acceptance quirks of field 202 in this operation, not proof that
fields 212 or 325 have identical contracts. Complete canonical component
records remain the documented emission grammar; do not turn a parser's prefix
acceptance into a new canonical wire format.

### Listing, file-info and owned cleanup controls

Every listing record retains the documented `20 + name_length` layout. Fresh
empty directories have type `fldr`, zero creator and numeric value zero.
The final root directory has value 26 and its `nest` child value 3, matching
their immediate entry counts; the ordinary `TEXT`/`MOTH` file has value 13,
matching its data length. These observations do not impose a common byte-size
meaning on files and folders or prove a universal listing sort order.

The directory's 206 reply contains 205=`Folder`, 206=`n/a`, 213=`fldr`, name
and two eight-byte dates; size 207 and empty comment 210 are omitted. The
ordinary file contains 205=`Text File`, 206=`MOTH`, 213=`TEXT`, two-byte
207=`000d`, name, dates and `fixture-comment`. Alias/unknown/zero-metadata
variants remain GAP-049.

Read-only catalogue observations retain 36 positive records below the owned
root before cleanup. Native 204 then moves that root, seven root-level marker
directories and the empty flush file into Trash. All 44 objects are positively
observed there, with the same catalogue IDs for the moved subtree. The ordinary
child still contains `mkdir-fixture`. This corroborates move-to-Trash rather
than recursive erasure, without closing permission/conflict/protected-object
requirements for 204 (GAP-050). The complete Files listing matches its pre-seed
bytes after cleanup; no unrelated Files entry is removed by the fixture script.

TSK renders some control/high bytes in path text, including caret rendering of
NUL. Raw filename assertions use native field-200 bytes, not that rendered
path. Catalogue probes are positive observations, not arbitrary absence proofs
or restart-durability tests. No guest restart, debugger, account mutation or
native configuration change is used.

[mkdir]: ../mothra/evidence/gap-remediation/2026-11-13/native-mkdir-01/manifest.json

## Captured alias and metadata matrix

The [native alias corpus][aliases] contains 44 completed reports and one retained
initial EOF timeout, 66 socket lifetimes reconciled independently at the host
and guest boundaries, fourteen identity-checked Ghidra queries and 33 positive
pre-cleanup catalogue objects. It uses a separately restarted OS 9.0.4 guest
and the timer-patched emulator. Its provenance does not claim a clean shutdown
of the earlier guest or a known cause for that process's disappearance.

### File-info presence and values

All successful 206 samples include alias/original name 201 and fields
205/206/213. Dates, when present, each occupy eight bytes. The ordinary file
contains 16 DATA bytes and 317 resource-fork bytes; its aggregate size is 333.
The file alias and chain also report 333: the size helper receives the
resolved target, whose DATA and resource forks total 16 + 317. That value is
neither the target's DATA-only length nor the alias file's own fork total.
The older read-only catalogue observations give the aliases' own fork totals
as 540/546; they have no stopped-image consistency or durability proof.
The [size-scope review](../mothra/evidence/gap-remediation/2026-11-14/alias-positive-basis-01/a131-size-scope.md)
retains the source/capture distinction and that provenance limit.

Field 207 uses two bytes in these small samples. The shared integer writer's
larger-value branches remain documented separately; this is not a fixed
universal two-byte size contract.

| Captured target | 205 description | 206 creator | 213 raw type | 207 | 208/209 | 210 |
| --- | --- | --- | --- | --- | --- | --- |
| Ordinary file | `Text File` | `MOTH` | `TEXT` | `014d` | Present | `alias-comment` |
| Empty file | `Text File` | `MOTH` | `TEXT` | `0000` | Present | Omitted |
| Zero-tag file | Four zero bytes | Four zero bytes | Four zero bytes | `0009` | Present | Omitted |
| Unknown-tag file | `XxYz` | `ZzQq` | `XxYz` | `000c` | Present | `unknown-comment` |
| Ordinary directory | `Folder` | `n/a` | `fldr` | Omitted | Present | Omitted when empty |
| File alias or file-alias chain | `TEXT (alias)` | `MOTH` | `TEXT` | `014d` | Resolved target's dates | Resolved target's comment |
| Directory alias or chain | `Folder Alias` | `n/a` | `fldr` | Omitted | Resolved target's dates | Resolved target's comment, omitted when empty |
| Cyclic self-alias, classified unattached | `Unattached Alias` | `n/a` | `alis` | Omitted | Omitted | Omitted |

The zero-tag fields are present binary values, not empty strings or missing
fields. Empty-file size is a present scalar zero. An alias named `derived-link`
returns that name in 201, whereas its downloaded FILP INFO names resolved target
`file`. Source classification/resolution in `1002f600`/`1002cf90` and handler
`10016ba0` explain this distinction: metadata comes from a resolved copy; the
emitted name comes from the originally addressed object.

A directory comment set through 207 appears through both ordinary directory
and alias 206 views. Present empty and single-NUL comments each clear it and
omit 210 from both subsequent views. Other rename/partial-failure combinations
remain GAP-052.

### Alias creation, collisions and transfer resolution

Thirteen of nineteen creation cases succeed. Nonempty 201 keeps the source
basename, including high byte `9a`; extra 211 is ignored. Missing, empty and
zero-count 212 select Files root. Absent/empty 201 with full source 202 and
full destination 212 creates the requested `derived-link`, `derived-empty` or
`derived-dir` leaf.

A pre-existing ordinary destination file is a significant exception to a
blanket no-overwrite rule: alias creation succeeds at `C/same`, leaves its
physical 21-byte DATA fork, and adds an `alis` ID 0 resource and Finder alias
flag. Listing, info and download then resolve the 11-byte source `same`,
including its source comment. An existing directory destination fails and
preserves its ordinary child. Repeating an existing alias destination also
fails; a separately created chain still resolves afterward.

The six negative creation cases retain exact status 1/text 100 bytes: missing
source, missing/non-directory destination, directory collision, and two
zero-privilege denials. Permission text is `You are not allowed to make aliases.`
Before/after listings, correlated ACKs, subsequent 500 and one measured second
of silence bound the observations.

Live file and directory aliases, including chains and a renamed destination,
resolve during 202/210 downloads. File DATA/resource forks match the target;
directory streams enumerate and transfer the ordinary `leaf`. Physical folder
aliases instead have type `fdrp`, creator `MACS`, Finder alias flags and `alis`
ID 0 resources. They are files on disk even when wire listings expose folders.

Same-location creation succeeds but makes `self` unattached. Its physical
`self-source` DATA remains, while listing reports `alis`/zero creator/value zero
and 206 omits size/dates/comment. Download fails with text saying there is no
file named `self`; that message does not prove physical absence. A genuine
removed-target case is still required for GAP-054.

The first file download received all 496 advertised FILP bytes but timed out
waiting for EOF. Its report remains failed. Subsequent cases read exact lengths,
observe three seconds of silence, cancel through 214, then observe EOF and a
live control connection. This bounds a transfer observation; it does not prove
all transfer-completion semantics.

Owned cleanup restores the complete 41-entry Files wire listing. The live
pre-cleanup snapshot contains 33 positive objects, but the immediate post-move
snapshot supplies only three positive Trash observations. Do not extrapolate
that partial disk view into complete Trash persistence or restart durability.

[aliases]: ../mothra/evidence/gap-remediation/2026-11-13/native-alias-01/manifest.json

## Captured rename and comment mutation matrix

The [native metadata corpus][metadata] supplies 36 file/folder cases, six
additional combined-empty cases, 22 comment-boundary writes and independent
administrator views. All 49 reports complete their recorded actions; 72 socket
lifetimes reconcile exactly at host and guest boundaries. Thirteen fresh,
identity-checked oracle queries trace presence, permissions, comment/rename
helpers and native Desktop Manager calls. This continues the same timer-patched
OS 9 guest; it is not restart-durability evidence.

For an ordinary file or directory, the captured administrator matrix is:

| 211 new name | 210 absent | 210 empty | 210 nonempty |
| --- | --- | --- | --- |
| Absent | Preserve name and comment | Preserve name; clear comment | Preserve name; set comment |
| Empty | Preserve name and comment | Preserve name; clear comment | Preserve name; set comment |
| Changed nonempty name | Rename; preserve comment | Rename and clear comment | Set comment, then rename |

Exactly one NUL byte in 210 also clears the comment. Interior NUL bytes in
`aa\x00bb` remain part of a five-byte comment. After a clear, 206 omits 210 rather
than returning a present empty value. A new name equal to the current name
skips the changed-name operation. No-op requests with both updates absent
succeed even for a zero-privilege account.

Permission controls use three owned temporary accounts with bitmaps
`0000000c00000000` (file/folder comments), `1100000000000000` (file/folder
renames), and all zeroes. Native 354 and administrator 352 views verify these
values. Comment processing precedes rename processing:

| Combined operation | Reply | Before/after result |
| --- | --- | --- |
| Comment permitted; rename denied | Status 1, rename-permission text | New comment persists; original name remains; new name does not resolve |
| Comment denied; rename permitted | Status 1, comment-permission text | Original comment and name remain; rename is not attempted |
| Comment permitted; destination name conflicts | Status 1, native collision text | New comment persists; original name remains; existing destination is unchanged |
| Both permitted; no conflict | Empty success ACK | New name resolves; old name fails; new comment persists |
| Comment absent; rename permitted | Empty success ACK | Rename succeeds and original comment is preserved |
| Comment absent; rename denied | Status 1, rename-permission text | Name and comment remain unchanged |

Exact permission text distinguishes `files` and `folders`. The comment denial
literal is `You are not allowed set comments for files.` (including the native
wording). The file collision example is `Cannot set info for` followed by the
quoted source name, CR, `A file or folder with the specified name already
exists.`, CR and `ID 4/115 [-48]`. Raw report bytes preserve native quote bytes
`d2`/`d3`; display punctuation is not the wire encoding.

The comment setter wrapper `1002c690` clips input to 255 bytes, and lower helper
`1007ea90` passes at most 200 bytes to `PBDTSetCommentSync`. This must not be
confused with observed 206 readback: writes of 198 and 199 bytes return those
lengths, while 200, 201, 254, 255, 256, 300 and 65,535 bytes each return 199 on
this profile. The read helpers call `PBDTGetCommentSync`; these captures do not
identify a universal storage capacity or establish how many bytes survive a
restart. Empty and one-byte controls are retained for both files and folders.

Each main case includes before/after metadata, directory listings, a 500
liveness reply and one measured quiet second. An independent administrator
session checks all 36 final objects. The observed silence does not promise
absence of later notifications. No comment/rename rollback is implied by an
error ACK: clients must re-read state when a combined request fails.

The initial cleanup used the wrong 351 login encoding and explicitly failed
for all three owned accounts. Their continued presence is retained. Corrected
complemented-login requests then succeed and raw 352 lookups prove all three
absent. The owned file tree and six supplementary entries are moved to Trash;
the complete 41-entry Files wire listing is restored. No full disk-persistence
claim follows from those ACKs or listings.

[metadata]: ../mothra/evidence/gap-remediation/2026-11-13/native-metadata-01/manifest.json

## Captured move and Trash outcomes

The [native move corpus][moves] contains 26 move cases, nine delete cases and
four auxiliary reports: 39 completed-action reports/75 paired socket lifetimes.
Eleven identity-checked oracle queries accompany exact plans, before/after
listings and metadata, one-second measured quiet windows and positive native
catalogue/fork observations. This continues the same live OS 9 guest. It does
not cover another volume, locked/protected targets, interrupted I/O or restart
persistence; GAP-050 and GAP-053 retain those unanswered requirements.

| 208 move case | Native reply and effect |
| --- | --- |
| Ordinary file or nonempty directory to another owned folder | Empty success ACK; source disappears, destination appears with original name/metadata and catalogue identity; directory children retain identity/bytes |
| Same parent, file or directory | Empty success ACK; both listings remain unchanged |
| Existing file or folder with the same name | Status 1/conflict text; source and destination remain unchanged; no overwrite |
| Missing source | Status 1/no-file-or-folder text; views unchanged |
| Missing or ordinary-file destination | Status 1/destination-folder-not-found text; views unchanged |
| Zero-privilege file/folder move | Status 1/permission text; source remains unchanged |
| Absent, empty or zero-count 212 | Success; selects Files root on this profile |
| Directory into itself or its child | Status 1/self-or-subfolder text; hierarchy unchanged |
| File-alias source | Alias object moves; its target stays in place; resolved metadata remains available |
| Alias to destination directory | Move succeeds into the resolved destination directory |

Twelve moves succeed, including two same-parent no-ops; fourteen fail with exact
status 1/text 100 outcomes. The collision literal says there is already a
file/folder in the destination folder with the same name. The hierarchy literal
says the source cannot move into itself or a subfolder of itself. File/folder
permission messages are distinct. Raw reports retain native `d2`/`d3` quote
bytes, rather than substituting display punctuation.

Handler `100177d0` checks move privilege 4 or 8 after source classification and
resolves destination 212. Helper `1002c130` flushes/prepares source state,
rejects different native volume references before calling `FSpCatMove`, verifies
the destination is a directory and updates its stored parent after success.
The differing-volume branch is static evidence; no actual cross-volume fixture
has run. The unchanged views for tested errors do not prove atomicity under
an interrupted native filesystem operation.

| 204 delete case | Native reply and effect |
| --- | --- |
| Ordinary file | Empty success ACK; original path stops resolving; positive catalogue identifies the same object in Trash |
| Nonempty directory | Success; directory and child move to Trash with original identities and fork bytes |
| Missing source | Status 1: cannot delete because it does not exist or cannot be found |
| Zero-privilege file/folder deletion | Status 1/permission text; view unchanged |
| Absent 201 with full owned-directory 202 | Success; resolves and moves that owned directory to Trash |
| Two equal basenames from distinct owned parents | Both succeed; positive catalogue shows `m-del22-dupe` and `m-del22-dupe1`, with distinct source bytes preserved |
| Target of a live alias | Target moves to Trash; 206 through the remaining alias still resolves its metadata |

Six deletes succeed and three return expected errors. The path-only case uses
an owned directory; it does not test deletion of the actual Files root. Native
204 is a Trash move, not recursive erasure. Collision helpers can enter
multi-step rename/move paths; this corpus does not force a failure between
those steps or prove rollback. Locked/protected/root and interrupted-operation
fixtures remain required by GAP-050.

The target-in-Trash case is especially important for alias containment: the
alias remains inside Files, while its target is positively identified outside
that share in Trash. Native 206 still exposes `TEXT (alias)`, resolved-target
aggregate size 332 and the target's comment. The alias resource bytes differ
by the final snapshot. This is a bounded metadata-resolution observation,
not a download fixture or a genuine missing-target case. Missing-target and
broader alias-resolution requirements remain GAP-054; the separately
published path contracts do not imply universal alias containment.

Read-only catalogue snapshots retain all 72 seeded identities before cleanup,
including moved subtrees, and add one independent flush file. Every ordinary
DATA/resource fork is unchanged. The only changed seeded resource fork is the
alias addressed after its target's Trash move. Positive child/fork controls
support the observed preservation; they do not prove every metadata attribute.

Owned cleanup restores the complete 41-entry Files wire listing. The immediate
post-cleanup disk snapshot positively identifies 70 objects in Trash, including
subtree paths. Three root-level file markers lack positive post-move probes.
Do not turn those missing positive observations into absence, complete Trash
persistence or restart-durability claims.

[moves]: ../mothra/evidence/gap-remediation/2026-11-13/native-move-01/manifest.json
