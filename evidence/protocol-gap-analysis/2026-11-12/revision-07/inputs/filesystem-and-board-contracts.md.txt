# Native filesystem, diagnostics and legacy-board contracts

This supplement refines GAP-037, GAP-046 and GAP-049–GAP-054 from preserved
native handlers and [batch 08][batch]. Native Toolbox calls are identified
explicitly so implementations do not inherit guessed portable filesystem
semantics. Runtime object/conflict/failure fixtures remain outstanding.

## File-info target kinds and field presence

Classifier `1002f600` distinguishes ordinary files (2), directories (3), file
aliases (4), directory aliases (5) and unattached aliases (6). It resolves
aliases through native resolution helpers/`ResolveAliasFile`, retaining whether
the source was an alias. Handler 206 builds these variants:

| Target kind | 205 | 206 | 213 | 207 size | 208/209 dates and 210 comment |
| --- | --- | --- | --- | --- | --- |
| Ordinary file (2) | Known native type description or raw four type bytes | Known creator description or raw four creator bytes | Four raw type bytes | Numeric value | Included, subject to empty-comment omission |
| File alias (4) | Four type bytes, space and `(alias)` | Creator description/raw bytes | Four raw type bytes | Numeric value | Included from resolved object |
| Directory (3) | `Folder` | `n/a` | `fldr` | Not added in this branch | Included |
| Directory alias (5) | `Folder Alias` | `n/a` | `fldr` | Not added in this branch | Included from resolved object |
| Unattached alias (6) | `Unattached Alias` | `n/a` | `alis` | Not added | Not added |

Successful branches add name 201. The literals and Pascal lengths are retained
in batch 08 at `10091cfd`. A descriptive 205/206 is a byte string, not a fixed
four-byte integer. Known type descriptions include application, StuffIt archive,
text, incomplete file and Hotline bookmark; unknown types preserve the raw
four bytes. Size and metadata alias/zero/unknown fixtures remain GAP-049.

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
Trash placement, conflicts, protected objects and failures remain GAP-050.

**205 create:** the handler caps Pascal name input at 255 bytes, normalizes the
name and resolves a creation target. Helper `1002b670` calls `FSpDirCreate`,
then updates its native spec. The empty success ACK follows creation/closing.
The handler distinguishes resolver failure conditions; it does not promise
idempotent success on existing names, automatic parent creation or overwrite.
Conflict/permission/root/empty/boundary native fixtures remain GAP-051.

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
or rename operations. Delivered refresh, comment round-trip and partial-failure
fixtures remain GAP-052; a nonzero reply does not prove unchanged metadata.

### Move and alias distinctions

Move handler 208 resolves source 201/202 and destination directory 212, then
calls `1002c130`. That helper rejects a different volume reference, verifies
the destination is a directory and calls `FSpCatMove`. It does not implement a
cross-volume copy/delete fallback or an explicit overwrite policy. Same-place,
collision and failure results remain platform/runtime questions (GAP-053).

Alias handler 209 uses source 201/202 and destination path 212, constructing
the destination with the same source name; it does not read a separate new-name
211. Helper `1002fb00` calls `NewAlias`, creates a resource file, stores an
`alis` resource with ID zero and sets Finder alias flags. Directories use native
folder-alias type/creator values; files use their native metadata. Error cleanup
can delete a partially created alias resource file.

This is a classic Mac alias, not a POSIX symlink wire promise. Alias-to-alias,
missing-target, destination conflict and transfer resolution fixtures remain
GAP-054. Native resource-fork/metadata preservation needs its own tests.

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

On the normal fan-out path, 102 contains field 101 holding the **new formatted
post segment**, not the whole retained board. It is sent to transport-ready
sessions with read-news privilege 20; this loop does not independently require
the online flag. The post already exists and has been ACKed before the spam
branch can suppress fan-out and close/temporarily ban the sender.

The old board and new hierarchical articles therefore have different framing,
discovery and mutation order. Exact header/separator bytes are retained through
`10004110` and its referenced data. Multi-post/empty/boundary/update-recipient
fixtures and filesystem durability remain GAP-046/021; no UTF-8 or CR/LF
normalization rule is invented here.

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
