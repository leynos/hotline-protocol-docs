# A130: positive live-alias proof rule

Read-only source review for the proposed GAP-054 bridge. No fixture, UI,
runtime, host leaf, image, or oracle project was changed.

## Retained 206 source

`native-alias-01/oracle-queries/AL-D-10016ba0.c` reads 201/202 and
resolves the addressed object. `1002cf90` calls `1002f600`, whose
successful alias resolution distinguishes ordinary file kind 2 from
file-alias kind 4, directory alias kind 5, and unattached alias kind 6.
For kind 4, handler 206 calls `1002c800` on the resolved info and emits:

- field 205: the four resolved type bytes followed by a literal space and
  `(alias)`;
- field 206: resolved creator bytes, or a known description if mapped;
- field 213: four raw resolved type bytes;
- field 207: `1002c4d0`'s resolved-target DATA-plus-RSRC aggregate in the
  measured file-alias case, which is not the target DATA length by itself;
- field 201: the originally addressed alias name, via `1002bce0`.

The existing native-alias-01 ordinary and chain fixtures confirm the
source distinction: their 206 fields are `TEXT (alias)`, `MOTH`, `TEXT`,
and aggregate 333 for a target with 16 DATA plus 317 RSRC bytes.
An ordinary copy of the target with the same tags would emit bare `TEXT`,
while an unattached alias emits `Unattached Alias` and raw `alis` in the
retained fixtures. Thus the space plus `(alias)` marker and target-specific tags
is a stronger positive gate than a size equality. It does not by itself
prove the host pathname of the resolved target.

## Extfs Finder-info staging

The SheepShaver Unix build uses `extfs_unix.cpp`, a symlink to the retained
`BasiliskII/src/Unix/extfs_unix.cpp` (same SHA-256
`3121708131dd9398a22d1ae3f1035b4e1d99613a13cbbb1b27d9b874a024b292`).
That implementation reads `R/shared/.finf/<leaf>` as 16-byte `FInfo`
followed by 16-byte `FXInfo`; `extfs_defs.h` puts type at offset 0 and
creator at offset 4. A private 32-byte sidecar with first eight bytes
`U54TM54X` and 24 zero bytes therefore supplies distinct type `U54T`
and creator `M54X` to this extfs path when the file is read through the
guest. The helper's successful 32-byte read returns before filename
extension fallback. Stage only the owned leaf's sidecar as UID 1000,
verify exact path, mode, inode, 32-byte length and hash before boot,
and recheck it after Finder creates/copies the alias; Finder might rewrite
metadata. No HFS image bytes need be read live for this staging check.

If the copied HFS alias resolves to that tagged leaf, the bounded 206
prediction is field 201 = copied alias name, field 205 exactly the 12 bytes
`55 35 34 54 20 28 61 6c 69 61 73 29` (`U54T (alias)`), field 206
exactly `4d 35 34 58` (`M54X`), and field 213 exactly `55 35 34 54`
(`U54T`). Require each field once, not a substring match; reject bare
`U54T`, `Unattached Alias`, wrong creator/type, missing field, duplicate
field, status failure, or an unrecognised modal/timeout. Field 207 is an
observation of resolved-target aggregate length only. Do not assert 20 DATA
bytes from it. No separately bounded 202 DATA read is needed for this
positive metadata gate if the distinct tuple and all identity checks pass.

Correlate the positive 206 tuple with a prior live `lstat` and content hash
of the exact owned leaf, its `.finf` hash, the guest's visible Unix-volume
leaf, copied alias entry under the owned HFS Files folder, and later
**stopped-image** `alis` resource/Finder-alias flag/catalogue ID/name.
Without that chain, another tagged target or an ordinary copied file could
be misidentified. The stopped alias proof identifies the HFS object; the
live 206 tuple demonstrates native resolution for this one target. Neither
alone proves how AliasManager will behave after host unlink.

Historical correction: the older native-alias-01 catalogue used to compare
fork sizes was a read-only direct observation of a working image, with no
retained PID-gone/FD-free gate. A131 limits its temporal and durability scope;
the distinct 205/206/213 positive gate above does not rely on that older
catalogue being a stopped-image snapshot.

If the tuple or identity chain fails, stop before any unlink. A bounded
202/210 transfer would require separate capture and approval; do not add it
to repair a failed positive gate or infer a 20-byte DATA size from 207.
