# A132: opportunistic extfs date comparison

Read-only proposal for the already planned positive 206 in the disposable
GAP-054 alias fixture. This adds no protocol request, clock change, file
write, or live-image read. It is a finite contribution to GAP-020, whose
original criterion still requires date producers/consumers, timezone,
units/range, and rollover fixtures across relevant paths.

## Source chain

`AL-D-10016ba0.c` classifies/resolves the addressed alias, then calls
`1002c910(iVar2, auStack_a28, auStack_a30)` on the resolved FSSpec. It
serializes `auStack_a30` as field 208 and `auStack_a28` as field 209, each
eight bytes. Frozen `D-1002c910.c` uses `PBGetCatInfoSync`, passes its
catalogue date values to `10058070`, and `D-10058070.c` writes BE16
year `0x0770`, BE16 zero, then the supplied BE32 value. The source layout
is creation 208 and modification 209; retain the raw fields to verify that
mapping in this case rather than rely on a displayed timestamp.

The SheepShaver Unix extfs source is the symlinked
`tools/macemu/BasiliskII/src/extfs.cpp`, built with
`src/Unix/extfs_unix.cpp`. Its Linux catalogue paths fill `ioFlMdDat`
from `TimeToMacTime(st.st_mtime)`. They do **not** fill `ioFlCrDat` from
Unix `ctime`: the explicit creation-time branches cover BeOS/Windows and
Apple only. `tools/macemu/SheepShaver/src/macos_util.cpp:322-344`
computes Mac seconds from the host process's `localtime(&t)` calendar,
with origin 1904-01-01. Therefore UTC host mtime plus a fixed constant
is valid only when the emulator's local timezone maps that instant to
the same wall time. The reverse `MacTimeToTime` helper is not this
read-only path and should not be used as the comparison oracle.

## Already available and as-run comparison

The stopped preparation receipt pins the owned target leaf's device
2097, inode 3818213780, UID 1000, DATA length 20, hash
`8d1841a0106a3d6e9a4e4cee76eecd48912545fcc73d87446b05ada0800ae5a8`,
and `mtime_ns=1794668290088333960` (2026-11-14 14:58:10 UTC).
`finf-supplement.json` repeats the unchanged target identity and pins the
32-byte Finder sidecar. Its sidecar mtime is separate and is **not** the
target's file modification time. Host `ctime` is metadata-change time,
not a comparable Mac creation timestamp.

At the pre-unlink positive gate, B111 should retain the **full raw 206
reply**, including fields 208/209 even if absent, and correlate its exact
request/alias name with the target/sidecar identity already recorded.
Retain the already planned immediate target `lstat`/hash receipt before
that reply and before unlink, plus the existing post-Finder target stat.
Record the emulator process's effective `TZ` environment if available
from its already required PID identity receipt; otherwise label the
timezone unknown. Do not make a new protocol request or change timezone.

Decode each present eight-byte field as `(BE16 year, BE16 middle,
BE32 seconds)` without inventing fractional units for a nonzero middle.
For field 209, compute `TimeToMacTime(floor(st_mtime_ns / 1e9))` using
the **same effective local timezone as the emulator process**. For a UTC
process and the unchanged pinned mtime, the source prediction is
`07 70 00 00 e7 1e 27 82`; that hex is conditional, not a required
on-wire result. Compare exact bytes and report any difference with the
host stat and timezone provenance. For field 208, record its bytes but do
not compare them to Unix ctime or assume zero solely from this source.

Finder activity or `set_finfo` can change target mtime; the Unix helper
calls `utime` when setting Finder info. If pre/post stat differs, use the
stat contemporary with the 206 request and describe the interval/uncertainty.
If timezone provenance or target identity is missing, retain the bytes as
an observation only. Even an exact 209 match establishes one extfs/Linux
modification-time conversion, not guest timezone rules generally,
creation-time semantics, news field 330 equivalence, nonzero middle-word
handling, range, or rollover. GAP-020 remains open.
