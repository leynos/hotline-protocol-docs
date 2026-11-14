# Hotline Server 1.9 account write ordering

This page records the direct account writer in the exact Mac PPC Hotline Server
1.9 binary, SHA-256 `ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`.
The [read-only Ghidra corpus](../mothra/evidence/gap-remediation/2026-11-14/account-write-ordering-01/manifest.json)
retains source functions, disassembly, exact query arguments, identity checks,
as-run scripts, and backend logs. The independent saved project was opened with
`--no-analyze --discard`; its program identity was unchanged before and after
both query batches. No failed-write runtime fixture was run.

## Direct 353 replacement path

The 353 handler prepares a 734-byte account record. If request field 106 is
exactly one NUL byte, it loads and copies the existing password, capped at 31
bytes. It then invokes the writer before constructing and sending the normal
acknowledgement, followed by the live account update helper. This is **call
order**, not a guarantee that an acknowledgement means the data reached durable
storage. See frozen `D-10014df0.c:49-65` in the corpus.

1. **Resolve:** `AC-D-100075e0.c` and `AG-D-1002af80.c` resolve
   `Users/<login>/UserData` from the account name.
2. **Open:** `AG-D-1002c220.c`, `A63-D-1007fc50.c`, and
   `A63-A-1007fc50.json` show mode `0x23`. A nonzero result goes to the SError
   helper. Assembly preserves the result in `r3`, despite the wrapper's
   misleading decompiled `void` signature.
3. **Set length:** `A63-D-1002c5a0.c` and `A63-A-1002c5a0.json` show a
   separate `SetEOF(ref, 734)` before writing. A nonzero result goes to SError.
4. **Write:** `A63-D-1002c440.c`, `A64-D-1002e370.c`, and
   `A64-A-1002e370.json` show one `PBWriteSync` with requested count 734. A
   nonzero OS result goes to SError. The helper returns the parameter block's
   actual count, but the account-writer wrappers do not compare it with 734.
5. **Close:** `A63-D-1002b2f0.c` calls `FSClose` for open references. This
   wrapper does not check the close result.
6. **Respond:** `D-10014df0.c` sends the normal ACK after the writer call,
   then invokes the live-update helper. Exceptional control flow outside this
   direct chain has not been traced.

The direct path contains no temporary-file replacement, swap, old-fork restore,
or rollback step. This local observation does **not** prove the absence of
outer recovery or OS-level guarantees. It also does not establish the exact
wire status after an exception, the stored bytes after a failed or short write,
or crash/power-loss atomicity. A zero OS result with a short actual count, if
possible for this path, is not checked by the shown account-writer functions;
no such short write has been observed.

The 350 creation helper (`AC-D-100071a0.c`) explicitly creates an account
folder and `UserData` before using the same open, length, write, and close
sequence. A prior successful 353 rename retained the target catalogue identity.
These facts distinguish normal creation from replacement; they do not define
either operation's failed-write behaviour. Field 111's role remains unknown.

## GAP-072 boundary

The [gap register](gap-analysis.md#gap-072) requires 350–353 mutation,
default, and atomicity rules, with existing-password, literal-x,
rename/conflict, and protected-delete fixtures. The existing native fixtures
cover those named password and identity cases. The direct writer trace adds
source-supported ordering and error checks; **failed single-operation 353
atomicity remains open**.

The smallest useful fault fixture would use one owned account on a disposable
image, preserve exact before/after `UserData` fork bytes and catalogue identity,
and prove that a controlled failure occurred after a successful `SetEOF` and
during or after `PBWriteSync`. It would retain the exact reply or disconnect
and restore the owned fixture. Finder's Locked flag may instead reject the
open or `SetEOF` step; that would measure an earlier failure branch, not the
write-phase atomicity question. No experiment should be described as a
write-phase failure without evidence that it reached that phase.
