# Account field 111: stored-record and consumer trace

This is a bounded GAP-071 trace for the hashed Hotline Server 1.9 PPC DATA image
(`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`). It adds
28 read-only Ghidra content queries, with six before/after identity queries
across three invocations, to existing native account fixtures. Every query
record names its tool, arguments, capture time and program identity. The
[query corpus][corpus] includes exact decompiler text, plans, the capture
wrapper and checksums. No native application or account was changed.

## Positive field and storage evidence

Field 111 (`0x6f`) is a byte-valued account TLV. In the 734-byte native
`UserData` record, its big-endian 16-bit length is at `0x254` and content
begins at `0x256`, in a 64-byte slot ending before the login field at `0x298`.
These are _internal storage_ offsets, not a wire struct.

| Native fixture             | Stored length and bytes   | Consequence established                    |
| -------------------------- | ------------------------- | ------------------------------------------ |
| [Absent][core] / empty 111 | 0 / 0                     | Both store a zero-length slot.             |
| Representative value       | 8 / `opaque-c`            | Exact bytes survive into `UserData`.       |
| [Sparse 353][update]       | 0 / empty                 | Replacement clears the slot.               |
| 65-byte input to 353       | 64 / 64 literal `X` bytes | The handler's copy cap is inclusive at 64. |

The create handler [100146f0][create] and replacement handler
[10014df0][replace] copy TLV `0x6f` with limit `0x40` into a freshly cleared
734-byte record. Batch handler [10015500][batch] uses the same field/cap. The
record creator [100071a0][creator] writes all `0x2de` bytes; its three direct
callers are the create path, batch path and local administrator update. The
replacement writer [100075e0][writer] also writes all `0x2de` bytes; its direct
callers are replacement and batch. The original native fixtures show absent,
empty, value, cap and sparse-clear outcomes; the static trace explains their
storage path.

The local administrator password update [10007780][admin-update] first reads
the complete record with `100073c0`, changes password/privilege fields, then
writes the same 734-byte buffer. Thus field 111 **can be carried through a
whole-record read-modify-write without a direct field-111 dereference**. This
is positive preservation-path evidence, not a human label or proof that the
attribute affects administrator behaviour. The verifier has a negative control
that deletes this whole-record write from a checksum-refreshed query and
requires rejection.

## Direct reader boundary and forwarded records

Ghidra's [direct-call query][reader-callers] returns ten callers of record
reader `100073c0`, with no additional direct caller on that result page. The
number describes this loaded program's direct call graph. Whole-record copies,
aliases, indirect calls and derived/indexed access remain possible.

| Caller     | Bounded visible use of the loaded record                                                                            |
| ---------- | ------------------------------------------------------------------------------------------------------------------- |
| `10003170` | Startup/admin-account path reads stored password data.                                                              |
| `10007780` | Local administrator password change reads and rewrites the whole record.                                            |
| `10007fa0` | Administrator password setup check reads a record then tests stored password length.                                |
| `10011960` | Normal login reads account name, password and bitmap for comparison/session state.                                  |
| `10011ee0` | Delayed login continuation passes the loaded record to `10004d50`; that inspected helper reads bitmap/name offsets. |
| `10014bc0` | Operation 352 builds lookup reply without field 111.                                                                |
| `10014df0` | Operation 353 reads the old record for the NUL password-preservation case and writes a new record.                  |
| `10015160` | Enumeration builds 348 account entries without field 111.                                                           |
| `10015500` | Batch update reads an old record for preservation cases and writes a new record.                                    |
| `100197e0` | Local account-list UI enumerates records, reading name/login/bitmap-derived values; its caller is `1001f140`.       |

The [live propagation helper][live] has two direct callers, replacement and
batch. Its inspected body uses bitmap, display-name and login offsets, but does
not show a direct `0x254`/`0x256` read. The `10004d50` and `10004bf0` session
helpers also inspect bitmap/name offsets in their retained snapshots. These are
local observations of named functions. They do not establish that all consumers
of copied records have been found.

The [string queries][strings] found 14 `Account`, three `User`, one `Note`, zero
`Comment` and zero `attribute` matches in Ghidra's string listing. The
inspected account-list UI and earlier ban-editing range supplied no field-111
label. String search does not exhaust resource-fork text, dynamic composition
or other UI paths. A semantic label therefore has **no positive support** in
this corpus; the field remains an opaque account attribute.

## Resource-fork search boundary

A [read-only resource inventory][resource-audit] checks the supplied
application resource fork against its recorded SHA-256. All 58 entries are
listed by type, ID, name, size and data hash. Case-insensitive account/user,
comment, note, description, directory/folder, email and owner/creator byte
searches yield 17 content hits, all in filesystem error resource EMSG 4. The
HTLS 0 resource name is Owner resource; no link to account field 111 has been
established. It is not a field label.

This closes the earlier unexamined-resource-fork search boundary. It supplies
no positive semantic consumer for 111: strings assembled dynamically, encoded
labels, DATA-fork UI paths and indirect record access remain separate
questions. The raw resource fork is not redistributed. The supplied extracted
application is required to rerun the retained parser and compare the frozen
inventory.

## Identified Classic client construction boundary

The
[identified Classic client's account constructors](classic-account-constructors.md)
provide a separate executable trace. The inspected 350/353 constructors append
105/106/102/110, and the 349 serializer adds conditional old-login 101 before
those fields. The deletion-list shape is inner 101 and outer 101. These
functions do not emit field 111; four immediate `0x6f` candidates instead pass
an error code. This does not establish whole-client absence or a semantic
label. The field remains opaque, with its server storage and fixture outcomes
specified above.

## Reproduce and decision boundary

From the private `mothra` checkout, run the verifier and its five tests:

```sh
python3 ../hotline-protocol-docs/scripts/verify_account_attribute.py \
  evidence/gap-remediation/2026-11-13/account-attribute-01 --root .
python3 -m unittest discover -s ../hotline-protocol-docs/scripts \
  -p 'test_account_attribute.py' -v
sha256sum --quiet -c \
  evidence/gap-remediation/2026-11-13/account-attribute-01/SHA256SUMS
```

GAP-071's wire byte type, observed presence/default and storage behaviour now
have bounded evidence. Its human meaning and any effect beyond preserving or
replacing bytes remain unanswered. No “unused” or “reserved” label follows from
the absence of a direct read in the inspected functions. A later closure
decision needs positive semantic consumer evidence or an explicit decision to
document only the opaque observed contract.

[corpus]: ../mothra/evidence/gap-remediation/2026-11-13/account-attribute-01/manifest.json
[core]: ../mothra/evidence/gap-remediation/2026-11-12/native-core-01/manifest.json
[update]: ../mothra/evidence/gap-remediation/2026-11-13/native-account-update-01/manifest.json
[create]: ../mothra/evidence/gap-remediation/2026-11-13/account-attribute-01/queries/AA-A-100146f0.json
[replace]: ../mothra/evidence/gap-remediation/2026-11-13/account-attribute-01/queries/AA-A-10014df0.json
[batch]: ../mothra/evidence/gap-remediation/2026-11-13/native-account-batch-01/oracle-queries/BA-D-10015500.c
[creator]: ../mothra/evidence/gap-remediation/2026-11-13/native-account-update-01/oracle-queries/AC-D-100071a0.c
[writer]: ../mothra/evidence/gap-remediation/2026-11-13/native-account-update-01/oracle-queries/AC-D-100075e0.c
[admin-update]: ../mothra/evidence/gap-remediation/2026-11-13/account-attribute-01/queries/AA-D-10007780.c
[reader-callers]: ../mothra/evidence/gap-remediation/2026-11-13/account-attribute-01/queries/AA-C-100073c0.json
[live]: ../mothra/evidence/gap-remediation/2026-11-13/native-account-update-01/oracle-queries/AC-D-10005d30.c
[strings]: ../mothra/evidence/gap-remediation/2026-11-13/account-attribute-01/queries/AA-S-account.json

[resource-audit]: ../mothra/evidence/gap-remediation/2026-11-13/account-resource-01/manifest.json

## Bounded reader-alias follow-up

The [A95–A98 trace][alias-trace] maps the native PEF's uncompressed Code
section to loaded addresses and records a limited scan for direct positive
`0x254`/`0x256` offsets. That scan found no matching direct positive-load word;
branch immediates containing `0x254` are not field references. Stack relative
offsets can differ, so this is a filter, not an absence proof.

Six read-only disassemblies followed the known record reader's concrete
caller-supplied buffers in account-list UI `100197e0`, enumeration `10015160`,
batch `10015500`, startup `10003170`, setup `10007fa0`, and local administrator
update `10007780`. Their calculated field-111 stack offsets had no direct
access in the inspected instruction listings. The batch listing was initially
limited to 500 of 555 instructions. One further query captured instructions
500–554 with `has_more=false`; no direct access to its calculated
`+0xa94/+0xa96` offsets appeared there either. The 555 instructions are
complete in Ghidra's **function model** for `10015500`, not a complete program
dataflow or proof about indirect callees.

Both query sessions used the independently saved PowerPC BE32 project,
1,840-function before/after identity, pinned DATA and extension JAR hashes, and
`--no-analyze --discard`. The conditional callback and callee queries were
unused because no positive field-derived edge was established. The wire/storage
schema and whole-record byte-preservation path above remain positive facts. No
field-111-specific value-dependent consumer or human meaning has been
established; GAP-071's use question remains open.

[alias-trace]: ../mothra/evidence/gap-remediation/2026-11-14/account111-alias-trace-01/manifest.json
