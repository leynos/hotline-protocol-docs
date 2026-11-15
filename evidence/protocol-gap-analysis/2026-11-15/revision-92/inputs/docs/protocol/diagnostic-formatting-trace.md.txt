# Native 1.9 diagnostic text: formatting and wire length

Transaction 303 returns generated diagnostic text in field 101 and the target
name in 102. Its text is presentation, not a second structured record format.
The [new static corpus][oracle] traces the final formatter and field writer
against the pinned native PPC DATA SHA-256
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`. This is
source evidence, distinct from the [recorded native replies][replies].

## Formatter-to-field trace

| Step                                                   | Native evidence                                                                                                                                         | Consequence                                                                                                         |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Handler `10016150`, instructions `10016a40`–`10016a60` | Destination in r3, `0x400` in r4; call `10054180`.                                                                                                      | Final destination has a 1,024-byte output budget.                                                                   |
| Wrapper `10054180`                                     | Saves variadic arguments, passes their address in r6, calls `10054310`, returns without changing r3.                                                    | The formatter's count reaches the handler. Its old decompiled `void` signature is misleading.                       |
| Formatter `10054310`                                   | Literal, converted-value and padding writes increment the count and return when it equals the supplied budget; end of format returns the current count. | The inspected positive-budget path produces at most 1,024 bytes here. It does not reserve or append a trailing NUL. |
| Handler `10016a68`–`10016a7c`                          | Saves returned r3, supplies it as r6 to `100568b0` with field `0x65` and the destination pointer.                                                       | Field 101 uses the returned byte count, rather than `strlen` or count minus one.                                    |
| Field writer `100568b0`                                | Accepts a positive length up to `ffff`, stores that TLV length and copies that many bytes. Zero length appends no field.                                | It adds no text terminator or character conversion to this payload.                                                 |

Thus **1,024 field-101 bytes** is the source-derived final formatting cap for
this handler. It is not a claim that a live at-cap fixture was captured, nor
that every intermediate transfer-summary construction was independently proved
safe. Clipping can stop within a label, line or encoded character; no
complete-line or Unicode-boundary guarantee appears in this path.

The format parser's `s` conversion distinguishes length-prefixed `%#s` from
NUL-terminated `%s`. Its precision/width and padding are formatting operations,
not evidence for a general text codec. The field writer copies counted bytes.
Native fixtures retain raw byte `8e` and CR byte `0d`; other field-specific
encoding requirements remain in GAP-018/019.

## Observed lengths and compatibility

The [idle/denied/missing-target matrix][replies] records 299- and 303-byte
successful text, plus the two observed error families. The
[active/queued witness](../native-evidence/native-diagnostic-existing-witness.md)
records 350 bytes at one active and one waiting download. The
[density witness](../native-evidence/native-diagnostic-density-witness.md)
records 417, 647 and 763 bytes. The
[partial near-boundary witness](../native-evidence/native-diagnostic-near-witness.md)
contains a complete 995-byte 303 reply, 29 bytes below the cap, inside an
**overall failed capture**. Its incomplete cancellation remains a failure; the
successful reply does not make the whole plan pass.

For this protocol baseline, exact diagnostic wording is **descriptive**.
Compatibility requires the documented request/permission/reply envelope and raw
field handling, not parsing or reproducing labels, spacing, percentages,
section prose or a particular host's displayed address. Exact captured bytes
remain available when comparing the pinned build and configuration. An mxd
release promise of byte-for-byte presentation parity is a separate decision;
further mxd validation remains on hold.

The inspected identified shx callback copies field 101 by its TLV length,
converts CR to LF, strips terminal escapes and passes the result to its output
callback. That output displays the text; these two inspected functions do not
parse native diagnostic labels. The corpus retains both source files. This is
one receiver path, not a claim about every client or all uses of 303.

## Reproduction and limits

The corpus retains four as-run query scripts, arguments, timestamps, backend
logs and raw results. Batch 1 imports the exact PEF into a **new independent**
PowerPC big-endian 32-bit project and analyses it; later batches open only that
project with `--no-analyze --discard`. All four before/after identities match
at 1,840 functions. No GUI-owned project was read or copied. The handler's 606
instructions are retained as a 500-instruction page and a second page starting
at offset 500. Two alternate-wrapper callback queries return
`FUNCTION_NOT_FOUND`; those errors remain evidence limits, not source.

Verify the corpus from `mothra` with `sha256sum --quiet -c` followed by its
`SHA256SUMS` path. Inspect the instruction and decompilation records above; the
archived scripts show the independent-import procedure. The static cap is not a
live maximum/maximum-plus-one test, and these captures do not settle arbitrary
names, locales, IPv6 display, concurrent transfer changes or every intermediate
buffer boundary.

[oracle]: ../../evidence/gap-remediation/2026-11-14/native-format-endpoint-oracle-01/manifest.json
[replies]: diagnostic-replies.md
