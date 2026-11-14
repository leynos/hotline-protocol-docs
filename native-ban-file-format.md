# Native Hotline Server 1.9 `Banned` data fork: observed v2 layout

This note describes three **stopped-image** data forks and the retained
PowerPC decompilations of the reader, writer, and record constructor. It is a
local server store, not a Hotline network packet. The [portable corpus](../mothra/evidence/gap-remediation/2026-11-14/ban-file-format-01/manifest.json)
contains all three 49-byte files, decoded offsets, source query results, and
SHA-256 inventory. The source queries identify the `HLserver19` PEF as
PowerPC big-endian 32-bit; the application DATA fork identity is
`ad7040db4eb6…`. No live image or Ghidra project was consulted for this note.

<!-- markdownlint-disable MD013 -->
| Offset | Size | Observed bytes and supported interpretation |
| --- | ---: | --- |
| 0–1 | 2 | `0002`: version 2, written by `10009d10`; reader `1000a070` branches for versions below 3. |
| 2–5 | 4 | `00000001`: one record, written from list count and iterated by the reader. |
| 6 | 1 | `01`: record flag at in-memory offset 0. Constructor sets 1. |
| 7–10 | 4 | `0a000202`: first address-range endpoint, 10.0.2.2 in these IPv4 fixtures; memory offset `+8`. |
| 11–14 | 4 | `0a000202`: second endpoint, memory offset `+0xc`; both fixtures are single-address ranges. |
| 15–47 | 33 | Fixed display area, memory offset `+0x10`: first byte `15` gives 21 displayed bytes, followed by 11 opaque remainder bytes. |
| 48 | 1 | `00`: reason-byte count zero. No reason bytes follow in these samples. |
<!-- markdownlint-enable MD013 -->

The one-record size is `2 + 4 + (1 + 4 + 4 + 33 + 1) = 49` bytes.
The first two endpoints and count match big-endian byte order. The C56 and C62
files are byte-identical (SHA-256 `53bec376…`); C68 is `671c8164…`.
The only C56–C68 byte differences are at offsets 27, 29, 32–33, 37–43,
and 46–47, all within the 33-byte display area. The leading 21 bytes are
`11/14/2026 3:10:23 AM` for C56/C62 and
`11/14/2026 4:50:02 AM` for C68. The constructor calls `10057e30`, whose
retained wrapper calls `GetDateTime` and `10057e90`; these are **display
strings**, not proven UTC instants. The 11 remaining bytes differ and have no
assigned meaning. They are not evidence for a UUID, binary expiry, or policy
flag.

## Reader and writer bounds

Writer `10009d10` emits version 2, four count bytes, then for each list entry
one flag byte, two four-byte endpoints, all 33 display bytes, and reason count
plus that many bytes. Its post-write branch removes a record whose flag is
zero or appends a nonzero record to the active vector. The source also shows
file housekeeping and a path for zero count, but this corpus does not establish
all replacement or empty-file outcomes.

Reader `1000a070` tests version `< 3`, reads count, and allocates a record for
each iteration. For version 1, it copies the first endpoint to the second and
reads an additional two bytes; these v2 samples do not test that branch. For
version 2, it reads both endpoints. It reads the fixed 33-byte display region,
then rejects a reason-count read that is not exactly one byte, a count above
`0x3f` (63), and a reason read shorter than that count. Earlier fixed-field
read lengths and the count itself have no comparably clear validation in this
decompilation; malformed files and resource exhaustion must not be described
as safely rejected. Versions 3 and above skip the list branch in the retained
reader. Nothing here proves compatibility for all historical versions.

Constructor `10006230` sets in-memory `+4` to `ffffffff`, fills the display
region and its length byte, sets the two endpoints, and caps the in-memory
reason length at 63. Reader `1000a070` also initialises in-memory `+4` to
`ffffffff`. **The v2 writer never serialises `+4`**: there is no four-byte
expiry field in these records. The call to `100539c0` copies reason bytes, but
its standalone implementation was not retained, so its handling of an input
Pascal string or field 101 cannot be inferred here.

## Replay and limits

From the Mothra corpus directory, run `sha256sum --quiet -c SHA256SUMS`.
Inspect `decoded.json` against `samples/*.bin`: read offsets 0–1 and 2–5 as
big-endian integers, compare the two four-byte endpoints, treat bytes 15–47 as
one fixed display region, and use byte 48 as the zero reason length. The
`different_offsets` lists allow direct byte-by-byte confirmation. The four
source query pairs in `queries/` retain the address and program provenance.

C62 demonstrates this exact C56 file surviving one observed restart and its
corresponding login denial; C68 was not restarted here. The three samples
cannot establish expiry, clock handling, arbitrary address ranges, non-empty
reasons, malformed-input behaviour, or a complete on-disk schema. A GAP-074
contract update can state the **observed v2 one-record layout and exact
readback**, with the display remainder opaque and these limits explicit;
closure of broader ban persistence or compatibility criteria needs additional
fixtures.
