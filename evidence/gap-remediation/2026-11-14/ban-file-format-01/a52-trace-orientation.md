# A52: native 1.9 `Banned` v2 stopped-fork trace (read only)

This note compares three already extracted, FD-free data forks. It did not
read a live image, query Ghidra, boot a guest or change any account/ban.
Canonical C56 `native-ban-control-01/case-c56/Banned.data.bin` and C62
`native-ban-reload-01/c56-reference/Banned.data.bin` are byte-identical,
49 bytes, SHA-256 `53bec37683dc9bab6cc812f38fa465724085e9c35fc5b7bdf72e25dd09b727d4`.
C68 `state/native-sessions/native-configured-apply-c66/stopped-files/Banned.bin`
is 49 bytes, SHA-256
`671c8164c116d26cf5bb863ba87b93174f81b1a59abb208491b57f9d41a87aa1`.
C68's extracted catalog explicitly resolves `11750 Hotline19/Banned`; it
is not a guessed filename match. Its portable C69 counterpart, if accepted,
should retain the same bytes.

Frozen native sources are `evidence/gap-remediation/2026-11-12/batch-06/queries/B06-D-1000a070.c`
(reader), `B06-D-10009d10.c` (writer), `B06-D-10006230.c` (constructor), and
`B06-D-10057e30.c` (date formatter wrapper). The default helper `10009930`
was **not** found as a retained standalone decompilation; its name in the
constructor is only a callsite. No new oracle result was obtained.

| Offset, bytes | C56/C62 and C68 | Positively grounded interpretation |
| --- | --- | --- |
| `0..1` (2) | `0002` | Big-endian file version 2: writer writes 2; reader branches on version `<3`, with a different version-1 path. |
| `2..5` (4) | `00000001` | Big-endian count 1: writer writes list count and reader iterates count. |
| `6` (1) | `01` | Entry flag from record offset 0; constructor assigns 1, reader/writer each transfer one byte. The writer retains records whose flag is nonzero. “Active” is supported in this narrow sense; no lifecycle rule inferred. |
| `7..10` (4) | `0a000202` | First address-range endpoint, 10.0.2.2 in observed IPv4 context, from in-memory offset 8. |
| `11..14` (4) | `0a000202` | Second endpoint, same value, from offset 0xc; C56 option-2 and C68 configured examples are one-address ranges. |
| `15` (1) | `15` | Length of following date-display bytes, 21 decimal; constructor calls `10057e30` over the record's 0x11 display region, stores returned length at 0x10. |
| `16..36` (21) | `11/14/2026 3:10:23 AM` vs `11/14/2026 4:50:02 AM` | Date/time **display string** generated through `GetDateTime`/`10057e90` on record construction. These are not a serialized binary expiry field or proven UTC instants. |
| `37..47` (11) | C56 `6e201dd2ed30220000481d`; C68 `000000000001000000a000` | Uninterpreted remainder of fixed 33-byte display area. Writer serializes all 0x21 bytes, reader restores all 0x21; only the leading length bytes are display content. Differences here are not evidence of a UUID, timestamp or policy field. |
| `48` (1) | `00` | Reason length 0; writer emits length plus that many bytes, reader checks `<=0x3f` and reads bytes. No reason payload in either sample. |

The 49-byte equation for one v2 entry is `2 + 4 + (1 + 4 + 4 + 33 + 1 + 0)`.
The source uses big-endian PowerPC integer storage; these two observed
address endpoints and count agree with the byte order. The constructor sets
in-memory offset `+4` to `ffffffff`, and the reader initializes that offset
to `ffffffff`, but the v2 writer emits **no offset-4 word**. Thus neither
sample stores a four-byte expiry at that position. The date-display string
is not a substitute expiry proof. C62's byte-exact reload proves these 49
bytes persisted through its one observed restart, while the separate C62
login refusal supports the loaded-ban behavior. It does not prove expiration
policy, clock handling, v1 behavior, arbitrary ranges/reasons, or C68
post-restart behavior.

The only sample differences are display text at offsets 27, 29, 32, 33 and
uninterpreted display-area tail at 37..43, 46..47. Header, count, flag,
address range, length and zero reason are identical. A protocol note can now
describe this bounded v2 record layout and explicitly opaque padding. It
should not convert `Banned` into a public protocol wire type or close GAP-020
or GAP-074 on these two distinct records alone.
