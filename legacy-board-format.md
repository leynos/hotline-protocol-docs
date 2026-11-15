# Native 1.9 legacy board format: static constants

This note records bytes recovered from the pinned Hotline Server 1.9 PEF, not a
captured board post. The
[read-only oracle corpus](../mothra/evidence/gap-remediation/2026-11-14/legacy-board-static-01/manifest.json)
contains the six memory replies, before/after program identities, query
script, and checksums. The binary SHA-256 is
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`. The saved
independent PowerPC BE32 project had 1,840 functions before and after the
`--no-analyze --discard` read-only session.

## Pointers and literal bytes

At `10089144`, two big-endian pointers are `100826bc` and `10082694`. The
former points to a Pascal string: byte `3c` means 60 content bytes, which are
`0d`, 58 copies of `5f` (`_`), and `0d`. The leading displayed `<` is the
length byte and is **not** emitted separator content.

At `10082694`, the NUL-terminated format bytes are
`From %#s (%s%2.2hu %2.2hu:%2.2hu):` followed by `0d 0d`. The `%#s` conversion
is retained as source syntax; its exact emitted text depends on the formatter
call and inputs. Neither these constants nor the month table at `1008fcf9`
establishes a timezone, full date rendering, or a general character encoding
rule. The table contains NUL-separated `Jan` through `Dec`, then `???` and
`***`.

At `1008ee20`, the pointer is `1008f87e`. That address begins with Pascal length
`10` (16) followed by `MessageBoard.txt`. Subsequent bytes in the 260-byte
read are adjacent strings, outside this filename.

The
[frozen writer `10004110`](../mothra/evidence/gap-remediation/2026-11-12/batch-08/queries/B08-D-10004110.c)
connects these pointers to board-segment construction and file writing. The
[101 reader](../mothra/evidence/hotline-server-1.9/queries/D-1000f130.c) and
[103 handler](../mothra/evidence/hotline-server-1.9/queries/D-1000f260.c)
establish the aggregate reply and post/update paths. See the
[legacy-board contract](filesystem-and-board-contracts.md#legacy-board-101102103)
for the bounded transaction rules.

The corpus also retains a read-only `istat` result on the immutable stopped
base disk for allocated `/Hotline19/MessageBoard.txt` catalogue record 11191:
zero-byte data fork, zero-byte resource fork, Finder type `TEXT`, creator
`ttxt`. This establishes an empty starting file in that particular base image.
It does not establish a live empty board buffer or prove write durability.

The multi-post, recipient, empty-input and size-boundary fixtures in
[GAP-046](gap-analysis.md#gap-046) remain to be run. No observed 102 or 101
wire segment is inferred from the static bytes alone.
