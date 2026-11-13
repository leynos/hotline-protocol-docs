# mxd framing and memory limits at 2e4c9c1

This review concerns GAP-011 at the pinned mxd base
`2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131`. The adjacent private
workspaces are identified in the [evidence manifest][run]. It separates
native Hotline Server 1.9 observations, mxd's configured limits and the
tested implementation boundaries. No native guest was contacted for this
packet.

## Native boundary and mxd policy

The [native startup assignment][native] writes 524,288 bytes (512 KiB) to the
receive-limit global. The receiver closes for a zero or greater-than-524,288
size word, while equality passes. Native request 500 dispatched after two
fragments with sizes two and 524,288, an aggregate of 524,290 bytes. That
observation does not establish an aggregate allocation cap, all later writes
to the global or mxd's intended interoperability policy.

mxd declares `MAX_FRAME_DATA = 32,768` and `MAX_PAYLOAD_SIZE = 1,048,576`
in `src/transaction/mod.rs`. Its physical decoder rejects a declared frame
data size above 32,768 before reserving payload bytes. Its logical transaction
validator rejects a declared total above 1,048,576; equality is accepted.
The limits are deliberate mxd configuration, not a measured copy of the
native 512 KiB comparator. Changing either default requires a separate
compatibility decision.

## Implementation paths and comparisons

- `src/wireframe/codec/physical_frame.rs::take_hotline_frame` reads the
  20-byte header, calls `validate_header` before `BytesMut::reserve`, then
  uses `checked_add` for header plus data length. `validate_header` in
  `src/wireframe/codec/mod.rs` uses `>` for both the 1 MiB total and 32 KiB
  physical data limit, so equality remains permitted. It rejects data greater
  than total and zero data with nonzero total.
- `src/wireframe/codec/framed.rs::HotlineCodec` accepts one physical fragment
  at a time. Continuation handling uses `checked_sub` for remaining bytes and
  rejects data greater than the remainder. It normalizes completed logical
  `data_size` to `total_size` before calling `HotlineTransaction::from_parts`.
  The original `from_parts` incorrectly re-applied the 32 KiB physical limit
  to this normalized logical header. The retained red run passed 32,768
  bytes but rejected 32,769 and 1,048,576 with `InvalidData`/“payload too
  large”. The private correction removes only that physical check from
  `from_parts`. Exact logical length, total/data consistency and the 1 MiB
  total limit remain checked there. The real physical decoder keeps its
  32 KiB rejection.
- `src/wireframe/codec/frame.rs::HotlineFrameCodec` is the server's frame
  adapter. It reports `HEADER_LEN + MAX_PAYLOAD_SIZE` as the logical message
  ceiling, while each inbound physical fragment still passes the physical
  decoder. Its series tracker rejects overshoot using a remaining-byte check.
  `src/wireframe/message_assembly.rs` carries checked cursor arithmetic.
- `src/transaction/reader/mod.rs::TransactionReader` and its streaming
  variant default to 1 MiB total and accept a caller-supplied maximum.
  `src/transaction/frame.rs::read_frame` checks declared total and 32 KiB
  physical data before allocating. Continuations reject zero progress,
  changed header fields and data beyond the remaining length.
  `TransactionWriter::with_max_frame` clamps to 1..=32 KiB; the buffered and
  streaming writer total limit can be configured per instance. These builder
  overrides are separate from the current Wireframe server setup.
- `src/server/wireframe/mod.rs` explicitly calls
  `memory_budgets(explicit_memory_budgets())`. The three configured fields,
  `bytes_per_message`, `bytes_per_connection` and `bytes_in_flight`, each
  equal 1,048,596 bytes (20-byte header plus 1 MiB payload). An existing
  unit test checks those exact values; an integration test shows a large
  fragmented request routes and a 1 MiB+1 declared total disconnects.
  Those tests do not measure the maximum aggregate memory across concurrent
  connections. Wireframe's documented budget mechanism is an external
  dependency assumption until a multi-connection acceptance run verifies it
  at this mxd revision.

## Boundary witnesses and error results

The [red and green logs][run] exercise the production `HotlineCodec` decoder.
The red run is preserved, not counted as a passing gate.

- A valid 32,768-byte logical payload decodes as one physical frame.
- A valid 32,769-byte logical payload decodes after two bounded physical
  frames. The red base failed with “payload too large”.
- A valid 1,048,576-byte logical payload decodes after 32 physical frames.
  The red base failed with “payload too large”.
- A declared total of 1,048,577 or `u32::MAX` returns `InvalidData` with
  “total size exceeds maximum” before payload buffering.
- Declared physical data of 32,769 returns `InvalidData` with “data size
  exceeds maximum” before payload buffering.
- A continuation larger than the remaining bytes is rejected by an existing
  codec test with “fragment exceeds remaining payload size”.

The 1 MiB exact and overflow-word controls demonstrate inclusive comparison
and absence of wrap into an accepted length on the tested 64-bit Linux host.
The checked `usize` conversion and `checked_add` remain explicit production
guards. No 32-bit executable was tested, and a bounded finite corpus is not
an exhaustive proof. The Kani harness source covers `validate_header` and
fragment ranges; Kani was not run for this packet.

The full mxd `make test` gate did not reach test assertions. The first
post-restart attempt and one serialized retry both failed while linking mxd
test targets: the linker terminated with signal 11. The recorded `cc`
invocation includes `-fuse-ld=mold`; these logs do not identify GNU `ld` as
the failing implementation. The original pre-restart
attempt has no exit record and remains unknown. Successful focused tests,
format and lint checks are separate evidence from this blocked full gate.

The two-file Rust correction remains an **uncommitted candidate** in the
isolated mxd checkout. Its portable patch and base/final source snapshots
are retained in the [evidence][run]. No source correction has been merged
into the canonical mxd repository.

GAP-011 remains open for a complete native later-write/configuration trace
and independently measured aggregate buffering, plus any release decision
about mxd's distinct defaults. The private correction and witnesses resolve
the demonstrated mxd logical/physical confusion only; root reviews and
integrates them before updating the central register.

[native]: session-transport-contracts.md#receive-limit-assignment-at-startup
[run]: ../mothra/evidence/gap-remediation/2026-11-13/mxd-limits-01/manifest.json
