# Native 303 final-text boundary preparation

**Status:** proposal only. No VM, service, native socket or image action is
authorized by this packet. This is one finite GAP-019 diagnostic cell, not a
general string-limit experiment.

## Evidence and prediction

- Retained A12 `native-diagnostic-near-01/near/report.json` records successful
  field 101 of 995 bytes at eight active and sixteen waiting downloads, inside
  an overall **failed** capture. Its 16 waiting rows were 29 bytes each.
  [The near-boundary witness](native-diagnostic-near-witness.md) records the
  failed cancellation and the separately successful restoration postflight;
  neither becomes a passed 1024-byte case here.
- Handler `D-10016150.c` checks at least `0x28` free bytes before each waiting
  row in a 512-byte section. Sixteen measured 29-byte rows use 464 bytes; 48
  remain, so that guard permits a seventeenth 29-byte row, leaving 19. **Actual
  queue admission and row length must be measured**, not inferred solely from
  that guard.
- The final `10054180`/`10054310` formatter and field writer trace in
  [the formatter trace](../protocol/diagnostic-formatting-trace.md) gives a
  **source-derived 1024-byte cap**. If all prior bytes remain fixed, the 17th
  row predicts 995+29=1024 input bytes to the final formatter. Changing only
  the online subject nickname `framing-fixture` (15 bytes) to
  `framing-fixtureX` (16 bytes) predicts 1025 pre-cap bytes. The nickname is
  visibly inside field 101's first line in A12; field 102 separately carries
  the name. A 1025-byte _TLV_ is **not** predicted: source says its emitted
  length caps at 1024.

## Dedicated-session prerequisites and authority gate

1. Parent must approve a **new isolated native instance**, an exact immutable
   stopped base and fresh runtime, display, ports, capture directory and lease.
   Do not use the original primary, alias R04, or the live Classic client.
   Verify the exact `HLserver19` DATA SHA-256
   `ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b` and PPC
   BE32 identity before any query or contact. `protocol_capture.py` hashes a
   supplied local binary but reports remote identity as operator supplied;
   independently prove actual emulator PID/start/exe, image FD, namespace,
   lock, recorder FDs, and host/guest PCAP readiness.
2. Prove admin privilege bit 24, the exact owned `mothra-race-fixture` file
   and its 202/206 path in the disposable instance, no unrelated sessions, zero
   existing downloads, and the frozen two-account/41-Files baseline.
   Save/reopen native General Options at **8 global / 8 per client / 5 per IP**
   before the case; record original values for restoration. An absent file,
   different account/limits, owner ambiguity, or packet capture gap stops
   before the case. Do not silently seed or mutate the source fixture.
3. Use a current runtime identity receipt, not A12's stale environment.
   Create fresh **nonexistent** plan/capture output paths. Parent sets the
   local namespace relay control/data ports; they must be fixed in the plan.
   Capture services and the mutex must cover the whole bounded case and
   independent restoration postflight. No published A12 filename/port is a live
   default.

## Exact planned wire actions

All numbered control requests use one authenticated admin session `a` and one
target UID saved from its own 300 roster. TRTP client hello is
`54525450484f544c00010002`; require exact 8-byte server hello
`5452545000000000`. Login 107 ID1 uses existing `native_plan.login()` bytes:
complemented `admin`/`mothra19`, version `00be`, name
`6672616d696e672d66697874757265` (15 bytes), icon `0001`.

| Order    | Request IDs / exact field intent                                                                                                | Required observation                                                                                                                                                                                                                                                                                  |
| -------- | ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Initial  | 300 ID10, empty parameter list                                                                                                  | Save the sole own UID as two bytes; require expected name/icon, no unrelated row.                                                                                                                                                                                                                     |
| Active   | 202 IDs100–107, each field201 `6d6f746872612d726163652d66697874757265`                                                          | Eight distinct status0 references107, then eight 16-byte `HTXF` data attach requests; do not consume their FILP data before diagnostics.                                                                                                                                                              |
| Waiting  | 202 IDs120–135, same field201                                                                                                   | Sixteen distinct status0 queued references107 and queue positions116=1..16; 303 ID139 after ID135 must reproduce eight active/sixteen waiting and field101=995 with complete row inventory.                                                                                                           |
| Boundary | 202 ID136, same field201; then 303 ID140 field103=own UID BE16                                                                  | Queue position17, eight active/seventeen waiting; complete status0 field101/102, field101 expected 1024 if all 17 rows are 29 bytes. Record actual byte count and raw text; any discrepancy is evidence, not a reason to adjust the case.                                                             |
| Plus one | 304 ID150 fields102=`framing-fixtureX` (16 bytes), 104=`0001`; then 500 ID151 with zero fields; then 303 ID152 field103=own UID | 304 has no success ACK. Require self 301 with UID/name/icon, then direct 500 ACK ID151 as same-socket barrier. Field101 has 1025 predicted _unbounded_ input and must be measured for status, length and exact prefix/clipping; field102 should carry the 16-byte name.                               |
| Teardown | No 214 cancellation requests; close eight owned data sockets, then control socket                                               | Retain all host/guest tails, FIN/RST and zero-drop recorder receipts. Independently verify zero active/waiting and original options, accounts, Files and fork hashes in a fresh bounded postflight. Teardown or postflight failure keeps the **whole case failed**, even if a 303 reply was received. |

The existing `native_diagnostic_existing_cases` constructors `roster`,
`request`, `diagnostic`; `native_queue_cases.session/attach`; and
`native_plan.packet/payload/send/read/close` express every action above.
`protocol_capture.validate_plan` accepts the composed plan offline. One
construction using those exact helpers has **94 actions**, 9 TCP connections
(one control, eight data), 32 numbered control requests (107×1, 300×1, 202×25,
303×3, 304×1, 500×1), 41 sends including TRTP and data attaches, 34 framed
reads, one 8-byte hello read and nine closes. The 304 frame is exactly
`0000013000000096000000000000001c0000001c0002006600106672616d696e672d6669787475726558006800020001`.
The request ID ranges and action counts were checked by offline composition;
the current runtime/ports remain deliberately unbound pending parent grant.

## Result classification and stop rules

- **Boundary witness:** paired host/guest complete control streams and the
  recorder agree on IDs139/140/152, status0, TLV shape, exact 995 baseline, 17
  admitted 29-byte waiting rows, 301 name transition and 500 barrier. ID140
  field101=1024 and ID152 field101=1024 with a demonstrable changed first-line
  nickname and a one-byte clipped suffix establishes this one final-formatting
  max/max-plus-one result. Compare complete raw bytes, not just lengths. The
  preceding/source-side 1025 is a conditional derivation.
- **Alternative native result:** error, close, different row length/count,
  different emitted length or no 301 is retained as observed. It does not
  validate the predicted clipping or authorize another queue/name variant.
- **Infrastructure failure:** identity, capture, lease, deadline, ownership,
  timeout or output mismatch stops the one attempt. Keep failed raw report,
  PCAPs, action index and cleanup evidence. A12 failed during 214 cancellation;
  this plan omits those 25 control requests but still needs positive teardown
  and restored-baseline proof. Closing local sockets alone is not server-side
  cleanup proof.

No blanket 303 wording parity, memory-safety claim, character limit, mxd policy
or GAP-019 closure follows from this one cell. Further live execution requires
its own root START and reviewed resource/port/deadline packet.
