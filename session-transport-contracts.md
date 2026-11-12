# Native session and transport contracts

The [guide](protocol.md) defines the ordinary frame. This supplement refines
GAP-008–GAP-011, GAP-024 and identifier allocation using the baseline dispatcher
and [batch 07][batch]. Static tables are derived from native code. The
[captured boundary cases](#captured-handshake-boundaries) separately identify
actual packet/stream outcomes; neither source establishes universal drain timing.

## Configured endpoints

Configuration reader `10008fd0` loads the base port and defaults an absent/zero
value to **5500** (`157c`). Startup `100007b0` binds these four endpoints using
a 12-byte native address structure:

| Configured port | Server field | Construction/consumer |
| --- | --- | --- |
| Base | `+0x18` | Ordinary handshake wrapper, constructor mode 1; consumed by session dispatcher. |
| Base + 1 | `+0x20` | Raw transfer endpoint, mode 1; consumed by HTXF acceptor. |
| Base + 2 | `+0x1c` | Alternative wrapper, constructor mode 0; consumed by session dispatcher. |
| Base + 3 | `+0x24` | Alternative raw transfer wrapper, mode 0; consumed by HTXF acceptor. |

Default ordinary control/data ports are therefore 5500/5501, with the alternate
pair at 5502/5503. The port halfword assignments narrow the additions; boundary
configuration still needs a fixture. The two modes use different transport
wrappers, with mode 0 wrapping Open Transport objects through `100738b0`.
This analysis does not assign TLS, HTTP or peer identity solely from that mode
flag. Complete alternate-wrapper wire negotiation remains outside the ordinary
session contract and requires separate tracing.

Both control listeners feed the same dispatcher, and both data listeners feed
the same HTXF acceptor. No independently negotiated per-request data-port field
appears in this startup mapping. Native fixtures now establish a primary
control exchange on 5500 and unmatched-reference HTXF rejection on 5501.
The alternate 5502/5503 listeners accepted TCP and acknowledged ordinary
unwrapped input but returned no application response within ten seconds.
They are not established as interchangeable plain-protocol endpoints. Full
alternate-wrapper negotiation and port-boundary configuration remain GAP-010.

## Handshake consumption and failures

The session handshake helper waits for availability of twelve bytes before
reading its twelve-byte structure. Its magic/version checks are followed by
the dispatcher's HOTL/sub-version checks. Derived outcomes are:

| Header contents | Native calls/outcome |
| --- | --- |
| `TRTP HOTL 0001 0002` | Queues eight-byte `TRTP 00000000`, then creates a normal session subject to connection limits. |
| `TRTP HOTL 0001 0003` | Queues the same success bytes, then hands the underlying connection to HTXF processing. |
| Wrong first magic | Helper reports unknown protocol; dispatcher disposes the pending wrapper. No failure handshake is built by that branch. |
| TRTP but version not 1 | Helper queues `TRTP 00000001`, returns its failure discriminator; dispatcher disposes the wrapper. |
| Version 1 but wrong sub-protocol or sub-version other than 2/3 | Dispatcher queues `TRTP 00000001` and invokes its disconnect helper. |
| Fewer than twelve available bytes | No complete handshake parse yet. |

A queued response is not proof that all eight bytes reach the peer before
closure. Connection-limit rejection can also follow the success-handshake call,
so success bytes alone do not promise authentication or admission. Drain
behaviour outside the recorded boundary cases remains unverified. Ordinary
transfer entry paths are captured below; broader native/peer scenarios remain
GAP-055/084.

## Captured handshake boundaries

The [native transport corpus][native-transport] records both host-to-proxy TCP
and guest/SLiRP-boundary Ethernet packets. Its final catalogue contains 14
addressed cases; the socket tuples select their exact packet flows. Packet
analysis checks sequence continuity and retransmissions against both recorded
application streams, retaining reset payloads as separate transport observations.

| Input on the ordinary control listener | Recorded application bytes and guest close order |
| --- | --- |
| Normal twelve-byte version-1/sub-version-2 handshake | Eight-byte `TRTP 00000000`; client then closes. |
| Wrong first magic | No handshake reply; guest RST with diagnostic payload. |
| Version 2 | Eight-byte `TRTP 00000001`, then guest RST. |
| Wrong sub-protocol / sub-version 4 | Eight-byte `TRTP 00000001`, then guest FIN before client closure. |
| Split after 1, 4, 8, 10 or 11 bytes | No response/EOF during a three-second window; remaining bytes yield success. |
| Eleven bytes followed by client write-half-close | No handshake reply; guest FIN follows the client FIN. |
| Handshake and login in one send | Success handshake followed by login ACK, 354 and 109; following frame is preserved. |
| Handshake plus byte 13, then the rest of login | Success handshake; byte 13 is retained as the frame prefix and login succeeds. |

These satisfy GAP-008's unchanged boundary-fixture criterion for the ordinary
session handshake. They do not certify matching-reference transfer completion,
alternate-wrapper negotiation, all network stacks or physical-network timing.
The observed RST diagnostics include `tcp_disconnect` and `No TCP`; they are
not Hotline error fields or additional handshake bytes. TCP permits reset
segments to contain diagnostic data, without defining a diagnostic format
([RFC 9293 section 3.5.3](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.5.3)).
The host proxy exposed EOF where the guest emitted RST, so a socket EOF alone
must not be described as a graceful native close.

### Sub-version 3 versus the data endpoint

The sub-version-3 path retrieves the underlying transport, sets the wrapper's
transport pointer to zero, disposes the wrapper and puts the preserved transport
into the pending HTXF collection. It does **not** allocate a normal user session
or require a second TCP connection in that branch.

The two derived entry sequences are:

1. On a control endpoint: send twelve-byte TRTP/HOTL version-1 sub-version-3
   handshake; consume eight-byte success response; continue on that same
   connection with the 16-byte HTXF header and direction-specific stream.
2. On a data endpoint: send the 16-byte HTXF header directly, followed by its
   stream/control exchange; the raw acceptor does not parse TRTP first.

The HTXF reference must still match a collection created by a control operation.
The handover does not fabricate a transfer or bypass the reference lookup.
Direct data-port and handed-over connections converge on the same acceptor.
Native negative fixtures now show raw HTXF reference zero rejected on 5501,
and the control sub-version-3 path returning success before rejecting the same
HTXF header on that connection. [Matched ordinary-file fixtures](transfer-contracts.md#captured-ordinary-file-round-trips)
now complete both entry paths for uploads/downloads. Banner matching remains
GAP-055 and alternate-listener wrapping remains GAP-010.

## Receive-limit assignment at startup

The immutable baseline retained the data-image value `00200000` (2 MiB) at
`10094a50` and correctly left its runtime value unresolved. New startup capture
`100007b0` explicitly assigns **`00080000` (512 KiB)** before loading server
configuration. This is stronger evidence for the ordinary initialization path
than treating the image initializer as the active limit.

Receiver `100590e0` rejects a total/data size word equal to zero or greater
than the current global; equality passes that comparison. The startup assignment
is not a sum-of-fragments, number-of-transactions or process-memory bound.
Later indirect writes/configuration still need verification. The captured
boundaries below apply to this runtime. The reference inventory does not prove
can be no other writes (GAP-011).

### Captured framing and reassembly boundaries

The [62-case framing corpus](../mothra/evidence/gap-remediation/2026-11-12/native-framing-01/verification.json)
reconciles socket bytes with host-loopback and guest Ethernet TCP lifetimes.
The guest continued the same hashed runtime used by the transport corpus.

| Native input | Captured outcome |
| --- | --- |
| Either size word zero, 524,289 or `ffffffff`, header only | Guest initiates close without a numbered reply. |
| Complete physical payload of 1, 2, 524,287 or 524,288 bytes | Request 500 dispatches and returns empty ACK. This handler does not inspect the TLV stream. |
| Flags `ff`; request error word `ffffffff`; request ID zero | Request 500 accepted; ACK preserves the request ID. |
| Reply byte 1, 2 or 255 with unmatched ID | No output during three-second window; a later request receives its ACK. |
| Two fragments, each two bytes, total four | No output for three seconds after first; ACK after second. |
| First total 100, second total four | ACK after four accumulated bytes; the later total governs this case. |
| Total three, accumulated four | ACK on overshoot. |
| Total 524,288, fragments two plus 524,288 bytes | ACK at accumulated 524,290; per-frame size comparison is not an aggregate limit. |
| First fragment type 500, final fragment type 304 | Settings notification 301; final fragment type governs this case. |
| Partial IDs 10/11, finish 11 then 10 | ACK order 11 then 10. |
| Abandoned partial ID 10, complete ID 11 | ID 11 ACKs; no output during the preceding three-second window. |
| Request and unmatched reply with same ID during assembly | Reply does not complete the request; final request fragment produces ACK. |
| TCP splits inside header and body | No output during each three-second incomplete-input window; ACK after complete bytes. |
| Sequential completed requests reuse ID 10 | Two distinct ACKs with ID 10. |

These fixtures do not establish an assembly-age limit, maximum simultaneous
partials, aggregate allocation cap, all reply-direction values or mxd policy.
The [TLV/handler matrix](native-wire-details.md#captured-tlv-and-scalar-boundaries)
separates structural indexing from request-specific outcome. GAP-011–013 and
GAP-015/017 retain their broader acceptance requirements.

## Identifier domains

The dispatcher allocates user IDs by incrementing a 16-bit counter and skipping
wrapped zero. No live-ID collision scan appears at that allocation site.
Room allocator `100067d0` combines random high bits with an incremented low byte,
then scans existing rooms and increments until its candidate is nonzero and
unused. This is distinct from the per-connection transaction counter and the
transfer reference allocator already documented elsewhere.

The saved client version is the generic numeric result stored as 32 bits;
it is not restricted here to a `u16` release identifier. A missing value becomes
zero. Early login completion depends on nonempty name 102 and nonzero icon 104
after 16-bit narrowing. Banner metadata uses the 151 threshold and category
format uses 15. No threshold proves a named client build. ID reuse/wrap,
version-boundary and identified-peer fixtures remain GAP-024/033/080.

## Activity clocks and incomplete input

The dispatcher samples `GetDateTime` once per invocation and uses unsigned
32-bit subtraction for its elapsed comparisons. This is the native seconds
clock, not evidence of a monotonic timer. Clock adjustment, counter rollover,
worker scheduling and transport drain still require runtime fixtures.

A new session initializes activity at `session + 0x9c` when the handshake has
been admitted. The request loop updates that slot only after
[complete-request selection `10058e80`][select] succeeds and before dispatching
the handler. Its selector requires accumulated payload length at least the
recorded total. The [frame receiver][receive] can consume a partial payload or
retain incomplete fragments without returning a dispatchable request.

Consequently, TCP byte arrival, a complete physical fragment and a processed
logical request are different activity events. Partial input does not refresh
the activity slot in these traced paths. Once online, the idle branch changes
status instead of imposing a universal frame-assembly deadline.

| State / counter | Native comparison and boundary | Reset / action |
| --- | --- | --- |
| Admitted but not online | Activity age at least 61 seconds | A selected request refreshes activity; expiry calls the close helper. |
| Authentication failure recorded | Failure timestamp nonzero and age greater than 30 seconds | Normal request loop is bypassed; expiry calls close helper. |
| Online idle status | Activity age greater than 600 seconds | Selected request clears idle state and refreshes activity; expiry sets idle, not a disconnect here. |
| Fewer than 12 handshake bytes | Availability test waits | No age comparison in the dispatcher's pending-handshake walk or the inspected handshake helper. |
| Raw HTXF accepted but fewer than 16 header bytes | Availability test waits | No age comparison in the inspected pending-HTXF walk; a transfer entry's separate timer is not automatically this connection's timer. |
| Incomplete online frame or fragmented request | Receiver retains available partial state | No assembly-age comparison in the receiver or complete-request selector. |

The last three rows are bounded negative findings. Lower transport/platform
behaviour can still close a connection, and no global claim of unlimited
lifetime is made. Native stalled-handshake/header/body/fragment fixtures remain
GAP-005/008/012/055/084. These observations also do not prescribe mxd's chosen
resource limits or deadlines.

### Captured failure-wait observations

The compiled age comparisons above are not unconditional wall-clock deadlines.
The dispatcher must run and its transport predicate must permit the branch.
The retained [transport guard queries][guards] show primary predicate `10070790`
checking Open Transport atomic bit 1 and endpoint state 6; closing helper
`10070610` calls `OTSndDisconnect`. No human meaning is assigned to that numeric
endpoint state without its platform definition.

In the [timing fixtures][timing], a failed-login reply was followed by 65.060281
host seconds with no guest FIN/RST before client cleanup. In a separate trial
with no other scripted guest connections, a 35-second bounded-silence action
completed; a new control SYN was followed 92.254 ms later by a reset of the
failed session. The analyser verifies these packet/stream observations. An
earlier trial overlapped data probes and is retained separately rather than
used as an isolated timing experiment.

This refines the close outcome, not a proof of the unique scheduling mechanism.
Dispatcher invocation, platform events, clock changes and other profile/config
conditions remain GAP-005. Do not publish a mandatory 30-second disconnect or
attribute the 65-second result solely to host-proxy FIN propagation.

## Flood and connection-burst counters

Two separate mechanisms appear in dispatcher `1000acf0`:

| Mechanism | Native state / comparison | Consequence |
| --- | --- | --- |
| Per-session request flood | Reset counter when window age is greater than 60 seconds. Before dispatch, reject if the existing counter is greater than 120; otherwise increment it. | Close path, with a timed address-ban entry whose expiry is native time plus 1,800 seconds. |
| Consecutive same-address connection burst | Server-wide last address, start time and repeat count. A changed address resets start/count to now/zero. For the same address, increment count, then test count greater than 10 and elapsed age less than 30 seconds. | Timed address-ban construction and pending-connection rejection. |

Starting from a reset request counter of zero, 121 requests pass the counter
check; the next is rejected unless the greater-than-60-second reset has occurred.
This is a code-derived boundary, not a measured per-second throughput promise.
At exactly 60 seconds this reset does not yet apply. The connection-burst branch
uses a different strict comparison: exactly 30 seconds is outside its rejection
window. Its initial address encounter has repeat count zero, so the twelfth
consecutive encounter reaches count 11.

The connection counter tracks the last address rather than a separate sliding
window for every address. The inspected same-address branch does not restart
its start time merely because 30 seconds have elapsed. Interleaved addresses,
window boundaries, ban expiry/restart and control-loop batching need native
fixtures before claiming a conventional rate-limit algorithm (GAP-045/074).

[batch]: ../mothra/evidence/gap-remediation/2026-11-12/batch-07/manifest.json

[select]: ../mothra/evidence/gap-remediation/2026-11-12/batch-16/queries/B16-D-10058e80.c
[receive]: ../mothra/evidence/gap-remediation/2026-11-12/batch-16/queries/B16-D-100590e0.c

[native-transport]: ../mothra/evidence/gap-remediation/2026-11-12/native-transport-01/manifest.json
[timing]: ../mothra/evidence/gap-remediation/2026-11-12/native-transport-01/timing-observations.json
[guards]: ../mothra/evidence/gap-remediation/2026-11-12/native-transport-01/transport-guards/transport-guards.json
