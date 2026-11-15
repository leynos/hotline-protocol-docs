# Native session and transport contracts

The [guide](protocol.md) defines the ordinary frame. This supplement refines
GAP-008–GAP-011, GAP-024 and identifier allocation using the baseline dispatcher
and [batch 07][batch]. The exchanges below are derived from native code; they
are not recorded client sessions or a certificate of transport-drain behaviour.

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
appears in this startup mapping. A successful bind or real client connection
on this historical runtime has not been exercised (GAP-010).

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
so success bytes alone do not promise authentication or admission. Exact drain,
pipelining, short-read and closure-order native fixtures remain GAP-008.

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
Pipelined/coalesced delivery and all positive/negative native stream fixtures
remain GAP-009/055.

## Receive-limit assignment at startup

The immutable baseline retained the data-image value `00200000` (2 MiB) at
`10094a50` and correctly left its runtime value unresolved. New startup capture
`100007b0` explicitly assigns **`00080000` (512 KiB)** before loading server
configuration. This is stronger evidence for the ordinary initialization path
than treating the image initializer as the active limit.

Receiver `100590e0` rejects a total/data size word equal to zero or greater
than the current global; equality passes that comparison. The startup assignment
is not a sum-of-fragments, number-of-transactions or process-memory bound.
Later indirect writes/configuration and actual boundary behaviour still need
verification. The TOC-indirect reference inventory is not evidence that there
can be no other writes (GAP-011).

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

[batch]: ../mothra/evidence/gap-remediation/2026-11-12/batch-07/manifest.json
