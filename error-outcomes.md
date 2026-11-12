# Native error and failure outcomes

This registry refines GAP-003/021 for the hashed 1.9-family code oracle. The
[status-call review][status-review] accounts for **68 direct calls in 35
functions** to native reply-error setter `10058a10`; every captured call passes
**1**. These are the complete direct callers returned by the retained query,
not proof that no other indirect/state-writing route can affect a reply.

## Wire status and failure classes

Normal success replies carry zero. The explicit operation failure paths below
use status 1 and usually text field 100. There is no established native mapping
that assigns a different envelope status for every permission, missing-object,
filesystem or internal exception class. mxd's own error constants must remain
separate from observations about this native server.

| Trigger / path | Native result established in the traced code | Remaining boundary |
| --- | --- | --- |
| Failed account/password comparison in 107 | Direct status 1 with 100; records failure time, then dispatcher closes after age exceeds 30 seconds. | Native delivery and close timing fixtures. |
| Explicit permission denial in file/news/account/PM handlers | Direct status 1 with 100 at captured send sites. | Operation-specific partial effects and exceptions. |
| Missing/disconnected PM target in 108 | Direct status 1 with 100, before ordinary successful-path routing. | Target state races and exact native packets. |
| Missing room in 115 | Direct status 1 with 100. | Concurrent room removal. |
| Resolver/missing-object branches calling `1000ef30` | Helper formats error text, sets status 1 and sends a direct reply. | Exceptions thrown inside the resolver are a separate path. |
| Unknown operation after online | `10014640` sends status 1 and text `Unknown transaction type!`. | Zero/reused IDs and native delivery. |
| Unknown/disallowed operation before online | Dispatcher close path rather than that online error helper. | Delivered transport sequence. |
| Invalid frame size words | Receiver closes transport; it does not construct a universal numbered error or 111. | Partial TCP delivery, buffering and drain fixtures. |
| Truncated TLV record | Index builder retains the valid prefix; enclosing handler can act on defaults or fail later. | No universal transaction-level failure is implied. |
| Internal `SError` thrown by a helper | Domain/code exception object, with separate text resources and UI/log formatting. | Enclosing catch/transport translation must be traced; do not invent a direct reply. |

A failure reply does not promise absence of earlier effects. In particular,
account batch 349 is sequential, comment mutation in 207 precedes rename checks,
and article creation in 410 precedes body validation/write. Old-board 103 writes
and ACKs before its repeated-hash branch can stop fan-out. See the corresponding
supplements for those operation-specific orderings.

## Derived unknown-operation example

The following **calculated layout**, not a captured packet, combines the native
unknown-operation literal, status setter and direct-reply writer. For request
ID 1 the reply has one field, 25 text bytes and a 31-byte payload:

| Component | Hex |
| --- | --- |
| Flags / reply / type | `00 01 00 00` |
| Request ID | `00 00 00 01` |
| Error status | `00 00 00 01` |
| Total size / data size | `00 00 00 1f 00 00 00 1f` |
| Count / field 100 / length 25 | `00 01 00 64 00 19` |
| Text | `55 6e 6b 6e 6f 77 6e 20 74 72 61 6e 73 61 63 74 69 6f 6e 20 74 79 70 65 21` |

The complete frame is 51 bytes, with no NUL terminator after the text. The
[raw memory query][unknown-text] retains the Pascal literal used by the handler.
This provides an auditable example while keeping GAP-003/084's native capture
requirement explicit.

## Internal exceptions and text resources

Constructor `10027c80` stores a pair of 16-bit domain/code values in an
`SError` object. `10027c30` constructs and throws that object. Toolbox-error
wrapper `10028190` first maps a native result through `100280b0`, then throws
another object of the same class. None of these constructions alone serializes
the pair as a transaction status.

Text helper `10027d40` loads an **EMSG resource whose ID equals the internal
domain**, then uses `10079b20` to look up the internal code in its IVA1 table.
The [decoded catalogue][catalogue] is tied to the preserved AppleDouble resource
fork and that native lookup routine:

| Internal domain | Resource role | Number of retained messages |
| ---: | --- | ---: |
| 1 | General value/protocol/data/limit/object exceptions | 13 |
| 3 | Memory-related exceptions | 3 |
| 4 | Filesystem exceptions, including existence, access, type and volume failures | 30 |
| 8 | Transport/address/connection/configuration exceptions | 13 |

The two direct callers of the text helper are file-log formatter `10027a20`
and native error-dialog code `10027ea0`. This is evidence for internal text
presentation. It is not a licence to publish resource keys as wire error codes
or claim all thrown filesystem exceptions become status-1 replies.

The dispatcher has a retained call site outside a currently recognized function
boundary. Its enclosing exception path has not been promoted to a guessed
function/catch contract or changed in the live analysis merely to obtain a
clean decompilation. Missing catch coverage and controlled native failure
fixtures remain explicit investigation work.

[status-review]: ../mothra/evidence/gap-remediation/2026-11-12/batch-11/error-status-callsite-review.json
[unknown-text]: ../mothra/evidence/gap-remediation/2026-11-12/batch-11/queries/B11-M-unknown-operation-text.json
[catalogue]: ../mothra/evidence/gap-remediation/2026-11-12/batch-11/internal-error-resource-catalogue.json
