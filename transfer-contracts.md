# Native transfer contracts

This supplement refines GAP-033 and GAP-055–GAP-064 against the same hashed
Mac PPC server as [the protocol guide](protocol.md). Evidence consists of the
baseline request/acceptor captures and [batch 04][batch]. These are static
findings, not exercised native transfer sessions. Folder control streams,
platform-specific metadata restoration and interruption fixtures remain open.

## HTXF connection header and dispatch

The baseline acceptor `1000bd20` waits until 16 bytes are available, consumes
that header and compares its magic. All integer fields below are big-endian.
The selector is a 16-bit value, not a four-byte direction bitmap.

| Offset | Size | Role in the acceptor |
| ---: | ---: | --- |
| 0 | 4 | Magic `HTXF` (`48 54 58 46`) |
| 4 | 4 | Transfer reference |
| 8 | 4 | Size copied into an ordinary upload's expected-byte count |
| 12 | 2 | Transfer selector |
| 14 | 2 | Consumed with the header; not examined in this path |

Reference parity takes precedence over the selector:

| Reference | Selector | Lookup / branch |
| --- | --- | --- |
| Even | 1 | Folder upload, `1000ec80` |
| Even | Any other value | Ordinary upload, `1000ec40`; copies the size word |
| Odd | 1 | Folder download, `1000e690` |
| Odd | 2 | Banner download, `1000e720` |
| Odd | Any other value | Ordinary download, `1000e600` |

This table describes what the native branch actually accepts. It does not
establish a canonical client's choice among all other selector values. Bad
magic or an unmatched reference removes the pending connection and closes it;
no transfer-specific error frame is built at that rejection site. The acceptor
does not validate bytes 14–15 as zero or compare an ordinary download's size
word to the advertised length.

The lookups match the reference in the selected collection. Ordinary/folder
download lookup also searches the download waiting queue; matching a reference
does not itself prove queue admission or completed transfer. These lookups do
not check an owning control session or peer address. IP admission checks occur
earlier in the acceptor and must not be confused with token ownership checks.
Valid/invalid-reference runtime fixtures and the relationship to handshake
sub-version 3 remain GAP-055/GAP-009.

## Reference allocation and request 214

The allocator `100046c0` combines an incremented 16-bit sequence in the high
half with a truncated random value in the low half. It skips zero on sequence
wrap. Transfer handlers force bit zero: set for downloads/banner, clear for
uploads. The allocator itself does not search outstanding references for
collisions; randomness is not a guarantee of uniqueness or authentication.
Reference lifetimes must be kept separate from transaction IDs (GAP-033).

Request 214 reads up to four bytes of field 107 into a zero-initialized word.
An absent/zero value skips cleanup. A nonzero value invokes `1000e760`, which
searches these collections in order:

1. Waiting downloads, including file and folder entries.
2. Active/pending ordinary downloads.
3. Active/pending folder downloads.

For a matched reference, cleanup checks that the owning session equals the
requesting session. On a permitted removal it removes the entry, closes the
attached transport if present, releases file/traversal resources and updates
server statistics. A missing reference or owner mismatch returns zero. The
handler ignores that return and sends an empty success ACK in every case.

This helper does not search upload or banner collections. Therefore 214 is not
a proven universal cancellation request. Its ACK means the request handler
finished, not that a transfer existed, belonged to the requester or was stopped.
Completion/cancellation races and repeated-cleanup runtime fixtures remain
GAP-062; these observations do not promise rollback of transferred bytes.

## Resume data: RFLT

Download handler 202 copies field 203 into a buffer capped at 512 bytes, then
passes nonempty data to `1002d650`. That helper requires at least 42 bytes,
magic `RFLT` and version 1. The upload-resume builder `1002db60` emits a
74-byte record with two entries, DATA followed by MACR.

| Offset | Size | Header value |
| ---: | ---: | --- |
| 0 | 4 | `RFLT` (`52 46 4c 54`) |
| 4 | 2 | Version 1 |
| 6 | 34 | Other header bytes; not interpreted by the traced resume consumer |
| 40 | 2 | Entry count `k` |
| 42 | `16 × k` | Entries |

| Offset within entry | Size | Entry value |
| ---: | ---: | --- |
| 0 | 4 | Fork tag: `DATA` or `MACR` |
| 4 | 4 | Resume offset in that fork |
| 8 | 8 | Other bytes; not interpreted by this consumer |

The download consumer initializes a fresh flattened-file state, then sets the
matching fork's start offset. For a single entry it sends
`max(fork_length - offset, 0)` bytes of that fork. It does not reject an offset
at/beyond EOF at this comparison. Unknown fork tags have no matching update.
The loop does not establish a separate per-entry bound against the supplied
buffer length after its initial 42-byte check; do not turn this into a safe
malformed-input acceptance rule. Duplicate-fork semantics and offset boundary
fixtures remain GAP-058.

On upload resume, the server reads both existing fork EOFs, returns them as
DATA/MACR offsets and retains those starting offsets for subsequent writes.
This is direction-specific negotiation, not a claim that every upload must
supply field 203 or that folder resume uses an identical state machine.

## Flattened ordinary-file stream

Initializer `1002d470`, serializer `1002d830` and size helper `1002d7b0`
establish the ordinary download stream components. A fresh transfer contains
this 24-byte file header and three fork records. Headers and contents have no
implicit padding; TCP read boundaries need not align with these components.

| File-header offset | Size | Emitted value |
| ---: | ---: | --- |
| 0 | 4 | `FILP` (`46 49 4c 50`) |
| 4 | 2 | Version 1 |
| 6 | 16 | Zero from cleared state |
| 22 | 2 | Fork count 3 |

Every fork record consists of a 16-byte header followed by its value:

| Fork-header offset | Size | Emitted value |
| ---: | ---: | --- |
| 0 | 4 | Fork tag: `INFO`, `DATA` or `MACR` |
| 4 | 8 | Zero from cleared state |
| 12 | 4 | Value length in bytes |
| 16 | Value length | Metadata or fork bytes |

The serializer has distinct stages for file header, INFO header/value, DATA
header/value and MACR header/value. For a fresh transfer the advertised size is
`72 + info_length + data_length + resource_length`: 24 file-header bytes plus
three 16-byte fork headers. Resume reduces the fork bytes as described above;
the header/metadata overhead remains. Preview option 2 bypasses this serializer
and reads raw bytes from the selected ordinary file data path.

### INFO metadata value

Builder `1002d130` clears the fixed metadata prefix, writes `AMAC` at offset 0,
and adds file metadata, name and comment. The following boundaries are traced;
unlisted fixed-prefix bytes must not be assigned invented portable meanings.

| Offset | Size | Observed value |
| ---: | ---: | --- |
| 0 | 4 | `AMAC` |
| 4 | 4 | Native file type value |
| 8 | 4 | Native creator value |
| 52 | 8 | Creation date via `10058070` |
| 60 | 8 | Modification date via `10058070` |
| 70 | 2 | Name length `n` |
| 72 | `n` | Name bytes |
| `72 + n` | 2 | Comment length `c` |
| `74 + n` | `c` | Comment bytes |

The value length is `74 + n + c`. Date bytes follow the fixed-1904-year
representation already documented in the guide. This layout does not establish
Unicode conversion, timezone conversion or exact metadata persistence after
upload. GAP-056/064 retain fork and metadata round-trip fixtures.

### Upload consumption and completion

The upload parser `1002ddf0` accepts partial components across input chunks.
It checks FILP/version, reads fork headers, writes DATA/MACR at the negotiated
starting offsets and skips unrecognized fork values by their declared length.
It checks the first word after the fork tag for zero. It buffers INFO with a
592-byte cap; this is not evidence that arbitrary larger INFO values are safe
or interoperable. The traced loop is not a proof of exactly three validated
forks or a fully validated final stream boundary.

Ordinary upload worker `1000d830` counts bytes delivered to the parser against
the expected count installed from the HTXF header. At count at least expected,
it calls parser finalization with zero input, closes the file and shuts down
the data connection. There is no additional numbered control-session success
reply in this completion branch. File flush guarantees, partial-file retention,
overshoot behaviour and metadata finalization errors remain GAP-064.

## Queue notification 211

Worker `1000cfa0` walks the shared file/folder download queue and compares active
counts with global and per-user limits. When an entry becomes admissible, it
sends **211** to its owning control session with:

- Field **107**: exactly four reference bytes.
- Field **116**: numeric zero, meaning admission from the waiting queue.

It moves the entry to the corresponding active collection and refreshes its
pending-connection timestamp. For a still-waiting entry whose computed position
changes, it sends the same fields with the new nonzero position. No additional
211 is sent from this branch when the computed position is unchanged. Queue
walking/order is observed; fairness under concurrent requests, exact limit
configuration and queue/connection races still require GAP-061 fixtures.

## Banner bytes and worker timers

Banner worker `1000d5e0` sends bytes directly from the server's current in-memory
banner buffer on the attached data connection, once per entry. It does not use
the FILP/fork serializer. Its send-time length comes from that current buffer;
the earlier request-212 reply is not a snapshot guarantee if configuration
changes between advertisement and sending. If the buffer is absent the worker's
outer guard does no work, which is not a validated immediate error response.

Observed timers use the same seconds clock as the dispatcher:

| Worker condition | Observed action |
| --- | --- |
| Ordinary download has no data connection for more than 500 seconds | Removes pending entry, closes file and logs no response. |
| Banner download has no data connection for more than 500 seconds, while banner-worker guard is enabled | Removes entry and logs no response. |
| Ordinary upload waits for its first connection beyond 500 seconds | Removes pending entry and closes file. |
| Connected ordinary upload has no recorded receive progress for more than 120 seconds | Close/cleanup path. |

Download completion means all advertised bytes have been enqueued by the worker;
it does not itself prove the peer persisted them. The complete folder streams,
transport-drain/EOF ordering and interruption semantics remain unresolved.

## Folder-download control states

The ordinary fork stream is reused per file, but the enclosing folder protocol
is bidirectional. Worker `1000c6a0` and traversal helpers `100273a0`/`100262e0`
are retained in [folder evidence][folder-batch]. Controls below are big-endian
16-bit words sent on the data connection, not numbered control transactions.

| Native state | Input from client | Server action / next state |
| --- | --- | --- |
| Await next item (0) | Control 3 | Advances native traversal, sends an item descriptor, then waits in state 0 for a directory or state 1 for a file. |
| Await file choice (1) | Control 1 | Initializes a fresh flattened stream, sends BE32 stream length, enters sending state 2. |
| Await file choice (1) | Control 2 | Enters state 10, reads a BE16 resume-value length, then in state 11 reads that many RFLT bytes. Applies resume, sends BE32 stream length, enters state 2. |
| Await file choice (1) | Control 3 | Skips this file and immediately advances traversal. |
| Sending file (2) | No per-chunk control | Queues FILP/fork bytes; when its per-file count reaches the chosen length, closes that file and returns to state 0. |

A completed file is followed by another client control 3 to request the next
item. When traversal has no next item, the worker removes its entry and closes
the data connection; it does not emit a numbered completion ACK here. Other
control values are consumed without an established protocol-error reply in the
inspected branches. They must not be assigned guessed actions.

The descriptor is constructed by walking backwards over a structured component
path, removing the root component, then prepending its length and directory/file
indicator. The decompiler's recovered stack-tail pointers are not sufficient
to certify every descriptor offset. Exact descriptor bytes, empty-folder and
nested traversal traces remain GAP-059, rather than a guessed symmetric upload
record. Pending folder downloads use the same greater-than-500-second wait
comparison as ordinary downloads.

## Folder-upload control states

Worker `1000dc60` implements a different receive protocol:

| Native state | Input/output | Next action |
| --- | --- | --- |
| Initial (0) | Server sends BE16 control 3 | Waits for an item's BE16 descriptor length (state 1). |
| Descriptor length (1) | Client sends BE16 length | Waits for the full descriptor (state 2). |
| Descriptor (2) | Client sends descriptor bytes | First BE16 word is item flags; the remaining bytes are a structured path, normalized by `1006e960` and resolved under the upload root. |
| New ordinary file | Server sends BE16 control 1 | Waits for BE32 stream length (state 3). |
| Resumable ordinary file | Server sends BE16 control 2, BE16 RFLT length, then RFLT bytes | Waits for BE32 stream length (state 3). |
| Skipped or directory item | Server sends BE16 control 3 | Counts that item, then waits for the next descriptor length or finishes. |
| Stream length (3) | Client sends BE32 length | Resets per-file received count and enters stream state 4. |
| Receiving stream (4) | Client sends FILP/fork bytes | Feeds the upload parser, finalizes/closes the file once count is at least expected; counts the item. |
| More items after a file | Server sends BE16 control 3 | Returns to descriptor-length state 1. |

Item flag bit zero selects the directory branch; other bits are not given
semantics by this pass. The ordinary-file branch checks the target's native
partial-transfer status before selecting resume, create or skip. Directory
creation and conflict handling use filesystem helpers, not an assumption that
every directory descriptor succeeds.

Completion compares the processed-item count with the item count saved from
request 213. On the final item it closes the data connection without sending
another next-item control. A control 3 can mean initial readiness, skip or
next-item readiness depending on state; a universal standalone meaning would
be wrong. Pending timeout is greater than 500 seconds, while the connected
worker closes when its recorded progress age is at least 121 seconds. Descriptor
and control reads do not all refresh that progress timestamp in these branches.

Zero/inconsistent item counts, truncated or tiny descriptors, invalid paths,
resume conflicts and byte-count overshoot remain GAP-060/064 fixture work.
Nothing here promises transactional rollback of previously uploaded items.

[folder-batch]: ../mothra/evidence/gap-remediation/2026-11-12/batch-05/manifest.json

[batch]: ../mothra/evidence/gap-remediation/2026-11-12/batch-04/manifest.json
