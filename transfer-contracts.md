# Native transfer contracts

This supplement refines GAP-033 and GAP-055–GAP-064 against the same hashed Mac
PPC server as [the protocol guide](protocol.md). Evidence consists of the
baseline request/acceptor captures, [batch 04][batch] and the ordinary-file
sessions cited below. Static findings are distinguished from captured outcomes.
Captured folder streams and cancellation cases are specified below. Broader
metadata, failure and persistence requirements remain open.

The [ordinary-download send path](native-download-send-path.md) distinguishes
advertised length, the worker's requested/enqueued byte count, queued bytes in
the inspected OpenTransport branch, and TCP acknowledgement. Reaching the
worker's count closes its file; it does not prove peer receipt or persistence.
The [failed disposable baseline](native-transfer-stall.md) remains a separate
runtime observation with an unexplained 98,304-byte prefix.

## HTXF connection header and dispatch

The baseline acceptor `1000bd20` waits until 16 bytes are available, consumes
that header and compares its magic. All integer fields below are big-endian.
The selector is a 16-bit value, not a four-byte direction bitmap.

| Offset | Size | Role in the acceptor                                      |
| -----: | ---: | --------------------------------------------------------- |
| 0      | 4    | Magic `HTXF` (`48 54 58 46`)                              |
| 4      | 4    | Transfer reference                                        |
| 8      | 4    | Size copied into an ordinary upload's expected-byte count |
| 12     | 2    | Transfer selector                                         |
| 14     | 2    | Consumed with the header; not examined in this path       |

Reference parity takes precedence over the selector:

| Reference | Selector        | Lookup / branch                                   |
| --------- | --------------- | ------------------------------------------------- |
| Even      | 1               | Folder upload, `1000ec80`                         |
| Even      | Any other value | Ordinary upload, `1000ec40`; copies the size word |
| Odd       | 1               | Folder download, `1000e690`                       |
| Odd       | 2               | Banner download, `1000e720`                       |
| Odd       | Any other value | Ordinary download, `1000e600`                     |

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
The ordinary-file corpus below exercises valid upload/download references and
control sub-version 3. The captured header/reference cases below add banner
matching, invalid selectors, owner cleanup and reuse. Alternate-listener
wrapping remains GAP-010; general identifier lifetimes remain GAP-033.

## Captured HTXF field and reference cases

The [HTXF corpus][htxf-corpus] retains 17 cases and a preceding 58-byte banner
preflight. Every socket stream matches both host and guest packet views, with
no unread suffix. These are observations of the identified native binary, not
historical-client interoperability results.

| Probe                                                                    | Native result                                                                                                                                        |
| ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Banner size word `ffffffff`, trailing word `ffff`                        | Delivers the complete 58-byte GIF; remains open through a three-second quiet check.                                                                  |
| Banner size word 1, trailing word `1234`                                 | Same complete GIF, rather than a one-byte stream.                                                                                                    |
| First 15 header bytes, then a three-second pause and byte 16             | No response during the incomplete-header window; complete GIF after the last byte.                                                                   |
| `HTXG` magic with a valid banner reference                               | Native close without application bytes.                                                                                                              |
| Ordinary download selector `ffff`, size `ffffffff`, trailing word `abcd` | Complete 510-byte FILP, including exact 13-byte DATA and 317-byte resource forks. Owner214 then closes the transport.                                |
| Folder-download reference with selectors 0, 2 or `ffff`                  | Native close without application bytes; the reference does not match those collections.                                                              |
| Ordinary upload selectors 0, 2 and `ffff`, trailing word `ffff`          | All route to ordinary upload and complete. Native exact-path fork reads retain the expected DATA bytes and TEXT/MOTH metadata.                       |
| Selector0 upload: request203 advertises 37 bytes more than its HTXF size | Completes at the HTXF byte count. Together with the acceptor assignment, this establishes replacement of the request count for this ordinary upload. |

The new upload catalogue records report resource-fork size zero. The attempted
resource-attribute reads return status1 with “Attribute not found”; their empty
output files are not represented as successful extraction. Read-only live fork
observations establish stored bytes at observation time, not durability after a
restart.

The earlier [ordinary-file corpus][htxf-forks] supplies valid raw/v3 handover,
selector7 fallback and wrong-selector1/2 rejection. The
[first banner corpus][htxf-banners] supplies selector2 delivery, wrong
selectors0/1/7, unknown/zero references and rejection after a bounded aged
pending-reference trial. Valid folder selector1 upload/download streams are
retained in the [folder corpus][htxf-folders]. These observations support the
complete static dispatch table above without treating every untested integer as
a separate protocol type.

Reference use is distinct from control-session ownership. HTXF contains no
account, user ID or control-socket identifier. Both banner and ordinary-file
data connections use the owner's reference successfully while a separate
`fixture-low` session with an all-zero privilege bitmap is live. This does not
authenticate those data connections as that account. The lookups compare the
full reference without a control-owner/address comparison; admission filters
still apply. All retained clients share one host/NAT address, so arbitrary
source-address admission is not established. Closing the original control
owner, then pumping the observer, causes subsequent attachment of either
reference to close without bytes. A banner reference also rejects attachment
after its first data connection closes and the owner is pumped.

A duplicate-banner case first receives all 58 bytes, then attaches a second
transport using the same reference. The second delivers nothing during a
three-second quiet window. After the owner closes, the second closes natively;
the first remains quiet through a further three-second window. The acceptor
assigns the new transport pointer without an existing-connection guard or
resetting the banner's sent count. This explains this bounded observation; it
does not establish a permanent orphan, a universal cleanup deadline or
collision/wrap behaviour. Those broader lifetime requirements remain GAP-033.
Request214's separate owner check remains as documented below: bearer matching
at data attachment does not remove that control-operation check.

[htxf-corpus]: ../mothra/evidence/gap-remediation/2026-11-12/native-htxf-01/manifest.json
[htxf-forks]: ../mothra/evidence/gap-remediation/2026-11-12/native-forks-01/manifest.json
[htxf-banners]: ../mothra/evidence/gap-remediation/2026-11-12/native-banner-01/manifest.json
[htxf-folders]: ../mothra/evidence/gap-remediation/2026-11-12/native-folder-01/manifest.json

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
finished, not that a transfer existed, belonged to the requester or was
stopped. The ordinary-file and controlled-queue captures establish these
bounded cases:

| Reference state / requester                              | Captured 214 outcome                                                                                                                               |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Absent field, explicit zero or unknown value             | Empty success ACK; no removal is certified.                                                                                                        |
| Previously removed reference, repeated cleanup           | Empty success ACK again.                                                                                                                           |
| Another session's admitted download                      | Empty success ACK; owner slot remains occupied and its waiter stays blocked.                                                                       |
| Owner's queued reference without data connection         | Removes waiter; later positions advance.                                                                                                           |
| Owner's queued reference with early HTXF attachment      | Removes waiter and closes attached data connection without file bytes.                                                                             |
| Owner's pending admitted reference                       | Removes entry and permits the next eligible waiter.                                                                                                |
| Owner's download after complete advertised-byte delivery | Empty ACK and data-transport close; already delivered bytes are not rolled back.                                                                   |
| Cancellation racing an in-progress download              | Partial baseline prefix, empty ACK and native close; the application can drain buffered bytes after reading the ACK. See the captured cases below. |
| Pending ordinary upload                                  | Empty ACK does not remove its reference; a later valid upload completes.                                                                           |

These observations do not promise rollback of transferred bytes or universal
cleanup of uploads and banners. Folder operation streams remain separately
tracked, and no universal race byte count or cancellation deadline is claimed.

### Captured cancellation and completion races

The
[native cleanup corpus](../mothra/evidence/gap-remediation/2026-11-12/native-cleanup-01/manifest.json)
retains ten cases: a seeded multi-chunk file, its full download, three
immediate owner cancellations, three cancellations after reading 1,024 bytes,
nonowner cleanup and cleanup of a pending upload. Every stream reconciles with
both host and guest packet views; an unread departure notification remains
pinned separately. Native HFS+ fork extractions match the uploaded source bytes
after all cases.

The baseline file has 1,048,576 DATA bytes (`00` through `ff`, repeated 4,096
times), 317 MACR bytes and a complete ordinary FILP stream of 1,049,073 bytes.
Each cancelled stream is an exact prefix of that baseline. Counts below include
FILP/INFO/fork headers, rather than only DATA bytes:

| Cancellation attempt     | Total stream bytes received | Application bytes read after owner ACK | Guest bytes first observed after complete incoming 214 |
| ------------------------ | --------------------------: | -------------------------------------: | -----------------------------------------------------: |
| Immediate 1              | 17,844                      | 17,844                                 | 17,844                                                 |
| Immediate 2              | 11,112                      | 11,112                                 | 11,112                                                 |
| Immediate 3              | 28,956                      | 28,956                                 | 28,956                                                 |
| After 1,024-byte read, 1 | 261,252                     | 260,228                                | 258,332                                                |
| After 1,024-byte read, 2 | 2,920                       | 1,896                                  | 0                                                      |
| After 1,024-byte read, 3 | 2,920                       | 1,896                                  | 0                                                      |

The distinct lengths are observations from six races, not minimum or maximum
delivery guarantees. Complete incoming-request observation does not instrument
handler entry. In these six cases, all native DATA packets and the first native
close precede the complete control ACK; zero data bytes are first observed
after that ACK. The application nevertheless reads buffered bytes afterwards.
The first close precedes ACK observation by about 1–3 host milliseconds here;
this is cross-connection packet evidence, not a protocol timing guarantee.

The nonowner case sends 214 from a second control session after HTXF
attachment. It receives an empty ACK, then 1,037,961 further stream bytes are
first observed on the guest network. The owning session receives the full
baseline and observes three seconds without more data or EOF before its own
cleanup closes the connection. After each owner cleanup, a repeated 214 still
ACKs and a new HTXF attempt using that removed reference closes with no
application bytes.

A pending-upload case sends 214 against the even reference from request 203
before connecting its upload stream. The ACK is empty, but the subsequent
HTXF/FILP upload completes with native EOF and correct DATA/MACR and TEXT/MOTH
file metadata. This exercises the helper's omission of the upload collection;
banner omission remains established by the traced collection search rather than
a new banner runtime fixture.

### Buffered receipt and packet ordering

Control ACK and data EOF belong to different TCP connections. A client reading
the ACK first can subsequently drain bytes already delivered to its data
socket. Consequently, an empty ACK cannot serve as a rollback of prior data, a
guarantee that no buffered bytes remain, or proof that an unknown/unowned
reference was removed. Preserve partial data according to the application's own
policy.

The verifier reconciles all bytes, checks baseline prefixes, matches the exact
request/reference/owner, and separately counts first-observed native bytes and
application reads around ACK receipt. Retransmissions are deduplicated for
those counts. Native resets can appear as host EOF; their diagnostic payloads
remain transport records and are excluded from Hotline stream bytes. Source
handler `10013040` ignores cleanup helper `1000e760`'s result before ACKing,
which explains why success-envelope presence alone cannot certify removal.

## Resume data: RFLT

Download handler 202 copies field 203 into a buffer capped at 512 bytes, then
passes nonempty data to `1002d650`. That helper requires at least 42 bytes,
magic `RFLT` and version 1. The upload-resume builder `1002db60` emits a
74-byte record with two entries, DATA followed by MACR.

| Offset | Size     | Header value                                                      |
| -----: | -------: | ----------------------------------------------------------------- |
| 0      | 4        | `RFLT` (`52 46 4c 54`)                                            |
| 4      | 2        | Version 1                                                         |
| 6      | 34       | Other header bytes; not interpreted by the traced resume consumer |
| 40     | 2        | Entry count `k`                                                   |
| 42     | `16 × k` | Entries                                                           |

| Offset within entry | Size | Entry value                                   |
| ------------------: | ---: | --------------------------------------------- |
| 0                   | 4    | Fork tag: `DATA` or `MACR`                    |
| 4                   | 4    | Resume offset in that fork                    |
| 8                   | 8    | Other bytes; not interpreted by this consumer |

The download consumer initializes a fresh flattened-file state, then sets the
matching fork's start offset. For a single entry it sends
`max(fork_length - offset, 0)` bytes of that fork. It does not reject an offset
at/beyond EOF at this comparison. Unknown fork tags have no matching update.
The loop does not establish a separate per-entry bound against the supplied
buffer length after its initial 42-byte check; do not turn this into a safe
malformed-input acceptance rule. The captured boundary and duplicate-entry
outcomes below distinguish size calculation from successful byte delivery.

On upload resume, the server reads both existing fork EOFs, returns them as
DATA/MACR offsets and retains those starting offsets for subsequent writes.
This is direction-specific negotiation, not a claim that every upload must
supply field 203 or that folder resume uses an identical state machine.

### Captured RFLT download boundaries

The
[native resume corpus](../mothra/evidence/gap-remediation/2026-11-12/native-resume-01/manifest.json)
contains 16 reviewed download cases and seven upload cases. Its packet
verifier reconciles every retained transcript with both host and guest TCP
streams; initial failed expectations remain separate and unchanged.

The source file has DATA length 13 and MACR length 317. A fresh stream is 510
bytes, including 180 bytes of FILP/INFO/fork-header overhead. Download field
207 remains the logical file size 330 in these resume responses.

| RFLT entries, in wire order                               | Captured DATA / MACR bytes                                | Advertised stream size           |
| --------------------------------------------------------- | --------------------------------------------------------- | -------------------------------: |
| Zero entries; DATA offset zero; unknown `XXXX` offset 123 | All 13 / all 317                                          | 510                              |
| DATA offset 3                                             | DATA `[3:13]` / all MACR                                  | 507                              |
| MACR offset 4                                             | All DATA / MACR `[4:317]`                                 | 506                              |
| DATA 3, MACR 4                                            | DATA `[3:13]` / MACR `[4:317]`                            | 503                              |
| DATA 13, MACR 317                                         | Empty / empty; metadata and all three fork headers remain | 180                              |
| DATA 14, MACR 318                                         | Same metadata-only stream                                 | 180                              |
| DATA `ffffffff`, MACR `ffffffff`                          | No stream bytes; native data connection closes            | 180 advertised but not delivered |
| DATA 3, DATA 4                                            | DATA `[4:10]` / all MACR                                  | 503                              |
| DATA 4, DATA 3                                            | DATA `[3:9]` / all MACR                                   | 503                              |
| DATA 14, DATA 1                                           | Empty DATA / all MACR                                     | 497                              |
| MACR 3, MACR 4                                            | All DATA / MACR `[4:314]`                                 | 503                              |

Ranges are zero-based and exclude the end. Repeated fork entries are not
equivalent to taking only the last offset: each updates the stored start offset
but subtracts from the **already remaining** length. For DATA 3 then 4, the
remaining count becomes `13 - 3 - 4 = 6`, starting at 4. Once a count becomes
zero, a later positive offset leaves it zero. These are native noncanonical
outcomes, not a recommended sender format; emit at most one entry per fork when
requesting a normal continuation.

The all-ones case shows why `max(length - offset, 0)` alone does not define
successful transfer behaviour: its control ACK advertises metadata overhead,
but the attached data connection closes with no FILP bytes. The initial plan
that tried to read those advertised bytes failed with EOF and is retained. No
safe universal acceptance rule for arbitrary beyond-EOF offsets follows.

Three negative inputs—41-byte RFLT, wrong magic and version 2—produce no reply
with request ID 10 observed before a three-second pause and a subsequent
request-500 ACK with ID 11 on the same connection. An initial 41-byte probe
waiting for a numbered reply timed out after 30 seconds. These are bounded
no-reply observations, not fabricated status codes or proof of permanent
silence. Entry counts exceeding the supplied record bytes were not executed;
the traced consumer lacks a demonstrated per-entry bound. A new implementation
must validate `42 + 16 × count` against its supplied buffer before iteration.

### Captured upload continuation and inconsistent state

Fresh request 203 with options absent creates a native incomplete file with type
`HTft`, creator `HTLC`. A seed transfer advertises 509 FILP bytes, sends 197
of them—complete INFO, all 13 DATA bytes and five of 317 MACR bytes—then closes
from the client after a three-second quiet window. Native file-info and
read-only HFS+ extraction retain DATA 13 / MACR 5, logical size 18 and the
incomplete-file type. No upload finalization success is inferred from this
client interruption.

| Request 203, option 204 = 1       | Captured result                                                                                |
| --------------------------------- | ---------------------------------------------------------------------------------------------- |
| Existing incomplete file          | ACK includes four-byte even reference 107 and 74-byte RFLT 203: DATA offset 13, MACR offset 5. |
| Missing partial file              | Numbered error status 1, message field 100, no reference.                                      |
| Existing completed TEXT/MOTH file | Numbered error status 1, message field 100, no reference.                                      |

The resume handler checks the existing type/creator pair against `HTft`/`HTLC`;
it does not compare the partial file with a separately authenticated original
length or digest. The returned offsets are existing fork EOFs. A correct
continuation sends a new FILP stream with INFO, zero DATA bytes and MACR bytes
`[5:317]`. Native EOF follows upload consumption; subsequent ordinary download
and HFS+ extraction exactly reconstruct DATA 13 / MACR 317 and TEXT/MOTH
metadata.

A second seed tests an inconsistent client. Its request includes a field-203
RFLT claiming zero offsets, but the native 203 handler does not read that input
field: it returns the actual 13/5 offsets. Sending full DATA and MACR values
despite those offsets appends them, producing DATA 26 / MACR 322. The native
server completes the upload and applies TEXT/MOTH metadata. Both downloaded and
independently extracted native bytes match those appended results. Native
completion therefore certifies neither client consistency nor a correct
reconstruction of the intended original file.

These cases satisfy the ordinary resume grammar/continuation requirement.
Folder resume remains separate; interrupted durability, large-size behaviour,
disk-full failure and restart persistence remain GAP-059/060/064.

## Flattened ordinary-file stream

Initializer `1002d470`, serializer `1002d830` and size helper `1002d7b0`
establish the ordinary download stream components. A fresh transfer contains
this 24-byte file header and three fork records. Headers and contents have no
implicit padding; TCP read boundaries need not align with these components.

| File-header offset | Size | Emitted value           |
| -----------------: | ---: | ----------------------- |
| 0                  | 4    | `FILP` (`46 49 4c 50`)  |
| 4                  | 2    | Version 1               |
| 6                  | 16   | Zero from cleared state |
| 22                 | 2    | Fork count 3            |

Every fork record consists of a 16-byte header followed by its value:

| Fork-header offset | Size         | Emitted value                      |
| -----------------: | -----------: | ---------------------------------- |
| 0                  | 4            | Fork tag: `INFO`, `DATA` or `MACR` |
| 4                  | 8            | Zero from cleared state            |
| 12                 | 4            | Value length in bytes              |
| 16                 | Value length | Metadata or fork bytes             |

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

| Offset   | Size | Observed value                               |
| -------: | ---: | -------------------------------------------- |
| 0        | 4    | `AMAC`                                       |
| 4        | 4    | Native file type value                       |
| 8        | 4    | Native creator value                         |
| 12       | 4    | Zero                                         |
| 16       | 4    | Native 16-bit catalogue flags, zero-extended |
| 20       | 32   | Zero                                         |
| 52       | 8    | Creation date via `10058070`                 |
| 60       | 8    | Modification date via `10058070`             |
| 68       | 2    | Zero                                         |
| 70       | 2    | Name length `n`                              |
| 72       | `n`  | Name bytes                                   |
| `72 + n` | 2    | Comment length `c`                           |
| `74 + n` | `c`  | Comment bytes                                |

The value length is `74 + n + c`. Date bytes follow the fixed-1904-year
representation already documented in the guide. This layout does not establish
Unicode conversion, timezone conversion or exact metadata persistence after
upload. The selected round trips below establish observed ordinary-file state;
restart and interrupted persistence remain GAP-064.

### INFO restoration after upload

The [restoration helper `1002d2c0`][info-restore] reads the existing file's
native catalogue information, then applies INFO type at offset 4, creator at 8
and the low 16 bits of the flags word at 16. It masks those flags with `0x7eff`
before writing the catalogue. This is not an unrestricted 32-bit flag
round-trip.

It does **not** read the transmitted dates at offsets 52/60. Instead, it sets
the catalogue modification timestamp to `GetDateTime`; if that equals the
existing timestamp, it adds one second. The catalogue slot is the same one that
the file-info and INFO builders serialize as modification time. Creation and
modification dates in an uploaded INFO value therefore do not instruct this
helper to restore those timestamps.

The embedded name is used to locate the comment, not to rename the file. A
nonzero comment is capped at 255 bytes and passed to the native comment setter;
a zero comment length skips that call and does not itself clear an existing
comment. The helper calls `FlushVol` without checking its return. These reads
and calls establish selected metadata effects, not complete length validation,
portable flag meanings or durable completion. Selected native fork/date/comment
round trips are captured below; broader date/failure fixtures remain
GAP-020/064.

### Upload consumption and completion

The upload parser `1002ddf0` accepts partial components across input chunks. It
checks FILP/version, reads fork headers, writes DATA/MACR at the negotiated
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

Worker `1000cfa0` walks the shared file/folder download queue and compares
active counts with global and per-user limits. When an entry becomes
admissible, it sends **211** to its owning control session with:

- Field **107**: exactly four reference bytes.
- Field **116**: numeric zero, meaning admission from the waiting queue.

It moves the entry to the corresponding active collection and refreshes its
pending-connection timestamp. For a still-waiting entry whose computed position
changes, it sends the same fields with the new nonzero position. No additional
211 is sent from this branch when the computed position is unchanged. Queue
walking/order is observed. The controlled fixtures below exercise admission,
position changes and two-owner ordering; they do not establish a starvation
bound or universal FIFO policy. Completion/cancellation races remain GAP-062.

### Captured controlled queues

The
[native queue corpus](../mothra/evidence/gap-remediation/2026-11-12/native-queue-01/manifest.json)
retains four cases with paired packet captures and exact byte/position checks.
The queue fixture configuration is **two simultaneous downloads globally and
one per client session**. Both owners log in as the same fixture account on
separate control connections; the native counters use their session UIDs.
Saved/reopened General Options screenshots retain the prior limits 100/10 and
the test limits 2/1. These are test settings, not protocol defaults.

The mode matrix first holds one pending ordinary download without attaching its
data connection, then requests the following on that same session:

| Field 204 / file                   | Initial 108 | Initial 207 | Reference 107       | Queue position 116      |
| ---------------------------------- | ----------: | ----------: | ------------------- | ----------------------: |
| Absent / nonempty ordinary blocker | 510         | 330         | Four-byte odd value | Omitted while admitted  |
| 0, 1, 3 or 65,535 / nonempty       | 510         | 330         | Four-byte odd value | 1, 2, 3, 4 respectively |
| 2 / nonempty preview               | 13          | 330         | Four-byte odd value | 5                       |
| Absent / empty ordinary file       | 181         | 0           | Four-byte odd value | 6                       |
| 2 / empty preview                  | 0           | Omitted     | Omitted             | Omitted                 |

Only numeric value 2 selects preview in the traced handler; the tested other
values use ordinary FILP serialization. Queueing does not remove the reference
or replace the transfer-size calculation. Empty preview returns before creating
a queue entry. After the blocker is removed, all six queued cases deliver their
advertised bytes with the expected FILP forks or raw preview data.

The first waiter receives 211 with position zero on admission. Remaining
positions decrease by one in queue order; each subsequent admitted/completed
transfer advances the next. The captured notification sequences for initial
positions 1 through 6 are `[0]`, `[1,0]`, `[2,1,0]`, `[3,2,1,0]`, `[4,3,2,1,0]`
and `[5,4,3,2,1,0]`. No extra unchanged-position notifications appear in this
finite case.

A cancellation case holds one active reference and three waiters. The middle
waiter attaches HTXF early and receives no bytes during a three-second window.
Owner 214 removes it and closes that attached data connection without file
bytes; the final waiter's position changes from 3 to 2. Removing the first
waiter changes it to 1; removing the active reference admits it with 211/zero.
It then connects and downloads successfully. A repeated cleanup ACK is empty.

The two-owner case distinguishes queue order from eligibility. Owner A holds
one active reference and two waiters; owner B then holds the second global slot
and adds a waiter at position 3. Removing B's active reference admits B's later
waiter while A's earlier requests remain blocked by A's per-session cap. The
native packet timestamps establish B's admission before A's later admission.
This is a bounded head-of-line bypass observation, not strict FIFO fairness.

After A's active reference is removed, A's first waiter is admitted and its
second waiter moves to position 1. That second waiter attaches HTXF early and
stays silent for three seconds. B's 214 against A's admitted reference ACKs but
does not free A's slot: the early data connection remains silent for another
three seconds. A's own cleanup then admits the waiter, which delivers its full
stream on the **already attached connection**, without a second HTXF exchange.
Absent, zero, unknown and duplicate cleanup requests also receive empty ACKs.
These fixtures support ownership and state-specific outcomes; in-progress
completion/cancellation races remain separately required by GAP-062.

### Captured pending-reference timeout

The fourth case creates an admitted pending download with no data connection,
then a same-owner waiter at position 1. It performs twelve measured 45-second
pauses, each followed by a request-500 ACK on the owner control session. After
that interval, attaching the old pending reference produces native reset and no
application bytes. Attaching the waiting reference delivers the full 510-byte
file stream. The guest-side reset's diagnostic payload is retained as transport
evidence, not decoded as Hotline data.

The waiter's 211/zero notification is observed in the guest capture
**542.973851 host seconds after the first download ACK**. This is when all its
frame bytes were first observed, not an instrumented timestamp of internal
entry removal or admission. The worker's traced predicate remains age greater
than 500 Mac seconds; no unconditional 500-second network deadline follows from
this run. Scheduling and flushing can affect when changes become visible. The
admitted waiter remains usable after the original long wait, consistent with
the traced timestamp refresh when a queued entry moves to the active list.

A client can wait for 211/zero before attaching the advertised reference. The
earlier cases also prove that this native server accepts an early attachment
and later delivers on that same connection. Reconnecting a removed reference
does not recreate a transfer: the expired reference above closes without a
numbered transfer error. These observations are bounded to ordinary file queues
at the recorded limits; mixed folder queues and universal starvation or
scheduling guarantees are not established.

## Banner bytes and worker timers

Banner worker `1000d5e0` sends bytes directly from the server's current
in-memory banner buffer on the attached data connection, once per entry. It
does not use the FILP/fork serializer. Its send-time length comes from that
current buffer; the earlier request-212 reply is not a snapshot guarantee if
configuration changes between advertisement and sending. If the buffer is
absent the worker's outer guard does no work, which is not a validated
immediate error response.

Observed timers use the same seconds clock as the dispatcher:

| Worker condition                                                                                       | Observed action                                          |
| ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| Ordinary download has no data connection for more than 500 seconds                                     | Removes pending entry, closes file and logs no response. |
| Banner download has no data connection for more than 500 seconds, while banner-worker guard is enabled | Removes entry and logs no response.                      |
| Ordinary upload waits for its first connection beyond 500 seconds                                      | Removes pending entry and closes file.                   |
| Connected ordinary upload has no recorded receive progress for more than 120 seconds                   | Close/cleanup path.                                      |

Download completion means all advertised bytes have been enqueued by the
worker; it does not itself prove the peer persisted them. The complete folder
streams, interruption semantics remain unresolved. The captured ordinary-file
cases below distinguish delivery count from transport close.

## Captured ordinary-file round trips

The
[native fork corpus](../mothra/evidence/gap-remediation/2026-11-12/native-forks-01/manifest.json)
retains two uploads, eight reviewed download cases, eight initial probes, both
packet views and read-only HFS+ observations. Both supported entry paths work:

| Entry path                    | Captured sequence on the transfer connection                                                                            |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Raw data listener 5501        | Connect, send 16-byte HTXF with reference from owning control ACK, then transfer bytes.                                 |
| Primary control listener 5500 | Connect, send `TRTPHOTL 0001 0003`, receive `TRTP 00000000`, then send HTXF on that same connection and transfer bytes. |

Both paths use a separate owning control session to request 203/202 first.
Upload references are four-byte even values; download references are four-byte
odd values. The
[earlier transport negatives](../mothra/evidence/gap-remediation/2026-11-12/native-transport-01/manifest.json)
retain unmatched-reference rejection through both paths. No 12-byte ordinary
control handshake is sent to the raw data listener. No second TCP connection is
inserted between the sub-version-3 reply and its HTXF header.

| Fixture                                               | Captured outcome                                                                                                   |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Raw upload, `mothra-fork-fixture`                     | FILP 509 bytes: INFO 107, DATA 13, MACR 317 plus 72 header bytes; native worker closes upload after consumption.   |
| Control-handover upload, `mothra-empty-fixture`       | FILP 179 bytes: INFO 107 with empty DATA/MACR; native worker closes upload.                                        |
| Raw and control-handover ordinary downloads           | FILP 510 bytes for nonempty file: INFO 108 uses actual requested filename, DATA 13, MACR 317.                      |
| Selector 7 with ordinary download reference           | Same ordinary-file stream; selector 7 reaches the ordinary branch.                                                 |
| Selectors 1 and 2 with an ordinary download reference | Connection closes without transfer bytes; ordinary reference does not match the selected folder/banner collection. |
| Preview option 2                                      | Exactly 13 raw DATA bytes; no FILP wrapper or resource fork.                                                       |
| Ordinary empty-file download                          | FILP 181 bytes: INFO 109, DATA zero and MACR zero.                                                                 |
| Empty-file preview                                    | Control ACK contains size 108 = zero, omits reference 107; no data connection opened.                              |

The nonempty data bytes are `646174612d666f726b0d0a00ff`. The resource fork is
a valid 317-byte resource file containing type `TEST`, ID 128 and bytes
`native!`. Independently extracted native forks match both uploaded and
downloaded bytes. HFS+ catalogue records 11210/11211 show requested names, type
`TEXT`, creator `MOTH` and resource sizes 317/zero. For the empty file,
SleuthKit reports the resource attribute absent; that failure is retained and
is not presented as a successful empty-fork extraction. The native download's
zero-length MACR supplies the wire observation.

Both uploaded INFO values deliberately contain name `metadata-only-name`,
comment `fixture-comment`, flags `00008100` and zero date bytes. Native
file-info replies and downloads retain the requested filenames and the type,
creator and comment. Download INFO flags are zero, consistent with the
restoration mask `7eff`; creation/modification dates are nonzero native values
rather than the transmitted zero dates. This proves those selected round trips,
not arbitrary flag meanings, date restoration or restart durability.

### Captured completion and EOF behaviour

The reviewed downloads read exactly the control-advertised size, then observe
three seconds without more bytes **or EOF**. Ordinary download worker
`1000c200` closes its file and marks its stream inactive when all bytes have
been enqueued; that branch does not shut down the transport. Receiving the
advertised count is therefore the observed byte-delivery boundary. Waiting for
server EOF as the only successful completion condition timed out after 30
seconds in five initial probes; those failed assumptions remain immutable.

In the reviewed raw download, request 214 on the owning control connection
after the full read and quiet window receives an empty ACK and EOF on the data
connection. The [cleanup races](#buffered-receipt-and-packet-ordering)
distinguish application read order from packet order across these two
connections. Other successful download cases close from the peer after the
quiet window. Uploads instead receive native EOF after their advertised input
has been consumed, with no additional numbered control ACK. Neither direction's
observation proves persistence on another host or after a guest restart. Queue
admission, resume, interrupted files and large-size representation remain
GAP-057/058/061/062/064.

One empty-download control stream has an additional 59-byte 301 notification in
both packet views after the application recorder's consumed prefix. The
verifier pins that complete unread suffix explicitly; the original report is
unchanged. It is not additional transfer data or an invented completion ACK.

### Transfer timer origins and resets

The timer slot belongs to the transfer entry, not automatically to the accepted
TCP connection. Request 203 initializes ordinary upload `entry + 0x0c`; request
213 initializes folder upload `entry + 0x10`, both from the native seconds
clock. The [HTXF attachment assembly][attach-asm] stores the transport (and
ordinary upload's expected byte count) without resetting these timestamps.
Reference lookup helpers `1000ec40`/`1000ec80` only find the matching entry.

| Entry / state                   | Clock origin or refresh                                                                 | Consequence in traced worker                                                                                               |
| ------------------------------- | --------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Ordinary upload, waiting        | Request 203 timestamp                                                                   | No connection: cleanup at age greater than 500.                                                                            |
| Ordinary upload, connected      | Same slot; each consumed parser-input chunk refreshes it                                | Check age greater than 120 before draining available chunks; attachment alone does not start a fresh 120 seconds.          |
| Folder upload, waiting          | Request 213 timestamp                                                                   | No connection: cleanup at age greater than 500.                                                                            |
| Folder upload, connected        | Same slot; file-stream receive chunks refresh it                                        | Continue only while age is below 121. Descriptor/control reads do not refresh this slot.                                   |
| Queued ordinary/folder download | Queue-admission worker resets entry timestamp when moving it into the active collection | Waiting in the queue is distinct from the active worker's greater-than-500-second no-connection comparison.                |
| Connected ordinary download     | Worker uses send-buffer/connection state and send-progress bookkeeping                  | No connected inactivity-expiry comparison is established in that worker; this does not rule out lower transport deadlines. |

Thus a code-derived case is an upload entry created at time zero, first data
connection attached at time 130, with no earlier received file chunks. The
connected worker's age check can reject it immediately even though its pending
500-second comparison did not yet expire. This is an inference from control
flow, not a captured native timing result. Available bytes are read only after
the connected age check passes.

No queue-age expiry comparison appears in the inspected admission worker
`1000cfa0`; owner/connection and capacity checks still apply. Whether a lower
layer times out every queued connection remains open. The recorded queue and
folder cases now exercise bounded queue-wait, late-attachment and descriptor
delay outcomes. Broader clock, failure and persistence requirements remain
GAP-005/064. Timers here do not guarantee exact wall-clock closure.

## Folder-download control states

The ordinary fork stream is reused per file, but the enclosing folder protocol
is bidirectional. Worker `1000c6a0` and traversal helpers `100273a0`/`100262e0`
are retained in [folder evidence][folder-batch]. Controls below are big-endian
16-bit words sent on the data connection, not numbered control transactions.

| Native state          | Input from client    | Server action / next state                                                                                                                                |
| --------------------- | -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Await next item (0)   | Control 3            | Advances native traversal, sends an item descriptor, then waits in state 0 for a directory or state 1 for a file.                                         |
| Await file choice (1) | Control 1            | Initializes a fresh flattened stream, sends BE32 stream length, enters sending state 2.                                                                   |
| Await file choice (1) | Control 2            | Enters state 10, reads a BE16 resume-value length, then in state 11 reads that many RFLT bytes. Applies resume, sends BE32 stream length, enters state 2. |
| Await file choice (1) | Control 3            | Skips this file and immediately advances traversal.                                                                                                       |
| Sending file (2)      | No per-chunk control | Queues FILP/fork bytes; when its per-file count reaches the chosen length, closes that file and returns to state 0.                                       |

A completed file is followed by another client control 3 to request the next
item. When traversal has no next item, the worker removes its entry and closes
the data connection; it does not emit a numbered completion ACK here. Other
control values are consumed without an established protocol-error reply in the
inspected branches. They must not be assigned guessed actions.

### Folder item descriptor bytes

[Assembly stores at `1000ca2c`–`1000ca98`][descriptor-asm] resolve the earlier
stack-tail ambiguity. Traversal builds a component path backwards, removes its
root component, then writes the adjusted component count, item flag and length
in front. The complete record sent on the data connection is:

| Offset | Size     | Value                                                            |
| -----: | -------: | ---------------------------------------------------------------- |
| 0      | 2        | Payload length `L`; excludes this length word                    |
| 2      | 2        | Directory indicator: 1 for a directory, 0 for a file             |
| 4      | 2        | Number of remaining path components `k`                          |
| 6      | Variable | `k` components: BE16 word, one-byte name length, then name bytes |

Thus `L = 4 + sum(3 + component_name_length)`. The upload worker consumes the
same two-byte item flag followed by the structured path. This establishes
shared descriptor framing, not symmetric control state machines or identical
path/conflict policies. The download traversal writes zero component words.

These examples are **calculated from the stores**, not captured native packets:

| Item after removing the transfer root   | Derived descriptor bytes              |
| --------------------------------------- | ------------------------------------- |
| Root directory, no remaining components | `00 04 00 01 00 00`                   |
| One file component `foo`                | `00 0a 00 00 00 01 00 00 03 66 6f 6f` |
| One directory component `foo`           | `00 0a 00 01 00 01 00 00 03 66 6f 6f` |

The captured cases below establish nested and empty-directory sequencing and
root exclusion from the request's item count. The calculated zero-component
root example above is not transmitted in those 210 captures. Unsafe/invalid
descriptor and path acceptance is not certified; broader validation and failure
coverage remains GAP-047/064. Pending folder downloads use the greater-than-500
second comparison already documented.

### Captured folder downloads

The
[folder corpus](../mothra/evidence/gap-remediation/2026-11-12/native-folder-01/manifest.json)
retains exact direction-specific control/item streams. Its HFS+ source tree is:

```text
mothra-folder-source/
  alpha       DATA 13, MACR 317
  empty/      empty directory
  inner/
    leaf      DATA 5, MACR 317
  zero        DATA 0, MACR 0
```

Request 210 returns aggregate 108 = **652**, item count 220 = **5** and a
four-byte odd reference 107. The count includes both descendant directories and
all three files, including the zero-length file, but excludes the transfer
root. The aggregate is the sum of DATA/MACR lengths in this fixture. It
excludes FILP, INFO, descriptor and per-file length overhead. Full flattened
file streams total **1,148 bytes**: alpha 496, leaf 487 and zero 165. Do not
read field 108 as the byte length of the entire enclosing bidirectional folder
protocol.

Descriptors arrive as alpha, empty, inner, inner/leaf and zero. This is the
observed HFS+ fixture order, not a universal cross-filesystem sorting rule. All
component words are zero. The first alpha descriptor is
`000c 0000 0001 0000 05 616c706861`: length 12, file flag, one component, zero
word and name `alpha`. The nested leaf descriptor has two components.

| Captured case       | File-choice and completion outcome                                                                                                                                |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Full                | Control 1 for each file; BE32 length followed by exact fresh FILP. Each later control 3 advances traversal; final 3 receives EOF without numbered completion ACK. |
| Skip all            | Control 3 skips each file and immediately yields the next descriptor. No per-file length or FILP body is sent.                                                    |
| Resume all          | Control 2 followed by BE16 length and RFLT; DATA offset 3 / MACR offset 4 for nonempty files, zero/zero for the empty file. Streams are 489, 480 and 165 bytes.   |
| Mixed               | Skips alpha, resumes leaf and reads zero fresh on the same data connection.                                                                                       |
| Unknown control 0   | Three-second silence in initial-next-item and file-choice states; later valid controls complete the full stream. No numbered error is invented.                   |
| Empty root          | ACK contains 108 = zero and 220 = zero, omits 107 and creates no live transfer.                                                                                   |
| Directory-only root | Aggregate zero, count one and a reference; emits the child directory descriptor, then closes on the next control 3.                                               |

The resumed aggregate/count ACK remains 652/5; per-file length words describe
the selected remaining flattened streams. A separate delayed-choice case holds
the first file descriptor for 130 measured seconds with control-session ACK
probes, then successfully completes all file streams. Its packet observation is
detailed below.

## Folder-upload control states

Worker `1000dc60` implements a different receive protocol:

| Native state              | Input/output                                                   | Next action                                                                                                                            |
| ------------------------- | -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Initial (0)               | Server sends BE16 control 3                                    | Waits for an item's BE16 descriptor length (state 1).                                                                                  |
| Descriptor length (1)     | Client sends BE16 length                                       | Waits for the full descriptor (state 2).                                                                                               |
| Descriptor (2)            | Client sends descriptor bytes                                  | First BE16 word is item flags; the remaining bytes are a structured path, normalized by `1006e960` and resolved under the upload root. |
| New ordinary file         | Server sends BE16 control 1                                    | Waits for BE32 stream length (state 3).                                                                                                |
| Resumable ordinary file   | Server sends BE16 control 2, BE16 RFLT length, then RFLT bytes | Waits for BE32 stream length (state 3).                                                                                                |
| Skipped or directory item | Server sends BE16 control 3                                    | Counts that item, then waits for the next descriptor length or finishes.                                                               |
| Stream length (3)         | Client sends BE32 length                                       | Resets per-file received count and enters stream state 4.                                                                              |
| Receiving stream (4)      | Client sends FILP/fork bytes                                   | Feeds the upload parser, finalizes/closes the file once count is at least expected; counts the item.                                   |
| More items after a file   | Server sends BE16 control 3                                    | Returns to descriptor-length state 1.                                                                                                  |

Item flag bit zero selects the directory branch; other bits are not given
semantics by this pass. The ordinary-file branch checks the target's native
partial-transfer status before selecting resume, create or skip. Directory
creation and conflict handling use filesystem helpers, not an assumption that
every directory descriptor succeeds.

Completion compares the processed-item count with the count saved from 213.
After a **final file**, it closes without another next-item control. A **final
directory or skipped/conflicting item** sends control 3 before the count check
and close. Control 3 can therefore mean initial readiness, a non-file outcome
or next-item readiness; it is not a universal success marker. Pending timeout
is greater than 500 seconds, while the connected worker closes when its
recorded progress age is at least 121 seconds. Descriptor and control reads do
not all refresh that progress timestamp in these branches.

The captured zero-count, interrupted, resumed and conflict cases below refine
these states. Tiny/truncated descriptors, invalid paths, overshoot and durable
failure recovery are not certified by this valid-record corpus; broader path
and controlled-failure requirements remain GAP-047/064. Nothing here promises
transactional rollback of previously uploaded items.

### Captured folder uploads

| Request/item sequence                        | Captured result                                                                                                                                                                                                 |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Fresh nested tree, count 220 = 5             | 213 ACK has only reference 107. Initial control 3; directories empty/inner each return 3; new alpha/zero/inner-leaf files each select 1 and consume BE32 length plus FILP. Final file closes without another 3. |
| Zero items, zero declared bytes              | Root directory is created; ACK is empty, with no reference or data connection.                                                                                                                                  |
| One final directory                          | Initial 3, descriptor, response 3, then EOF.                                                                                                                                                                    |
| Interrupted count-three upload               | First alpha file completes; part receives 197 of 509 declared FILP bytes, then the client closes. The complete first file and partial second file remain.                                                       |
| Resume existing root, option 204 = 1         | Completed alpha returns 3 (skip); partial part returns 2, BE16 length 74 and RFLT DATA 13 / MACR 5; remainder FILP completes; final new directory returns 3 then EOF.                                           |
| Completed-file skip as final item            | Initial 3, file descriptor, response 3 then EOF; no file stream.                                                                                                                                                |
| Directory descriptor naming an existing file | Same 3/EOF wire result; the existing file remains intact. The response does not distinguish this conflict from a successful non-file outcome.                                                                   |

The interrupted part has DATA 13 / MACR 5 and native type/creator HTft/HTLC.
Correct continuation sends INFO, zero DATA bytes and MACR bytes `[5:317]`;
afterwards its forks are 13/317 and type/creator TEXT/MOTH. The completed alpha
survives both interruption and later conflict handling with the original bytes.
All uploaded INFO values contain a different embedded name; descriptor-selected
paths are retained. Type, creator and comment are verified through native
downloads and direct catalogue/fork observations.

For the fresh five-item test, client-supplied 108 is 1,189, the sum of its
three uploaded FILP stream lengths. The server accepts that declaration; the
later 210 aggregate is 652. Handler 213 uses the client's value for free-space
and progress bookkeeping, while per-file BE32 lengths and the processed-item
count govern these stream transitions. This fixture does not establish a
canonical historical client's aggregate-upload formula or a universal
total-byte validator.

### Captured folder timing and filesystem observations

Two upload timing cases use distinct roots and control sessions and
intentionally overlap; the following download case runs separately. All pauses
and packet bytes are retained. Control 500 is used as an operator-chosen ACK
probe, not evidence of a historical client's request-500 scheduling.

| Timing case                                                   | Host-clock observation at guest packet boundary                                                                                                         |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Attach upload after 125 seconds of pauses                     | Native close 126.838249 seconds after request ACK, with no initial readiness bytes.                                                                     |
| Directory-only progress after 90 seconds, then further pauses | Native close 127.964718 seconds after request ACK, 35.018523 seconds after the directory reply, despite only one of two declared items being processed. |
| Download file choice delayed by 130 seconds of pauses         | First file length arrives 130.427736 seconds after the descriptor; full folder download succeeds.                                                       |

These observations support the traced upload clock origin and the absence of an
equivalent connected inactivity check in this download worker. The directory
exchange does not buy a fresh full upload interval. Packet timestamps do not
instrument the exact internal check or prove an unconditional network deadline;
the intentional upload overlap also precludes isolated scheduler causality.

Path-based SleuthKit lookup of the live image failed with a catalogue-node-size
error before and after an auxiliary finalization through the native FlushVol
path. Those failed attempts are retained as failures. Direct catalogue-ID
`istat`/`icat` observations succeed: each positive path is verified before its
fork bytes are read. The bounded scan is not an exhaustive directory listing or
proof of absence. Before/after records independently validate the retained
partial resource prefix, complete continuation, empty directories and unchanged
conflicting file. A missing zero-length resource attribute is labelled as an
absent attribute, rather than a successful extraction. No restart-durability
claim follows from these live-image observations.

[folder-batch]: ../mothra/evidence/gap-remediation/2026-11-12/batch-05/manifest.json

[batch]: ../mothra/evidence/gap-remediation/2026-11-12/batch-04/manifest.json

[descriptor-asm]: ../mothra/evidence/gap-remediation/2026-11-12/batch-10/queries/B10-A-1000c6a0.json

[info-restore]: ../mothra/evidence/gap-remediation/2026-11-12/batch-13/queries/B13-D-1002d2c0.c

[attach-asm]: ../mothra/evidence/gap-remediation/2026-11-12/batch-16/queries/B16-A-1000bd20.json

## Captured banner observations

The
[banner corpus](../mothra/evidence/gap-remediation/2026-11-12/native-banner-01/manifest.json)
adds native GIF and URL fixtures to the handler traces. These are bounded
observations of the identified 1.9-family oracle, rather than a claim that
every advertised image type or historical client has been tested.

With a nonempty local GIF buffer, request212 returns an odd four-byte
reference107 and the current byte count108. Selector2 transfers the raw data
fork, without FILP, INFO, DATA or MACR wrappers. The43-byte fixture preserves
CRLF, NUL and high bytes. After those bytes, the connection remains open
through a three-second quiet window. Request214 ACKs both before attachment and
after delivery without cancelling this banner entry. Wrong selectors0/1/7 and
unknown/zero references close without application payload in the retained cases.

Delayed121 completion advertises152=`GIFf` or `0x55524c20`, with the configured
link bytes in153, for reported versions151 and190; version150 receives no122.
Early-completed107 does not emit122. An empty remote URL and a failed
local-file load suppress122. In those configurations,212 produces no reply
through a three-second quiet window before a later500 ACK; an initial
empty-configuration probe also retains a30-second read timeout. These
observations do not establish an eventual numbered error, an unconditional
close or a zero-byte transfer.

The changed-buffer fixture advertises43 bytes, then changes the configured
filename to the58-byte fixture during a45-second pause. The original reference
subsequently delivers all58 replacement bytes. Its control stream contains only
the original122, with no unsolicited replacement advertisement. Advertised size
therefore does not freeze the banner payload for the reference's lifetime.

An unattached reference rejects without payload544.059729 host seconds after
its 212 ACK, following twelve planned45-second pauses and twelve successful
owner500 replies. The native boundary sends RST on the attempted attachment.
The image configuration changes during this observation, including temporary
absence; image content is available at final attachment. This establishes the
retained aged-reference outcome, not an exact internal deadline or
uninterrupted image-present timing guarantee.

Failed GUI/path probes and unsuccessful restoration attempts are retained with
their original reports. The following format/recovery corpus supplies
successful phase-confirmed restoration and JPEG/PICT/BMP streams. Broader
reference reuse/ownership boundaries, general timing guarantees and
identified-client rendering remain open.

## Captured banner formats and recovery

The [second banner corpus][banner-formats] extends the GIF/URL controls with
identified native files and complete type-specific streams. Each nonempty
payload equals the loaded data fork, with no flattened-file wrapper or resource
fork. The PICT result includes its file's 512-byte prefix; it is not stripped.
These are server byte/type observations, not historical-client rendering tests.

| Native file/control             | Finder type  | Advertised 152 | Stored / delivered bytes |
| ------------------------------- | ------------ | -------------- | ------------------------ |
| JPEG                            | `JPEG`       | `JPEG`         | 634 / 634                |
| BMP                             | `0x424d5020` | `0x424d5020`   | 58 / 58                  |
| PICT                            | `PICT`       | `PICT`         | 642 / 642                |
| PNG with an unrecognized suffix | `PNGf`       | `PNGf`         | 69 / 69                  |
| PNG with type zero              | zero         | no 122         | 69 / 69                  |
| GIF bytes with a `.jpg` suffix  | `GIFf`       | `JPEG`         | 43 / 43                  |
| Extensionless TEXT control      | `TEXT`       | `TEXT`         | 43 / 42                  |
| Present empty GIF file          | `GIFf`       | `GIFf`         | 0 / 0; service reset     |

A zero advertised type suppresses122 even when a nonempty buffer can be fetched
through 212. A suffix-derived type can differ from the payload encoding; this
loader does not validate JPEG content before advertising the JPEG tag. The TEXT
control keeps 43 native file bytes, but the loader changes CRLF to CR before
advertising 42 and transferring those 42 bytes. Loading does not rewrite that
native data fork. Its earlier `.gif` counterpart finalized with `GIFf`/`ogle`
metadata and was rejected as a TEXT control; no cause is inferred from the
filename coincidence alone.

Both login-completion paths have phase-checked recovery fixtures. In the
delayed variant, the owner receives 122 advertising `GIFf` before the 58-byte
reference is issued; a separate baseline confirms that advertisement and size.
The early variant establishes the corresponding reference without an owner122.
In the delayed variant, selecting Remote with an empty URL removes the loaded
image; in the early variant, a failed filename load does so. A separately
authenticated 121 session confirms no 122, while the original data connection
remains quiet for three seconds. Restoration is confirmed by another 121
session advertising `GIFf` and the configured link. With periodic owner 500
requests, the original reference and waiting data connection deliver the58
bytes and remain open through the final quiet window. The plan has two
180-second configuration windows. In the early variant, native DATA first
appears 270.473290 host seconds after the original ACK, before the
application's delayed read at 368.076401 seconds from capture start. The
verifier records both variants' timings; these are observations, not
restoration deadlines.

A present zero-length buffer is a different state from a missing buffer. It
still produces 122 and a successful 212 reply with size zero and an odd
reference. On attachment, the retained fixture observes native RSTs on the data
connection, its owner control session and a separate authenticated observer.
The GUI log records `SERVER RESET - too many errors`. A fresh login and 500
then succeed without an operator restart. The worker calls a temporary-buffer
allocator with size zero; that allocator throws internal `SError` domain 1/code
2. The sent-count would remain zero, so the normal nonzero completion guard is
not established. The repeated-error/reset observation is not a numbered
banner-error packet or a successful empty transfer. General reset thresholds
and recovery guarantees remain outside this fixture's claim.

For a missing buffer,212 reaches the size helper with null and raises the same
internal domain/code before constructing its ACK. The preceding corpus retains
bounded silence and subsequent control liveness; do not turn the internal pair
into a wire status. The null-buffer worker guard also skips banner processing,
whereas the present-empty path reaches the allocator. Taken with the earlier
43-to58-byte replacement and aged-reference fixtures, these cases establish
GAP-063's stream, size/lifetime and missing/changed-content outcomes. The HTXF
header/reference cases above add owner cleanup and bounded duplicate/reuse
outcomes. General identifier lifetimes, client rendering and mxd policy remain
separate acceptance work.

[banner-formats]: ../mothra/evidence/gap-remediation/2026-11-12/native-banner-02/manifest.json
