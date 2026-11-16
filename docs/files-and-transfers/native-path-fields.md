# Native 1.9 structured path observations

This page records one disposable Hotline Server 1.9 run for fields **212**
(Files move destination) and **325** (News listing path). The exact case and
its source closure are in Mothra's portable
`evidence/gap-remediation/2026-11-14/native-path-fields-01` corpus. The
standalone offline verifier is `scripts/verify_native_path_fields.py`; run it
from an adjacent checkout, or pass `--corpus /absolute/path/to/corpus`. It does
not boot a VM or contact a server.

## Scope and results

The single retained admin case connection used native version `160=00be`, made
82 numbered requests including login, and sent 20 owned mutation requests. An
unchanged, closed 18-action control readiness connection ran first. The twelve
literal field values are frozen in the plan and each request's raw bytes. The
verifier checks the measured direct reply, 200/206 candidate-parent readbacks
for moves, and 370 field-323 listing records for News. Every case returned
direct status 0 in this run.

| Field | Tested values                                                                                                                                                         | Measured selected location                                                                                           |
| ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| 212   | High-byte nested path; final zero-length component; declared extra but absent component; `ffff` component word; valid prefix plus `ee` padding to 2048 and 2049 bytes | Owned `H-9a` folder for each of six `p0`–`p5` markers, independently seen in the three parent listings and after 206 |
| 325   | High-byte owned News folder; second zero-length component; declared extra but absent component; `ffff` word; valid prefix plus `ee` padding to 2048 and 2049 bytes    | Owned high News folder's `m-cat47` category in field 323 for each of six reads                                       |

The malformed and over-width values were accepted in this particular run. The
observations do not establish a universal parser rule, the purpose of the
opaque component word, or interchangeability with field 202. A positive 212
status alone was not used as location proof. A positive 325 status was paired
with the category row, which identifies the owned folder. That row does not
round-trip the original path bytes.

## Provenance and limits

The verifier requires the exact 37-module as-run source closure and three
helper hashes. Literal hashes of both approved manifests are checked before any
retained Python is imported; a test changes a dependency and every matching
source receipt, then confirms the changed code never executes. It also requires
regenerated plan, original PEF identity, actual emulator
PID/start/namespace/working inode, capture-ready receipts, fixed deadline and
stopped-image receipts. It replays the frozen report parser and independently
compares both complete namespace and guest TCP lifetimes with the recorder's
sent and received bytes, including terminal tails. The host primary-port
recorder saw zero SYNs in its filtered scope; no host-wide traffic conclusion
follows. The host and namespace recorder journals report zero kernel drops.
There is no equivalent guest drop counter.

The owned 380/380/204 cleanup moved objects to Trash. Stopped HFS catalogue IDs
place the six markers under the owned high folder there; the category fork has
1024 data bytes and zero resource bytes in the stopped image. Those reads
happened after the emulator PID was gone and the working-image FD was free.
They are post-cleanup evidence, not a temporal snapshot before each move or a
crash-durability test. The original admin, fixture-low, Prefs, server DATA and
RSRC fork SHA-256 values match the prepared baseline through retained
stopped-read command receipts. The raw original forks and the 8 GB disk are not
distributed in this corpus, so the verifier cannot rehash those bytes
independently. The emulator was force-terminated after application Quit;
orderly guest OS shutdown is not established.

The offline fault tests refresh corpus checksums after semantic changes. The
verifier rejects symlinked corpus files and directories before reading or
importing any retained source, so the archive must contain its own bytes. They
include a report whose events, frame and stream agree with each other but
disagree with the independently retained PCAP. Passing the inventory hashes or
the report's internal checks alone is insufficient for a native claim. The
original GAP-047 criterion and any status change remain a separate supervisor
decision after reviewing this bounded evidence.

> Status note (2026-11-16): the register now lists
> [GAP-047](../../gap-analysis.md#gap-047) as Resolved. Its closure text
> records the original criterion as closed against the frozen finite fixtures.
