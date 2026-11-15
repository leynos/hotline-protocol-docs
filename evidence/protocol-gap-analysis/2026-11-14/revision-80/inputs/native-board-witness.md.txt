# Native Hotline Server 1.9 message-board witness

This finite, isolated Mac OS 9 fixture exercises Hotline Server 1.9 message-board
requests `101` and `103`, the `102` update, recipient access, size boundaries, and
stopped HFS storage. The portable corpus is
[`native-board-01`](../mothra/evidence/gap-remediation/2026-11-14/native-board-01/manifest.json).
Run `python3 scripts/verify_native_board.py` from this repository, or pass
`--corpus PATH` after exporting this repository beside `mothra`. The verifier
uses frozen source, reports, whole packet captures, and stopped fork bytes; it
needs no guest, ROM, server process, or Ghidra project. Its 17 fault controls run
with `python3 -m unittest discover -s scripts -p test_native_board_corpus.py`.

## Fixture and observed results

The disposable lab used immutable base SHA-256 `e5cbbaaf…`, ROM `18da89e4…`,
server DATA `ad7040db…`, and resource fork `fe83a2cf…`. The actual emulator was
PID `1441133`, start tick `7213582`, network namespace `4026532471`; its owned
working image had inode `1678261667`. Port `15860` was reached only within the
lab namespace. A managed recorder watched the original server's host ports
`15500/15501` and captured zero SYNs. The case deadline was fixed at
`2026-11-14T09:22:28.893022Z`; both recorders reported zero kernel drops.
The preparation found two original active accounts, an empty board DATA and
resource fork, and no ban file. Separate 18-action control preflight and
postflight passed the account, file, metadata, agreement, roster, and idle
checks. This was a **control-only** fixture: the full A7 file transfer was not
exercised.

The one board case completed in 35.620 seconds. Its four sockets sent 32
numbered requests: four logins, nine reads, thirteen posts, and six `500`
barriers. The report retains 71 frames, 429 events, all application streams,
and socket tails. Six complete SYN lifetimes, comprising the control preflight,
four board sockets, and postflight, match byte for byte between the namespace
and guest packet captures and the corresponding reports. The case unit records
`NetworkNamespacePath=/proc/1441133/ns/net`; its source guard ran, but an
independent `/proc` namespace observation of the short-lived runner was not
retained. The paired TCP streams separately locate the traffic in the owned
namespace. The two TCP views have different packet counts; they carry the
same application bytes.

The sender and access-eligible observer each received twelve `102` updates.
The denied observer received none, and its read returned an error. The waiting
observer received no `102` during the measured interval. That absence does not
isolate an online-state rule: its active ACL and transport predicate were not
independently measured. No total order is inferred across sockets.

The thirteen post payload lengths were `0, 7, 7, 8191`, six times `8192`,
`7155`, `1`, and a rejected `8193`. The first twelve produced board segments;
the thirteenth returned an error and left the stored whole unchanged. Recorded
read lengths included `0`, `93`, `193`, `293`, `58287`, and capped `65535`
results. Each of the twelve raw segments has 93 bytes of header/separator overhead
(33-byte header and 60-byte separator). A read returned the first 65,535
bytes even after the whole exceeded that length; the stored file itself was
not truncated.

After the server was quit and the owned emulator stopped, read-only HFS
extraction found `Hotline19/MessageBoard.txt`, catalog ID `11191`, Finder
`TEXT/ttxt`, DATA length **65,629** and resource fork size **0**. Every DATA byte
equals the reverse-order concatenation of the twelve retained `102` segments;
its SHA-256 is `a676c6349bb500411c0e0d73f29763a092cc1d9471809636c93433c5b430c4e0`.
The five named original user, preference, and server forks still match their
preboot hashes. The working image is retained separately and excluded from the
portable corpus. The emulator was forcibly retired after the native app quit;
this is not evidence of orderly Mac OS shutdown or crash durability.

## Provenance and limits

`manifest.json` inventories every corpus file and `SHA256SUMS` binds each byte.
The corpus retains as-run plans, source hashes and frozen import closure, full
reports, whole PCAPs, recorder readiness and terminal journals, the approved
capture-receipt helper, screenshots, immutable preparation, stopped HFS DATA,
and original-fork hashes. The verifier replays the frozen board producer and
semantic validator, then checks both packet views, the stopped file, deadline,
source identity, capture loss, and retirement. The separate parent stream
review is retained as corroboration and checked against the replay.

This one run supports the measured empty-board, multi-post, size-boundary,
recipient, read-prefix, and stopped-storage clauses of GAP-046. It does not
establish all timing interleavings, a universal online predicate, non-ASCII
rendering, spam policy, power-loss persistence, or a full-file server health
baseline. The [criterion decision](../mothra/evidence/gap-remediation/2026-11-14/criterion-acceptance-07/decision.json)
accepts GAP-046 against its original finite fixture requirement, with these
limits retained.
