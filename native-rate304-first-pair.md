# Native 1.9 rate 304: failed first pair

This is a **failed fixture**, retained to bound the next rate and reset test.
The live runner stopped at its first response wait. It establishes neither a
304 limit nor a reset interval or ban rule. The corpus is
[`native-rate304-first-pair-01`](../mothra/evidence/gap-remediation/2026-11-14/native-rate304-first-pair-01/manifest.json).

## What ran

The disposable Hotline Server 1.9 lab used the original DATA fork `ad7040db…`,
RSRC fork `fe83a2cf…`, immutable base `e5cbbaaf…`, and a separate stopped
working image. A separate control preflight completed 18 actions: TRTP and
numbered 107, 348, 200, 206, 300, and 303. That preflight is a control-only
check; it did not run the full file transfer baseline.

The case opened two further sessions. The observer `admin` and paced subject
`fixture-low` each completed Login107 and roster300. The observer's 301 ID3
reported the _initial join_ of subject UID3 with icon1. The paced subject sent
one 304 ID1000 with field104=`0002`, then one same-socket 500 ID2000. The pair
wait was 0.55 seconds. It raised
`Missing paced subject/observer301 and500 ACK icon2` before the expected
responses reached the recorder.

| Event                                      | Elapsed from case start |
| ------------------------------------------ | ----------------------: |
| paced 304 send completed                   | 0.837840 s              |
| paced 500 send completed                   | 0.837877 s              |
| runner began observer `shutdown_write`     | 1.388185 s              |
| paced received observer-departure 302 UID2 | 1.580643 s              |
| paced received its 301 UID3/icon2          | 1.585971 s              |
| paced received successful type0 ACK ID2000 | 1.585993 s              |

The last three frames arrived **during client cleanup**. The observer had
already sent FIN, so its missing icon2 notification cannot be treated as an
independent server outcome. The paced 302 is observer departure, not a subject
ban. The first 301 is a login join, not a 304 update. The case emitted no
second 304, 26-pair trial, 27th limiter request, 70-second reset wait, or fresh
ban probe. It contains no native server RST or crash witness.

## Packet and terminal boundary

Namespace and guest PCAPs contain the same three complete TCP lifetimes,
including both tails. The control preflight carries 231/2759 client/server
bytes. Observer and paced lifetimes carry 108/448 and 159/521 bytes. The case
recorder's send and receive streams match both packet views byte for byte. Host
primary-port capture recorded zero SYN packets; both active recorders reported
zero kernel drops. The one 304 appears twice in guest packets at the same TCP
sequence because of retransmission, not as two logical requests.

The case unit exited 1. The server application was quit through its GUI and the
guest then shut down through the Mac Special menu. The actual emulator PID
disappeared without a manual TERM. All owned capture, lease, bridge, and
display services stopped before the fixed deadline. Read-only extraction from
the stopped image found the original two account forks, Prefs, server DATA and
RSRC hashes unchanged, an empty MessageBoard data fork, and no allocated
`Banned` path. Those observations do not establish crash durability or a native
rate rule.

The initial operator summary incorrectly said that zero 304 and 500 requests
had been sent. The case recorder, the paired PCAPs, and independent A102/B90
audits in the corpus correct that statement. The next test design needs an
explicit timing strategy; the B90 audit proposes a separate synthetic process
rehearsal before another native lab. This corpus grants no live retry.

## Offline replay

From `hotline-protocol-docs` with an adjacent `mothra` export:

```sh
python3 scripts/verify_native_rate304_partial.py
python3 -m unittest discover -s scripts -p test_native_rate304_partial.py
```

`--corpus PATH` selects a copied corpus. The verifier checks the complete SHA
inventory, source closure, failed case boundary, exact 304 and 500 bytes, late
frames relative to client cleanup, all three paired TCP streams, zero primary
SYN/drop receipts, and stopped fork and service receipts. It requires no VM,
Ghidra, mxd, or network access.
