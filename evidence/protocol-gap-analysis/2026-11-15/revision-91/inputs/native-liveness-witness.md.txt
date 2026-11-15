# Native preonline liveness witness

The
[portable corpus](evidence/gap-remediation/2026-11-14/native-liveness-01/manifest.json)
records one finite Hotline Server 1.9 lab run against an isolated, disposable
Mac server. The source-declared schedule admitted an online observer (`O`), a
partial-107 connection (`A`), a preonline connection (`B`), a failed-login
connection (`F`), and three short TRTP stimulus connections. The separate
18-action control readiness passed before and after the case: original two
accounts, 41 Files descriptors, agreement, metadata, roster, and idle. This was
a **control-only** run; the full A7 file baseline was not exercised.

Replay without a VM, ROM, or source checkout:

```sh
python3 scripts/verify_native_liveness.py
python3 -m unittest discover -s scripts -p test_native_liveness_corpus.py
```

## Finite results

`T0` is the runner's local monotonic marker after O's successful 107/354/109.
The 135-second observation window ended at T135.000159328. These are local host
measurements. Packet timestamps are a separate capture clock; neither is a
calibrated Mac server timer.

- **O:** Successful login, then 26 correlated 500 ACKs at five-second
  intervals from T5 through T130. No EOF through T135. The client closed its
  write half in final drain; local EOF followed at T135.008015.
- **A:** TRTP then nine bytes of a 107 header, never completed. Local EOF
  arrived at T65.116360.
- **B:** TRTP without early login. Valid 107 at T45 yielded a success ACK at
  T45.009757 and 109 at T45.014993. O's T46 roster omitted B. B's 121 at T50
  was one payload byte short and drew no numbered reply in the window. Local
  EOF arrived at T110.017097.
- **F:** Incorrect-password 107 yielded a status-1 reply at T0.825468.
  Local EOF arrived at T35.138506.
- **S35, S75, S120:** Each completed TRTP. The runner closed its own socket
  after bounded observation; these flows set no server-close deadline.

O received six unsolicited 302 frames, each 28 raw bytes, with field 103 UIDs
`0005`, `0006`, `0003`, `0007`, `0004`, `0008` in observed order. No 301 was
present in O's case frames. Admission order suggests possible labels for those
UIDs, but this packet has no independent allocation readback and does not
assign a proven person to each UID. The 302 arrivals are finite observer
evidence, not proof of a universal cleanup order or ID recycling rule.

Nine unique TCP lifetimes are tied to the runner's nine connection events. The
guest PCAP has ten initial SYN packets because S120 retransmitted one SYN with
the same initial sequence number. Every namespace stream matches the guest
stream and runner bytes in both directions, including recorded tails; the table
counts client/server application bytes. Raw FIN/RST packets remain in both
captures and are not added to the application stream.

| Flow       | Sent | Received |
| ---------- | ---: | -------: |
| Readiness  | 231  | 2,759    |
| O          | 678  | 1,131    |
| A          | 21   | 8        |
| B          | 92   | 310      |
| F          | 77   | 50       |
| S35        | 12   | 8        |
| S75        | 12   | 8        |
| S120       | 12   | 8        |
| Postflight | 231  | 2,759    |

The Mac-side guest TCP capture shows **RST** on A, B, and F near their terminal
observations. The namespace relay delivered local EOF to the runner; its
FIN/RST flags need not match the guest's. O's write-half-close after the window
preceded a guest FIN and then local EOF. The three stimuli have client-first
FINs. These transport distinctions prevent treating a runner EOF as a Mac FIN
or turning the observed T35/T65/T110 into exact native 30/61-second timeout
rules.

## Provenance and limits

The owned emulator was PID 1221811/start tick 6825819, working-image inode
71221932, netns `4026533605`, and executable SHA `9c943042…`; its DATA and RSRC
forks match the pinned native app. A managed oracle lock and two SYSTEM
recorders were live across the case with independent deadline-plus-five
coverage. The host primary-port SYN capture contains no packets; both recorders
logged zero kernel drops. The app was quit, then the owned Sheep unit was
stopped. The Mac OS was not shut down orderly. All owned processes, ports, and
lock were released before the fixed deadline; the stopped original UserData,
Prefs, DATA, and RSRC forks matched preflight. This checks those named records,
not every byte of the mutable working image.

The first recorder readiness attempt ran as UID 1000 and could not read the
SYSTEM tcpdump `/proc` namespace links. Its empty outputs and the operator
error note are retained. A separately authorized root invocation passed before
the first socket, so the initial failure is not a native result.

This evidence narrows [GAP-005](gap-analysis.md#gap-005) for the listed
preonline, failed-login, partial-frame, and O500 observations. It narrows
[GAP-036](gap-analysis.md#gap-036) for six delivered observer 302s. It does not
establish configuration defaults, a calibrated native timer threshold, the
unique cause of any wake-up, online idle behaviour beyond 600 seconds, normal
EOF or kick cleanup, rooms/transfers, ID reuse, or broad gap closure.
