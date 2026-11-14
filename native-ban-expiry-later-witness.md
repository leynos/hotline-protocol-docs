# Native temporary-ban later epoch

This control-only witness follows the [first temporary-ban epoch](native-ban-expiry-first-witness.md)
on the **same** disposable Hotline Server 1.9 VM and working image. The complete
portable corpus is
[`native-ban-expiry-later-01`](../mothra/evidence/gap-remediation/2026-11-14/native-ban-expiry-later-01/manifest.json).
The full file-transfer A7 baseline was **not exercised** in this lab.

## The missed pre-window

The first option-1 request and ACK were bounded at 05:55:01.616113–
05:55:01.632067 UTC on 14 November 2026. The planned host-relative pre-probe
window was 1,600–1,700 seconds after the request. C79's two managed recorders
and lock were ready, but the single C80 controller exited **before a socket or
case action**. Its identity check compared receipt start tick `"5983214"` to
ban-clock integer `5983214`. Both C79 PCAPs remained 24-byte headers with
zero captures/drops. The window elapsed, and no pre-window login was observed.

The retained pre-C80 controller and later controller differ by one line:
the latter converts the receipt start tick to an integer in `TimingBounds.gate`.
The frozen regression source tests equal string/integer ticks and rejects a
wrong string tick. The later controller ran only after the pre-window was lost.
The failed C80 launch remains a failed experiment, not a native rejection.

## Later login and cleanup

C82's first post-window lookup used one fresh TRTP handshake and valid Login
107. The host timing gate reported **2,032.227663 seconds after the original
ACK**, inside its 1,900–2,400 second window. The native reply was type 0,
correlated ID 1, status 0, with fields 160 and opaque two-byte 161. The same
connection received the expected 354 and 109 messages and a roster reply.
The server's log shows `Expiry Zero` login successful at 06:28:53. The guest
menubar clock was visibly 05:55:26 after the first epoch, 06:20:05 at C79,
06:27:48 before C82, and 06:29:36 afterward. Screenshots have host before/after
command timestamps. These observations support progression, without calibrating
the native `GetDateTime` call or measuring the exact 1,800-second boundary.

The later guest PCAP starts with the frozen first-epoch guest PCAP prefix. It
contains the original 13 SYNs and exactly four later SYNs, with no intervening
unexpected control connection. Each later flow has complete bidirectional
bytes matching the Recorder and both packet views:

| Flow | Namespace packets | Guest packets | Sent bytes | Received bytes |
| --- | ---: | ---: | ---: | ---: |
| Post login | 17 | 17 | 120 | 389 |
| Owned-account guard | 19 | 19 | 169 | 496 |
| Owned-account delete | 27 | 26 | 274 | 645 |
| Control postflight | 29 | 34 | 231 | 2,759 |

C83 guarded both owned accounts with type 352 and checked exact name,
complemented key, `x` attribute, and zero versus bit-23 access. Only after the
guard passed did C84 send two type-351 deletes. Type-352 readbacks reported
both missing; type 348 listed the original two accounts. The separate
18-action control postflight passed its original accounts, files, metadata,
agreement, roster, and idle checks. This was a control-only postflight, not
a repeat of the full A7 file-transfer baseline.

The app's Quit control closed the server window. The owned SheepShaver user
unit then stopped the emulator; this was **not an orderly Mac OS shutdown**.
The actual emulator, wrapper, bridges, display, capture units, and lock were
gone before the fixed 06:38 UTC deadline. The primary-port PCAP is a 24-byte
header; both recorders reported zero drops. The original primary server and
client PIDs remained unchanged. The stopped 8 GB working image has SHA-256
`01e8621f…`, while the immutable base and ROM retain their original hashes.

Read-only HFS extraction occurred only after the actual emulator PID was gone
and a root process-FD scan found no open working image. Original admin and
fixture-low UserData, Prefs, and application DATA/RSRC fork hashes match the
preboot baseline. No `Banned` file appears in the stopped catalogue. The two
owned account folders and 734-byte UserData forks are nevertheless **allocated
under `/Trash`**, with HFS catalogue IDs 11754–11757. Their type-352 absence
and type-348 original-two roster prove removal from the active server account
set; they do not prove erasure from disk. That storage observation belongs to
the separate account-deletion durability questions in GAP-021/GAP-072.

## Offline replay and limits

From this protocol repository beside Mothra:

```sh
python scripts/verify_native_ban_expiry_later.py
python -m unittest discover -s scripts -p test_native_ban_expiry_later.py
```

Replay verifies the immutable first-epoch corpus, source snapshots and the
one-line controller correction, the failed C80 pre-window, managed unit and
capture receipts, exact post/guard/delete/postflight plans and semantics,
four SYN-scoped paired streams, clock brackets, stopped FD boundary, and HFS
fork hashes. The later post report's B68 metadata is adapted **only in a
temporary generic-verifier view**; raw events, frames and streams are not
changed. Fault controls rehash mutated corpora before checking timing,
identity, plan scope, packet tails, captures, clock claims, and storage state.

This witness supports that an immediately rejected temporary-ban login later
succeeded on the same VM after a host-relative 2,032-second wait. The missed
pre-window means it does **not** measure the native cutoff or independently
demonstrate rejection just before it. The 1,800-second rule is from the
separate static Ghidra finding; whether removal was lazy at login or from a
background purge remains unknown. No later restart, persistence, protection
matrix, or general server-health claim follows from this control-only run.
