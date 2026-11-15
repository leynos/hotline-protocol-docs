# Native preonline liveness fixture preparation

This is a prepared GAP-005/GAP-036 **control-only** fixture. It has not run
against the Mac server. A fake socket consumer tests the generated request
bytes and failure gates; that is tool validation, not native evidence.
The fixture does not claim a universal 30- or 61-second TCP close.

## Source and case boundary

`native_liveness_cases.py` produces a versioned 135-second coordinator schedule.
`native_liveness_control.py` executes exactly its seven TCP flows inside a
separately authorised isolated Mac server namespace. The operator runs a
separate unchanged 18-action control-only readiness flow before and after:
nine flows total, at most five simultaneous in the coordinator. Pre/post must
prove the original two accounts, 41 Files entries and the controlled 242-byte
agreement; full A7 and full file transfer are `not_exercised`. No account,
disk, configuration or clock write belongs to this packet.

The observer O completes 107 early with a nonempty name/icon, receives 354 and
controlled 109, and sends 500 at host schedule seconds 5, 10, …, 130, with
unique IDs and exact ACKs. A sends a nine-byte prefix of a 107 header after
TRTP at T0. B is admitted by TRTP at T0; at T45 it sends one valid 107 with
owned admin credentials, nonempty 102 `TimerB`, and **absent 104**. The frozen
`10011960` handler sends success ACK and 109 but needs nonzero 104 as well as
nonempty 102 before early 354/online completion. O sends 300 at T46 and must
exclude B. B sends a complete 121 header with only one of its two payload
bytes at T50. The runner refuses that send if B's 107/109 or observer roster
witness differs, or if B gets 354. F sends one validly framed wrong-password
107. S35, S75 and S120 make short-lived TRTP-only connections. Neither B nor
any stimulus sends preonline 500: that would take a different close path.

The source anchor is `D-1000acf0.c`: only selected complete logical requests
refresh `session+0x9c` before handler dispatch. The accepted preonline age
comparison is >=61 native seconds; failed-auth age is >30. `10070790` permits
its transport predicate when atomic bit 1 **or** endpoint state 6 is present.
The numerical endpoint state is not interpreted here. Dispatcher scheduling,
transport state and guest clock can change when, or whether, a wire close is
observed. The coordinator records fixed checkpoints and every arrival; an
open socket at T135 is `bounded_no_eof_through_window`, not a server fault.

## Preflight and exact runner inputs

Use a NEW disposable control-only runtime, display, working image and guest
capture prepared from a stopped immutable base, with proposed port **15840**
only after parent availability review. No live working-image copy. Root owns
boot, captures, primary isolation and the live oracle lease. Before native
contact, require actual emulator executable SHA, PID/start, working-image
inode, FD6/16, namespace inode, loopback-only interfaces/empty v4/v6 routes,
managed host/namespace recorder active PIDs and writable PCAP FD/inodes,
900-second service cap covering the group deadline plus margin, and managed
oracle-lock FD/inode with independent nonblocking contention. The inherited
`runtime_gate` rechecks these from the receipt before the coordinator and
after O's login. Run inside the actual private emulator namespace through the
approved direct system service `NetworkNamespacePath`; the runner compares
its own namespace inode to the prepared emulator inode. It does not create a
namespace or acquire the lease itself.

Prepare a runtime JSON with `fixture_profile: control-only`, `emulator_pid`,
`emulator_starttime`, `emulator_sha256`, `emulator_netns_inode`,
`owned_working_image`, and `owned_working_image_inode`. Use fresh absent output
leaves. The receipt must contain the complete existing B68 managed-capture,
network, guest-FD and managed-lock schema, `epoch_started_utc` and
`deadline_utc`. Parent must review exact paths, ports, command and identities
before live START. The 12-minute group includes boot (budget <=3 minutes),
separate pre/post controls, and this 135-second window; managed captures may
have a 900-second cap but must cover the fixed group deadline. The runner's
own 160-second hard cap includes O login, 135-second window and <=3-second
tail drain. If boot or preflight consumes too much time, stop before contact.

```sh
PYTHONPATH=scripts python3 scripts/native_liveness_cases.py \
  --runtime state/native-liveness-01/runtime.json \
  --output state/native-liveness-01/plans --port 15840

sudo env PYTHONPATH=scripts python3 scripts/native_liveness_control.py \
  --plan-dir state/native-liveness-01/plans \
  --capture-receipt state/native-liveness-01/receipt.json \
  --binary state/mac-runtime/native-liveness-01/shared/Hotline\ Server \
  --output state/native-liveness-01/coordinator
```

The second command is **illustrative**, not a live grant: use the actual
verified Mac PEF path and exact approved network namespace service; do not
launch it in the host namespace. In the private development checkout, tests
need `PYTHONPATH=scripts:/data/leynos/Projects/hotline-protocol-docs/scripts`
because its older clone omits the imported ban-control dependency; a fresh
adjacent canonical export supplies dependencies from the committed repository.

## Retained output and interpretation

The runner keeps exact request/response chunks, UTC and monotonic timestamps,
frame bytes and parsed fields, per-flow unparsed bytes, schedule labels with
contiguous event/frame ranges, checkpoint socket statuses, EOF/RST and final
client-close/tail observations. Limits: 128 frames, 128 KiB total recorded
bytes, 64 KiB per-flow tail, <=160 seconds coordinator. It never equates a
read timeout with EOF. A malformed or incomplete response, changed agreement,
premature B online state, stale ID/status, lost capture/identity, exhausted
budget or unexpected route invalidates the fixture; retain its failed report
and raw PCAPs without retry. The custom report is checked by
`verify_report`, not generic `verify_capture`.

The portable verifier reconstructs each window and final socket outcome from
its retained EOF/RST/close events. It checks global event-time monotonicity,
operation times against their declared seconds, and the measured 135-second
window marker. Up to 5 ms early is allowed for float-to-nanosecond conversion;
up to 5 seconds late is allowed for scheduling/transport jitter. A larger
delay makes this finite fixture timing-invalid, without proving a native
timer fault. Source and raw bytes remain independently pinned.

A future native report may constrain GAP-005 selected-request reset and
partial-input timing, and GAP-036 timeout/failure 302 recipients/fields if
seen. It cannot prove a unique dispatcher wake cause, configurable timers,
normal EOF/kick room and transfer cleanup, or the online >600-second idle
branch. That branch needs a separate >=620-second post-boot epoch and grant.
