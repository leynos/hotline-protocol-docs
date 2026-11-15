# Native roster overlap fixture preparation

B70 prepares one control-only GAP-035 case. It neither boots a guest nor sends
traffic. The frozen question asks whether initial 301 includes its subject,
when a session appears in 300, and how 300 orders against concurrent changes
and 354. Initial login and later rename already have retained examples in
`presence-messaging-contracts.md` and `native-live-accounts-01`; this case
measures one outstanding 300 while a session-only 304 changes a peer's name and
icon. One schedule cannot prove an atomic snapshot/subscription rule or all
possible interleavings.

## Plan and isolation

Generate a plan from a separately reviewed disposable runtime JSON with
`fixture_profile: control-only` and exact emulator PID, start time, executable
SHA, network namespace inode, working-image path and inode. Root must first
verify the stopped base/ROM, source application forks, owned display/port
15820, no prior lab contact, primary silence, guest capture, and exclusive
managed oracle lease. Do not use the original native 15500/15501 server or
change an account, disk file, configuration, or clock.

```sh
python3 scripts/native_roster_overlap_cases.py \
  --runtime state/native-roster-overlap-01/runtime.json \
  --output state/native-roster-overlap-01/plans --port 15820
```

The live runner takes the exact plan directory, fresh capture receipt, pinned
native data fork and a **nonexistent** output leaf. It reuses
`native_ban_expiry_control.runtime_gate`: prepared-vs-receipt PID/start/exe,
namespace/image identity, actual emulator FD 6/16, recorder PID/start/writable
PCAP FD, fresh namespace/IPv4/IPv6 route/lo-only checks, managed unit lifetime
and busy canonical flock. The receipt deadline must be within 10 minutes and
managed services must cover it. Both host and guest captures must start before
first SYN and retain complete TCP lifetimes. This runner does not create
capture services, acquire the lease, or establish an original A7 full-file
baseline; those are root-owned live prerequisites.

Use a finite managed unit with
`NetworkNamespacePath=/proc/<actual-emulator-pid>/ns/net`; the inherited runner
gate rejects a different process namespace before opening a socket. The
equivalent namespace context for its payload is:

```sh
roster_emulator_pid="$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["emulator_pid"])' \
  state/native-roster-overlap-01/runtime.json)"
sudo nsenter --target "$roster_emulator_pid" --net -- \
  python3 scripts/native_roster_overlap_control.py \
  --plan-dir state/native-roster-overlap-01/plans \
  --capture-receipt state/native-roster-overlap-01/receipt.json \
  --binary /absolute/owned/native-server-data-fork \
  --output state/native-roster-overlap-01/results
```

The two **owned connections** use the existing public fixture admin account; no
account creation or edit is in the plan. Distinct requested 102 names and
nonzero icons, with measured naming privilege 26, make both sessions early
online. The runner checks each 107 success and 354 access, A's B-UID 301, and
both current 300 snapshots for exactly two unique UID/name/icon rows. It
preserves the actual UIDs; it never guesses a UID from connection order. At
most two control connections are opened, below the ten-connection cap.

## Bounded causal sequence

1. After setup and bounded quiet, A sends 300 ID 11. Before reading its
   reply, B sends 304 ID 20, changing B's effective name from `Order B` to
   `Order New` and icon from 2 to 3. A and B then each send 500 ID 12 on their
   own sockets. Send completion times are retained per chunk.
2. A bounded `select` drain retains raw byte chunks, exact decoded frames,
   connection labels and monotonic frame-completion timestamps. It waits for
   A's 300 ACK, A/B rename 301, and both 500 ACKs in **either** arrival order.
   It caps the drain at five seconds, 32 frames and 65,536 bytes. Any extra
   301/302, malformed/fragmented frame, incomplete tail or failed ACK is
   retained and fails the case; none is silently skipped.
3. A's first 300 must show complete old B name/icon or complete new pair,
   always with the same B UID and the unchanged A row. After both observed
   barriers, A requests 300 ID 13; that stable snapshot must show the new pair.
   Both sockets then have bounded quiet, planned half-close/EOF and close; A's
   B-UID 302 is checked. Unexpected bytes remain in the failed report and
   external packet captures.

The versioned `coordinator.operations` schedule declares five injected sends,
two unordered drains with exact required frame keys, and two quiet checks.
Custom drain receives use action `-1`. The as-run report records schedule SHA
and operation labels with event/frame ranges. `verify_operation_map` checks
plan/schedule hashes, contiguous ranges, injected bytes, custom receive
provenance, quiet connections and reconstructed streams. Generic
`protocol_capture.verify_capture` does **not** certify this custom report.
Freeze the plan, report and exact producer/runner sources for portable
publication; host/guest packet parity remains a separate check.

`overlap_status` becomes `completed` only after ID 11 and stable ID 13 pass.
Teardown has a separate status. Planned half-close/read-to-EOF retains late
bytes without requiring empty tails; observed extras are classified as
`completed_with_late_bytes`. Cleanup failure leaves overall `status=failed`
while retaining a completed overlap result. The B-UID 302 is required, but
other late frames do not invalidate the earlier roster measurement.

TCP preserves each connection's request order. Treat the 500 ACK as a
same-socket **handler** barrier only after confirming the traced dispatcher
finishes the prior handler before processing 500. Neither barrier gives a
global order between A and B. The report records request send order, decoded
frame arrival and old/new snapshot outcome. Host/guest PCAP comparison later
bounds packet arrival; it cannot identify the instant a server handler ran. A
300 ACK after B's 304 send is not proof that 304 executed first.

## Verification and unresolved requirements

Six focused tests feed a generated plan to the bounded reader and whole
coordinator over fake socketpairs. They cover both ACK-before-301 and
301-before-ACK, nonempty late EOF, changed injected bytes and action `-1`,
truncated and malformed frames, wrong ID, torn name/icon pairs, extra frames,
an unexpected third roster row, and modified plan hash. Ruff format/check,
`ty check`, Markdownlint and Nixie are the scoped gates. The private clone uses
canonical `native_ban_expiry_control` dependencies; a fresh adjacent export
must include those pinned source files before live approval.

Root must choose the actual runtime/ports and approve live work separately.
Before then, verify the serial-dispatch assumption in retained code, observe
managed capture readiness and source identities, define postflight and cleanup,
and test host/guest packet parity. A natural early reply/error, capture gap,
identity drift or time limit ends this one case without retry or widened
window. A finite old/new result can document the observed schedule; it does not
close broader GAP-035 concurrency by itself.

B71 raised source/test/prose caps to 760/380/160 physical lines for the
declared schedule, whole-run socketpair regression and separate late-tail
classification. No live authority was added.
