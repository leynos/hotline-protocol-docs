# Native temporary-ban expiry fixture preparation

This prepares a separately authorised GAP-074 control-only run. No guest,
native contact or clock change occurs here. The full-file A7 baseline is
`not_exercised`; no expiry result is claimed.

## Scope and owned identities

- Use a new disposable runtime at `state/mac-runtime/native-ban-expiry-01`, a
  new display at `state/mac-displays/native-ban-expiry-01`, and ports
  15800–15803. The live operator must prove the stopped base, ROM, new
  image inode, emulator PID/start/exe SHA, FD 6/16, namespace, loopback-only
  routes and zero primary contact. Never copy a live working image.
- The two new account keys are `m-expiry-zero` (zero 64-bit ACL) and
  `m-expiry-protected` (only privilege bit 23). They never name the original
  administrator. Existing names cause the guard to fail; no overwrite or retry
  is prepared.
- Each epoch has its own managed host and namespace TCP recorders, guest
  capture, managed oracle-lock service, and <=12-minute case deadline. Each
  service has a 900-second cap and must cover the case deadline plus five
  seconds. Use fresh paths and preserve complete streams and EOF tails. The
  primary capture must have no SYN before the case. Three epochs are separate:
  stop recorders and release the lease during the approximately 30-minute idle
  interval. No source writes or scheduled mutations occur in that interval.
- The control-only 18-action login readiness capture must pass **only before
  the first epoch**. Option 1 bans the shared guest address, including admin;
  a pre-epoch admin 107 would fail. A post-epoch admin 107 could itself invoke
  lazy purge before the intended owned probe. The pre and post epochs use
  fresh recorder, PID, FD, route, mutex, and source gates; the intended owned
  probe's TRTP handshake is their first socket. The runner rechecks actual managed
  service properties, PID/start, writable FD/inode, lock FD/inode and
  independent lock contention, native binary SHA, guest FD 16, and the frozen
  plan hash. The runner requires root only to inspect `/proc`; no privilege
  adjustment occurs inside the guest.
- The runtime gate binds prepared PID, start, exe, namespace and image inode
  to the receipt, then rereads the recorder's actual namespace, both IP route
  tables and the interface list. Only `lo` and empty main routes pass.

## Prepared case order

- **First, account setup:** guard-zero, guard-protected, seed-zero,
  seed-protected. Both keys must be absent; create and read back exact values.
- **First, kick-only:** kick0, kick0-probe. Guard admin privilege 22,
  target UID/name/ACL/roster, option 0 without 101, EOF without 104,
  and a successful fresh 107.
- **First, protection:** protected. Guard owned bit-23 target; option 0
  must return a protection error without 104/EOF; target 500 succeeds.
- **First, temporary ban:** tempban, immediate-probe. Guard owned zero-ACL
  target; option 1 without 101, one 104 notice, EOF, requester ACK,
  and exact temporary-ban error on fresh 107.
- **Pre:** pre-probe. Fresh 107 remains rejected in the host-time window.
- **Post:** post-probe. Fresh 107 succeeds in the host-time window.

The first epoch records a deadline-checked 35-second socket-free runner wait
after its 18-action readiness and before guard-zero. This reduces the native
same-address request-counter confound; it does not prove a guest clock rate.
The protected case checks a target 500 ACK, then one second of bounded quiet.
Rejected 107 cases claim only their correlated reply; retain raw TCP tails.
The target UID is captured from an actual 301 and checked against a fresh roster
300, not hardcoded. Every 110 is blocked unless admin access, target access,
name and UID match. The successful and rejected 107 vectors are complete fresh
handshakes. No option 2 is repeated here; the retained C56/C62/C68
permanent-branch corpus supplies it.

## Repeatable offline commands and live prerequisites

Generate the plans only after preparing a runtime identity JSON with
`source_a7_sha256` equal to the frozen A7 hash, `fixture_profile: control-only`,
`full_file_baseline: not_exercised`, `emulator_pid`, `emulator_starttime`,
`emulator_sha256`, `emulator_netns_inode`, `owned_working_image`, and
`owned_working_image_inode`. Use a fresh, nonexistent output leaf:

```sh
python3 scripts/native_ban_expiry_cases.py \
  --runtime state/native-ban-expiry-01/runtime.json \
  --output state/native-ban-expiry-01/plans --port 15800
```

For each authorised epoch, supply a fresh receipt JSON containing all
`native_control_readiness.capture_gate` keys: `primary_syn_count`, `ns_routes`,
host/namespace/guest PCAP paths, host/namespace recorder PID and start time,
emulator PID/start/SHA, `emulator_netns` symlink, owned working-image path, plus
`guest_pcap` and its actual emulator FD 16. Also supply
`owned_working_image_inode`, `emulator_netns_inode`, `epoch_started_utc`,
`deadline_utc`, `oracle_lock`, `managed_capture.host`,
`managed_capture.namespace`, and `managed_lock`. Each managed entry records
unit, PID, FD and exact `systemctl show` properties `ActiveState`, `SubState`,
`MainPID`, `RuntimeMaxUSec`, `ActiveEnterTimestampMonotonic`, `KillMode`; the
lock entry additionally records `busy_exit: 1` from a nonblocking independent
flock probe. Capture the real 18-action readiness directory before the first
epoch only. Later epochs must omit `--readiness-dir`; the runner rejects it.
The runner checks live values again and refuses a stale receipt. Root
must review and grant the actual unit, launch, capture and cleanup commands
before use.

The runner must itself share the verified emulator network namespace. Set
`NetworkNamespacePath=/proc/<actual-emulator-pid>/ns/net` on its finite managed
unit. The runner rejects a different namespace before opening any socket.
The equivalent payload context for the command templates is:

```sh
expiry_emulator_pid="$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["emulator_pid"])' \
  state/native-ban-expiry-01/runtime.json)"
sudo nsenter --target "$expiry_emulator_pid" --net -- \
  python3 scripts/native_ban_expiry_control.py --run --phase first \
  --plans state/native-ban-expiry-01/plans \
  --readiness-dir state/native-ban-expiry-01/epoch-first/readiness \
  --capture-receipt state/native-ban-expiry-01/epoch-first/receipt.json \
  --binary /absolute/owned/native-server-data-fork \
  --output state/native-ban-expiry-01/epoch-first/results
sudo nsenter --target "$expiry_emulator_pid" --net -- \
  python3 scripts/native_ban_expiry_control.py --run --phase pre \
  --plans state/native-ban-expiry-01/plans \
  --capture-receipt state/native-ban-expiry-01/epoch-pre/receipt.json \
  --binary /absolute/owned/native-server-data-fork \
  --ban-clock state/native-ban-expiry-01/epoch-first/results/ban-clock.json \
  --output state/native-ban-expiry-01/epoch-pre/results
```

The `post` command uses `--phase post`, the post epoch receipt/output,
and the same first-epoch ban-clock file. These commands are templates: the
binary path and runtime receipt must be checked against the actual prepared
guest. A failed semantic condition is retained in the case report and stops the
epoch; no automatic retry is built in.

The first summary records `full18_control_only`. The pre summary records
`not_exercised_ban_active`; the post summary records
`not_exercised_preserve_first_lookup`. Run a full 18-action control baseline
**after** the intended post-probe 107 succeeds and the two owned accounts
are guarded and removed through the
[staged cleanup](native-ban-expiry-cleanup.md),
as a separately captured operator postflight. The runner does not execute
it. It cannot substitute for
pre-probe readiness or count as the first lookup. No prior Login107 of any
account is permitted in pre/post.

The private checkout lacks canonical `native_ban_control_cases.py` and
`native_control_readiness.py`. Offline tests use
`PYTHONPATH=scripts:/data/leynos/Projects/hotline-protocol-docs/scripts`.
Root must import these dependencies before a fresh export.

## Time and interpretation

The option-1 request send and complete ACK receipt become `T_req` and `T_ack`.
Their host UTC bracket must be at most 20 seconds. The pre probe starts
1600–1700 seconds after `T_req`; the post probe starts 1900–2400 seconds after
`T_ack`. The same emulator PID/start/exe, namespace and working-image inode must
persist. These host bounds do not prove that guest `GetDateTime` advanced at
host rate: a separately retained read-only guest clock witness is required
before claiming an actual 1800-second expiry boundary. Source at 100064d0
performs a lookup-time lazy purge, so fresh-login success cannot distinguish
purge at lookup from earlier background removal. The idle interval is unobserved
by the stopped recorders; a later run must document any other authorised use of
this isolated lab.

## Verification and decision gates

Offline checks: Ruff format/check, `ty check`, eight focused `unittest`
controls, Markdownlint and Nixie. The producer limits the port and source A7
identity; the consumer rejects changed plans, account identity, admin privilege,
wrong notice/EOF, mistimed probes, emulator/image changes and incomplete
reports. Root still owns native lease and live approval, exact capture receipt
assembly, per-epoch zero-primary evidence, guest clock witness, option-2 corpus
linkage, postflight, cleanup, and any GAP-074 status decision. Unexpected UI,
source identity, route, capture, mutex or outcome stops the authorised epoch
without widening the fixture.

B66 allowed 960 production lines for managed-unit, mutex, PID/FD, deadline
and failure-report safeguards; B67 allowed 1040 for readiness ordering.
B68 allows 1120 production and 490 test lines for identity, namespace and
the 35-second order regression (68 formatted test lines, 35 estimated).
No live work is part of this packet.

## Observed first epoch

The [first-epoch witness](native-ban-expiry-first-witness.md) records C76's
wrong-namespace failure and C77's corrected nine cases. Its frozen B68 source
precedes the additional runner-namespace guard above. Expiry remains a later
measurement; this guide is not evidence that the timed probes have run.
