# Native temporary-ban expiry fixture preparation

This packet prepares a **future, separately authorised** GAP-074 control-only
run. It does not launch a guest, contact the native server, adjust a clock, or
claim temporary-ban expiry. The original full-file A7 baseline is explicitly
`not_exercised` in these plans.

## Scope and owned identities

- Use a new disposable runtime at `state/mac-runtime/native-ban-expiry-01`, a
  new display at `state/mac-displays/native-ban-expiry-01`, and ports
  15800–15803. The live operator must prove the stopped base, ROM, new
  working-image inode, actual emulator PID/start time/executable SHA, FD 6/16,
  namespace, loopback-only routes, and zero primary contact. Never copy a live
  working image.
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
- The control-only 18-action readiness capture must pass in **each** epoch,
  then run `first`, `pre`, or `post`. The runner rechecks actual managed
  service properties, PID/start, writable FD/inode, lock FD/inode and
  independent lock contention, native binary SHA, guest FD 16, and the frozen
  plan hash. The runner requires root only to inspect `/proc`; no privilege
  adjustment occurs inside the guest.

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
flock probe. Capture the real 18-action readiness directory before invoking each
epoch. The runner checks live values again and refuses a stale receipt. Root
must review and grant the actual unit, launch, capture and cleanup commands
before use.

```sh
sudo python3 scripts/native_ban_expiry_control.py --run --phase first \
  --plans state/native-ban-expiry-01/plans \
  --readiness-dir state/native-ban-expiry-01/epoch-first/readiness \
  --capture-receipt state/native-ban-expiry-01/epoch-first/receipt.json \
  --binary /absolute/owned/native-server-data-fork \
  --output state/native-ban-expiry-01/epoch-first/results
sudo python3 scripts/native_ban_expiry_control.py --run --phase pre \
  --plans state/native-ban-expiry-01/plans \
  --readiness-dir state/native-ban-expiry-01/epoch-pre/readiness \
  --capture-receipt state/native-ban-expiry-01/epoch-pre/receipt.json \
  --binary /absolute/owned/native-server-data-fork \
  --ban-clock state/native-ban-expiry-01/epoch-first/results/ban-clock.json \
  --output state/native-ban-expiry-01/epoch-pre/results
```

The `post` command uses `--phase post`, the post epoch receipt/readiness/output,
and the same first-epoch ban-clock file. These commands are templates: the
binary path and runtime receipt must be checked against the actual prepared
guest. A failed semantic condition is retained in the case report and stops the
epoch; no automatic retry is built in.

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

Offline checks: Ruff format/check, `ty check`, the five focused `unittest`
controls, Markdownlint and Nixie. The producer limits the port and source A7
identity; the consumer rejects changed plans, account identity, admin privilege,
wrong notice/EOF, mistimed probes, emulator/image changes and incomplete
reports. Root still owns native lease and live approval, exact capture receipt
assembly, per-epoch zero-primary evidence, guest clock witness, option-2 corpus
linkage, postflight, cleanup, and any GAP-074 status decision. Unexpected UI,
source identity, route, capture, mutex or outcome stops the authorised epoch
without widening the fixture.

Production allowance increased from 900 to 960 physical lines for fresh
managed-unit, mutex, PID/FD checks, deadline-clamped reads and preservation of
semantic failures. No live work is part of B66.
