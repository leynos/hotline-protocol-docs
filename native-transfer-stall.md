# Disposable lab transfer stall before the option-two ban fixture

C35's second disposable Mac server never reached its option-two request. The
required A7 baseline failed during the 1,049,073-byte FILP transfer:
`report.json` retains `status=failed`, 21 completed actions, and
`TimeoutError: timed out`. The data connection yielded 98,304 bytes, SHA-256
`b4c6dc15be0d82de42d3aa7102c1feca67397b978591ac8be2d2c846d6a62e7c`. The account
guard, seed, request 110 and post-ban probe were not run. This failure cannot
be counted as an option-two notice or ban result.

The compact frozen corpus is
`../mothra/evidence/gap-remediation/2026-11-13/native-transfer-stall-01/`. It
retains the immutable and as-run 29-action plans, failed report, terminal
receipt, exact lab namespace/guest/host PCAPs, recorder logs and C36/C37
analyses. Those lab captures total less than 250 KiB; the primary server's
large guest capture, ROMs and disk images are not included. The manifest and
source-provenance records bind each exported byte to its original ignored
source file. The lab was stopped; the original server and client FD identities
remained intact. Host and namespace records show no use of the fixed
primary-port bridge.

## What the frozen TCP views establish

The report's data socket was `127.0.0.1:60206` to the lab namespace frontend
`127.0.0.1:15731`, corresponding to guest `10.0.2.2:60206` to `10.0.2.15:5501`.
SYN-scoped reassembly found the same 98,304 application bytes in both packet
views and in the failed runner. There was no packet-stream suffix. The guest's
later RST carried `tcp_disconnect`, a SLiRP diagnostic excluded from
application bytes. This falsifies C36 H1's claim that further data left the
guest and was lost before the namespace client.

TCP headers independently falsified C37 H2's zero-window or unacknowledged tail
claim. The last payload byte, relative 98,304, was ACKed in the lab namespace
by packet 178 with an effective receive window of 79,872 bytes. Both namespace
SYNs negotiated window scale 7. In the guest TCP flow, packet 190 ACKed the
same byte with an unscaled 8,760-byte window; neither guest SYN advertised
scaling. No ACK in either flow advertised zero, and there was no retransmitted
data tail. The guest made no pure window update in the subsequent idle minute.
These observations do not explain why the native producer stopped, and they do
not establish a continuous receiver state throughout the idle period. C38 did
not test H3 or add a cause.

Replay without a VM, ROM, Ghidra project or live socket:

```sh
python3 scripts/verify_native_transfer_stall.py \
  ../mothra/evidence/gap-remediation/2026-11-13/native-transfer-stall-01
python3 -m unittest discover -s scripts -p 'test_native_transfer_stall.py'
```

The verifier checks the failed report and source-plan bounds, PCAP flow
association, identical prefixes, TCP window-scale negotiation, full ACKs,
positive windows, no primary bridge traffic and recorded lab retirement. It
rejects a resealed false-success report, zero-window packet and truncated guest
packet in focused controls. GAP-044 still lacks the option-two notice, post-ban
login result and persistence observations.

## Repeated baseline and a successful comparison

An offline comparison completed on **14 November 2026**. The new portable
corpus,
`../mothra/evidence/gap-remediation/2026-11-14/native-transfer-repeat-01/`,
keeps the original and as-run A7 plans, reports, launch and retirement
receipts, configuration hashes, and guest, namespace and host PCAPs for three
disposable labs. Its verifier selects each download flow by SYN and the
runner's local port and time, then reconstructs application bytes from each
packet view independently:

| Lab | A7 actions | Lab guest bytes | Lab namespace bytes | Outcome   |
| --- | ---------: | --------------: | ------------------: | --------- |
| C32 | 29/29      | 1,049,073       | 1,049,073           | Completed |
| C35 | 21/29      | 98,304          | 98,304              | Timed out |
| C45 | 21/29      | 98,304          | 98,304              | Timed out |

Both C32 packet views have the full flattened file, SHA-256
`7d1f5bf5e2b69b8a18906633ce2ef550876b78252c0639e7d36eb61142787ab8`. C35 and C45
each have the same byte-identical 98,304-byte prefix, SHA-256
`b4c6dc15be0d82de42d3aa7102c1feca67397b978591ac8be2d2c846d6a62e7c`. Each prefix
ends after 72 payload packets; C32's 73rd followed its 72nd by 5.337 ms in the
guest capture. This confirms C32 success in the wire views, not just in a
recorder label. It does not identify why C35 and C45 stopped.

The three runs used the same 29 A7 steps and driver hash, immutable base disk,
ROM, native app, emulator executable, 512 MiB RAM and guest preference file
hash. Their normalized SheepShaver preferences match; display and frontend
ports differ. The original download settings in the plans refer to an earlier
screenshot, with `captured_options=false`, so contemporaneous lab GUI settings
were **not recorded**. No guest worker counter, send queue or callback state
was sampled at the stalled byte. C45 retired its owned lab after the mandatory
A7 failure, before account creation or option two; its cleanup receipt retains
the `/proc` race and unit absence rather than silently treating those
intermediate errors as clean exits. Neither failure is evidence for a native
transfer-size limit or permanent-ban behaviour.

The exact emulator binary has DWARF and symbols for guest RAM and PPC CPU
state, but its build disables the monitor and the PPC flight recorder is not
started automatically. A future test would need separately approved,
scheduling-aware observation of the download worker, queued bytes, `OTSnd`
acceptance and callback delivery at the 98,304-byte boundary. No live
attachment or new lab run was performed for this comparison.

Replay the exported corpus without a VM or live socket:

```sh
python3 scripts/verify_native_transfer_repeat.py \
  ../mothra/evidence/gap-remediation/2026-11-14/native-transfer-repeat-01
python3 -m unittest discover -s scripts -p 'test_native_transfer_repeat.py'
```

## One focus event on the repeated prefix

C50 ran the same 29-action A7 once more in an isolated disposable lab. Both
packet views again stopped at the 98,304-byte prefix. After at least five
seconds without further bytes, one click activated the server Log window; the
title changed from inactive to active, but neither stream advanced in the
following ten seconds. The stock A7 then timed out after 21 actions. The
one-event resume claim is contradicted under this recorded state. The cause of
the transfer stall remains unknown; no option-two ban was attempted. The
offline replay and focus-delivery limits are in
[native-ui-focus-witness.md](native-ui-focus-witness.md).
