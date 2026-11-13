# Disposable lab transfer stall before the option-two ban fixture

C35's second disposable Mac server never reached its option-two request.
The required A7 baseline failed during the 1,049,073-byte FILP transfer:
`report.json` retains `status=failed`, 21 completed actions, and
`TimeoutError: timed out`. The data connection yielded 98,304 bytes,
SHA-256 `b4c6dc15be0d82de42d3aa7102c1feca67397b978591ac8be2d2c846d6a62e7c`.
The account guard, seed, request 110 and post-ban probe were not run. This
failure cannot be counted as an option-two notice or ban result.

The compact frozen corpus is
`../mothra/evidence/gap-remediation/2026-11-13/native-transfer-stall-01/`.
It retains the immutable and as-run 29-action plans, failed report,
terminal receipt, exact lab namespace/guest/host PCAPs, recorder logs and
C36/C37 analyses. Those lab captures total less than 250 KiB; the primary
server's large guest capture, ROMs and disk images are not included. The
manifest and source-provenance records bind each exported byte to its
original ignored source file. The lab was stopped; the original server and
client FD identities remained intact. Host and namespace records show no
use of the fixed primary-port bridge.

## What the frozen TCP views establish

The report's data socket was `127.0.0.1:60206` to the lab namespace
frontend `127.0.0.1:15731`, corresponding to guest
`10.0.2.2:60206` to `10.0.2.15:5501`. SYN-scoped reassembly found the
same 98,304 application bytes in both packet views and in the failed
runner. There was no packet-stream suffix. The guest's later RST carried
`tcp_disconnect`, a SLiRP diagnostic excluded from application bytes.
This falsifies C36 H1's claim that further data left the guest and was
lost before the namespace client.

TCP headers independently falsified C37 H2's zero-window or unacknowledged
tail claim. The last payload byte, relative 98,304, was ACKed in the lab
namespace by packet 178 with an effective receive window of 79,872 bytes.
Both namespace SYNs negotiated window scale 7. In the guest TCP flow,
packet 190 ACKed the same byte with an unscaled 8,760-byte window; neither
guest SYN advertised scaling. No ACK in either flow advertised zero, and
there was no retransmitted data tail. The guest made no pure window update
in the subsequent idle minute. These observations do not explain why the
native producer stopped, and they do not establish a continuous receiver
state throughout the idle period. C38 did not test H3 or add a cause.

Replay without a VM, ROM, Ghidra project or live socket:

```sh
python3 scripts/verify_native_transfer_stall.py \
  ../mothra/evidence/gap-remediation/2026-11-13/native-transfer-stall-01
python3 -m unittest discover -s scripts -p 'test_native_transfer_stall.py'
```

The verifier checks the failed report and source-plan bounds, PCAP flow
association, identical prefixes, TCP window-scale negotiation, full ACKs,
positive windows, no primary bridge traffic and recorded lab retirement.
It rejects a resealed false-success report, zero-window packet and truncated
guest packet in focused controls. GAP-044 still lacks the option-two notice,
post-ban login result and persistence observations.
