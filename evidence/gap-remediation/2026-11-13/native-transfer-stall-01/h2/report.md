# C37 H2 falsification: acknowledged data and positive receive windows

This checks only H2 in `docs/debugging/debugging-plan-2026-11-13-lab-transfer-stall.md`:
whether a zero advertised receiver window or unacknowledged server tail blocked
additional output. `analyze_h2.py` reads the immutable C35 failed report and
C34 namespace/guest PCAPs, selects the report's exact SYN-scoped data flow,
parses TCP options and raw window/ACK headers, and excludes RST diagnostic
payload from application bytes. `analysis.json` pins input SHA-256 values.
No guest, socket, service, Ghidra or source was changed.

| View | Client → server | SYN window scale | Final payload ACK | Last positive window |
| --- | --- | --- | --- | --- |
| Namespace Linux TCP | 127.0.0.1:60206 → 127.0.0.1:15731 | 7 from both peers | Packet 178 ACKed relative byte 98,304 at 23:06:32.848734 UTC | Raw 624 × 128 = 79,872 bytes, packet 184 at 23:07:32.527499 UTC |
| Guest SLiRP/native TCP | 10.0.2.2:60206 → 10.0.2.15:5501 | None from either peer | Packet 190 ACKed relative byte 98,304 at 23:06:32.848696 UTC | Raw/effective 8,760 bytes, packet 192 at 23:07:32.512912 UTC |

The last server application payload in both views ends at relative byte
98,304. Both TCP flows therefore acknowledge **all** observed file bytes.
No client ACK advertised a zero window. Each view had 72 server payload
packets, 98,304 raw payload bytes, and no overlapping retransmitted data.
The guest's last pre-close ACK was packet 190 with positive 8,760-byte
window. It sent no later pure window update during the roughly 60-second
idle period; its next relevant packet was a client FIN at packet 192, still
advertising 8,760 bytes. The namespace client's pure ACK at packet 184,
after its FIN/server FIN exchange, advertised 79,872 bytes. The guest server
then emitted a RST packet 195 carrying `tcp_disconnect`, which is a SLiRP
diagnostic, not extra file data. The namespace end used FIN packets 180/183.

**H2 is falsified as stated.** A zero receive window or unacknowledged
98,304-byte tail is absent at the stopping point. This does not establish
why the native producer stopped, nor does the lack of guest window updates
prove a continuous receiver state throughout the idle period. The Linux
namespace and guest TCP states are distinct and were not merged. H3 and any
producer/scheduling hypothesis remain outside this packet. The A7 full
transfer still failed, and no option-2 ban request was run.

Replay from canonical Mothra:

```sh
python3 state/native-sessions/native-banlab-c37/analyze_h2.py
cd state/native-sessions/native-banlab-c37 && sha256sum --quiet -c SHA256SUMS
```
