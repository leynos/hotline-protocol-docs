# C36 H1 falsification: no extra guest data

Inputs are immutable C35 `a7-capture/report.json` and C34 `lab-namespace.pcap`
and `lab-guest.pcap`. `analyze_h1.py` uses `pcap_tcp.read_packets`, `lifetime`
and `stream`; `analysis.json` records SHA-256 of each input. No runtime or
protocol process was started. The original failed report remains `failed`,
21 actions, `TimeoutError: timed out` at the complete 1,049,073-byte FILP read.

The report's data connection is client `127.0.0.1:60206` to lab frontend
`127.0.0.1:15731`, connected at the report's action 19. The namespace SYN
lifetime has 152 TCP packets. Its server-to-client application stream is
98,304 bytes, SHA-256
`b4c6dc15be0d82de42d3aa7102c1feca67397b978591ac8be2d2c846d6a62e7c`.
It exactly equals the recorder's 98,304 bytes. The last server payload is
packet 177 at 23:06:32.848662 UTC. The lifetime ends with client and server
FIN packets 180/183 at about 23:07:32.52 UTC.

The corresponding guest SYN lifetime is `10.0.2.2:60206` to
`10.0.2.15:5501`, 151 TCP packets. Its server-to-client application stream
is the same 98,304 bytes and SHA-256, with **zero suffix** beyond the
recorder. The last server payload is packet 184 at 23:06:32.817578 UTC. The
client FIN is packet 192; the guest's subsequent RST packet 195 contains the
hex diagnostic `7463705f646973636f6e6e656374` (`tcp_disconnect`). The
reassembler excludes RST diagnostic bytes from application data. Both views
have 72 server payload packets, 98,304 raw payload bytes and no overlapping
retransmitted payload bytes. The raw PCAPs preserve all retransmissions and
terminal packets independently of the derived stream.

**H1 is falsified.** The claim that additional file data left the native
guest and failed between guest and namespace recorder predicts a guest
application suffix. There is none in the exact SYN-scoped flow, and the
namespace and recorder match it byte for byte. This result says nothing
about why the guest stopped after 98,304 bytes; it does not test receive
window state, native worker scheduling, or a protocol size limit. H2/H3
remain for the planner to grant separately. No option-2 ban request ran.

Replay from canonical Mothra:

```sh
python3 state/native-sessions/native-banlab-c36/analyze_h1.py
cd state/native-sessions/native-banlab-c36 && sha256sum --quiet -c SHA256SUMS
```
