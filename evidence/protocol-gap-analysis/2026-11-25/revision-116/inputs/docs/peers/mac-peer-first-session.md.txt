# First Classic Mac peer session: finite wire observations

The retained capture records one manual connection from an HFS-installed
[Classic Hotline client candidate](../glossary.md#classic-client) to the
controlled local [Hotline Server 1.9](../glossary.md#hotline-server-19) fixture
on 2026-11-13. The source archive was labelled “Hotline Client 1.9.2 for OSX
and OS9”, while its `vers` resources say 1.9.1.0. The data and resource forks
survived a Finder round trip unchanged. Neither the archive label nor the
session proves vendor authenticity or a precise client release identity.

This document belongs to the [peer implementations](README.md) set; the
[glossary](../glossary.md) defines the terms it uses.

The replay stopped for safety after the client made automatic HTTP requests to
a public IP. This is a **partial session**, not the planned 130-second
local-only quiet test. The raw host, client-guest, and server-guest PCAPs,
verification output, copied B12 staging report, and staging manifest are in
`evidence/gap-remediation/2026-11-13/mac-peer-first-session-01/`. Run:

```sh
python3 scripts/verify_mac_peer_first_session.py evidence/gap-remediation/2026-11-13/mac-peer-first-session-01
```

## Observed control exchange

The client connected once to guest `10.0.2.2:15500` at 17:48:04 UTC. The guest
source port 49152 mapped to host loopback source port 59232; the same NAT
source port appeared on the server guest at destination port 5500. All three
SYN-scoped capture views contain identical 150-byte client and 514-byte server
control streams. The 23-packet host PCAP contains the complete control
handshake through FIN, with no second host SYN.

| Direction | Complete captured frame sequence                                                                                                                                                                                                                                                                                                                                    |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Client    | `TRTPHOTL00010002`; 107/id1 login with 105, 106, 160=`00be`; 121/id2 with 102=`unnamed`, 104=`019e`, 113=`0000`; 300/id3 empty roster request; 212/id4 empty                                                                                                                                                                                                        |
| Server    | `TRTP00000000`; success reply/id1 with 160=`00be`, 161=`0000`; 109/id1 field101=exact controlled 242-byte agreement; success reply/id2; 354/id2 field110=`fff3cfefff800000`; 122/id3 fields152=`GIFf`, 153=`https://example.invalid/mothra-banner`; success reply/id3 field300=`0007019e00120007756e6e616d6564`; success reply/id4 fields108=`003a`, 107=`00038325` |

_Table 1: Complete captured frame sequence of the client and server control
directions, with their frames by ID._

The first agreement click only woke the screen saver. At 17:49:48 UTC the
operator accepted the UI text after matching it to the 109 wire bytes. The
client then showed Connected and a roster containing `unnamed`. The 354 bitmap
remains opaque. The 212 acknowledgement's field107 reference equals the
`00038325` reference in a separate observed HTXF request; this is an identity
observation, not a general transfer rule.

Both guest PCAPs contain that data connection: client guest `10.0.2.15:49155` to
`10.0.2.2:15501`, mapped to server guest `10.0.2.2:36936` to `10.0.2.15:5501`.
Their complete 16-byte HTXF request streams and 58-byte `GIF89a` response
streams match. The host PCAP filter covered only port 15500 and cannot
establish host-side data-stream parity.

## Measured limits and safety stop

The client guest PCAP contains five distinct, reassembled HTTP request/response
lifetimes to `207.148.248.143:80`. Each sent
`GET /zipads/zip-hot.asp?c=82&h=69` with `Host: www.developingnetwork.com` and
received `HTTP/1.1 404 Not Found`. The first GET was at 17:48:07, before the
agreement was accepted; four more occurred at 17:49:49–51. Cancelling the
first-run wizard did not prevent these automatic requests. The capture proves
the exchange, not the current operator or purpose of that endpoint.

The last numbered client control request was at 17:49:49.111363; the client FIN
at 17:52:13.506772 gives 144.395409 seconds of measured control-wire silence.
The SYN-to-FIN control session lasted 248.777271 seconds. No type 500 appears
in that finite captured stream. The safety stop means these observations do not
establish an automatic-500 schedule, a valid local-only idle test, or a broader
peer tolerance/fallback policy. The client was disconnected and quit without a
retry. Further client replay requires a separately tested egress boundary.
