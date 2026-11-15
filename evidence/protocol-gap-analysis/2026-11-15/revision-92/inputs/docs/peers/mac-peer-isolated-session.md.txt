# Isolated Classic client: one finite 1.9 session

This witness covers one controlled login by the archived “Hotline Client 1.9.2
Classic” candidate against the native Hotline Server 1.9 guest. Its embedded
`vers` says 1.9.1.0, and vendor authenticity remains unproved. It is a measured
client session, not a general client profile or release-policy rule.

The client ran in a separate loopback-only network namespace. Fixed AF_UNIX
bridges led to host loopback control port 15500 and data port 15501; a third
bridge reached the chosen X display. Retained B20 identities distinguish this
actual emulator boot from the earlier synthetic bridge tests. Four final PCAPs
and the identity receipts are in the mothra
[`mac-peer-isolated-session-01` corpus][corpus]. The verifier checks the raw
SYN-scoped control and data streams across host, client guest and server guest.

- Client handshake was `54525450484f544c00010002`. Login 107 id 1 received
  type 0/status 0, field 161 `0000`. The known 242-byte server agreement 109
  matched the earlier controlled fixture byte-for-byte before acceptance.
- Client 121 id 2 named `unnamed`; 300 id 3 received a one-user roster. The
  record's observed UID was 14, a session value rather than a fixed protocol
  constant. Server 354 remained opaque. Server 122 advertised the controlled
  banner URL. Client 212 id 4 received status 0 and a four-byte transfer
  reference `002e037f`.
- An automatic 15501 connection sent a 16-byte `HTXF` header carrying that
  same reference and received 58 bytes beginning `GIF89a`. The guest capture
  then showed a client R packet while the host flow ended with FIN. The client
  UI still said **Loading banner image**; receipt of the bytes does not prove
  image decoding or display.
- The guest sent 15 DNS A requests for `www.developingnetwork.com` to 10.0.2.3.
  Each was quoted by a matching ICMP network-unreachable response. There was no
  public-IP guest TCP flow in this capture. The host recorder restricted to the
  earlier ad IP and two diagnostic IPs retained a header-only PCAP with zero
  matching packet records. This is finite containment evidence for the observed
  path, not proof of all possible egress paths.
- From the last data-flow packet to the quiet-end snapshot, 147.229 seconds
  elapsed; 139.908 seconds elapsed after the final pre-disconnect DNS error. No
  new numbered control request, including kind 500, appeared in that interval.
  This does not establish a universal timer interval or purpose. One manual
  connection was disconnected and the client app quit. Both guests remained
  live with no owned established 15500/15501 socket at handoff.

Run the portable offline checks from the mothra root:

```sh
sha256sum --quiet -c evidence/gap-remediation/2026-11-13/mac-peer-isolated-session-01/SHA256SUMS
python3 ../hotline-protocol-docs/scripts/verify_mac_peer_isolated_session.py \
  evidence/gap-remediation/2026-11-13/mac-peer-isolated-session-01
python3 -m unittest discover -s ../hotline-protocol-docs/scripts \
  -p 'test_mac_peer_isolated_session.py'
```

The verifier checks byte parity, dynamic reference consistency, DNS/ICMP
pairing, the recorded observation times and namespace receipts. UI state and
lack of manual actions are operator observations linked to the retained
screenshots and action timestamps. The old B13 public HTTP capture and its
partial-session verifier remain separate evidence; this isolated run does not
reinterpret that earlier safety stop.

[corpus]: ../../evidence/gap-remediation/2026-11-13/mac-peer-isolated-session-01/
