# Native 1.9 diagnostic density with existing downloads

The [A9 corpus][a9] records one fixed density capture against the
[A7-verified existing file][a7], `mothra-race-fixture`, and a separate
restoration postflight. The earlier [one-active/one-waiting witness][a8]
provided the native row grammar. This packet used the same Hotline Server 1.9
process and application DATA SHA-256
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`.

## Fixed 303 observations

General Options was saved and reopened at eight simultaneous downloads
**globally and per client**, with five connections per IP unchanged. One
administrator connection resolved its live UID from a one-row 300 roster. It
requested the known file eight times and attached eight data sockets, leaving
their inbound data unread by the recorder. It requested eight more references
without attachment. The first eight 202 replies were admitted; the next eight
had distinct four-byte references and positive initial waiting positions 116 =
1 through 8.

| Fixed point                            | Native 303 field 101 | Complete file-download rows | Complete waiting rows |
| -------------------------------------- | -------------------: | --------------------------: | --------------------: |
| 4 active / 0 waiting                   | 417 bytes            | 4                           | 0                     |
| 8 active / 4 waiting                   | 647 bytes            | 8                           | 4                     |
| 8 active / 8 waiting                   | 763 bytes            | 8                           | 8                     |
| After exact-reference 214 cancellation | 303 bytes            | 0                           | 0                     |

All four replies were successful 303 responses with field 102 naming the same
current user. Folder-download, file-upload and folder-upload sections were
empty. Each 214 request targeted its saved reference and received a successful
ACK. The native text of the final idle response matches the prior idle shape;
the [capture reports][a9] retain every raw field byte.

The maximum measured field 101 is **763 bytes, 261 below** the handler's
`0x400` destination bound. This finite 8/8 fixture did not reach that bound. It
does not establish a truncation rule or a near-1,024-byte native example. The
exact wording and progress percentages remain descriptive native output; The
[later formatter trace](../protocol/diagnostic-formatting-trace.md) gives the
source-derived cap and baseline text classification; an mxd promise of exact
presentation parity remains a separate decision.

## Packet views and restoration

The control stream is byte-for-byte identical in recorder, host and guest
views: 1,420 client bytes and 3,839 server bytes. Each of the eight data
sockets sent the exact 16-byte HTXF request with its saved reference. Recorder
read **zero** inbound data bytes from those sockets. The host PCAP nonetheless
observed 81,920–120,220 bytes per data socket and the guest PCAP 81,920–491,520
bytes. For every socket, host bytes are a prefix of guest bytes, and guest
bytes a prefix of A7's verified 1,049,073-byte ordinary FILP stream. The exact
per-socket lengths, SHA-256 hashes of unread tails, terminal packets and source
ports are in [verification-packets.json][packets]. These are incomplete
transfer-stream prefixes, including FILP framing and metadata where present;
they do not prove complete delivery or DATA-fork byte counts. Raw guest RST
diagnostics `tcp_disconnect` and `No TCP` are retained separately from
application bytes.

The test saved and reopened the original General Options **100 global / 10 per
client / 5 per IP** after the density case. The postflight capture matched A7's
exact two accounts, all 41 root Files entries, complete-file 206 metadata and
idle same-connection 303. Its host and guest control streams both match the
recorder. The live server stayed on the same PID and executable hash; no
restart or durability observation was made.

## Replay

From `mothra`, the committed evidence can be checked without contacting the
native server:

```sh
a9=evidence/gap-remediation/2026-11-13/native-diagnostic-density-01
sha256sum -c "$a9/SHA256SUMS"
python3 ../hotline-protocol-docs/scripts/protocol_capture.py verify "$a9/density"
python3 ../hotline-protocol-docs/scripts/protocol_capture.py verify "$a9/postflight"
python3 "$a9/verify_density.py"
```

[a9]: ../../evidence/gap-remediation/2026-11-13/native-diagnostic-density-01/manifest.json
[a7]: ../../evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/manifest.json
[a8]: native-diagnostic-existing-witness.md
[packets]: ../../evidence/gap-remediation/2026-11-13/native-diagnostic-density-01/verification-packets.json
