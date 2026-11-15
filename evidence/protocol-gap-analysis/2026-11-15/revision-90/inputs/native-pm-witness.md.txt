# Native 1.9 private-message 104 witness (A29)

The [A29 corpus][corpus] contains one seven-request 108 sequence between two
full A7 readbacks. It uses only two existing `admin` sessions, named
`PM-Main-A26` and `PM-Peer-A26`, with current-connection UIDs `002b` and
`002c`. The source is [handler 1000f4e0][handler]; the
[producer matrix](native-104-variants.md) keeps other type-104 origins
separate. This capture completed 151 actions with no retry, extra PM request,
account/file/config change or native restart.

| 108 case; identifier        | Session flags (main/peer)   | Recorded 104; raw action | Exact field set and identity                                                                                                                                                                   |
| --------------------------- | --------------------------- | ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Direct quoted; 60           | 0/0                         | Peer; 33                 | 103=`002b`, 102=`PM-Main-A26`, 113=`0001`, 101=`pm-a26-direct`, 214=`quote-a26`.                                                                                                               |
| Recipient refuses; 61       | 0/1                         | Main; 49                 | 103=`002c`, 102=`PM-Peer-A26`, 113=`0002`, 101=`PM-Peer-A26 does not accept private messages.` Peer receives no 104.                                                                           |
| Automatic plus original; 62 | 0/4, peer 215=`pm-a26-auto` | Main; 65 and peer; 66    | Main gets recipient identity 103=`002c`/102=`PM-Peer-A26`, 113=`0004`, 101=`pm-a26-auto`; peer gets original sender identity 103=`002b`/102=`PM-Main-A26`, 113=`0001`, 101=`pm-a26-with-auto`. |
| Sender refuses; 63          | 1/1                         | None                     | Both feedback and original delivery suppressed in this state; both 500/quiet barriers passed.                                                                                                  |
| Option 2; 64                | 0/0                         | Peer; 111                | Sender identity 103=`002b`/102=`PM-Main-A26`, 113=`0002`, 101=`PM-Main-A26 does not accept private messages.`                                                                                  |
| Option 3; 65                | 0/0                         | Main; 120                | Sender identity 103=`002c`/102=`PM-Peer-A26`, 113=`0003`, 101=`PM-Peer-A26 does not accept private chats.`                                                                                     |
| Empty ordinary text; 66     | 0/0                         | None                     | Empty 101 request receives empty success ACK but no 104; both quiet barriers passed.                                                                                                           |

Every 108 received an empty success ACK. The retained main TCP byte stream
places the id-61 ACK before its refusal feedback and the id-62 ACK before its
automatic feedback. This is **same-flow** order. Recorder reads on separate
sockets and static send-call order do not prove universal ACK-before-recipient
delivery or client render timing. The only quoted 214 in this matrix is the
direct original; it is absent from generated feedback. The six 104 frames above
are the entire observed set; option 2/3 generated text is measured as bytes,
not a general locale rule.

The preflight and postflight both executed the exact pinned 29-action A7 plan
(SHA-256 `5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e`).
Stable 348/200/206 replies matched A7 and each other: two accounts, 41 root
Files descriptors, and the same fixture metadata. Each read back a complete
1,049,073-byte FILP transfer whose DATA SHA-256 is
`fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83` and MACR
SHA-256 is `40a42dbcf2d879e22d9a5a9acf46bf15fa9fe3a77837f757a990e514436801e5`.
Same-connection 300/303 idle controls passed with fresh UIDs `002a` then
`002d`. Both PM sessions restored their 304 name/icon/options and closed before
postflight; no server option was changed.

The direct SYSTEM loopback recorder was ready before the first socket and
stopped with SIGINT: 3,382 packets captured, zero kernel drops. Saved
cumulative host/guest PCAP snapshots identify every SYN lifetime and
reconstruct all recorded application prefixes. The main PM connection has one
unconsumed 28-byte 302 departure for UID `002c` in both packet views; it is
retained as an unread tail, not silently included in the Recorder response.
Guest download connections have terminal RST diagnostics outside application
data while host views have FIN. Packet direction, tails and terminal flags are
in `packet-reconciliation.json`; none is used as an extra 104 message.

From an adjacent repository export, run:

```sh
(cd evidence/gap-remediation/2026-11-13/native-pm-01 && \
  sha256sum --quiet -c SHA256SUMS)
python3 ../hotline-protocol-docs/scripts/verify_native_pm_packet.py \
  evidence/gap-remediation/2026-11-13/native-pm-01
python3 -m unittest discover -s ../hotline-protocol-docs/scripts \
  -p 'test_native_pm_packet.py'
```

The verifier requires only the exported corpus and protocol scripts; it does
not connect to the guest, server or mxd. It checks three Recorder reports,
exact 104 fields, same-flow order, full fork hashes, host/guest packet streams
and their untrimmed tails. This evidence advances GAP-044 for routed PM and
feedback variants. Native 110 ban-option notice fixtures still require an
isolated source-address design because those operations ban the address used by
the shared oracle. Origin can remain ambiguous for identical 104 field sets; no
universal variant discriminator is asserted.

[corpus]: evidence/gap-remediation/2026-11-13/native-pm-01/manifest.json
[handler]: evidence/hotline-server-1.9/queries/D-1000f4e0.c
