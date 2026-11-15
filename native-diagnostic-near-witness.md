# Native 1.9 diagnostic near-boundary observation

The [A12 corpus][a12] retains one **failed capture** against Hotline Server 1.9
and its independently completed restoration postflight. The capture did record
two successful transaction 303 replies before it failed:

| Point                          | Native field 101 | Complete active rows | Complete waiting rows |
| ------------------------------ | ---------------: | -------------------: | --------------------: |
| Eight active / eight waiting   | 763 bytes        | 8                    | 8                     |
| Eight active / sixteen waiting | **995 bytes**    | 8                    | 16                    |

The exact raw field bytes are in `near/report.json`. All 24 transaction 202
replies have distinct four-byte references; the sixteen waiting replies carry
field 116 queue positions 1 through 16. The five native text sections are
complete at both points, with folder and upload sections empty. The 995-byte
observation lies **29 bytes below** the handler's `0x400` destination size. It
is a below-boundary example, with no evidence here of clipping at or beyond the
cap. It does not decide whether mxd must reproduce the native text exactly.

The subsequent cancellation sequence was incomplete. The recorder received
successful 214 replies for IDs 215 through 208. It sent ID 207, then reported
`EOFError: EOF before 20 requested bytes` at action 94. Its capture status is
**failed**; later cancellations and the planned idle 303 ID 240 were never
reached. The guest PCAP contains a 22-byte successful ACK for 207 that the host
PCAP and recorder do not contain. The host control stream has 1514 client and
3617 server bytes; the guest stream has the same 1514 client bytes and 3639
server bytes. The guest-only 22-byte tail decodes to reply ID 207, type 0,
error 0. Guest-side client RST packets and host-side FIN packets are retained.
The cause of the failed delivery is unknown. The guest ACK is not a
host-confirmed cancellation.

The eight data sockets were deliberately unread by the recorder. Each sent its
saved-reference 16-byte HTXF request. In both packet views, the received bytes
are prefixes of the A7 verified full FILP stream; the guest prefix extends the
host prefix. Their distinct unread tails and terminal packets are individually
recorded in [packet verification][partial]. These are transfer-stream prefixes,
not full transfers or DATA-fork byte counts.

After the failure, the native Statistics window showed zero connections,
downloads, uploads and waiting downloads. General Options were saved and
reopened at the original **100 global / 10 per client / 5 per IP**; screenshots
record both the temporary 8/8/5 and restored settings. A fresh postflight
capture with its own ready-before-connect host PCAP matched A7's exact two
accounts, 41 root Files entries, fixture 206 metadata and idle 303 with zero
active/waiting rows. This postflight does not retroactively complete the failed
cancellation capture.

## Replay

From `mothra`, the read-only checker verifies both capture reports, the
preparation/execution plan's operator-only difference, the 303 rows and bytes,
request prefix, saved references, guest-only ACK, packet lifetimes, unread FILP
prefixes and restored A7 postflight:

```sh
a12=evidence/gap-remediation/2026-11-13/native-diagnostic-near-01
sha256sum -c "$a12/SHA256SUMS"
python3 ../hotline-protocol-docs/scripts/protocol_capture.py verify "$a12/near"
python3 ../hotline-protocol-docs/scripts/protocol_capture.py verify "$a12/postflight"
python3 "$a12/verify_partial.py" > /tmp/a12-partial-replay.json
```

The first capture verification reports `failed; 94 actions` as expected. The
partial checker reports `positive-partial-observation; capture-failed` and must
not be read as a fully verified near plan. The [preparation][prep] records the
fixed proposal and its original 24-reference bound. The
[later formatter trace](diagnostic-formatting-trace.md) establishes the
source-derived cap and descriptive baseline text rule; it does not turn this
partial observation into a passed capture or an at-cap fixture.

[a12]: ../mothra/evidence/gap-remediation/2026-11-13/native-diagnostic-near-01/manifest.json
[partial]: ../mothra/evidence/gap-remediation/2026-11-13/native-diagnostic-near-01/verification-partial.json
[prep]: native-diagnostic-near-preparation.md
