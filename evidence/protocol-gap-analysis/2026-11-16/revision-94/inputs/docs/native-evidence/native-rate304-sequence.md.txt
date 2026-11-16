# Native 1.9 rate304 sequence: measured prefix, failed final control

The frozen [C118/C119 corpus][corpus] records one disposable Mac OS 9 server
run on 14 November 2026. Its coordinator report is **failed**, with
`ValueError: Reply is not direct success`, `timing={}`, and
`phase_receipts={}`. The separate 18-action control readiness passed. This page
describes only the prefix independently reconstructed from the failed report
and paired packet captures. The independent [A114 audit][audit] reached the
same bounded observations.

## Identity and capture boundary

The run used the pinned Hotline Server 1.9 DATA fork (`ad7040…`), emulator
executable (`9c9430…`), immutable base (`e5cbba…`) and ROM (`18da89…`). The
owned working image had inode 1687370702; actual emulator PID 3125063/start
tick 8100939 occupied a private loopback-only namespace. The fixed epoch was
11:38:21.652926–11:50:21.652926 UTC. No full A7 file-transfer baseline was
exercised in this lab.

Boot used staged identity checks: disk phase confirmed the process and FD6,
then capture phase confirmed the **same** process and writable FD16 with a
complete classic PCAP 2.4 Ethernet header. The first completion attempt stopped
before contact: a nested `sudo` caused Git's dubious-ownership check to fail
while recording source HEAD. A root-approved continuation retained that
failure, used process-local `safe.directory`, verified the same capture
identity, and completed source freezing and readiness. The post-event
single-`sudo`/nested-`sudo` reproduction is retained separately; it is not an
initial-run observation. No global Git configuration was changed.

Both packet views contain exactly five SYN lifetimes. Every reassembled byte in
both directions matches its recorder stream; there are no unmatched application
tails. Namespace TCP has 206 packets, guest TCP 227. The host primary-port
recorder captured zero SYN packets; terminal tcpdump logs report zero kernel
drops for both managed recorders. The guest emulator PCAP has no separate drop
counter.

| Connection         | Client port | Sent bytes | Received bytes |
| ------------------ | ----------: | ---------: | -------------: |
| Separate readiness | 36960       | 231        | 2,759          |
| Observer           | 59848       | 526        | 5,897          |
| Paced subject      | 34152       | 1,459      | 2,495          |
| Burst subject      | 38334       | 1,437      | 2,418          |
| Fresh ban probe    | 38344       | 91         | 76             |

For the burst lifetime, the guest PCAP ends with a server RST carrying the
14-byte diagnostic `tcp_disconnect`; the namespace relay presents FIN to its
client. That diagnostic is outside the reassembled Hotline stream. A local
socket EOF label is not a guest FIN claim.

## Observed request and notification sequence

The observer first saw dynamic paced UID 3 and burst UID 4. The paced subject
sent 26 ordered `304` icon values 2–27, each with a numbered `500` barrier (IDs
2000–2025). Subject and observer each received one `301` per icon with matching
UID, name `fixture-low`, and status `0x0020`; all 26 barrier ACKs succeeded.
First `304` to last required notification/ACK arrival took 1.238364 host
seconds.

After the last required arrival, the paced subject sent no request for a
measured **70.103186 host seconds**. Fourteen observer idle `500` calls ran
during that interval. Paced icon 28 then yielded a `301` on subject and
observer, plus ACK 2026.

The offline verifier bounds each action timestamp between its own send event
and the next global event. It maps frame bytes to cumulative receive offsets,
including the eight-byte TRTP reply, and bounds frame arrival between the
completing receive event and the next global event. These causal checks allow
separate runner clock calls; the 70.103186-second bracket remains the recorded
value, not a reconstructed native clock.

The burst subject sent 26 ordered `304` icon values 2–27 with `500` IDs
4000–4025. Both recipients received the matching 26 `301`s and all barriers
succeeded within a 0.231387-second host bracket. Its 27th `304` requested icon
28 without a following `500`. No UID 4/icon 28 notification or ACK 4026
appears; the burst connection then closed as described above. A fresh valid
Login 107 received error 1 and field 100
`You are temporarily banned on this server.`

Retained observer controls 348, 200, 206, and 300 (IDs 6000–6003) returned
success. The 348 reply had two accounts; 200 had 41 Files records. **Final 303
ID 6004 had no target UID field.** It received error 1 with field 100
`Cannot get info for the specified client because it does not exist.` The
runner failed at this expected-success assertion. This invalid final fixture
does not erase the earlier observed 304/500/301/ban prefix, but it prevents a
completed-case claim and leaves the final idle diagnostic unanswered.

The coordinator did not calibrate the guest clock. These are host monotonic
brackets and packet observations, not a direct measurement of the native `>60`
predicate's interval or counter origin. The temporary ban's expiry,
persistence, and later login behaviour were not tested here. This run does not
close GAP-045 by itself.

## Stopped state and replay

The owned app quit. The actual emulator was then terminated with SIGTERM, so
this was **forced retirement after app Quit**, not an orderly OS shutdown. All
owned units and private ports stopped before the fixed deadline; original
primary/client PID ticks stayed unchanged. Root FD scans found no holder of the
owned base, working image, or ROM. Stopped HFS catalogues show only the
original admin and fixture-low active UserData, unchanged 734-byte fork hashes,
unchanged 175-byte Prefs and server DATA/RSRC hashes, an empty MessageBoard
DATA fork, and no allocated `Banned` path. No stopped-disk durability
conclusion extends beyond these named reads.

From a committed adjacent export containing `mothra` and
`hotline-protocol-docs`, run:

```sh
cd hotline-protocol-docs
python3 scripts/verify_native_rate304_sequence.py
python3 -m unittest discover -s scripts -p test_native_rate304_sequence.py
```

The default verifier uses only frozen corpus files. `--corpus PATH` selects a
copied corpus for fault checks. It checks the root-relative SHA inventory,
exact approved 35-module closure and three helpers, case source/plan, staged
identity, original failed report, event/frame reconstruction, notification and
ACK sequence, five paired packet streams and tails, capture counters, and
stopped named forks. It never imports a live server project or starts a VM. Its
`PASS` means this **failed-run witness** is internally and independently
replayable; it does not reclassify C119 as a completed experiment.

[corpus]: ../../evidence/gap-remediation/2026-11-14/native-rate304-sequence-01/manifest.json
[audit]: ../../evidence/gap-remediation/2026-11-14/native-rate304-sequence-01/reviews/a114/audit.md.txt
