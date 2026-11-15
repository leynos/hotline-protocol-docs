# C48 preparation: one GUI focus event after a frozen A7 plateau

Prepared 2026-11-14 UTC. This is a **proposal**, not authority to boot, run A7,
or click. Lab runtime: `state/mac-runtime/native-eventlab-one-01`; source:
`state/mac-runtime/hotline22-recovery/{base.dsk,rom}`. `preflight.json`,
`prepare-run.json`, and `postflight.json` bind source inode/mode/mtime/hash,
new owned-copy hashes, helper hash and available space. The source base and
ROM were hashed before and after copying; no live working image was copied.

Pinned identity: base SHA `e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910`;
ROM `18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd`;
SheepShaver binary `9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4`;
server PEF `ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`;
A7 source plan `5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e`;
A7 driver `2fba0972f4d9a8e3845c4204dce150dd7c90da0e19a9e5720d5289e2c94faf01`.
Helper `scripts/mac_runtime.py` current source SHA is in `preflight.json`.

Proposed display `:112`, frontend `127.0.0.1:15750..15753`, guest server
`10.0.2.15:5500..5503`, and data endpoint `127.0.0.1:15751`. Prep checks
found display socket/lock and host listeners absent; recheck immediately
before any later boot. Use the existing generic `mac_runtime.py display` and
`mac_runtime.py sheep ... --display :112 --port 15750 --guest-pcap
state/native-sessions/native-eventlab-one-01/guest.pcap --service
--isolate-network`; do not enable an isolated data port. Its fixed primary
15500/15501 bridges remain present but must never be targeted. Before
bootstrap, run an independent direct SYSTEM host-primary SYN recorder. After
actual lab PID/netns identification, start a direct SYSTEM namespace recorder
with `NetworkNamespacePath=/proc/<actual PID>/ns/net`, `tcpdump -U`, and the
lab frontend plus primary ports. Require both PCAP 24-byte headers and actual
recorder PIDs before first lab socket. Primary host and namespace SYN counts
must remain zero throughout. Require distinct lab, primary and client netns,
lab loopback-only/empty routes, actual emulator exe/UID/capability/FD6/FD16
identity, and source base unchanged. Retain launch argv, unit properties,
GUI readiness screenshot and dialog acknowledgements. No other server setup,
options, Tracker, account, ban or clock changes.

Adapt only A7 runtime/endpoints from the immutable 29-action plan, keeping
all steps and 1,049,073-byte FILP read unmodified. Run the standard capture
under a retained managed direct SYSTEM service in the actual lab namespace,
with a maximum four-minute unit cap. Record the actual runner PID and
as-run plan. Launch `event_probe.py` on the host with:

```sh
python3 state/delegation/c48-eventlab/event_probe.py \
  --guest-pcap state/native-sessions/native-eventlab-one-01/guest.pcap \
  --namespace-pcap state/native-sessions/native-eventlab-one-01/namespace.pcap \
  --a7-pid ACTUAL_A7_PID \
  --a7-capture-dir state/native-sessions/native-eventlab-one-01/a7-capture \
  --out state/native-sessions/native-eventlab-one-01/focus-event
```

This script performs no socket I/O. It associates the single data SYN in
both views with the same local port, reassembles server bytes, and demands
both views hold exactly 98,304 bytes with the recorded prefix SHA for at least
five seconds while the A7 reader process is live and its report absent. Any
progress before that becomes `healthy_progress_before_event` with **no click**.
That status means only that the stalled-prefix precondition was absent; the
original 29-action A7 report and full stream still need separate validation.
If this state never occurs, the event hypothesis remains untested. If the
layout differs, no click. If the Log window is already active, no click.
The prepared coordinate `(450,180)` lies in the Log window's blank white
content in C44's 1024x768 ready screenshot; its title crop `(220,35)-(300,46)`
was inactive grey while the server title was active gold. Capture before,
click once by XTest, capture after and require the Log title gold pixels to
rise, proving the guest processed an activation event. If not verified, mark
inconclusive; do not repeat input. Record UTC immediately before and after
XTest. Over at most ten seconds, compare both SYN-scoped views for next bytes
or full FILP. No progress after verified focus falsifies this **one ordinary
GUI event resumes this plateau** claim. Any progress is event-associated, not
by itself causation. A one-view-only change is inconclusive. Let the original
A7 finish or time out normally; no extra request 500, key, click, retry,
shortened transfer or extended read timeout.

After the one trial, stop only owned A7, lab, display, bridge and recorder
units, then validate actual emulator PID/starttime/exe/netns absence even if
the generic user unit has exited. Preserve process/port/PCAP/terminal proof,
including any `/proc` or collected-unit cleanup race instead of smoothing it
over. Verify no lab frontend listeners, unchanged primary/client identities,
zero primary SYNs and zero recorder drops. Never copy/hash a live working
image. This preparation has no live result and does not supersede the C32,
C35 or C45 packet evidence.
