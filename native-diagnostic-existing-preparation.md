# Existing-file diagnostic load preparation

This A8 packet was prepared before phase 1. The
[phase-1 witness](native-diagnostic-existing-witness.md) records the completed
2/1 case and restoration. The
[8/8 density witness](native-diagnostic-density-witness.md) records A9. This
packet uses the already verified
`mothra-race-fixture` on native Hotline Server 1.9 for bounded transaction 303
observations. No upload, file deletion, rename, account edit or server restart is
part of this packet. The [A7 full readback][a7] proved the current DATA fork
(1,048,576 bytes, SHA-256
`fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83`)
and resource fork (317 bytes, SHA-256
`40a42dbcf2d879e22d9a5a9acf46bf15fa9fe3a77837f757a990e514436801e5`)
match the prior native extraction byte for byte. A7 also matched the exact two
accounts and 41-entry Files baseline and paired both packet views.

## Bounds and order

Root must grant an exclusive native server lease before any connection or UI
change. Confirm the live SheepShaver executable hash and PID against the A7
runtime, `DISPLAY=:99`, managed service, control/data listeners, oracle binary
hash, the A7 fixture and General Options 100 global / 10 per client / 5 per IP.
The separate `:101` client must not connect during this packet. Stop on any
drift, error dialog or repair prompt.

The A8 ceiling is **six captures including failures and reviewed corrections**.
Three are planned:

1. Save and reopen General Options at **2 global / 1 per client / 5 per IP**.
   Capture one held unread active 202 download and one positive queued 202
   reference on the same current-UID connection. Record 303 for that UID,
   invalid `ffff`, then idle after cancelling both references.
2. After positive verification of step 1, save and reopen **8 / 8 / 5**.
   Capture fixed 303 density points at **4 active / 0 queued**, **8 active / 4
   queued**, and **8 active / 8 queued**. Maximum 16 references and eight data
   sockets. The eight data sockets remain unread; after 214 cancellation they
   are closed without draining into the recorder, which has an 8 MiB byte
   limit. Retain and identify all unread host and guest packet tails.
3. Restore and reopen exact original **100 / 10 / 5**, then capture 348, full
   root Files 200, fixture 206 and idle same-connection 303. Compare with A7.

The remaining three capture slots are **not automatic retries**. If an active
transfer already completed before its claimed 303, 116 is absent/zero for a
claimed queue, any reference is ambiguous, the packet pair is incomplete, or
a capture fails before planned cancellation, preserve all raw evidence and
escalate. Restore original settings at the first safe point. Do not create more
transfers or rerun a failed case without review.

## Prepared commands

These commands are examples for a fresh directory under `mothra` after approval;
**none was executed during preparation**. The exact generator creates a new
plan file and refuses an existing output.

```sh
mkdir -p state/native-sessions/A8
a8_scripts=../hotline-protocol-docs/scripts
a8_batch=evidence/gap-remediation/2026-11-13
for case in one-active-one-queued density postflight; do
  python3 "$a8_scripts/native_diagnostic_existing_cases.py" "$case" \
    --runtime-record "$a8_batch/native-diagnostic-load-01/runtime.json" \
    --output "state/native-sessions/A8/plan-$case.json"
done
```

For each case, after the correct General Options values are saved, **reopen and
photograph the saved values** on display `:99` (for example, `import -display
:99 -window root state/native-sessions/A8/options-CASE-reopened.png`), then
close the dialog. Start a fresh host recorder and confirm its ready message and
24-byte PCAP header *before* launching `protocol_capture.py`:

```sh
sudo -n tcpdump -i lo -s 0 -U \
  -w state/native-sessions/A8/host-CASE.pcap \
  'tcp and (port 15500 or port 15501)'
# In a separate shell only after tcpdump is ready:
python3 ../hotline-protocol-docs/scripts/protocol_capture.py capture \
  state/native-sessions/A8/plan-CASE.json \
  --oracle-binary evidence/hotline-server-1.9/inputs/HLserver19.pef \
  --output state/native-sessions/A8/CASE
```

Stop the host recorder with SIGINT after the capture, record its drop count,
then copy the continuing guest PCAP to a new immutable snapshot. Verify the
standard capture and run the structural witness checker:

```sh
python3 ../hotline-protocol-docs/scripts/protocol_capture.py verify \
  state/native-sessions/A8/CASE
python3 ../hotline-protocol-docs/scripts/verify_native_diagnostic_existing.py \
  CASE state/native-sessions/A8/CASE \
  --a7-baseline "$a8_batch/native-diagnostic-existing-preflight-01/capture" \
  --output state/native-sessions/A8/verification-CASE.json
```

Reconcile exact SYN lifetimes and client/server byte streams in both PCAPs.
For unread density sockets, the recorder's received stream is only an observed
prefix, while the packet views can hold more bytes. Preserve terminal packets,
including SLiRP diagnostics, separately. The verifier splits the five native
section headings and requires complete
fixture rows: 1/1 in the first case; 4/0, 8/4 and 8/8 at the density points;
and 0/0 after cancellation and in postflight. It requires unrelated transfer
sections to remain empty and checks each 214 request against its saved reference
and successful ACK. An incomplete or clipped section is written as
`incomplete-witness` and exits nonzero; it is not labelled proof of the planned
counts. These native text markers do not define mxd's required prose. If 8+8
stays below the source `0x400` formatting bound, report that negative reach
result rather than enlarging the matrix. GAP-037's near-boundary witness and
exact-text release decision remain open until independently resolved.

[a7]: ../mothra/evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/manifest.json
