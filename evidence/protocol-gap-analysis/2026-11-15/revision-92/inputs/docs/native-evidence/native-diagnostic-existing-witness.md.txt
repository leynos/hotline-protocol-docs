# Native 1.9 diagnostic with one active and one waiting download

This bounded A8 phase-1 witness uses the existing `mothra-race-fixture` file.
The [A7 readback][a7] had verified its 1,048,576-byte DATA and 317-byte
resource forks against the earlier native extraction. No upload, rename or file
deletion was used to construct this state. The exact plans, reports, packet
views and General Options screenshots are in the [A8 corpus][a8].

## Native observation

The server was Hotline Server 1.9 in the disposable SheepShaver Mac OS 9
runtime, with oracle DATA SHA-256
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`. General
Options was saved and reopened at **2 simultaneous downloads globally, 1 per
client, 5 connections per IP**. It was restored, saved and reopened at the
exact initial **100 / 10 / 5** after the one observation. Host tcpdump was
ready before each protocol connection; both recorders reported zero kernel
drops. The guest capture was snapshotted after each case.

One administrator session resolved its current UID from a one-row 300 roster.
It requested the known file twice by 202. The first reply supplied reference
`00 04 4c fb` without a queue position; the data socket sent its HTXF header
and was left unread until cancellation. The second reply supplied reference
`00 05 22 ab` and positive initial waiting position 116 = 1. Transaction 303
for that same current UID then returned success, field 102 = `framing-fixture`,
and 350 bytes of raw field 101. The two relevant lines are:

| Native section    | Row bytes (escaped CR)            |
| ----------------- | --------------------------------- |
| File Downloads    | `mothra-race-fixture   5%   1M\r` |
| Waiting Downloads | `mothra-race-fixture   (File)\r`  |

The [raw reply][load] retains the exact heading bytes, CR separators and all
other content. Folder downloads, file uploads and folder uploads were each
`None.`. Both 214 requests targeted their saved four-byte references, and both
ACKs succeeded. The same connection's post-cancel 303 had zero active and zero
waiting rows, 303 bytes of field 101. It also captured the unmatched `ffff`
target failure as a separate negative control.

The first offline verifier result was `incomplete-witness`: it applied the
active percent/size row form to the waiting section. That result is retained
unaltered. The separate corrected result counts one complete active row and one
complete waiting row. This distinction is independently supported by the
[oracle string capture][strings]: active row format at `10091b11 + 0x73`,
waiting file row `"%#-21.21s (File)\r"` at `10091b9b`, and the five-section
outer format at `10091bc1`. The decompiled [303 handler][handler] iterates
active transfer collections and the waiting collection separately. This
native-specific text check establishes the witness; it does **not** select a
mandatory exact-text policy for mxd.

The active data socket delivered 65,536 flattened transfer-stream bytes after
its 16-byte HTXF request. The saved prefix begins with the FILP header and INFO
fork, so this count includes framing and metadata. Recorder, host and guest
packet views match exactly for this case; there is no unread application
payload tail. The host data lifetime ended with FIN packets. The guest data
lifetime has a server RST carrying the raw five-byte SLiRP diagnostic `No TCP`,
followed by client RST+ACK packets. That terminal diagnostic is outside the
file data stream. The 303 row's `5%` is reported as native text, not
recalculated from the later byte count or presented as a timing guarantee.

The restoration postflight had two exact baseline accounts, the exact 41
baseline root Files entries, unchanged complete-file 206 metadata, and an idle
same-connection 303. Its host and guest control streams match the recorder byte
for byte. This proves restoration for the observed live session; it does not
establish persistence after a guest restart.

## Scope and reproduction

The [prepared procedure][preparation] contains the bounded generator, settings
and capture steps. From `mothra`, verify this committed corpus with:

```sh
a8_parent=evidence/gap-remediation/2026-11-13
a8="$a8_parent/native-diagnostic-existing-01"
a7="$a8_parent/native-diagnostic-existing-preflight-01"
sha256sum -c "$a8/SHA256SUMS"
python3 ../hotline-protocol-docs/scripts/protocol_capture.py verify \
  "$a8/one-active-one-queued"
python3 ../hotline-protocol-docs/scripts/protocol_capture.py verify \
  "$a8/postflight"
python3 ../hotline-protocol-docs/scripts/verify_native_diagnostic_existing.py \
  one-active-one-queued "$a8/one-active-one-queued" \
  --a7-baseline "$a7/capture" \
  --output state/native-sessions/A8/verification-one-active-new.json
python3 "$a8/verify_packets.py"
```

The corrected semantic checker refuses to overwrite an output. The retained
initial verifier result is expected to say `incomplete-witness`; it records a
historical checker limitation, not a failed native 303. The paired packet
checker reads the committed corpus without writing unless `--output` names a
new file.

The later [A9 density witness](native-diagnostic-density-witness.md) reached 8
active and 8 waiting downloads, but measured only 763 field-101 bytes. The later
[near-boundary observation](native-diagnostic-near-witness.md) contains 995
bytes inside an overall failed plan. The
[formatter trace](../protocol/diagnostic-formatting-trace.md) supplies the
static cap and distinguishes descriptive baseline wording from a separate mxd
release promise. Live at-cap behaviour remains unobserved. This one
active/queued example must not be generalized into mandatory wording, progress
percentages or transfer scheduling guarantees.

[a7]: ../../evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/manifest.json
[a8]: ../../evidence/gap-remediation/2026-11-13/native-diagnostic-existing-01/manifest.json
[load]: ../../evidence/gap-remediation/2026-11-13/native-diagnostic-existing-01/one-active-one-queued/report.json
[strings]: ../../evidence/hotline-server-1.9/queries/S004-strings.json
[handler]: ../../evidence/hotline-server-1.9/queries/D-10016150.c
[preparation]: native-diagnostic-existing-preparation.md
