# Native 1.9 client diagnostics (303)

This note records five bounded Mac OS 9.0.4 Hotline Server 1.9 exchanges
against the [exact Mac PPC oracle][corpus]. It addresses GAP-037 as measured
evidence; the original criterion is assessed with the later formatter trace
below. The application DATA SHA-256 is
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`. The
continuing emulator PID, executable hash, guest configuration and capture
method are in the [runtime record][runtime]. The [manifest][manifest]
identifies all five plans and the preserved earlier plan generator.

## Representative reply matrix

The [preflight][preflight] found the new `m-diag31-zero` account absent and
enumerated exactly two prior accounts. Only that new account was created; its
effective login privilege bytes were all zero. The [cleanup][cleanup] deleted
it, confirmed a missing-account lookup and restored the exact account
enumeration bytes. Every captured reply below is a transaction 303 numbered
reply (`type=0`, `is_reply=1`) unless stated otherwise.

| Case                             | Same-session target proof                                                                                                | Reply fields and bytes                                                                                                                             |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Admin → owned user               | Admin received 301 for `Diag31-\x8e`, UID `0090`; the later 300 roster contained exactly that user                       | status `0`; 101 = 299 bytes, SHA-256 `390ffeac952f7b830280bad443cdc5ff9dc133acadc805b31aac466ab0950776`; 102 = `44 69 61 67 33 31 2d 8e` (8 bytes) |
| Owned zero-privilege user → self | The same `0090` UID was sent by the zero-privilege connection                                                            | status `1`; only 100, 46 bytes: `You are not allowed to get client information.`                                                                   |
| Admin → `ffff`                   | Explicit unmatched target value                                                                                          | status `1`; only 100, 67 bytes: `Cannot get info for the specified client because it does not exist.`                                              |
| Admin → prior-session `008d`     | Preflight had `008d`; current 300 identified admin `008f`, so `008d` is stale                                            | status `1`; same 67-byte missing-client field 100; **not** a self request                                                                          |
| Admin → self                     | Separate [self exchange][self] saved UID `0091` from its own one-entry 300 roster, then sent 303 on that live connection | status `0`; 101 = 303 bytes, SHA-256 `452b6f03fab68394e7f7132896a13beb1b5c908c0051635914224abfbc529400`; 102 = `framing-fixture` (15 bytes)        |

The first success text is raw single-byte data. It begins with the following
escaped bytes:

```text
Nickname:   Diag31-\x8e\rName:       Diag31-\x8e\r
Account:    m-diag31-zero\rAddress:    10.0.2.2
```

The self text begins with these escaped bytes:

```text
Nickname:   framing-fixture\rName:       administrator\r
Account:    admin\rAddress:    10.0.2.2
```

Both then contain five labelled file-download, folder-download, file-upload,
folder-upload and waiting-download sections, each with `None.\r` in this idle
fixture. The exact data is retained in each report's field-101 hex, not
reconstructed from typography here. The high byte `8e` survives unchanged in
the owned user's 102 nickname and both corresponding text lines. CR is byte
`0d`; the recorded replies show no LF conversion. `10.0.2.2` is the
guest-visible address in this emulator, not a fixed Internet address protocol
constant.

## Contract boundary

The [303 handler][handler] requires privilege bit 24 and reads field 103 as a
numeric target UID. Its successful reply writes name 102 and generated data
101; the two observed failure families use status 1 and text field 100. An
implementation needs to preserve those request, authorization, success-field
and failure-envelope roles for the documented cases. The full failure taxonomy
is tracked separately.

The field-101 prose, labels, spacing, section headings, address spelling and
transfer descriptions are generated presentation. They are not a structured
profile or proof of a stable text grammar across builds, configurations or
locales. The [formatter-to-field trace](diagnostic-formatting-trace.md) shows a
final cap of 1,024 output bytes, returned as the field-101 length without
reserving or appending a NUL. This is a source-derived bound; the largest
recorded native example is 995 bytes, not an at-cap clipping test. The raw `8e`
byte and CR separators are observations, not a general codec.

For this protocol baseline, exact field-101 wording is **descriptive and is not
required for compatibility**. Preserve the request, authorization,
success/error envelopes and raw field roles. Do not parse generated labels,
spacing, addresses or progress text as a stable record grammar. Exact bytes
remain recorded for comparisons with this build/configuration. An mxd release
promise of exact presentation parity remains a separate decision, with further
mxd validation on hold.

Later [active/queued](native-diagnostic-existing-witness.md) and
[density](native-diagnostic-density-witness.md) fixtures add representative
transfer summaries. The
[near-boundary observation](native-diagnostic-near-witness.md) retains a
successful 995-byte reply inside a failed overall capture; its incomplete
cleanup plan remains failed. Together with the traced output cap and envelope
rules, these meet GAP-037's original documentation criterion. They do not
establish a universal character set, every intermediate buffer boundary or live
behaviour at and above the formatting cap.

## Reproduction and checks

From `mothra`, with an explicitly leased, identity-checked native emulator and
a fresh evidence directory, generate plans using:

```sh
python3 ../hotline-protocol-docs/scripts/native_diagnostic_cases.py \
  --runtime-record <runtime.json> --output <new-plan-directory> \
  --stale-uid <measured-prior-session-uid>
```

Use `protocol_capture.py capture` with the generated plan, oracle binary
`evidence/hotline-server-1.9/inputs/HLserver19.pef` and a new output directory
for preflight, seed, observe, self and cleanup. The stale UID is a negative
control; never use it as a current self identity. The self plan saves its own
300 roster UID from the same live connection. Run cleanup even after a failed
observation when the native process remains live; preserve the failed report.

The committed corpus has a full cumulative guest Ethernet snapshot, a host
loopback capture with zero kernel drops, exact plans/reports and separately
retained unread 302 departure bytes. Check its hashes and semantics with:

```sh
sha256sum -c evidence/gap-remediation/2026-11-13/native-diagnostics-01/SHA256SUMS
python3 ../hotline-protocol-docs/scripts/verify_native_diagnostics.py \
  evidence/gap-remediation/2026-11-13/native-diagnostics-01
python3 -m unittest discover -s ../hotline-protocol-docs/scripts \
  -p test_native_diagnostics.py
```

The verifier rejects a wrong field, status, target UID, ambiguous self roster
or changed reply order and reconciles six host/guest TCP lifetimes, including
the unread removal notice. Hash agreement alone is not a semantic proof.

[corpus]: ../mothra/evidence/gap-remediation/2026-11-13/native-diagnostics-01/
[manifest]: ../mothra/evidence/gap-remediation/2026-11-13/native-diagnostics-01/manifest.json
[runtime]: ../mothra/evidence/gap-remediation/2026-11-13/native-diagnostics-01/runtime.json
[preflight]: ../mothra/evidence/gap-remediation/2026-11-13/native-diagnostics-01/preflight/report.json
[cleanup]: ../mothra/evidence/gap-remediation/2026-11-13/native-diagnostics-01/cleanup/report.json
[self]: ../mothra/evidence/gap-remediation/2026-11-13/native-diagnostics-01/self/report.json
[handler]: ../mothra/evidence/hotline-server-1.9/queries/D-10016150.c
