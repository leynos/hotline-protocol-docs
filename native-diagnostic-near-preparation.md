# Native 303 near-boundary preparation

This A11 packet is prepared but **has not run**. The [A9 density witness][a9]
measured field 101 at 763 bytes with eight active and eight waiting transfers.
Each saved waiting file row is 29 bytes including CR, so adding eight identical
rows predicts **995 bytes** at eight active and sixteen waiting. This is 29
bytes below the `0x400` destination size in the [native handler][handler]. Both
995 and 996 (allowing one byte for termination) are below 1024; this prediction
does not assert untraced formatter termination semantics. The handler's
512-byte waiting section has a `0x28` reserve check before each row; sixteen
fixed 29-byte rows occupy 464 bytes. Admission of sixteen queued references is
still unverified.

## Fixed bounds and decision gate

Only after a separate live START, use the already verified
`mothra-race-fixture`, eight unread data sockets and exactly 24 distinct 202
references. This **explicitly extends** A9's 16-reference limit for this case
only. Save/reopen limits 8 global / 8 per client / 5 per IP, then restore and
reopen original 100 / 10 / 5 at the first safe cleanup point. No uploads,
renames, deletions, account changes, disk repair or restart.

The generated plan uses active request IDs 100–107, queued 120–135, diagnostics
140 at 8/8 and 141 at 8/16, queued cancellation IDs 200–215, active
cancellation IDs 220–227 and idle 240. Login is ID 1, roster ID 10; all IDs are
unique. Every cancellation targets its saved four-byte reference. Require queue
positions 1–16, complete eight active and sixteen waiting rows, three unrelated
sections empty, 995 field-101 bytes and post-cancel zero rows. If any request
errors, claimed row is missing, data socket completes before its witness, or
ownership is ambiguous, retain the failed capture and stop. Do not retry or
enlarge the live matrix.

Plan two captures (near case and restoration postflight), with a hard ceiling
of three including failure. Start and confirm the independent host recorder
before each connection, then save an immutable cumulative guest PCAP snapshot.
Do not drain unread data into the recorder. Compare control streams exactly;
compare each host data prefix with its guest prefix and the A7 full FILP
stream, retaining separate tails and terminal diagnostics. Reopen restored
options and run the existing [A8 postflight][a8] against A7's exact two
accounts, 41 Files entries, fixture metadata and idle 303. A 995-byte result
would be a below-boundary example; it would not settle truncation or mxd's
exact-text release policy.

## Offline preparation and replay commands

Run from private `mothra`; the generator refuses an existing plan output. No
command in this block opens a native connection.

```sh
mkdir -p state/native-sessions/A11
a11_parent=evidence/gap-remediation/2026-11-13
python3 ../hotline-protocol-docs/scripts/native_diagnostic_near_cases.py \
  --runtime-record "$a11_parent/native-diagnostic-load-01/runtime.json" \
  --output state/native-sessions/A11/near-plan.json
PYTHONPATH=../hotline-protocol-docs/scripts \
  python3 -m unittest -q test_native_diagnostic_near
```

After a separately approved capture, run the standard
`protocol_capture.py verify` on each capture, then
`verify_native_diagnostic_near.py near-boundary CAPTURE --output NEW.json`. For
restored postflight use the same verifier's `postflight` case with
`--a7-baseline evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/capture`.
The verifier returns `incomplete-witness` for complete but unexpected row/size
combinations and nonzero for malformed or inconsistent evidence.

[a9]: ../mothra/evidence/gap-remediation/2026-11-13/native-diagnostic-density-01/manifest.json
[handler]: ../mothra/evidence/hotline-server-1.9/queries/D-10016150.c
[a8]: native-diagnostic-existing-preparation.md
