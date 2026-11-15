# Native 1.9 settings field 113 preparation

This preparation defines the GAP-015/016/017 packet for transaction 304,
field 113. [Captured results](native-settings-witness.md) are now retained;
this recipe alone does not authorise another live execution.
It uses the same native 1.9 binary SHA-256
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`.
The generic numeric reader is `10056b90`; the shared 121/304 settings helper
is `10004d50` (`presence-messaging-contracts.md:8-35`). These code paths
predict absent/empty/three-byte zero and low option bits, but the native
capture, when authorised, must decide actual outcomes. No result is inferred
from a generated plan.

## Bounded matrix and observer

`scripts/native_settings_cases.py` emits exactly ten independent plans:
absent 113; present-empty; two-byte zero; one-byte `01`; two-byte `0004`;
three-byte `000001`; four-byte `00000005`; five-byte `00000001ff`;
duplicate `0001,0004`; and reversed duplicate `0004,0001`. The reversed
duplicate interleaves identical 104/102 controls. Each plan uses only two
existing admin sessions, logs in an observer first, then a subject with an
explicit name/icon. The observer's 301 supplies the **dynamic two-byte subject
UID**. Each 304 is followed by an observer 301 and a numbered 500 barrier;
304 has no normal ACK. A single uniquely labelled option-1 PM to that UID
tests refusal and automatic response independently of 301, which does not
carry those flags. Numbered 500 barriers on both sockets collect possible
104 delivery/feedback without requiring a notification to exist. The plan
restores the subject's 113 to two-byte zero, observes the resulting 301, then
closes both owned sockets. Ten PM probes total are below the 20-probe cap.

For duplicate cases the verifier accepts only a measured result corresponding
to one of the submitted values and records it. It **does not** assert a
universal last-wins rule. A reported result without the expected PM ACK,
dynamic UID, 301 controls, PM delivery/refusal feedback or restore/barrier
is rejected. The source-local tests exercise plan validity, exact UID
substitution and a missing-delivery fault; they do not attest any native
capture or both packet views.

## Preparation and later authorised capture

From the private protocol checkout:

```sh
python3 -m unittest discover -s scripts -p test_native_settings.py
python3 scripts/native_settings_cases.py \
  --runtime-record /absolute/approved/runtime.json \
  --output /absolute/new/plan-directory
```

The native lease holder must validate the current runtime PID, guest/host
capture sources and original binary hash, then run each plan once with
`scripts/protocol_capture.py capture`, retaining a separate directory per
case and failed reports unchanged. Host/guest PCAP reconciliation and corpus
SHA inventory remain publication requirements, not supplied by this prep.
After the ten cases and socket closure, replay the **exact immutable A7
postflight** from canonical Mothra
`evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/capture/plan.json`
with its original `verify.py`: 29 actions checking admin and fixture-low
accounts, 41 Files descriptors, 206 metadata, idle 303 and the full
1049073-byte FILP fixture. A looser account-enumeration check is insufficient.
Only the lease holder may substitute current runtime provenance and execute
this postflight; any difference is retained and escalated before publication.

For captured cases, `verify_native_settings.py <corpus-directory>` expects
one capture directory per plan and checks the captured semantic results.
Publication must add source/plan/report hashes, both network views, the A7
postflight receipt and observed duplicate choices. This packet establishes
one field and one operation only; the original all-core GAP-015/016/017
criteria stay open.
