# Native private-message fixture preparation (A26)

Status: prepared offline, then executed in the
[native PM witness](native-pm-witness.md). GAP-044 remains open for other
producer fixtures. This packet uses the existing `admin` account in two named,
simultaneous sessions. It creates no account, file or persistent option. The
native server lease requires a separate supervisor START.

## Matrix

| Case              | Sender -> recipient | Session settings 113 | Request 108                      | Expected 104                                                   |
| ----------------- | ------------------- | -------------------- | -------------------------------- | -------------------------------------------------------------- |
| direct-quoted     | main -> peer        | 0/0                  | option 1, unique text, 214 quote | peer: original with sender 103/102, 113=1, 101/214             |
| recipient-refuses | main -> peer        | 0/1                  | option 1                         | main: generated refusal, recipient identity, 113=2; peer quiet |
| auto-and-original | main -> peer        | 0/4, peer 215 set    | option 1                         | main: 113=4 auto text; peer: original 113=1                    |
| sender-refuses    | main -> peer        | 1/1                  | option 1                         | neither; sender refusal suppresses feedback                    |
| option-two        | main -> peer        | 0/0                  | option 2                         | peer: generated refusal text, 113=2                            |
| option-three      | peer -> main        | 0/0                  | option 3                         | main: generated chat-refusal text, 113=3                       |
| empty             | main -> peer        | 0/0                  | option 1, empty 101              | neither                                                        |

Every 108 has a separately checked empty success ACK. Each case ends with a
two-connection 500 drain and two bounded quiet checks. Generated refusal text
is required to be nonempty and retained byte for byte, but its exact value is
not predeclared. This is seven PM actions; no repetition or timing
generalization is inferred. UIDs are from the current connection only: the
one-row initial 300 and the peer's observed 301. The verifier rejects ambiguous
initial identity, different announced peer identity, wrong 104 fields,
unexpected extra 104, or missing delivery. Other 104 producers remain separate
GAP-044 evidence.

## Operator sequence after separate START

The explicit baseline input is the committed A7
`../mothra/evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/capture/plan.json`
(SHA-256 `5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e`).
The generator checks that exact byte hash, oracle/profile, 29-step shape, data
endpoint, full 1,049,073-byte read, DATA/MACR expected hashes, and runtime
PID/hash/guest-PCAP identity. It writes the **unchanged input bytes** as both
`preflight.json` and `postflight.json`; these retain the A7 operator,
environment, expectation and GAP-037 label. Only `observe.json` is a new A26
plan with GAP-044 and a reference to the baseline input hash. A missing or
changed baseline aborts export.

1. Revalidate the live oracle process, binary hash, control listener and
   two-account/41-file baseline. Start an independent host capture before the
   first connection and preserve a fresh immutable guest-PCAP snapshot after
   each plan. Stop on identity drift, unexpected banner/session, or capture
   loss.
2. Generate new plan files using:

   ```sh
   python3 scripts/native_pm_cases.py --runtime-record RUNTIME.json --baseline-plan A7_PLAN.json --output NEW_PLAN_DIR
   ```

   Refuse any pre-existing destination. Capture `preflight`, then `observe`,
   then `postflight` with:

   ```sh
   scripts/protocol_capture.py capture PLAN.json --oracle-binary ORIGINAL_ORACLE --output NEW_CAPTURE_DIR
   ```

   Record exact plan/report hashes and independent host/guest packet streams.
3. Run
   `python3 scripts/verify_native_pm.py OBSERVE_CAPTURE --output NEW_RESULT.json`
   and `python3 scripts/protocol_capture.py verify POSTFLIGHT_CAPTURE`. The
   repeated A7 plan includes 348, 200, 206, 300, idle 303, 202, full
   FILP/INFO/DATA/MACR download, cancellation and final idle 303, after both PM
   sessions restore 304 name/icon/options and close. Check the new
   pre/postflight reply fields against the original A7 capture, including two
   accounts and 41 Files rows; decode the full transfer and compare DATA/MACR
   hashes to the pinned expectation. The current PM verifier checks only
   `observe`, and `protocol_capture verify` checks transcript integrity, so
   these readback comparisons require separate evidence before reporting
   baseline restoration.

The generated plans are **preparation**, not authority to contact the server.
If a 304/500 barrier or expected 104 read fails, retain the failed report and
raw packet views, close only these two sessions, and escalate before any retry.
The native 104 sender/recipient order is a captured observation to assess; the
plan does not claim a universal cross-socket delivery order. If postflight
cannot prove the A7 baseline, stop and hand back the live process unchanged.
