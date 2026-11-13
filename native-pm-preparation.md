# Native private-message fixture preparation (A26)

Status: prepared offline; no native capture or GAP-044 closure claim. This packet
uses the existing `admin` account in two named, simultaneous sessions. It creates
no account, file or persistent option. The native server lease requires a separate
supervisor START.

## Matrix

| Case | Sender -> recipient | Session settings 113 | Request 108 | Expected 104 |
| --- | --- | --- | --- | --- |
| direct-quoted | main -> peer | 0/0 | option 1, unique text, 214 quote | peer: original with sender 103/102, 113=1, 101/214 |
| recipient-refuses | main -> peer | 0/1 | option 1 | main: generated refusal, recipient identity, 113=2; peer quiet |
| auto-and-original | main -> peer | 0/4, peer 215 set | option 1 | main: 113=4 auto text; peer: original 113=1 |
| sender-refuses | main -> peer | 1/1 | option 1 | neither; sender refusal suppresses feedback |
| option-two | main -> peer | 0/0 | option 2 | peer: generated refusal text, 113=2 |
| option-three | peer -> main | 0/0 | option 3 | main: generated chat-refusal text, 113=3 |
| empty | main -> peer | 0/0 | option 1, empty 101 | neither |

Every 108 has a separately checked empty success ACK. Each case ends with a
two-connection 500 drain and two bounded quiet checks. Generated refusal text is
required to be nonempty and retained byte for byte, but its exact value is not
predeclared. This is seven PM actions; no repetition or timing generalisation is
inferred. UIDs are from the current connection only: the one-row initial 300
and the peer's observed 301. The verifier rejects ambiguous initial identity,
different announced peer identity, wrong 104 fields, unexpected extra 104, or
missing delivery. Other 104 producers remain separate GAP-044 evidence.

## Operator sequence after separate START

1. Revalidate the live oracle process, binary hash, control listener and
   two-account/41-file baseline. Start an independent host capture before the
   first connection and preserve a fresh immutable guest-PCAP snapshot after
   each plan. Stop on identity drift, unexpected banner/session, or capture loss.
2. Generate new plan files using
   `python3 scripts/native_pm_cases.py --runtime-record RUNTIME.json --output NEW_PLAN_DIR`.
   Refuse any pre-existing destination. Capture `preflight`, then `observe`, then
   `postflight` with `scripts/protocol_capture.py capture PLAN.json
   --oracle-binary ORIGINAL_ORACLE --output NEW_CAPTURE_DIR`. Record exact
   plan/report hashes and independent host/guest packet streams.
3. Run `python3 scripts/verify_native_pm.py OBSERVE_CAPTURE --output
   NEW_RESULT.json` and the existing A7 postflight verifier against its saved
   baseline. The postflight plan is the exact A7 read-only 348/200/206/300/303
   sequence, after both PM sessions have restored 304 name/icon/options and
   closed. Confirm original two accounts, 41 Files rows, and owned fixture.

The generated plans are **preparation**, not authority to contact the server.
If a 304/500 barrier or expected 104 read fails, retain the failed report and
raw packet views, close only these two sessions, and escalate before any retry.
The native 104 sender/recipient order is a captured observation to assess; the
plan does not claim a universal cross-socket delivery order. If postflight
cannot prove the A7 baseline, stop and hand back the live process unchanged.
