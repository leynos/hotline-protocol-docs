# A148 independent P02 prestage review

Reviewed `evidence/gap-remediation/2026-11-14/native-alias-prestage-01`
manifest SHA256
`f2c3d694c9e2dce1c3cc09608eed2b9acad8a346c9f8f880e4a5b035da2f3663` (295 listed
files), against retained O02/P02. `sha256sum --quiet -c SHA256SUMS` passed.
All 286 epoch/preparation files mapped byte-for-byte to retained sources. The
two separately frozen root helpers match the source approval hashes: pin
writer `b311bf40…` and parent readiness reviewer `8e067fac…`. Service metadata
and historical review notes are separately identified in the manifest.

## Positive evidence

- `protocol_capture.verify_capture(readiness)` and
  `native_control_readiness.readiness(report)` pass on the original closed
  18-action report. Report status `completed`, eight frames, 27 events. This
  control flow includes its ordinary 206; it does not contain an alias-target
  206.
- One namespace TCP SYN lifetime (`127.0.0.1:36428` to `:15960`) and one
  corresponding guest lifetime (`10.0.2.2:36428` to `10.0.2.15:5500`)
  reconstruct exactly the report's 231 sent and 2,759 received bytes in both
  views. No extra application bytes or RST payload occur in these two
  lifetimes; FIN/ACK terminal packets are retained. The primary SYN PCAP
  contains zero TCP packets. Frozen tcpdump journal reports namespace 29
  captured, 0 dropped; host 0 captured, 0 dropped. The guest view has 32 TCP
  packets; cross-view application streams match byte-for-byte.
- The root-0600 prestage receipt binds emulator PID 3737215, start tick
  10252051, netns 4026533895, disk/capture receipt hashes, and one image SHA
  repeated under Finder/Unix/target screenshot names. The actual image shows
  the Files parent (41 items), the Unix window with one selected
  `m-alias54-target`, and Finder. Root's recorded Hide Others, System 9 window
  close and Unix drag are visibility actions, not alias creation. Current
  source-freeze 35 protocol modules plus three helpers match the proposed
  snapshot hashes. Snapshot code head `f6ec1a6…` and actual protocol head at
  approval `bf32b9a…` are distinguished in the manifest; the frozen bytes are
  explicit.
- The pre-case abort at 17:43:46Z records 367.6 seconds remaining, below the
  required 390; `case-begun.json` and coordinator are absent. Root retirement
  proof records app Quit observed, actual PID gone at 17:47:41Z before the
  fixed deadline, then FD-free working inode 203082518. Guest OS shutdown was
  not orderly; VM stop was forced. Stopped, read-only HFS extraction after PID
  disappearance/FD-free shows two original UserData, Prefs, native DATA/RSRC
  hashes unchanged; Board empty, Banned absent and alias wrapper absent. The
  host target content remains unchanged. Finder sidecar differs from the
  stopped preparation hash after selection and matches the runtime pin; no
  claim is made that Finder left metadata untouched.

## Scope and residuals

This is a prestage/readiness and safety-retirement witness only. There is no
Make Alias, Copy/Paste, case 205, alias-target 206, missing-target result, or
durable alias conclusion. The one screenshot file duplicated under three names
establishes one concurrent visible state, not three independent times. The
forced VM stop limits orderly persistence claims. No source, VM, service, or
protocol action was changed during this review.
