# Isolated native settings persistence preparation (A42)

A46 and A48 ran on the same private A41 working image. Their bounded result is
recorded in [the persistence witness](native-settings-persistence-witness.md).
The A46 plan/report remain frozen historical evidence: 64 planned observations
plus two runner-added EOFs require explicit legacy validation. Never rewrite
their counts, checksums or driver hash.

The same-session 304 transitions and delayed 121 defaults are already measured
in `native-settings-transition-witness.md` and `native-121-default-witness.md`.

## Assets and authority

Use only private Mothra `state/mac-runtime/native-settings-persistence-01`:
source/target disk SHA-256
`e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910`, ROM
`18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd`. The ignored
`state/delegation/a41-assets.json` pins distinct source/base/working inodes and
path-based baseline UserData/Prefs fork hashes. C50's working disk is separate
and must not be used. A live run requires a new root START; this preparation
gives no permission to boot, send traffic, change original accounts, change
server options, modify files, adjust the clock, or restart the primary.

The fixture profile is `control-only`, `full_file_baseline=not_exercised` from
`native-control-readiness.md`. The 18-action control plan checks original two
accounts, 41 Files, admin privilege and agreement, roster and idle 303. It is
**not** full A7. The C52 shared module's actual `readiness` and `capture_gate`
functions are used; no alternate weaker API is invented. An isolated lab port
such as 15760 and display :113 require renewed owner checks. Hold `oracle.lock`
while operating the native lab. Independent 900-second host, namespace and
guest recorders must be ready, with actual PID, PCAP header, zero primary SYN
and empty routes before the readiness capture. Each phase has a separate
12-minute runner limit and fresh capture receipt.

## Fixed observation

Generate plans from a runtime JSON whose `source_a7_sha256` is the exact
`5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e`. The private
protocol checkout command is:

```sh
python3 scripts/native_settings_persistence_cases.py \
  --runtime "$RUNTIME_JSON" --port 15760 --output "$OWNED_PLAN_DIR"
```

The corrected generator includes two planned EOF actions after a 64-action
phase one observation or 26-action phase two observation. The runner writes
hold-ready after observation, then executes those planned EOFs after visible
File > Quit. A completed report now has exactly 66 or 28 actions and passes the
generic capture format gate; the separate semantic gate still checks both EOFs
and stage results.

The generator writes exact `readiness.json`, `phase1.json`, `phase2.json`,
`source-hashes.json` and `source-code-sha256.json`. Re-run it after reboot with
the **new** PID/runtime receipt; compare `fixed_login_hex` and baseline login
steps across the two generations. Do not edit plan operator/source fields to
bypass the runner's equality and SHA gates. Root must approve actual as-run
metadata and separate live execution. Check the independent recorder receipt
before running the readiness capture into a fresh directory:

```sh
python3 scripts/protocol_capture.py capture "$OWNED_PLAN_DIR/readiness.json" \
  --oracle-binary "$NATIVE_DATA_FORK" --output "$READINESS_CAPTURE_DIR"
```

Then run the phase gate:

```sh
python3 scripts/native_settings_persistence.py --run \
  --plan "$OWNED_PLAN_DIR/phase1.json" \
  --readiness-dir "$READINESS_CAPTURE_DIR" \
  --capture-receipt "$CAPTURE_RECEIPT_JSON" \
  --binary "$NATIVE_DATA_FORK" --output "$PHASE1_CAPTURE_DIR"
```

Use the same command with `phase2.json` and fresh phase-two paths after the
separately approved restart. The runner demands root for `/proc` FD, netns,
start-time and executable checks. It validates readiness before creating a
Recorder. Stage gates reject wrong observer/subject UID/name/icon before PM,
wrong 301 before dependent PM, wrong original/automatic 104, ACK or missing
quiet barrier. It stops at the first unexpected state and retains raw events.

Phase 1 has one fixed observer and admin subject. A fixed 107 name/icon
(`A41-Baseline`, 3) is saved verbatim; one PM checks baseline absence of
automatic feedback. Three 304 stages then set explicit `A41-Persist-On`/17,
113=4/custom ASCII 215; disable via absent 113/215 with `A41-Persist-Off`/18;
and re-enable the same On values. Each stage has paired 301, PM delivery,
feedback/quiet controls. The final live subject is explicitly On. Phase 2
repeats the **same fixed 107 bytes**, 301 and one PM on a newly proven server
PID; the fresh login is a control, not by itself a durability verdict.

The plan intentionally omits socket-close actions. When `hold-ready.json`
appears, the operator must use the native application's **File > Quit** UI
while both owned sessions remain connected. The runner waits for both EOFs and
then closes local descriptors. EOF alone is not proof of File > Quit. Retain
screenshot, action times, native listener disappearance and unit logs. At
Finder use Mac OS 9 **Special > Shut Down** and capture the final screen;
require natural emulator exit and no disk FD owner before read-only HFS
inspection. A host TERM, forced unit stop, ambiguous prompt or emulator death
without proved guest shutdown is a failed persistence boundary. Preserve live
handles/image and escalate; do not call it flushed.

After each clean guest shutdown, use repository-local Sleuth Kit
`ifind -f hfs -n PATH IMAGE` for `/Hotline19/Users/admin/UserData`,
`/Hotline19/Users/fixture-low/UserData` and `/Hotline19/Prefs`, then
`icat -f hfs IMAGE CATALOG-4352-0` to hash/compare complete data forks. IDs
must be rediscovered by path; initial IDs 11193/11201/11202 are only A41's
baseline. A41 data hashes are `26612ad4...`, `fce81359...`, `4ed2b3e1...`;
compare full 64-hex hashes from `a41-assets.json`. Record stopped-image
SHA/stat/inode, Prefs bytes/hash differences and account bytes without printing
credentials. If any record or Prefs changed unexpectedly, preserve both
snapshots and identify the writer before deciding persistence. Restart the
**same** owned working image only after the first stopped-image checkpoint and
root approval; prove a new actual PID/start, unchanged image path and separate
recorder.

The frozen 304 handler `10016ad0` calls session helper `10004d50` with account
argument zero; 353's account-file writer is a separate path. If live 304
changes 301/PM but cleanly stopped account records remain identical and a fixed
fresh login returns to its baseline state, this supports session-only 304
behaviour. Fresh 107 reruns the helper, so its output alone cannot prove
nothing was stored elsewhere. Unexplained Prefs deltas, failed shutdown, packet
loss or changed account inventory leave GAP-029 open. Preserve failed reports;
no retry or scope expansion without a new parent packet.
