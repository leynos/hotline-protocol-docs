# Isolated permanent-ban control fixture (C52 preparation)

The preparation below was exercised by the
[C56 permanent-ban witness](native-ban-control-witness.md). The root-approved
[control-readiness profile](native-control-readiness.md) applies only after a
separate live grant for any new run. Set `fixture_profile=control-only` and
`full_file_baseline=not_exercised` in every report. The C35, C45, and C50 lab
full-file baselines all failed at the 98,304-byte prefix; this fixture cannot
turn them into passes or support transfer claims.

## Prepared image and immutable inputs

Reuse the **stopped** C50 owned runtime
`mothra/state/mac-runtime/native-eventlab-one-01`. C50 terminal receipt says
actual emulator 2055952 gone. C52 rechecked no process has its `working.dsk`
open; the HFS `Hotline19/Users` contains exactly `admin` and `fixture-low`; both
`UserData` SHA-256 values equal the immutable base. Recursive HFS listing
found no `Banned` or `Banned.bak`. The source base is
`e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910`, ROM
`18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd`, emulator
`9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4`, server DATA
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`. The
original C50 A7 source plan SHA-256 is
`5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e`. The ignored
C52 preparation record and five plan hashes are at
`mothra/state/delegation/c52-native-ban-control/`. Prepared plans have
`emulator_pid=null`; regenerate with a current runtime record after boot.

## Bounded next live sequence (requires separate grant)

1. Recheck no C50 image holder, no ban record, source identities, free display
   `:112` and ports `15750`–`15753`. Start an independent primary `15500/15501`
   SYN recorder **before** lab bootstrap. Start display and ordinary isolated
   SheepShaver from the owned C50 runtime; do not enable a data bridge. Prove
   actual PID/start/exe/FD6 working image/FD16 guest PCAP, unique loopback
   namespace, empty routes, namespace recorder and zero primary SYN. The fixed
   `15500` bridge may exist; it must remain unused.
2. Capture a fresh runtime JSON with actual `emulator_pid`. Regenerate the
   five plans from this repo using:

   ```sh
   python scripts/native_control_readiness.py prepare --runtime-record RUNTIME.json --port 15750 --output PLANS
   ```

   Preserve `source-hashes.json`, source plan and as-run plan SHA-256 values.
   Prepare `CAPTURE-READY.json` with `host_pcap`, `namespace_pcap`,
   `guest_pcap`, `host_recorder_pid`, `namespace_recorder_pid`, both recorder
   start times, `emulator_pid`, `emulator_starttime`, `emulator_sha256`,
   `owned_working_image`, `emulator_netns`, `ns_routes=[]`, and
   `primary_syn_count=0`. The coordinator verifies live process identities and
   24-byte PCAP headers before the first socket and each phase.
3. Run **once** inside the actual lab namespace as root (UID 0):
   `python scripts/native_control_readiness.py run --plans PLANS --binary
   MOTHRA/evidence/hotline-server-1.9/inputs/HLserver19.pef
   --capture-ready CAPTURE-READY.json --output CAPTURES`.
   Set a managed one-shot system unit with direct `NetworkNamespacePath` to
   the actual lab, retained stdout/stderr/exit and bounded runtime. Root is
   required to read the non-dumpable UID-1000 emulator's `/proc` executable and
   FD links; the emulator itself remains UID 1000. The guarded ban capture
   records `controller_uid=0`. Never target primary `15500` or use the original
   server. The coordinator stops at the first failed semantic gate and closes
   all owned sockets.
4. The 18-action first plan checks exact admin login/privileges/agreement,
   original account attributes (348), 41-entry Files listing (200), fixture
   metadata (206), one-admin roster (300), and idle 303 as a correlated
   liveness barrier. It contains no 202, HTXF or full-file read. Guard 352
   proves `m-ban52-only` absent. Seed one account `m-ban52-only` with zero
   privilege and read it back. The ban plan confirms a fresh target Login107,
   target 354 zero, current 301 name/UID and 300 roster before its sole request
   110 with field113 `0002`; it omits optional field101 reason.
5. Require target type104 field101 exactly
   `You are permanently banned on this server.` (42 bytes), target EOF, one
   admin ACK and one 302, without fixing cross-socket arrival order. The **same
   existing admin socket** then reads account3, unchanged original two
   accounts/attributes, unchanged Files listing and fixture metadata, and an
   admin-only roster. Only after closing it, one fresh TRTP followed by valid
   owned-target Login107 must yield direct reply type0/id1/status1/field100
   with the same 42 bytes. Do not run full A7 after the ban, fresh-login
   postflight, ban removal or a restart.
6. Stop only owned lab/display/bridges/recorders. Independently prove actual
   emulator PID/start gone, listeners absent, primary/client unchanged and zero
   primary SYN; a stopped unit alone is insufficient. Only after that, read the
   owned image with the existing `fls`/`icat` HFS tools and export raw
   `Banned`/`Banned.bak` plus inode/size/hash metadata. Do not infer reload
   persistence or unknown file-field semantics.

The plan source reuses `native_plan`, `native_live_account_cases`, and
`protocol_capture`. Full paired host/guest control-stream reconciliation and
packet-drop receipts remain live acceptance gates. Any missing identity,
capture, account, UID, access, baseline, reply, or cleanup evidence stops the
run; there is no substitute account, retry, or weaker profile.
