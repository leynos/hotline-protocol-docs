# C110 stopped preparation plateau — native rate 304 lab 02

Status: **prepared, stopped; no live START**. The failed lab 01 remains quarantined
at `state/mac-runtime/native-rate304-01`; nothing here resets or reuses it.

## Exact owned paths

- `R=state/mac-runtime/native-rate304-02` — prepared from the **immutable,
  stopped** `native-board-02/base.dsk` and ROM, never from a working image.
- `D=state/mac-displays/native-rate304-02` — intentionally absent until an
  approved boot, display `:120`.
- `O=state/native-sessions/native-rate304-epoch-02` — intentionally absent;
  future capture and service receipts, frontend `15880`–`15883`.
- This preparation directory holds commands, outputs and source snapshots.
  No tracked repository file was changed.

`preflight.json` records root fuser exit 1 with empty output for both stopped
immutable sources **before** source byte reads. Source base inode 1678261666,
mode 0444, SHA `e5cbbaaf…`; source ROM inode 1678261665, SHA `18da89e4…`.
Hashes/stats matched after preparation. The new independent base inode is
77099976 (0444), working inode 65602436 (0644), ROM inode 65578607 (0644).
New base and working each match `e5cbbaaf…`; new ROM matches `18da89e4…`.
Available space fell from 161,076,883,456 to 160,425,984,000 bytes.
`prepare.py` records exact `mac_runtime.py prepare` argv and exit 0.

Root fuser exit 1 and empty output on the new base, working, ROM is repeated
in `supplement.json`. Future display directory/socket and epoch path are
absent, and ports 15880–83 are free at this preparation time. Primary PID
1099659/start 767842 and client PID 1012834/start 2357813 still match.
The full and allocated HFS catalogues each have 5,504 lines; only original
admin and fixture-low UserData are allocated. Five named forks have exact
baseline SHA: admin `26612ad…`, fixture-low `fce813…`, Prefs `4ed2b3…`,
server DATA `ad7040…`, RSRC `fe83a2…`. MessageBoard catalog 11191 has
DATA/RSRC size 0, TEXT/ttxt. No `Banned` path is allocated. No account edit.

## Reviewed source proposal, not approval pin

Current B91 `native_rate304_cases.py` SHA is `1c95329c…`; control SHA is
`9c25e60b…`. Root subsequently supplied an exact two-entry
`approved-rate304-sources.sha256`; it checks against current canonical files.
`proposed-source-closure.json` records the full 35-module AST
local import closure and two Mothra helper hashes. `proposed-sources/` contains
those exact current bytes, including `native_board_cases.py` and
`native_board_control.py`. The proposed closure is review evidence; the
two B91 source hashes are now root pinned. The
existing B83 helper pin names SHA `e3faecd2…`; capture readiness helper SHA
is `7a75f4b7…`. At live runtime, `build-runtime-r02.py` copies and checks the
entire transitive closure again. `run-case-r02.sh` compares **all 35 frozen
copies and both helpers** against current origins before the first case
socket, writing `source-prerun-check.json`; it also checks the two approved
source pins. Any drift aborts before case traffic.

## Future gates requiring separate START

1. `boot-r02.sh` is prewritten and static checked. It refuses existing D/O,
   repeats **root fuser no-holder proof for all three owned image/ROM paths
   before hashing any of them**, confirms their inodes/hashes, then fixes one
   hard deadline exactly 720 seconds after first managed lease start.
   It starts an exclusive finite 900-second SYSTEM lockholder and a host
   primary-SYN recorder before display/VM. Its bounded five-second waits
   require live managed PID/FD and a 24-byte PCAP header before capture
   readiness. `wait-emulator-r02.py` independently identifies one actual
   UID1000 emulator within five seconds by pinned exe SHA, FD6 working inode,
   FD16 guest PCAP/header, start tick and netns; no wrapper PID is accepted.
2. After an independently identified actual emulator PID/exe SHA `9c943…`,
   FD6 working inode 65602436, FD16 owned guest PCAP, unique loopback-only
   namespace and unchanged originals, `complete-readiness-r02.sh PID` uses
   HOST-root B83 receipt builder and a separate SYSTEM root namespace
   recorder. It freezes source closure, generates control/rate plans, then
   runs exactly one 18-action control-only readiness in the actual emulator
   namespace. It requires at least 390 seconds before the unchanged hard
   deadline. Capture units independently cover deadline +5 seconds.
3. After root reviews that receipt/plan and separately grants the case,
   `launch-case-r02.sh PID` checks that same >=390-second margin and launches
   only the approved B91 runner via direct SYSTEM root
   `NetworkNamespacePath=/proc/PID/ns/net`. Source hard case limit is 210
   seconds; managed process limit is 240 seconds. No full A7, account,
   option, clock, native-server configuration, or mxd action is included.
   B91's five retained-observer controls are in its case plan; a fresh
   18-action login postflight after a possible IP ban is not authorised.
4. On any failed gate or case, stop traffic without retry/retune. On terminal
   result, quit only the owned app/guest if possible, stop exact owned
   capture/lock/bridge/display units before the same hard deadline, prove
   actual emulator PID/start gone and root FD-free working image, zero
   primary SYN/zero drops and originals unchanged. Only then may stopped
   HFS forks and any `Banned` path be read. A forced emulator TERM must be
   labelled separately from an orderly guest shutdown. Preserve raw failure
   and do not reset the disposable image.

The prewritten scripts are `boot-r02.sh`, `complete-readiness-r02.sh`,
`build-runtime-r02.py`, `wait-managed-r02.py`, `wait-emulator-r02.py`, `run18-r02.sh`,
`run-case-r02.sh`, and `launch-case-r02.sh`. `script-SHA256SUMS` binds their
reviewed bytes. Bash syntax, ShellCheck, Python compile, and embedded case
source-gate AST parse passed offline. None of those launch scripts was run.
