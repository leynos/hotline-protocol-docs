# C145 offline P02 implementation — no live START

Status: ten P02 scripts staged, not approved for a live call. New R02 is
owned by B119. This packet did not copy a disk, start a service, open X or
make a socket. Canonical M1 is `f6ec1a62b52366ae8f5dfa2bb26671cae09225fd`.
The first lab's P01, R01, receipts and failure are immutable.

## Authority and fixed layout

P is `state/native-sessions/native-alias-live-preparation-02`.
B119 alone writes P/stopped-preparation/preflight.json and
finf-supplement.json, after source FD and hash gates. R is
`state/mac-runtime/native-alias-live-02`, D is
`state/mac-displays/native-alias-live-02` on `:123`, and O is
`state/native-sessions/native-alias-live-02`, frontend 15960–15963.
P has no root approval pins yet. `candidate-source-closure.json`,
`proposed-source-closure.json`, proposed source/helper snapshots and the
proposed script hash inventory are review inputs only. Root must review
B119 receipts and all source/script bytes and create exact approval pins
before the first service. Never repoint a failed approval to make it pass.

The current generic emulator helper verifies disk FD 6 and capture FD 16.
These are implementation checks in its reviewed source, not a general
claim about future emulator layouts. Each actual run records the observed
FD numbers, target inodes, PID/start and namespace. If the helper rejects
an otherwise live emulator with different FDs, stop and request a separate
reviewed helper change; do not bypass or recast the failure as terminal.

## Source and image gates

The boot script checks exact M1 pair, complete proposed canonical local
import closure, three capture helpers, two launchers and all ten P02
scripts against root-created public hash pins before its first managed
unit. It verifies no D/O conflict, root fuser exit 1 for each owned
base/working/ROM before byte hashing, stopped B119 receipt inodes,
source hashes, exact owned 20-byte leaf and 32-byte Finder sidecar,
primary/client PID ticks, free ports and free oracle lock. It starts one
fixed 720-second epoch with 900-second capture/lease units. No working
image byte is read after boot. Source freeze takes the current canonical
imports, hashes them against root approval and copies them once into O.
`initial_finf_sha256` is read from the full current sidecar **after**
reviewed Finder selection. The stopped preparation hash remains a distinct
`prepared_finf_sha256` provenance field. No subsequent re-pin is allowed.

## Staged live sequence, each requiring root START

1. Boot once using `boot-alias-live-02.sh`. It checks inputs, starts the
   direct managed lease and host primary-SYN capture, display and VM in
   that order, then performs the disk-only gate. Guest PCAP is lazy and is
   never precreated. Observe normal guest/server startup from fresh
   screenshots. Unknown prompt stops; no account, Options or clock change.
   A root-only no-X call after display startup freezes its actual PID,
   start tick, Xvfb path/hash, UID and command in O/display-identity.json;
   every later X input rechecks that same chain.
2. Run the existing generic capture-phase helper on the HOST as root,
   after guest Ethernet activity and before Finder prestage. Its exact
   reviewed arguments are: `--phase capture`, R/working.dsk, the
   `prepared["working.dsk"]["inode"]` from B119 preflight,
   executable SHA `9c943042...b743c4`, UID1000, O/case-deadline.utc,
   `--disk-receipt O/disk-ready.json`, `--guest-pcap O/lab-guest.pcap`,
   `--output O/guest-capture-ready.json`. Keep its command, output, exit
   and full 24-byte guest header. A different capture FD stops here.
3. Use `ui-input-alias-live-02.py startup` only against the fresh owned
   `:123` display. Review the actual Finder and Unix volume from new
   screenshots, select the single owned leaf, then create root-owned
   mode-0600 O/prestage/reviewed.json. It names the same PID/start/ns,
   display `:123`, `finder_target_selected_reviewed`, target name,
   `finder_visible`/`unix_volume_visible`/`hfs_files_parent_visible`,
   no alias/prompt, the SHA256s
   of O/disk-ready.json and O/guest-capture-ready.json, and fresh
   O/prestage/screens/{finder,unix,target}.png SHA256s. If selection or
   target identity is ambiguous, stop before any Hotline socket.
4. Run `sudo -n bash P/complete-readiness-alias-live-02.sh ACTUAL_PID`
   only after that receipt. It verifies same disk/capture PID/start/exe/
   UID/ns, Finder review and current full sidecar, starts namespace
   capture, builds host-root managed receipt, freezes source, generates
   the closed18 and M2b plan, and runs exactly one closed18 readiness in
   the actual namespace. Require >=390 seconds remain before case grant.
   Root independently reviews all raw receipt/plan/runtime/stream gates.
5. After a separate case START, run `sudo -n bash
   P/launch-case-alias-live-02.sh ACTUAL_PID`. It creates one exclusive
   root0600 case marker and a direct SYSTEM root namespace unit capped
   at 240 seconds. READY must match exact plan SHA, PID/ns and count 3;
   each case UI action must occur before marker+110 seconds and pass the
   current active-unit/no-final-report gate. Perform one Make Alias,
   one Copy/Paste, and only the reviewed read-only Original inspection.
   No host unlink or M3 action belongs in this packet.
6. On terminal case or explicit root0600 pre-case abort, use the narrow
   `retire` phase only with a fresh root0600 O/retire-approved.json tied
   to same PID/start/display/deadline and named screenshot controls.
   Exactly one Quit and, if it appears, one Quit Now click are allowed.
   Each click has its own fresh image hash/coordinates and 60-second
   review window. No alias action, Escape or general key is allowed in
   retire phase. If a recognized control is unavailable, stop the owned
   VM before the same deadline and label the retirement forced. Only
   after actual PID gone and root FD-free proof may stopped HFS be read.

No phase implies permission to run the next. No image reset, second
Finder action, changed endpoint or new protocol request is authorized.

## Offline acceptance and pending gates

Run `bash -n` and ShellCheck on the five shell scripts; Python compile
and Ruff on five Python scripts; an AST read on embedded Python blocks;
compare all ten script hashes, canonical M1 pair, full local import
closure and three-plus-two helper/launcher snapshots. Model short or
malformed approval pins in a temporary copy, never P02. Import the UI
helper without X and test its case cutoff at 109/110 seconds, future
start rejection, invalid coordinates/action and root-only retire rules.
The script tree must remain at ten files and below the root-approved 1,300
physical script lines (actual 1,291); identity guards raised the earlier cap;
this prose below 180. Root independently reviews the B119 stopped
receipts, final scripts, proposal and no-service validation before any
later live START. Current P02 has no approval pins and no prepared R02
claim from this agent.
