# C149 R03 offline operational packet

Status: prewritten only. This packet grants no service, VM, Finder input,
protocol or host unlink. R03 stopped preparation belongs to B123. P is
`state/native-sessions/native-alias-live-preparation-03`; D is the new
`state/mac-displays/native-alias-live-03` at `:124`; O is the new
`state/native-sessions/native-alias-live-03`; frontend 15980–15983.
R02/O02 and their evidence remain unchanged. R03/D03/O03 are not claimed
ready by this operational author.

## Exact sources and approval boundary

The ten P03 scripts are adapted from accepted P02 operations. Source
proposal bytes come from the canonical protocol head
`beaf0b598081990be63e59403b9c90b85b3eaa3b` after M1b import. The
M1b pair is `native_missing_alias_cases.py` SHA `5c497aec...c0a759`
and `native_missing_alias_control.py` SHA `c467976e...ccd90`.
`candidate-source-closure.json` and `proposed-source-closure.json` are
review inputs. The latter freezes 35 canonical protocol modules, three
capture helpers and two launchers. All actual P03 script, helper,
launcher and protocol bytes must match root-created exact public pins
**before the first managed service**. Those five approval pin files are
absent at this plateau. A changed byte after root pinning stops work.

B123 alone creates P/stopped-preparation/preflight.json and
finf-supplement.json after root FD-free, immutable source hashes, target
DATA20 and `U54TM54X` sidecar checks. Boot derives R03 base/working/ROM
inodes from that reviewed receipt; it does not reuse R02 inode numbers.
Current generic readiness checks disk FD6 and lazy guest capture FD16.
They are reviewed helper requirements, not a general claim that all
emulator runs use those FD numbers. A changed actual FD must stop for
separate helper review, with no observer bypass.

## Future ordered live grants

1. A separate root BOOT START may run `boot-alias-live-03.sh` once as
   UID1000. It checks all pins, R03 stopped receipts and root fuser
   before image hashes, primary/client PID ticks, lock/display/ports;
   fixes one 720-second deadline just before the finite 900-second
   lease and host-primary recorder; starts display then VM and passes
   the disk-only actual-PID gate. No guest PCAP is precreated. The
   root-only no-X display identity capture binds actual Xvfb PID/start/
   exe/UID/argv before later X input.
2. Root supervises normal guest server startup. Once guest Ethernet
   opens, the existing generic CAPTURE phase runs on the HOST as root,
   binding the same disk-receipt PID/start/image/ns and writable guest
   PCAP. This is separate from `complete-readiness-alias-live-03.sh`.
3. **Operator checkpoint:** by `epoch-start.utc + 270 seconds`, the
   sole owned Unix target must be visibly selected in Finder; Unix and
   the owned HFS Files parent must be visible; root must review and
   fsync mode-0600 `O/prestage/reviewed.json`, matching screenshot/
   disk/capture hashes, PID/start/ns/display and no alias/prompt. If
   this checkpoint is missed, stop before new Hotline readiness and
   retire within the original 720 seconds. The checkpoint adds no
   machine guard and never lowers the separate >=390-second case gate.
4. Only then may root grant complete-readiness: namespace recorder and
   host-root capture receipt first, current full `.finf` SHA pinned
   **once** in runtime JSON after Finder selection, exact source
   closure frozen, closed18 control captured once in actual namespace.
   Root independently checks semantic readiness and the unchanged
   >=390-second margin before a distinct case START. Closed readiness
   includes its own 206; it does not exercise alias resolution.
5. A distinct case START may launch the finite 240-second system root
   namespace unit and M1b 210-second controller. A valid READY binds
   plan SHA, PID/ns and three pre-Finder numbered requests. Every case
   X action requires the current active unit, no terminal report and
   `case-begun.utc <= now < case-begun.utc + 110 seconds`; controller
   Finder wait remains 120 seconds. The sole positive M2b case allows
   one Make Alias, one Copy/Paste and a reviewed read-only Original
   observation, never host unlink or M3. Failed UI gates end input,
   preserve raw report/tails and never fabricate a Finder receipt.
6. On terminal case or explicit pre-case abort, root may separately
   approve the helper's narrow retirement phase. Each fresh screenshot
   binds one named Quit control and optionally one subsequent Quit Now.
   An attempted click consumes that control even if X errors. If there
   is no recognized control or time remains insufficient, stop the
   owned VM and label forced retirement truthfully. Only after actual
   PID gone and root FD-free proof may stopped HFS bytes be read.

## Offline validation and limits

Use Bash syntax/ShellCheck for five shell scripts, Ruff/AST for five
Python scripts and embedded Python blocks, exact source/snapshot/script
SHA checks, and no-X models for display replacement, live executable/
FD16 replacement and attempted Quit replay. Test full 2/35/3/2/10
pin sets and one-short failures in temporary files, not real approvals.
Scripts cap 1,300 physical lines; this packet plus the separate operator
checklist cap 180 prose lines; no new dependencies, generic API or
tracked code changes. Revalidate all source hashes if canonical code
changes before root pinning. No START is implied by this packet.
