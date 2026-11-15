# C135 prepared M2 operational packet — no live START

Status: prewritten only. R is the stopped `native-alias-live-01` with working
inode 1815238450. C133 and C134 receipts are under this preparation
directory. D is `state/mac-displays/native-alias-live-01` on `:121`; O is
`state/native-sessions/native-alias-live-01`; frontend 15920–15923. D/O
must remain absent until separate M2 START. Never use primary 15500/15501.

## Authority and sources

The ten prewritten scripts total 955 physical lines. `candidate-source-
closure.json` records 35 **private candidate plus canonical dependency**
protocol modules and three current Mothra helpers. It is not a root pin.
After final M1 import, `freeze-after-import.py` snapshotted canonical
bytes into `proposed-source-closure.json`, `proposed-sources/`, and
`proposed-runtime-launchers/`. Root must review that proposal and create
these currently absent approval files:
`approved-alias-live-sources.sha256`, `approved-source-closure.sha256`,
`approved-helpers.sha256`, `approved-runtime-launchers.sha256`, and
`script-SHA256SUMS`. Snapshot and pin `scripts/mac_runtime.py` plus its
subprocess target `scripts/mac_network_isolation.py` separately from the
35 protocol modules and three capture helpers. The boot script verifies
all approved hashes and exact closure entries before its first service.
The ten-entry script pin must include `ui-input-alias-live.py`.
Root-created approval pins may be mode 0444 because they contain hashes
and paths only; protected runtime receipts remain root-owned mode 0600.
The boot validator checks exact 2/35/3/2/10 pin sets and the reviewed
proposal SHA before its first managed service. A temporary, no-service
model accepted all five complete pins and rejected shortened M1,
closure, helper, launcher, and script pins.
Any changed script or source requires review and new pins; do not update
pins to silence a failed gate.

After START, run `boot-alias-live.sh` once from Mothra. It checks fresh D/O,
the owned image/ROM/executable/source closure, leaf and `.finf` identity,
original PID ticks, four ports, root fuser and lock. It fixes a single
720-second deadline immediately before the managed 900-second lease and
host-primary recorder, starts display then VM with checked dependent
commands, and performs the disk-only actual-PID gate. It does **not**
precreate the guest PCAP. Observe the owned GUI/server startup using
fresh screenshots; do not change options, accounts or clock.

After guest Ethernet is active, run
`sudo -n bash P/complete-readiness-alias-live.sh ACTUAL_VM_PID` on the host.
That root command binds the same PID to guest capture, starts namespace
recorder, runs the host-only capture receipt builder, freezes all approved
canonical local imports and helpers, generates closed 18-action control
and M2 plans, then runs only the closed control readiness in the actual
VM network namespace. It requires at least 390 seconds remaining. The
independent readiness has one TRTP handshake, one Login107 and five
numbered controls (348, 200, 206, 300, 303). No full-file A7 claim.

Root independently reviews readiness, as-run source hashes, runtime and
capture receipt, plan SHA, actual PID/FDs/namespace, zero primary SYNs and
unit deadlines before separately granting the M2 case. The case uses
one additional retained admin flow, with TRTP/Login107 then 205/200/200/
206 (IDs 10–13): eleven numbered requests total across readiness/case,
two handshakes, one protocol mutation, zero 500 barriers.

After case START, run
`sudo -n bash P/launch-case-alias-live.sh ACTUAL_VM_PID` on the host. It
requires root, sets umask 077, enforces the 390-second margin, and creates
an exclusive root-owned mode-0600 `case-begun.json` marker; an existing
marker is a hard stop. It then
starts a 240-second root managed unit inside that actual namespace.
`run-case-alias-live.sh` verifies current and frozen
sources, then invokes the 210-second controller with root-owned
`O/operator/receipt.json`, preserving `O/coordinator.stdout` and stderr.
The operator must wait for its flushed JSON `READY` with exact plan SHA,
actual PID/namespace and stage `awaiting-reviewed-Finder-receipt`, and
verify the case unit is active and no terminal report exists. No READY,
no Finder action.

The six screenshot gates in the M1 guide are: owned Unix target selected,
Finder File > Make Alias enabled, separate alias result, Finder Copy
enabled, Paste enabled, and destination alias visible. No old coordinate,
shortcut or unknown prompt is approved.
`ui-input-alias-live.py` runs as root and accepts only fixed `:121`
startup/case phases and move, click, double-click, down, up, or startup
Escape actions. Down/move/up can hold the Finder File menu for a reviewed
screenshot. It validates coordinates before X is opened,
the owned display, emulator disk receipt, PID/FD6, and fixed deadline
before opening X. Each case action also requires the exclusive case marker,
active case unit, exact READY plan/PID/namespace/count, and no terminal
report. Case input also stops 110 seconds after the exclusive case marker,
even if the managed unit remains active; this leaves ten seconds inside
the controller's 120-second Finder receipt wait. Root queries UID 1000's
display manager through its explicit user
bus, reads the protected disk receipt and writes a mode-0600
`O/operator-inputlog.jsonl` with before/after timestamps. The no-X model
read a root-owned mode-0600 receipt and queried that user bus successfully.
Root reviews fresh UI images and exact actions separately; the helper
does not certify Finder selection or a copy by itself.
After selecting the copied HFS alias, root may inspect at most one
identified Get Info / General Information window without modifying it.
The visible Original must identify Unix and the exact owned leaf. Save
the extra image and binding JSON under `O/operator-extra/`, separate
from the six receipt screenshot keys, then close only that known window.
Do not use Find, Locate or Select New Original. If the Original is not
visibly bound to the owned Unix leaf, stop M3; no target unlink is allowed.
Use user-owned raw screenshots,
then root-reviewed copies plus root mode0600 receipt and exact hashes in
`O/operator/screens/`; the receipt is created **after** real UI actions,
never from the illustrative generator. The controller may see Finder
metadata position/flag changes, but target bytes/inode and sidecar type/
creator remain guarded. On ambiguity, stop UI input and allow bounded
controller failure; preserve partial frames and tails. No host unlink,
transfer, second alias or retry in M2.

On terminal case success or failure, capture final unit/journal/drop/host
and namespace PCAP receipts. Retire only owned app, VM, bridges, display,
recorders and lock before the same deadline. Prove actual emulator PID
gone, original PID ticks unchanged, primary SYN count zero and root fuser
exit1/empty output for the working image before stopped HFS catalogue,
Finder flag or `alis` fork reads. If forced TERM follows app Quit, label it
forced; do not call it orderly Mac shutdown. Quarantine the image. No
control postflight with a fresh login, cleanup request, or M3 unlink is
part of this packet. Root reviews positive 206 and stopped alias proof
before any new M3 decision.

`build-runtime-alias-live.py` records only the emulator's `TZ` environment
entry or absence and the host `/etc/localtime` pointer. It does not dump
full process environment or infer the Mac clock from host timezone.
