# Observe a genuinely missing Hotline alias target

> Record note (2026-11-16): this is a working record, kept as written. It was
> written in the capture toolset's repository before the evidence and records
> moved here, so the paths and revision numbers in it describe that time. The
> gap audit is now at the revision named in the
> [gap register](../../../gap-register.json); refer to the register for the
> current number.

Current plateau, 2026-11-14: R04 is retired after the parent's pre-stage
receipt missed the hard checkpoint. No protocol request or alias ran.
`native-alias-prestage-abort-02` retains the GUI, cutoff and stopped checks.
All original criteria remain; audit88 has62 Resolved,24 Investigating,1 Open.
Any R05 work is offline only until a new reviewed execution grant.

This document belongs to the [provenance](../README.md) set; the
[glossary](../../glossary.md) defines the terms it uses.

This ExecPlan is a living document. Status: M1 COMPLETE after A136 review and
609 native tests. The first M2 epoch ended at the Finder receipt timeout,
before alias creation or 206. Its stopped image is quarantined. The reviewed
failed-prefix corpus preserves that outcome. M2b source preparation is approved
within the bounds below; a new native START and M3 host unlink remain subject
to separate root gates. GAP-054 remains Investigating.

## Purpose and observable result

Hotline Server 1.9 can resolve an alias whose target was moved to Trash. That
target is still findable, so the existing fixture cannot answer what the server
does when the target is genuinely absent. This plan first proves a newly
created alias resolves a known file on an owned Unix volume, then tests that
**same** alias after only that file is removed. Success is a portable capture
of the before/after native 200, 206 and bounded transfer outcome, with exact
file identity and paired packet evidence. An unsupported Finder operation,
modal dialog or timeout remains a measured partial result, not a successful
missing-target fixture.

## Context and orientation

Run commands from `/data/leynos/Projects/mothra`; the sibling
`../hotline-protocol-docs` holds protocol scripts and contracts.
`scripts/mac_runtime.py prepare` makes a new Mac disk/ROM copy and a `shared/`
directory; `sheep --isolate-network --service` mounts that directory as
SheepShaver's guest Unix volume (`extfs`) and forwards four namespace-local
ports. It isolates networking, not the host mount.
`tools/macemu/SheepShaver/src/extfs.cpp` calls host `stat` for catalogue/info;
`src/Unix/extfs_unix.cpp` stores Finder/resource sidecars in `.finf` and
`.rsrc`. This suggests a host unlink can remove an extfs target, but does not
prove the Mac Alias Manager cannot re-find or cache it.

The original server binary is the retained
`evidence/hotline-server-1.9/inputs/HLserver19.pef`, DATA SHA-256
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`; its
resource fork SHA-256 is
`fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12`. Use
immutable stopped base SHA-256
`e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910`, ROM SHA-256
`18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd`, and
SheepShaver executable SHA-256
`9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4`. Resolve
current source paths against those hashes **only after** root FD-free checks;
do not infer they remain immutable by name. Never read or copy original live
working images.

The native-alias corpus `evidence/gap-remediation/2026-11-13/native-alias-01`
covers live aliases and chains.
`../hotline-protocol-docs/filesystem-and-board-contracts.md` records that
moving a target to Trash leaves native 206 reporting resolved target metadata,
and that unresolved-kind 6 has the literal `Unattached Alias` source branch.
Neither is an observed deleted-target result. Native 205 creates a directory,
native 209 makes an alias from a source the server can resolve, native 200
lists, native 206 reports file info, native 202/210 start transfers. An `alis`
resource is a classic Mac alias payload; a Finder alias flag identifies an
alias file. The proposed Finder route is **unproved**: make an alias of an
extfs file in the guest, copy it into an owned HFS Files directory, then
require a positive native 206 before considering unlink. Do not substitute a
guessed 209 extfs source.

## Conformance basis

The unchanged original `../hotline-protocol-docs/gap-analysis.md` GAP-054 says:
trace alias creation/resolution and document source, destination and
default-name rules with live, missing-target and alias-to-alias cases. The
existing corpus advances the live/chain clauses; only the genuinely
missing-target clause is assigned here. GAP-054 also depends on GAP-047 and
GAP-049; this plan must retain their separate path and 206 field rules. The
source anchors are `evidence/hotline-server-1.9/queries/D-10017c10.c`,
`../hotline-protocol-docs/filesystem-and-board-contracts.md` (especially the
alias and target-in-Trash sections),
`state/delegation/b102-gap054-extfs-feasibility.md`, and
`state/delegation/c129-gap054-missing-target-alias.md`. These ignored notes
orient this draft; the instructions and evidence needed for execution are
restated here. No separate Terms of Reference, technical design or ADR governs
this fixture.

Trace: original GAP-054 missing-target clause → M1 feasible setup and guarded
plan → M2 live-alias witness → M3 exact-object absence and native response → M4
portable contract and independent closure audit. GAP-047/GAP-049 remain
independent; no observation here changes them without a separately reviewed
impact check.

## Constraints

The user's mxd validation hold remains in force. Only new disposable images,
guest sessions, capture files and uniquely named objects under this plan may
change. Never touch the original primary/client disks, accounts, options,
clock, Files roots, Trash contents or network routes. Do not read any working
image while its emulator has an open FD. No original server port 15500/15501
contact is permitted; the fixed bridge may exist in an isolated namespace but
must be unused, with independent host SYN capture. Start captures and lease
before protocol contact and preserve every raw failure.

Use one reviewed complete source closure: protocol
generator/coordinator/verifier, `scripts/mac_runtime.py`,
capture/readiness/receipt helpers and their local imports. Record exact
revisions/hashes; root pins **all** files and reviewed scripts before the first
service. The actual emulator PID, start tick, UID, executable, working-image
FD/inode, guest-capture FD, network namespace, empty external routes, listener
ports, recorder PIDs/headers and deadline must pass current repository
runtime/capture gates. Record observed FD numbers; FD6/FD16 were prior-run
facts, not a general contract. Run guest protocol controllers as root in the
actual emulator namespace and the capture receipt helper on the host as root. A
missing capture FD is an observation timeout, not proof the emulator died;
retain the same handle and fixed deadline.

Do not infer that an alias is unresolved from a Trash move, self-cycle, missing
209 source, an error string, or an empty transfer. The exact alias must first
resolve a positively present owned target. A Locate dialog is not to be
navigated; one recognized Cancel may be approved for M3. Never extend a live
epoch or retry/retune a failed case for a preferable result.

## Tolerances (exception triggers)

The ExecPlan itself is excluded from file and size budgets. M1 may add at most
four new protocol files: `scripts/native_missing_alias_cases.py`,
`scripts/native_missing_alias_control.py`,
`scripts/test_native_missing_alias.py`, and
`native-missing-alias-preparation.md`; up to 700 production, 360 test and 120
guide physical lines, respectively. If the Finder UI needs a separate
automation file, public interface, dependency or changed harness, stop for a
bounded new packet and root review. M3 may add one exact-object host-unlink
helper and one focused test, at most 150 production and 100 test lines, only
after root approves the precise procedure. M4 may add a portable
verifier/test/guide plus one immutable corpus, at most 600 production, 250
test, 180 guide lines and 120 evidence files/24 MiB excluding bounded PCAPs.
These categories cannot offset each other; escalate before crossing any cap.

C133 may prepare only the new stopped `native-alias-live-01` runtime and
baseline receipts in parallel with M1. Before reading source image/ROM bytes,
prove them stopped and root FD-free; then verify the pinned hashes, independent
new inodes, source immutability, free capacity and original process identities.
Prepare the known 20-byte host target as UID1000/mode0600, regular/nlink1 under
this runtime's own `shared/`; do not stage a Finder sidecar until its exact
format is reviewed. Retain full stopped catalogue and five named baseline fork
hashes. This30-active-minute preparation packet permits no boot, service,
display, socket, plan generator, host unlink or working-image mutation after
preparation. Exact launch scripts and complete source-closure pins still await
M1 acceptance and separate root review.

M1 and M4 have 30 active minutes each; M2/M3 each have one 720-second live
epoch and at most 20 active operator minutes outside the managed wait. A
service/recorder cap of 900 seconds must cover its fixed case deadline plus
five seconds. M2 uses exactly the existing **separate, closed** 18-action
control-readiness plan, then at most one additional retained admin case flow
with its login/handshake, one 205, one 200 directory readback, one 200 alias
list and one 206 positive info; Finder alias creation/copy is separately
counted. M3 repeats that setup on its new image, then one guarded host unlink,
one 200 and one 206 after absence, one 202 **or** 210 only if 206 responds, and
optional one 204 owned cleanup. Thus the business-case cap is four numbered
requests in M2 and at most eight in M3; the total cap also includes the frozen
18 readiness actions and the exact case-login/handshake or 500 barrier count.
M1 must calculate and test that complete count before M2 approval, rather than
silently calling only business operations the case total. At most one
**additional** admin case flow after the separate closed preflight and one
owned leaf/alias per image. Stop if any extra account, target, request, UI
action or service is needed.

M2 case START requires at least 390 seconds remaining **after readiness, before
any Finder/positive-206 case step**. M3 case START requires at least 510
seconds after readiness; the actual unlink gate requires at least 240 seconds
remaining **after the positive 206** (120 for post probes/modal and 120 for
retirement). The fixed 720-second deadline is never extended. The allocation is
boot/readiness 180, Finder/setup/positive gate 180, guarded unlink and post
probes/modal 120, retirement 120, with 120 seconds slack. These are proposed
ceilings, not measured guest timings. If a phase exceeds its allocation or
cannot leave the stated downstream margin, stop before the next mutation. No
automatic second epoch is authorized; an unsuccessful epoch ends with
quarantined image and a new decision.

## Risks

Finder may not create an extfs alias, or copying it to HFS may lose
`alis`/Finder metadata (high severity, unknown likelihood): M2 stops before
unlink and preserves screenshots/forks. Alias Manager may re-find or cache a
removed target (medium/unknown): require exact host absence, then report the
actual response without forcing kind 6. A Locate modal or blocked transfer may
consume the remaining epoch (high/unknown): bounded observation and one
preapproved Cancel only; retire before deadline. A host path check may race
with another writer (high/low in owned volume): open parent FD, recheck leaf
inode/device/UID/mode/nlink/size/hash immediately, use literal basename and
`dir_fd` unlink, and stop on mismatch. A Mac UI coordinate may point at another
object (high/unknown): require before/after screenshots and identity checks; no
blind click or deletion. Control-only 18-action readiness is not full-file
health.

## Progress

- [x] (2026-11-14) Read original GAP-054, existing alias/Trash evidence, extfs
  harness and B102/C129 feasibility.
- [x] (2026-11-14) M1 B114 final687 production/360 test/101 guide lines,
  eight focused tests and A136 review. The full native suite passes609 tests.
  Root clarifies preparation-versus-START wording in the guide.
- [x] (2026-11-14) C133/C134 stopped candidate and tagged target prepared.
- [x] (2026-11-14) C139 operational scripts accepted by A140: ten scripts,
  955 physical lines; structural pin, privilege, held-menu and cutoff fixes.
- [x] (2026-11-14) Root created and validated all source pins before C140 START.
- [x] (2026-11-14) First M2 epoch retired after the Finder receipt timeout;
  preserve nine observed numbered requests and no alias or 206 result.
- [ ] M2b reviewed source and operational changes, fresh pre-staged GUI,
  independent approval pins and separately granted START.
- [ ] M2 fresh live-alias rehearsal, positive 206 and retirement; **no
  unlink**.
- [ ] M3 separate fresh missing-target epoch after independent M2 review and
  root authorization.
- [ ] M4 portable replay, protocol correction and original-criterion decision.

## Surprises & discoveries

The already captured Trash move keeps the target resolvable, so it cannot stand
in for deletion. The extfs volume maps to an owned host `shared/` tree, but
Finder creation/copy and Alias Manager post-unlink behaviour are not
established by that mapping. These are M2/M3 decision gates, not assumptions.

## Decision log

- 2026-11-14, draft author: split M2 positive rehearsal from M3 destructive
  host unlink. The unlink requires independent proof that the exact copied HFS
  alias resolved the owned extfs target; a separate image prevents an M2
  failure from contaminating M3.
- 2026-11-14, draft author: use native 200/206 as positive and after-loss
  controls, with 202 or 210 conditional on a responsive 206. Transfer or Locate
  UI cannot be safely predicted from the retained source. Root reviews the
  exact future unlink procedure before M3 START.
- 2026-11-14, draft author: proposing file/line/runtime ceilings for review.
  Any unknown Finder action, missing source interface or different UI path
  triggers a bounded scope decision; the plan does not grant improvisation.

## Verification plan

Invariant V1, ownership: every mutation targets only the new image, its
`shared/` regular leaf or one new Files directory/alias. A finite test over
correct/wrong UID, changed parent/leaf inode, symlink, hard link and wrong
basename must reject each unsafe unlink; save test output. The non-vacuous
positive fixture is one exact regular UID1000/nlink1 leaf with known bytes and
a matching parent FD. This verifies the repository helper's guards, not the
kernel's unlink implementation.

Invariant V2, transition: `present target + copied alias + positive 206`
precedes host absence, which precedes after-loss requests. M1
state-machine/model tests must reject missing positive 206, changed alias
identity, wrong target tags, early unlink, duplicate post request and a second
Finder action. Record a model positive path and a seeded early-unlink failure.
M2/M3 actual captures discharge native behaviour; a model cannot prove Alias
Manager behaviour.

Invariant V3, provenance: every plan/request/report frame and packet lifetime
belongs to the actual new namespace/ports and pinned sources; host primary SYN
count and capture drops are zero. Offline verifier tests with rehashed wrong
UID, missing positive 206, changed packet byte, altered source hash, missing
SYN flow and drop count must reject for semantic reasons. Pair namespace and
guest streams byte-for-byte including tails; view-specific TCP FIN/RST flags
need not match. Capture recorder events are the timing bound, not operator
labels.

Lemma L1: if the same `alis` object and owned target inode are positively bound
before unlink, and the validated leaf is ENOENT afterwards, then the later
206/transfer probes concern a genuinely missing target for this extfs-origin
alias. Discharge with before/after catalogue/forks, host FD/stat/unlink receipt
and correlated native IDs. This lemma does not assert the server must return
`Unattached Alias`; its observed outcome is the answer. A changed alias
resource or identity forces a narrower conclusion.

External axioms: the committed SheepShaver extfs mount exposes `R/shared` and
uses host filesystem lookup; POSIX `unlinkat` removes the named leaf after
successful exact checks; Mac Finder/Alias Manager semantics are external and
**untrusted until M2/M3 observations**. A post-retirement HFS snapshot cannot
by itself prove earlier state. No new universal invariant, protocol
implementation or proof of all Mac aliases is claimed.

## Retained Finder basis and remaining live gates

The portable `evidence/gap-remediation/2026-11-14/alias-ui-basis-01` corpus
retains the actual Finder File menu with **Make Alias** (Command-M), Finder
Edit **Copy/Paste** entries, Unix volume screenshot and C132's scoped review.
The earlier application-copy witness is
`evidence/gap-remediation/2026-11-13/mac-peer-isolated-session-01/B20-observation.txt`.
Root inspected the File menu image. These identify named controls for M1; old
coordinates, Edit-menu enablement and application fork preservation do not
prove the new alias operation will work.

M2 may select only its owned Unix target, confirm Finder is active and Make
Alias enabled, invoke that named item once, and stop on an unexpected prompt.
Only a positively separate resulting alias may be selected for one enabled
Copy, followed by one enabled Paste in the identified owned HFS destination.
Stop on disabled commands, overwrite prompts, ambiguous source/destination or
missing alias identity. Do not substitute shortcuts or another copy route. The
operator retains fresh screenshots at every gate. The coordinator waits for an
explicit reviewed operator receipt; it does not guess coordinates or invoke
arbitrary commands. Native206 and stopped HFS alias-resource checks then decide
success. No host unlink is authorized in this rehearsal.

This resolves B109's missing-control-label objection without another boot. It
does not claim extfs alias creation/copy success in advance. If M1 discovers
another required control is unidentified, return that exact missing step for
review; a passive UI-only epoch would need its own bounded START packet.

## Read-only original-target binding

B115 finds an existing resource-map walker that can extract `alis` ID0, but no
local primary AliasRecord target-field parser. Searching its bytes for a
filename is not a complete target-binding proof. M2 may therefore make one
read-only Finder Get Info observation of the newly copied HFS alias before
publishing the operator receipt. Inspect the observed File > Get Info menu;
activate only an explicitly labelled general-information entry. Stop if that
entry or its meaning is unclear. Read the Original field; both the Unix volume
and exact owned target basename must be visible. Do not activate Find Original,
Select New Original, Locate, sharing, rename or other controls. Close only the
identified information window with its close box.

Retain `O/operator-extra/alias-original-info.png` and a separate reviewed
binding receipt with its hash, visible volume/leaf and alias identity. These
are additional supervisor evidence, not extra keys in the controller's exact
six-screenshot receipt. This adds one information-window observation and no
Hotline request or target mutation; the120-second UI wait and fixed deadline
remain unchanged. If it cannot fit or the path is ambiguous, stop without
unlink. Actual206 tags, host identity, stopped Finder alias flag and `alis` ID0
remain mandatory. A reviewed structural AliasRecord parser is an alternative
later basis, not an assumed capability. M3 stays gated until the complete
binding chain is independently accepted.

## Corrected positive-resolution proof

A130/A131 trace the retained206 handler and native alias fixtures. Field207 is
the resolved target's DATA-plus-resource aggregate in those successful
file-alias cases:333 equals16 DATA plus317 resource bytes, while the aliases'
own forks total540/546. Never call that value the alias file's own size or use
it alone as a target DATA-length proof.

Before boot, stage only the owned target's32-byte
`R/shared/.finf/m-alias54-target` as UID1000/mode0600, regular/nlink1. Its
bytes are `U54TM54X` plus24 zero bytes: type `U54T`, creator `M54X` at FInfo
offsets0/4. Pin the parent/leaf identity, length and full hash. The retained
Unix extfs implementation reads16-byte FInfo plus16-byte FXInfo; this is a
source-backed staging format, not an already observed alias result. The target
DATA remains exactly20 bytes with its separately pinned hash.

Positive206 requires status0 and exactly one of each field:201 equals the
copied alias name from the reviewed UI receipt;205 is the twelve bytes
`553534542028616c69617329` (`U54T (alias)`);206 is `4d353458` (`M54X`); 213 is
`55353454` (`U54T`). Reject bare `U54T`, `Unattached Alias`, wrong or duplicate
tags, a mismatched name, error, timeout or unknown modal. Record 207 as
observed; no new202/210 read is authorized to repair a failed gate.

Before and after Finder interaction, require the same owned target inode, UID,
regular/nlink1, DATA bytes/hash and stable type/creator bytes. Record
full32-byte Finder-info hashes at both times. Finder may update other flag or
position bytes: a full-sidecar hash change is not silently restored or
mislabelled as a protocol result. Retain the actual metadata and reject
identity/type/creator changes. Correlate the live tuple with the sole owned
host target and the later stopped HFS catalogue, Finder alias flag and `alis`
ID0, with Unix-volume/leaf binding established by the reviewed
information-window evidence or a structural record parser. Both parts are
needed; 206 alone does not name a host pathname. This establishes a bounded
positive metadata-resolution witness, not a downloaded DATA-content witness.

The four business requests and single retained case flow remain unchanged. M1
tests must reject an ordinary copy, unattached alias, wrong/duplicate fields,
forged UI/host identity and207-only size proof. C133 may stage the exact
reviewed sidecar while stopped, under a separately recorded receipt; it may not
modify the source base or ROM or launch the guest.

## M1: offline packet and guarded rehearsal design

Produce the four bounded protocol files using existing
`../hotline-protocol-docs/scripts/protocol_capture.py` and
`native_control_readiness.py`, plus Mothra
`scripts/native_emulator_readiness.py`, `scripts/capture_readiness.py` and
`scripts/native_capture_receipt.py`. Confirm actual imported APIs before
implementation; if one differs, revise the plan and obtain review. Start with
failing tests for exactly one owned target, one directory, deterministic IDs,
205/200/200/206 order, no unlink in rehearsal, source-closure pin check, UI
gate and stop-on-ambiguity. Then implement the minimal producer/coordinator and
rerun focused tests. The coordinator must retain raw frames/events/tails and
terminal status on failure; it may drive only the reviewed Finder action
sequence. Do not automate an unknown menu or assume extfs alias support.

The retired first M2 used `native-alias-live-01`, display `:121` and
15920–15923. Never reuse that working image. The fresh M2b proposal uses
`state/mac-runtime/native-alias-live-02`, display directory
`state/mac-displays/native-alias-live-02` on `:123`, session
`state/native-sessions/native-alias-live-02`, frontend 15960–15963. Propose M3
**different** runtime/session `native-alias-missing-01`, display `:122`,
frontend 15940–15943. These are suggestions, not reservations: check
absence/free resources and immutable source hashes at each START; refuse an
existing path. The owned leaf is `R/shared/m-alias54-target`, UID1000/mode0600,
exact DATA `alias54-live-target\n` (20 bytes), nlink1; new Files directory
`m-alias54-only`. Name collisions or other same-name leaves stop the packet.

M1 exit evidence is deterministic plans, tests demonstrating fail-closed
guards, a reviewed UI action proposal grounded in existing
screenshots/resources, a reviewed root FD-safe unlink specification **not
executed**, source closure and proposed commands. New guest screenshots belong
to M2. If Finder controls cannot be identified read-only from existing
resources, stop and request a separately bounded UI inspection milestone; do
not approve M2 by guessing coordinates. M1 changes are committed as one
reviewable plateau after Ruff, ty, focused unittest, Markdownlint and Nixie. It
leaves the genuine native result unknown.

## M2: one positive-resolution epoch without host unlink

Root separately reviews M1 and gives M2 START. Prepare the new image from a
stopped immutable base/ROM using
`python3 scripts/mac_runtime.py prepare R
--rom IMMUTABLE_ROM --disk IMMUTABLE_BASE`
only after confirming R absent, source FD-free and hashes pinned. Start
managed direct system lease and host primary-port recorder before display/VM;
start namespace recorder after actual PID identity. Use
`python3 scripts/mac_runtime.py display D --display :123` and then
`python3 scripts/mac_runtime.py sheep R --display :123 --port 15960
--guest-pcap O/lab-guest.pcap --service --isolate-network`
as **dependent checked commands**. Do not precreate the guest PCAP; readiness
is staged disk-FD then capture-FD after normal owned server GUI startup. The
exact as-run commands, unit properties, PID/FDs, source closure, full PCAP
headers and fixed deadline are frozen before contact. Endpoint for the root
controller is `127.0.0.1:15960` inside the actual VM namespace, never 15500.

Run the unchanged control-only 18-action readiness, then one 205/200 setup and
the reviewed Finder alias creation/copy; this is a mutating guest UI rehearsal,
not a read-only one. While live, use GUI and protocol-side observations only;
do not extract HFS bytes from the working image. Run the exact 200/206 positive
probe. Acceptance M2 is a 206 correlated to the copied alias with the exact
resolved-tag tuple below, plus captured host target inode/DATA hash and stopped
alias binding. Field207 is not a DATA-only length and is observed without
a20-byte equality assertion. If not positive, M2 records a stopped feasibility
failure and M3 is blocked. **No host unlink or after-loss probe occurs in M2.**
Quit only owned app/VM, prove actual PID gone and root FD-free, then extract
catalogue/Finder flag/`alis` ID0 and both alias forks from the stopped image.
Quarantine it; never reset it for M3. Independent replay and root review of
this positive gate and stopped alias identity precede M3.

## M3: one separately authorized missing-target epoch

M3 is conditional on an accepted M2 positive result and root review of the
exact-object unlink helper and UI Cancel policy. Use a **fresh** absent runtime
and the same source/ownership gates; repeat the exact positive sequence once on
its own alias. A previous image's 206 or stopped `alis` snapshot cannot
authorize deletion in this image. Before unlink require GUI/protocol alias
identity, correlated positive206 with the distinct resolved-target tags below,
exact host leaf identity, capture views, current namespace, fixed deadline and
120-second retirement reserve. Compare M3 `alis`/fork bytes only after this VM
stops; do not read its live working image to satisfy the pre-unlink gate.

The reviewed helper opens the owned `R/shared` parent FD, compares recorded
parent device/inode, and uses `lstat`/`fstat` to reject symlink, nonregular
file, unexpected UID/device/inode/size/hash, nlink !=1, a changed basename,
mount ambiguity or open target handles. It unlinks the literal basename using
`dir_fd`, records return, then requires exact-leaf `lstat` ENOENT. It neither
removes sidecars nor touches Trash or an HFS file. A failed check performs
**zero unlink** and ends the experiment. Keep the alias on HFS and run only one
200/206 and conditional one 202 **or** 210. Record status/fields and complete
control/data lifetimes; if a recognized Locate modal appears, capture it and
use only the separately approved one Cancel. A timeout or unknown prompt stops
further requests. Optional 204 cleanup is allowed only after status and
identity checks and within retirement margin; quarantine instead if unsafe.

Retire all owned units before the same fixed epoch deadline, verify original
primary/client identities and zero primary SYN/drop counts, actual VM PID gone
and root image FD-free, then extract exact alias forks/catalogue and target
absence. M3 acceptance is a bounded native response to an owned target that was
first positively resolved and then proved absent. It does not require a
particular success/error/kind-6 result. If 206 blocks, the retained
modal/timeout is a partial observation, not closure.

## M4: portable evidence and protocol decision

Freeze complete plans, as-run commands, statuses, frame/event streams, paired
namespace/guest PCAPs with SYN-scoped tails, host SYN/drop journals, UI images,
pre/post source and file hashes, stopped HFS forks, unit/lease/retirement
receipts and negative controls. Keep ROM/disk/executable and secrets out of the
portable corpus. New verifier
`../hotline-protocol-docs/scripts/verify_native_missing_alias.py` must replay
both M2 and M3 offline from a fresh adjacent two-repository export, without
VM/Ghidra/mxd. Tests must include checksum-refreshed semantic faults, not only
stale-hash failures. The guide
`../hotline-protocol-docs/native-missing-alias-witness.md` must state precisely
whether M3 gives a genuine missing-target outcome or only a partial
modal/timeout; update `filesystem-and-board-contracts.md` and GAP-054 through a
separately reviewed root-owned integration. Do not mark GAP-054 resolved merely
because a script passes.

At each plateau, check conformance: original GAP-054 clause unchanged;
extfs-only scope explicit; no original object, account, option, route or
deadline changed; no new dependency/public API/persistent format; source and
evidence hashes agree. If any item fails, record the exact variance in Decision
log, set BLOCKED and request the smallest root decision. No compatibility shim
is planned.

## Commands, gates and recovery

For M1/M4 focused checks, from Mothra use
`python3 -m unittest discover -s
../hotline-protocol-docs/scripts -p 'test_native_missing_alias*.py'`,
`ruff format --check ../hotline-protocol-docs/scripts/native_missing_alias*.py`,
`ruff check ../hotline-protocol-docs/scripts/native_missing_alias*.py`,
`ty
check --extra-search-path ../hotline-protocol-docs/scripts --python
tools/ghidramcp/.venv/bin/python scripts ../hotline-protocol-docs/scripts`,
and `make markdownlint nixie`. Match actual executable paths/repository Make
targets during M1 and record exact exits; if a tool is missing, stop and update
this section before claiming a gate. The root later runs the exact
`test_native*.py` suite; broad discovery that includes held mxd checks is not a
native acceptance gate. For M4, add verifier default and `--corpus PATH` runs
against a fresh committed adjacent export; expect an explicit success receipt
and all negative controls to reject the intended semantic mutation.

> Record note (2026-11-16): the focused unittest command in this section is
> quoted as it was planned. Its test module has since been brought to the
> repository's Python standard and now lives at
> `scripts/tests/test_native_missing_alias.py`, which runs under pytest as
> `uv run --group dev pytest scripts/tests/test_native_missing_alias.py`. The
> `mac_runtime.py` commands belong to the mothra toolset and are not restated
> here.

For live M2/M3, record `python3 scripts/mac_runtime.py --help` and
`python3 scripts/mac_runtime.py sheep --help` outputs before exact command
approval. The commands above are templates until path/free-port/source-closure
pins and managed unit names are reviewed. A single failed
capture/readiness/positive/unlink gate stops further contact, preserves raw
evidence and retires within the immutable deadline; do not restart or reset the
image. Commit each complete plateau with a temporary message file and
`git commit -F` under the shared repository lock. Never push, merge or publish
by implication of this plan.

## Outcomes & retrospective

M1's four-file offline packet is accepted after eight focused tests and A136
review. A duplicate-row concern was withdrawn when the imported decoder and a
coordinator integration test proved existing rejection. A real-file regression
reproduces timestamp-only rejection; identity/content checks now preserve
timestamps without requiring equality. READY exposes the checked 205/200
handoff before operator input. All609 native tests and source/type gates pass.
C133/C134 prepare the stopped copy and exact target tags; no guest has booted.
C136 launch scripts still require independent review.

The evidence does not yet establish that Finder can create an extfs-origin
alias that Hotline resolves or its response after true target loss. M2–M4
remain outstanding, and all 87 original protocol criteria are unchanged.
Further mxd validation stays on hold.

Revision note, 2026-11-14: B109 correctly stops before guessing Finder input.
C132 supplies retained named menus and prior application-copy evidence; root
freezes that basis and permits M1 to use an explicit operator UI gate. Keep
actual alias creation/copy and positive206 as M2 observations. No extra UI-only
boot, native START or host unlink is authorized by this revision.

Revision note, 2026-11-14: Permit bounded stopped C133 preparation in parallel.
B110 identifies that206 field207 is an aggregate rather than target DATA
length; the positive proof rule is under A130 review before coordinator
implementation. No size-equality assertion or native result is authorized while
that correction is unresolved.

Revision note, 2026-11-14: Accept the A130/A131 metadata predicate for M1.
Correct the DATA-length assumption using resolved-target type/creator and
alias-form fields, host identity and stopped alias-resource binding. Keep 207
observational; stage one exact owned Finder-info sidecar. No data-channel or
request-count expansion, native START or host unlink is authorized.

Revision note, 2026-11-14: B111 stops at the production-size exception:
formatted producer/coordinator total605 lines against550. Root increases only
production to700 for explicit pre/post host DATA/Finder-info identity guards,
operator screenshot receipts, exact206 tags, runtime/capture gates and partial
I/O retention. Four files,260 test/120 guide lines and experiment scope stay
fixed; allow20 additional active minutes. No guard may be dropped to fit.

Revision note, 2026-11-14: A134 finds that set equality accepts duplicate alias
listing rows despite the exact-one-entry requirement. Authorize a bounded B112
correction with320 test lines (previously260), keeping700 production/120
guide/four-file limits. Preserve a failing duplicate-row fixture before fixing
the predicate; allow20 active minutes for review fixes. No native START or
scope expansion follows.

Revision note, 2026-11-14: A135 withdraws A134's duplicate-row finding: the
imported decoder already rejects duplicates before returning a dict. B112
verifies that existing guard through the actual coordinator; no production fix
was necessary. B113 corrects a separate reproduced issue: extfs Finder-info
writes can quantize targetmtime to seconds without changing inode or DATA.
Preserve timestamps but exclude them from identity equality.

Revision note, 2026-11-14: Add an observable operator-ready stdout event only
after the205/200 gates, carrying stage, plan SHA, PID/namespace and counted
requests. Root requires that bound event, an active owned case unit and no
terminal report before Finder input. The existing in-memory partial stage is
not externally observable while waiting. B114 may add this within700
production/360 test/120 guide lines and15 active minutes; no request, file, GUI
action or native START scope is added. UI receipt wait remains120seconds.

Revision note, 2026-11-14: C133/C134 complete stopped preparation, preserving
an overstrict-ROM-mode failure before correction. The pinned source ROM is 0644
and untouched, not permission-immutable. C135 may prewrite at most10
operational launch/readiness/case/UI/retirement scripts totalling800 physical
lines in the preparation directory, with30 active minutes. No execution,
source-plan generation or service is authorized. Complete canonical source
closure, scripts and staged receipts require independent root review before
START; all script hashes must be frozen first. The task-specific XTest helper
may address only the new display121 and must be included in that review.

Revision note, 2026-11-14: C135's nine scripts total798 lines but do not
include an executable input helper for the new display; the old helper is
hardcoded to101. C136 may add one task-specific fixed121 XTest helper and its
recorded guards, increasing only the operational preparation cap to920 lines
across10 scripts. Startup input requires owned display/PID/deadline; case input
additionally requires the bound READY event, active owned case unit and absent
terminal report. Refuse startup-mode input once the case has begun. Log actual
input arguments/times; accept no arbitrary shell commands. All code is
reviewed/pinned before START; no GUI action is authorized now.

Revision note, 2026-11-14: A137 requires three preboot corrections before any
START. Enforce exact reviewed M1(two), protocol(35), helper(three),
launcher(two) and script(ten) pin entries before the first service; a shortened
valid pin must not reach a lease. Add down/up held-menu primitives from the
retained Finder method. Run the UI helper as root to read root0600 receipts,
querying the display user manager explicitly as UID1000 while querying the case
system manager as root; keep receipt permissions intact. C137 has20 active
minutes and1040 operational lines across the same10 files for these fixes and
safe model/negative checks. Independent review remains required.

Revision note, 2026-11-14: B115 identifies the AliasRecord parser boundary.
Authorize one read-only Get Info observation on the owned alias, preserving
Original volume/leaf separately from the six controller screenshots. Keep all
wire/source/runtime limits unchanged and M3 gated on independent binding.

Revision note, 2026-11-14: Make the operator's input window explicit. C138 may
add a case-input cutoff110 seconds after the exclusive case-begun marker
(earlier than the coordinator's minimum120-second receipt-wait expiry), while
preserving the global deadline, READY and active-unit guards. This avoids input
during coordinator cleanup before its terminal report appears. Keep ten
operational files/1040 lines; no controller/request/GUI scope change.

Revision note, 2026-11-14: A139's no-X model finds future case markers pass the
upper-bound-only cutoff. C139 must require `start <= now < start+110s`, reject
future/naive markers, explicitly require root for launch-case, apply umask077
for its exclusive marker, and document sudo invocation. Ten scripts/ 1040 lines
remain the cap. Root pins and START await that narrow correction.

Revision note, 2026-11-14: A140 accepts the corrected preboot packet and no-X
boundary models. Revision 81 reviews 520 sections with 61 Resolved, 25
Investigating, 1 Open; all 87 criteria remain unchanged. Source approval, one
separately granted M2 boot and later case readiness remain outstanding.

## M2b: correct GUI readiness before another positive rehearsal

The first epoch reached login, 205 and the Files-root 200; the operator receipt
then timed out. The initial screenshot shows a screensaver and the wake
screenshot shows server windows covering the desktop. Neither proves that the
Unix volume was absent or that native alias creation was rejected. The corpus is
`evidence/gap-remediation/2026-11-14/native-alias-positive-first-01`; its
manifest, raw failed report and independent A141 review preserve the boundary.
The VM was forcibly stopped without app Quit or orderly OS shutdown. Stopped
catalogue/hash receipts describe the observed state, not durability. No alias,
Get Info, 206, transfer or unlink occurred.

Root approves only the B116 four-file source correction before another START.
The updated caps are 760 production, 430 test and 150 guide physical lines,
with a delta of at most 35 production, 35 test and 20 guide lines from M1. No
dependencies, arbitrary runtime paths, extra requests or metadata resets are
allowed. The separate failed corpus has 272 raw files plus one review, manifest
and checksum list; this exceeds the original 120-file M4 estimate because it
retains complete preparation, source and failed-session evidence. Accept that
one 275-file, approximately 12 MiB corpus as a failed witness; keep future M4
verifier/test/guide budgets unchanged.

Use only fresh live-02 paths and the fixed 15960 port after availability
checks. Preserve the old live-01 source snapshots for replay. Tests first must
demonstrate that a selected target with nonzero Finder flag/position bytes
passes with its exact pinned full sidecar hash; missing, malformed or wrong
pins fail before socket creation. First-eight-byte type/creator, DATA20, inode,
device, UID, mode and link-count guards remain mandatory. Retain all previous
duplicate-row, READY-order, partial-I/O and 206 controls.

Before final runtime JSON, plan or closed readiness, positively identify and
select the owned Unix target in an awake Finder window and expose the HFS Files
parent. Do not make an alias, Copy or Paste yet. Record screenshots and all
reviewed input. No clock, screensaver preference, account or option edits are
allowed. Unknown window controls require a bounded operational review; do not
guess coordinates or infer Unix-volume absence.

After this pre-stage, capture the full 32-byte sidecar SHA as the required
runtime `initial_finf_sha256`, a lower-case 64-hex string. Validate it against
the real file before sockets, along with the unchanged identity and first eight
bytes. Never reset Finder metadata to recover the initial zero hash. Freeze the
final runtime JSON before plan/readiness; a later changed pin is a stop, not a
reason to re-pin. Source and builder approval still precede the first service.
Recheck awake target visibility after closed readiness.

The original 720-second epoch, 900-second lease/recorder caps, minimum
390-second case reserve, 210-second controller, 240-second case unit,
120-second receipt wait and 110-second input cutoff remain. Keep six readiness
plus five planned case requests, one 205 mutation, no 500 or transfer, no
unlink. READY and every live identity/capture gate still apply. M2b needs
independent source and operational review before fresh START. Positive 206
alone does not discharge stopped alias identity and Original binding; M3
remains gated on that full chain. Retain forced-stop wording if native app Quit
and OS shutdown were not actually observed.

Revision note, 2026-11-14: Commit921a41b4 freezes the first failed-prefix
corpus, including A141's byte-exact independent review. A142 accepts the
revised M2b plan. B's private d4d57cbc packet is imported into the canonical
protocol checkout: three source/test files match exactly, and the guide retains
the parent's earlier START/Get Info clarifications. Actual totals are696
production,381 test and112 guide lines; deltas from canonical M1 are9,21 and4
lines. Eight focused tests and code/Markdown/Mermaid gates pass. C143 supplies
the read-only operational proposal; no new service or input has occurred. A143
accepts the canonical import, and all609 native tests pass in88.305s. Protocol
commitf6ec1a6 records the four-file correction. Fresh operational scripts and
source pins still precede START. The guide change requires a new audit
snapshot; revision82 must preserve all87 statuses and criteria.

Revision note, 2026-11-14: Root accepts C144's offline operational packet only.
Own new ignored `state/native-sessions/native-alias-live-preparation-02` files:
at most ten scripts/1150 physical lines,180 prose lines and150 separate
model-test lines. Preserve all first-lab scripts and pins. Use canonical
committedf6ec1a6 sources and their complete local-import closure. No disk/ROM
copy, image preparation, socket, display, service, VM or GUI operation is
authorized by this implementation packet. Validate scripts and all negative
models without X before independent review and source approval.

The new helper may include a narrowly scoped retirement phase fixed before
source hashing. Require root0600 approval binding fresh screenshots, same owned
PID/start/display and unexpired global deadline, plus a terminal case or
explicit pre-case abort receipt. Permit at most two named clicks: the
identified native server Quit control and recognized Quit Now if present. No
alias operation, menu navigation, key input or third click is allowed. The case
controller never invokes retirement. Preserve the existing startup and case
guards unchanged. If controls cannot be identified or time expires, retire the
owned VM and record forced stop accurately; app Quit alone is not an orderly OS
shutdown. This phase adds no protocol request or unlink. Source drift, helper
FD assumptions, ambiguous controls or a budget overrun requires escalation
before source freeze or START.

Revision note, 2026-11-14: B119 has a separate30-active-minute stopped
preparation grant for new `state/mac-runtime/native-alias-live-02` and
`P02/stopped-preparation/` receipts. C retains ownership of P02 scripts. Use
the exact pinned board-02 base and ROM only after root FD-free checks before
every byte read/copy. Preserve source inode/mode/mtime/hash, accepting the
unchanged0644 ROM without chmod, and require new destination inodes, capacity
and unchanged original primary/client identities. Stage the same DATA20 and
initial32-byte Finder sidecar as UID1000/mode0600/nlink1; retain stopped
catalogue and five named fork hash receipts. No service, display, VM, socket,
GUI input, source edit or alias operation is in this grant. Existing
destination paths, hash drift or uncertain FD ownership stops it. This
preparation does not authorize the later boot or case START.

Revision note, 2026-11-14: C escalated before source freeze because Ruff
formatting the inherited templates produces1216 operational lines. Root raises
only the same ten-script cap from1150 to1250; preserve all guards and the
inventory script, with no new behaviour, dependency or file. Prose180 and
separate model150 limits remain. The parent-only post-readiness review is
prepared separately and will be hashed in root approval metadata before boot.
It binds future actual PID/namespace, regenerated15960 plan, full Finder pin
and fixed deadline; it has not been run against a new lab.

Revision note, 2026-11-14: B119 preparation is complete; parent receipt review
and current root FD checks pass for new base203082517, working 203082518 and
ROM24979350. Both original process identities are unchanged. No image bytes
were read in the parent review and no service has started. A145's parent-review
identity gap is corrected by exact disk start/exe/inode, pre-stage start and
disk/capture/screenshot hashes before PASS.

A146 found two operational defects before approval: every UI input must bind
current emulator executable/capture FD and display process identity, and a
partially attempted retirement click must not be retried. Root approves only
those corrections, raising the same ten-script cap to1300 from1250 for an
estimated45–60 additional formatted lines. Add a root-only no-X
display-identity capture mode immediately after managed display start; write
one root0600 receipt with unit, actual PID/start, executable path/hash, UID1000
and exact display command. Every later input compares current identity to that
receipt. Check actual emulator executable hash in all phases and capture FD
path/device/inode whenever its receipt exists; startup before lazy capture
creation remains allowed. Retirement consumes an attempted control even if
completion fails, with Quit Now allowed only after a completed Quit. Negative
models must cover replacements, wrong executable/capture FD and attempted-click
retry. No new live authority or dependency is granted. Independent re-review
and exact pins still precede START; prose180 and model150 limits remain.

Revision note, 2026-11-14: M2b live-02 positively identified Finder, the Unix
target and HFS Files parent before final runtime construction. Finder selection
changed the full sidecar hash from1d0021b6… to8f0333df…; exact DATA and
first-eight-byte guards passed. Closed18 readiness completed, but its
367.6-second remainder failed the390-second case gate. No case marker, case205,
alias or alias-target206 occurred; baseline readiness has its own206. Native
app Quit was observed, then forced VM retirement completed before
17:48:52.587463Z; parent verified PIDgone/rootFDfree at17:47:41Z. There was no
orderly OS shutdown. R02 is quarantined. Authorize at most35 additional guide
lines to record this observed preparation and refusal, without changing wire
claims or gap status. C148 freezes its stopped evidence and A148 reviews it
independently; B121 proposes the next measured timing decision. No new native
START or profile has been approved.

Revision note, 2026-11-14: A148 independently accepts the live-02 pre-stage
corpus; commit801e59ed preserves the raw witness and review. The review's
wrapped author copy updates only its prose and manifest hashes. B121 measures
readiness completion at epoch+352, about22 seconds beyond the+330 case-start
ceiling. The90-second Finder-activation-to-Hide-Others interval is a measured
opportunity, not a guaranteed saving. Root accepts one fixed fresh retry,
keeping every original time/count/identity guard and the390-second reserve.

A149 accepts B122's literal-only fixed profile: live-03, display:124 and
15980–15983. Protocol commitbeaf0b5 records the three production literal
changes, matching test paths, observed live-02 guide and operator checkpoint.
Target selection and root review should finish by epoch+270; if the view is not
established then, retire rather than rush or extend the epoch. A150 will
capture the final guide in audit83 with all87 criteria/statuses intact.

B123 has a separate stopped-only30-minute preparation grant for new R03 and
P03/stopped-preparation receipts with exactly B119's FD/source/hash/target and
catalogue obligations. C149 owns new P03's ten offline scripts and
proposals:1300 script,180 prose and150 separate model lines, using accepted P02
guards and only the new fixed paths/display/ports/source hashes. Neither packet
grants a service, display, VM, socket, GUI input or approval-pin write. No
first/second-lab image or source pin may be reused or reset. Independent
review, fresh root pins, boot and later case grants remain separate gates.

Revision note, 2026-11-14: Audit83 accepts the final147-line guide, including
observed live-02 limits and fresh03 preparation. It covers521 sections and 4116
links with all87 original criteria and61/25/1 statuses unchanged. For the next
operator checklist, expose usable Files-parent space for the new owned wrapper.
A fresh, identified window resize control may use the existing bounded
down/move/up input; this changes presentation only. No server Options, account,
clock or preference edit is permitted. A read-only inspection of Make Alias may
be cancelled before READY; disabled or unclear controls end the attempt. No
alias creation, Copy or Paste is allowed before READY, and these checks do not
extend the+270 preparation checkpoint.

Revision note, 2026-11-14: B123 prepares R03 stopped, with parent receipt and
current FD-free review accepted: base2302714961, working2302714962 and
ROM2302714960; target2850088362 and sidecar1320636081. The original source and
live primary/client identities are unchanged. C149's fixed03 offline plateau
has1291 script,127 prose and129 model lines; no service has started. A151
catches two stale02 inventory basenames in the parent pin writer; both are
corrected to03 before execution. A152 independently reviews this final packet
and the corrected parent scripts before any new pins or START.

## Revised shared-gate milestone: explicit longer preparation profile

Live-03 retired before its deadline after failing the+270 preparation
checkpoint. It ran no controller, readiness or alias request. The operator
opened an unexpected empty Broadcast dialog at18:11:13, clicked Cancel at
18:11:22 and then continued preparation. That continuation violated the
stop-and-escalate rule. Preserve this as a process deviation, not valid
pre-stage evidence. App Quit was observed before forced VM stop; parent
verified PID503 absent and the working image FD-free at18:17:12. No orderly OS
shutdown was observed. All first three working images remain quarantined.

B125 identifies coupled720/900 hard limits in host capture/receipt and protocol
live gates. Root approves one OFFLINE shared-gate milestone before any further
runtime or service. Its observable result is a named, bounded alias preparation
profile that passes the same identity and deadline checks, while ordinary
fixtures and frozen old receipts keep their existing bounds. A longer window
does not excuse unknown controls or the operator deviation.

Use the exact name `native-missing-alias-ui-30m-v1` in an optional
`capture_window_profile` field, separate from `fixture_profile=control-only`.
Require `capture_window_purpose=native-missing-alias-positive` with this
profile, consistently bound in approved runtime, plan and receipt. An absent
profile plus absent CLI option retains the legacy720-second epoch and900-second
lease/recorders/sleep. The sole named profile permits an1800-second epoch and
exact2100-second lease/recorders/ sleep. Unknown names, non-alias purposes and
runtime/plan/CLI/receipt mismatches fail before any protocol socket. Never
infer a profile from a path, measured duration or arbitrary numeric argument.

Modify only existing shared functions; do not duplicate whole gates or raise
their default constants globally. The alias controller explicitly requests the
named profile only after validating its plan and runtime. Ordinary ban/native
callers retain the default path and reject a long receipt unless the caller
explicitly selects the matching alias profile. Later alias-specific
closed-readiness and parent-review wrappers must pass that same approved
profile; the generic readiness semantics remain18 actions. Keep absent-profile
output/replay compatible with prior captured receipts.

For each lease and recorder, parse the actual `RuntimeMaxUSec`, require the
selected exact cap and re-read actual unit properties. Recompute monotonic
coverage using ActiveEnterTimestampMonotonic plus the actual selected cap,
requiring coverage of the fixed UTC deadline plus at least5 seconds. A
correct35-minute cap with stale activation time must fail. Retain current
PID/start/executable/UID, image and capture FD/inode, namespace/routes, lock,
source-hash and no-primary-SYN checks. The epoch is fixed once before the first
service; never reset it after GUI work, readiness or a failure.

Preserve the390-second case-start reserve,210-second controller,240-second
managed case,120-second receipt wait and110-second input cutoff. Keep the same
six readiness and five case requests, one205 mutation, zero500 barriers, zero
transfer and zero host unlink. The old+270 target becomes a preparation aim
under the longer profile, not an excuse to alter a running epoch. A fresh exact
lab and its separate finite operator checkpoint require their own later
reviewed operational packet and START.

The bounded source packet owns only Mothra `scripts/capture_readiness.py` and
`scripts/native_capture_receipt.py`, and protocol
`scripts/native_ban_expiry_control.py`, `scripts/native_missing_alias_cases.py`
and `scripts/native_missing_alias_control.py`: at most220 new or changed
production lines in total. Tests own the existing Mothra capture/receipt tests
and protocol `test_native_ban_expiry.py` and `test_native_missing_alias.py`: at
most260 new or changed test lines. Allow at most60 guide lines; the ExecPlan is
excluded. No new dependency, module, arbitrary duration/profile or unrelated
caller migration is allowed. Escalate before exceeding a category; unused test
space does not offset code.

Write failing controls first, then implement and refactor. Prove legacy
missing-profile720/900 passes; legacy721-second epoch or a cap above900 fails;
named1800/2100/sleep2100 with matching alias runtime/plan/CLI/receipt passes;
unknown/mismatched profile, non-alias purpose,1801-second epoch and 2101-second
cap fail. Exercise stale activation, deadline coverage below5s, wrong
PID/FD/namespace and actual-versus-recorded unit mismatch. Run focused alias,
capture, receipt and ban suites, Ruff/ty, and a fresh adjacent offline export.
Root independently reviews exact diffs and all tests before import. No
synthetic service is authorized by this source packet. A later separately
reviewed managed lease/capture rehearsal must verify actual systemd duration
representation before any Mac VM START.

The later operations packet has a separate delta budget: at most140 script, 90
no-X model and70 prose lines against the accepted packet. Its exact new paths
and identifiers await approval. Preserve every failed command's argv, stdout,
stderr and exit file, including observation/argument errors; a failed
relative-path capture invocation in live-03 currently survives only in the
agent transcript and must be stated as an evidence limitation.

For menu operation use held down, a fresh menu image, move to the named item, a
fresh highlighted-item image, then up and a fresh result image. Never release
and click a row based on an old menu screenshot. Any unexpected dialog may
receive one clearly identified safe Cancel, then input stops and the parent is
notified immediately. Cancellation does not authorize continued preparation or
protocol work. Preserve the deviation receipt/screens before retiring; a new
root decision is required to do anything beyond retirement.

Revision note, 2026-11-14: B126 implements the named-profile gate privately;
A154 finds missing protocol-side live-service branch tests. B127 adds actual
fake-systemctl cap/coverage/mismatch checks and a named runtime gate through
all three managed units; A155 accepts the correction. Canonical import now
passes613 native tests in75.402s,21 host capture/receipt tests and code gates.
Production delta179/220 and test delta192/260 remain within their categories.
The guide now distinguishes observed Finder preparation from an individual
selection action; the curated old pre-stage manifest is clarified without
changing raw evidence. Final canonical parity review and audit84 precede
commit. No experimental VM is running and all three retired images remain
quarantined.

C154 may prepare an offline synthetic service-profile rehearsal packet: 160
script,80 model-test and80 prose lines, no dependency or tracked helper change.
It may propose one fresh ignored directory, a dedicated lock distinct from the
oracle lock, two local-only tcpdump filters on unused ports and one User1000
lease. Use the selected1800-second fixed deadline and2100-second unit
caps/sleep through the real helpers. No connections, original server ports, VM,
disk/ROM bytes or GUI are involved. Preserve argv, stdout/stderr, exit files,
actual process/FD identities and systemd properties. Check actual 35-minute
representation and monotonic coverage, then stop only the three owned units
promptly within120 seconds. This proves managed service-profile plumbing, not a
full native capture receipt or alias behaviour. Independent script review,
committed source pins and a separate root START are required before any
synthetic service begins.

Revision note, 2026-11-14: A156 accepts canonical source parity and the limited
before/after sidecar wording. A157 finds synthetic-rehearsal cleanup
obligations still missing: its120-second verdict excluded teardown, actual
PID/start retirement was not proven, and subprocess timeouts omitted raw
failure receipts. C155 may correct exactly those issues within190 script lines,
replacing the160 cap; model80/prose80 remain. All service starts stay blocked
pending independent re-review and fresh source/script pins. The source gate
itself is accepted after613 native and21 host tests; the synthetic rehearsal is
a distinct acceptance boundary, not native evidence.

## Read-only AliasRecord v2 identity decoder

B128 finds published primary Alias Manager material, Apple-authored XNU layout
and an author-maintained mac_alias format description, checked against three
retained old alias payloads. The raw public record identity may be stale;
decoding it is not native resolution. The sources disagree on the labels at
offsets122/126, so this packet must not interpret type/creator there. Use those
fields only through native206 evidence, not this decoder.

Root approves one OFFLINE decoder packet, independent of the longer-window
source work: new protocol `scripts/alias_record_v2.py` and
`scripts/test_alias_record_v2.py`, at most180 production and180 test physical
lines; one JSON fixture at most4KiB and `alias-record-v2.md` at most45 lines.
No dependency, native call, disk/ROM read or other existing module change is
allowed. Own only these four new files; no Makefile edit while C157 owns its
separate gate change. Escalate before widening format or budget.

The input is an already extracted **AliasRecord payload**, not a resource fork.
The caller separately proves the stopped Finder alias flag and unique
resource-map `alis` ID0 and pins the extracted bytes. Decode v2 only: require
at least150 bytes, declared big-endian size at offset4 equal to the exact
payload length, version2 at6 and file/directory kind0/1 at8. Bound volume
Pascal length at10 by27 and target Pascal length at50 by63 before reading;
retain raw name bytes as hex and the recorded parent/target CNIDs at46/114. Do
not resolve CNIDs, infer host inodes, normalize paths or claim liveness.

Starting at150, parse signed16-bit tag/unsigned16-bit length entries with
bounded data and even-byte padding. Support only the reviewed legacy tags 0,1,2
and terminator-1; reject unknown/duplicate tags, overruns, invalid odd padding,
missing/duplicate terminator and trailing bytes. The terminator has zero length
and ends the record. Require a unique supported Carbon path tag2 when asserting
directory/path binding. Treat the known tag1 bytes as recorded CNID path data
only. Unknown versions/tags remain unsupported and require the separate
reviewed Original UI observation; do not scan for a target substring.

Provide a pure decoder and explicit recorded-target comparison against caller
supplied expected volume, basename and full Carbon-path bytes. Mismatch fails
closed. JSON/CLI output must label the result **recorded identity only**. For
any future Unix alias, positive206 target tags, actual operator receipt,
stopped alias flag and resource-map proof remain separate mandatory evidence.
The decoder alone never permits M3 unlink or GAP-054 closure.

Use payloads from the three already tracked11444/11445/11446 alias resources as
fixed controls, recording their exact source paths/fork hashes and payload
hashes in the small fixture. They came from an older read-only live-image
catalogue, not a stopped durability snapshot. Never read that working image or
change those raw resources. Test fixed expected volume/name/path/kind and
byte-mutated short header/size/version/kind/Pascal/TLV/padding/terminator,
unknown tag and mismatched expected identity failures. Run Ruff/ty, dedicated
unit tests and a minimal fresh export without state, VM, ROM or source forks.
An independent layout/source review and exact fixture provenance review must
pass before canonical import or trusting a future Unix target record.

## Course correction and next finite native attempt

The user challenged the unchanged closure count. Root concentrated all three
journeymen on alias scaffolding and review work instead of advancing separate
protocol questions. Freeze the reviewed tools now. A163/A164 owns scalar
contracts (GAP-015); B131 owns semantic length limits (GAP-019); C owns one
alias experiment. Check each agent at most15 active minutes apart and at every
native execution boundary. Progress means documented protocol evidence or
satisfaction of an original criterion, not a commit or test count alone.

B133 independently accepts the exact A164 scalar table hash877c0c75… against
the complete core inventory. Root adjudicates GAP-015 Resolved with the
original text unchanged; source/corpus/independent review are retained in
`scalar-width-contract-01`. Register counts become62 Resolved,24 Investigating,
1 Open. GAP-019 remains Investigating with finite named unmeasured cells. No
alias result has been obtained. A165 records the integrated review in
revision85 without changing any other status or original closure criterion.

For C's sole next attempt, propose new R/O/D/P `native-alias-live-04`,
`native-alias-live-preparation-04`, display:125 and ports16000–16003, subject
to fresh absence checks. Stopped preparation uses the same pinned source, root
FD-free checks before every image/ROM read, separate copy inodes and unchanged
original process identities. Require free space for both logical
8,388,608,000-byte disks plus2GiB headroom. Never reset/reuse the first three
working images. A failed source/hash/ownership check stops preparation.

Only the existing alias cases/control/tests may receive literal runtime/port
updates: at most8 changed production and8 changed test lines. No new shared
helper, API, dependency or harness feature is allowed. The new ignored
operations packet reuses the accepted ten scripts, with explicit named-profile
flags at host, namespace, receipt, closed-readiness and parent-review gates.
Use exact1800 epoch/2100 lease+recorders/sleep and both profile/purpose runtime
markers. Its separate delta cap remains140 script/90 model/70 prose lines;
absolute caps are1440/220/200 from the accepted base. Hash all code before
first service and retain argv/stdout/stderr/exit for every invocation.

The target/review aim is+600 seconds, hard pre-stage stop+1200 seconds; the
fixed deadline and390-second case reserve remain authoritative. Bootstrap,
Finder preparation, closed readiness and case each need a separate parent
grant. During a live phase check in within60 seconds with stage, elapsed, last
reviewed screen and blocker. Parent stops an agent that continues after an
exception or misses its checkpoint; the deadline observer retains its
independent exact-unit retirement cutoff.

Bootstrap grants only normal boot, the two identified startup dialogs and
server startup/capture gate. Then stop for a parent screen review. Finder
activation should use the freshly identified System9 Finder title rather than
clicking a row from a released application menu. Close only that System9
window, then use a held, highlighted Hide Others selection. Stop again with the
Unix volume visibly exposed. The next grant opens/resizes Files for usable
space, opens/moves Unix and selects the sole target; no Make Alias, Copy, Paste
or Get Info occurs before READY. Parent reviews the complete view and creates
the protected pre-stage receipt.

After exact closed18 and independent live review, the case remains exactly five
numbered requests including login, one205, no500/transfer/unlink. The
existing210/240/120/110-second controller/unit/receipt/input limits remain. The
read-only v2 decoder may supply recorded-target identity after stopped
resource-map extraction; it does not replace positive206 or alias-flag/map
proof. Optional Original UI observation is permitted only within the existing
case window and reviewed controls. Unsupported data/UI remains unproved.

Any unexpected UI, conflicting oracle identity, unsafe or out-of-scope
condition stops the actor immediately. One clearly identified safe Cancel is
permitted, followed by an immediate parent report with screen/log paths; no
resumed preparation or protocol action is authorized by cancellation.
Retirement has a separate bounded grant. Observation timeout requires
rechecking the same live handle, never an inferred restart. No new native START
is implied by this plan revision or by the finished tooling reviews.

## Prospective required-reflink storage amendment

C161 correctly stopped at the original two-disk capacity gate; that refusal
remains valid. A166 independently reviewed an alternative preparation method.
For R04 only, replace the two-full-copy capacity requirement prospectively with
required reflinks for **both** base and working disks from the pinned,
immutable canonical base. Use `cp --reflink=always`; no ordinary-copy fallback
is permitted. Do not change the generic runtime preparation implementation.

Require at least10,536,091,648 available bytes on the destination filesystem
before each clone and immediately before boot: one complete8,388,608,000-byte
working-disk divergence plus2GiB headroom. The base must remain read-only. This
is headroom, not reserved capacity; another writer can consume it. If a
capacity check fails, stop and report without retrying or deleting evidence.
The small same-XFS proof in `state/delegation/cow-storage-proof-01/report.json`
confirms separate inodes and copy-on-write source preservation; it does not
prove the full-image copy or current free capacity.

Before every image or ROM byte read, including every hash and copy, retain root
FD-free evidence. Reject symlinks or unexpected source identity, size, mode or
hash; require absent destinations. Source and destinations must be on the
reviewed XFS device. Retain before/after source stats and full hashes, exact
copy argv/stdout/stderr/exit, and distinct source/base/working inodes with link
count1. Both image hashes must equal the pinned source, base mode must be
read-only, and working mode writable only by the expected owner. Recheck
capacity, identities, modes, hashes and FD-free status before boot. Never hash
the working disk while an emulator has it open.

All existing stopped HFS catalogue, application/resource-fork, board and Finder
metadata checks remain mandatory. Preserve the receipt schema consumed by the
reviewed boot gate and explicitly record the required-reflink method. No
retained working image, ROM or canonical source may be modified or removed. The
stopped-preparation command itself needs parent review before execution; this
amendment grants no copy, service start, VM boot or protocol request.

C escalated the stopped-preparation authoring budget before execution: the
173-line review-only draft exceeded the170 cap and lacked full target/Finder
metadata and board receipts. Root approves a prospective230-line cap for this
one self-contained script to retain those mandatory gates. Keep the draft as
superseded evidence; do not execute it. No helper/API expansion or other budget
change follows. A168 must review the complete successor hash before START.

A168 rejects the229-line successor before execution: missing UID guard, raw
account-fork dumps, incomplete ownership/baseline assertions and a potentially
false success status after a failed final check. Root approves a prospective
270-line cap for the same script solely to repair those mandatory checks. For
`icat` commands retain argv, exit, stderr and stdout size/hash, following the
earlier preparation; do not retain raw account/application fork dumps. Ordinary
command stdout remains retained. A168 must review the complete next freeze. The
ten operational scripts are unchanged. Root must separately record the full
capacity check immediately before any later boot; a stopped preparation's
earlier measurement never satisfies that launch-time gate.

The single stopped R04 preparation exited1 at the account catalogue guard. Both
cloned disk hashes matched the immutable source, but the filter selected 54
historical Trash UserData records as well as the two active accounts. The
catalogue hash equals the accepted P03 catalogue exactly. Retain the failed run
in `native-alias-preparation-04-failure-01`; no VM or protocol started, and the
source-after/fork/board/target steps were not reached.

Root permits offline authoring of one R04-only continuation, at most110 lines,
using the corrected scoped filter and retained-catalogue regression. It must
verify the same never-booted clones and all original guards, copy no image, and
write new command logs. Preserve the failed receipt and commands unchanged
until its immutable corpus is committed. A final operational receipt may
supersede the failed preflight only after that commit and a separate parent
execution grant; link the exact predecessor hash and retained copy. No boot,
automatic main retry, disk reset or generic recovery API is allowed.

## R04 capacity recovery and stopped handoff

Continuation01 stopped before image reads because available space had fallen
to8,822,157,312 bytes. Root reviewed four inactive source-export caches using
Git-blob inventories, owner confirmation and fresh process/inotify gates. Only
those four trees were removed; `export-cache-cleanup-01` retains exact removed
paths and the observed3,460,472,832-byte available-space increase. No runtime
image, ROM, canonical Git history or retained evidence was removed.

Continuation02 differs only in its fresh output directory and completed once
under the oracle lock. Source/copy hashes and protected process ticks match;
the two active accounts, five forks, empty board and target/Finder bytes pass.
The parent validated the31 command receipts and promoted the operational
preflight only after preserving the failed original and committed corpus. The
new operational preflight hash is `ff29875a…`; Finder supplement is
`ab64121a…`. Raw continuation receipts remain separate and unchanged.

This handoff grants no service, display, GUI, socket or alias action. The next
plateau requires fresh capacity and exact reviewed code pins before
BOOT/bootstrap only; all later Finder/readiness/case grants stay separate. No
missing-target result or GAP-054 closure is claimed.

Before any BOOT-phase GUI input, install a separate UID1000 transient cutoff
timer using `systemd-run --user --on-calendar=<fixed UTC deadline>` with 1ms
accuracy. Its sole command is `systemctl --user stop <owned VM unit>`; validate
that unit against R04's service receipt and deterministic launcher identity.
Record exact argv and the actual timer deadline. If installation or identity
verification fails, stop before GUI input and retire only that VM. This
independent cutoff does not extend the epoch or replace ordinary retirement,
capture-tail collection or cleanup of other owned units.

## R04 abort and next supervision correction

The actor selected the target before+1200; root's protected receipt command was
authored too late and rejected itself at the hard checkpoint. No closed
readiness, case or native alias response followed. The exact owned VM was
forcibly stopped before its fixed deadline. Application Quit and OS shutdown
were not observed. Both captures contain zero TCP; the stopped catalogue, five
named forks, two users and empty board match, while Finder metadata changed at
offsets8/13. Preserve this as a parent-checkpoint preparation abort.

Root's per-dialog review loops consumed the window. For the next finite packet,
pre-author and review the parent's receipt command before BOOT. Bootstrap may
handle only already identified routine Launcher activation, owned application
launch, Sounds Disabled OK and bounded recognized-saver wakes without another
parent grant between those named steps. Finder may perform the already reviewed
activation/close/Hide Others/Files/Unix/target sequence as one bounded grant.
Unfamiliar UI, identity or evidence failures still stop immediately; readiness
and case each retain a separate grant. Do not change the1200 hard
checkpoint,390 reserve,1800 epoch or case limits. No new shared harness feature
or generic recovery interface is authorized.

A179 pre-authors the R05 parent receipt operation before any next BOOT. Root
prospectively approves120 lines (from90) for complete identity, exclusive
publication and late-receipt guards, with a separate100-line offline model
budget. Parent review caught a string namespace inode; the corrected writer
emits an integer and the model asserts the consumer schema. Root reviews the
exact target-role PNG and seals the directory before invoking it. This approves
the saved operation only, not a live receipt or new START.

Supervision must use `followup_task` to assign or resume an idle journeyman;
`send_message` supplies notes but does not start a completed agent. Recheck
agent status when awaiting a correction. This fixes a second parent latency
source without widening actor scope or weakening any protocol gate.
