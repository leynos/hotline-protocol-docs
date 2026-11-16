# Disposable Mac OS 9 runtime recovery, 13 November 2026

This run restored a native Hotline Server 1.9 oracle after a host restart. The
previous SheepShaver process and user service had disappeared. The old
`hotline21/working.dsk` was preserved; all guest writes went to a new
`hotline22-recovery/working.dsk`. The evidence is in the adjacent mothra
[recovery batch][batch] and its [operator transcript][as-run]. This is a
bounded readiness check, not a claim that every protocol gap is resolved.

## Recovery boundary

The source was an 8,388,608,000-byte stopped image with SHA-256
`e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910`. The
[preboot gate][gate] records inode, size, mtime, ROM and emulator hashes, no
disk owner, no emulator or display process, no forwarded port listener and
sufficient free space. The first gate refused an occupied `runtime-25` session
path without writing anything; the operator used a fresh `recovery-20261113-01`
path. Never reuse an existing target, capture or display path. Recheck
ownership and source stat immediately before copying.

The toolset's `mac_runtime.py prepare` command, described in the
[build and runtime preparation guide](https://github.com/leynos/mothra/blob/57aeaac4f12065bfb2de3d47943f4b45622392a9/docs/preparing-a-capture-run.md#build-the-emulator-and-prepare-a-runtime),
copied the stopped source to a read-only base and created a separate writable
working image. The original remained at its recorded inode, size and mtime
after both smokes. Independent SHA-256 reads confirmed both new disk files
matched the source before boot; the copied ROM matched
`18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd`. The
read-only `scripts/snapshot_native_hfs.py` probe on the new stopped base found
exactly one catalogue 11183 entry at `/Hotline19/HLserver19`. Its DATA and
resource forks extracted successfully and matched the [recorded hashes][forks].
An absent catalogue probe would not prove the application absent.

The commands below are the preparation and snapshot commands as run for the
completed 13 November run, as the [as-run transcript][as-run] records them. The
`mac_runtime.py` command is the toolset's; its general procedure is in the
[build and runtime preparation guide](https://github.com/leynos/mothra/blob/57aeaac4f12065bfb2de3d47943f4b45622392a9/docs/preparing-a-capture-run.md#build-the-emulator-and-prepare-a-runtime).
They are historical provenance, not a current recovery recipe: the `hotline21`
input was retired on 15 November 2026; `hotline22-recovery` is an occupied live
runtime. Never copy these commands verbatim into an occupied path.

```sh
python3 ../mothra/scripts/mac_runtime.py prepare \
  ../mothra/state/mac-runtime/hotline22-recovery \
  --rom ../mothra/state/mac-runtime/hotline21/rom \
  --disk ../mothra/state/mac-runtime/hotline21/working.dsk
sha256sum ../mothra/state/mac-runtime/hotline22-recovery/{base.dsk,working.dsk,rom}
python3 scripts/snapshot_native_hfs.py \
  --image ../mothra/state/mac-runtime/hotline22-recovery/base.dsk \
  --tsk-bin ../mothra/tools/sleuthkit/usr/bin \
  --catalog-range 11183 11183 --root /Hotline19/HLserver19 \
  --output ../mothra/state/native-sessions/recovery-20261113-01/preboot-app
```

For a new disposable run, retain the same source-content checks but use the
FD-free read-only `native-board-02/base.dsk` donor and its matching ROM. The
retained
[retirement records](../../evidence/gap-remediation/2026-11-15/runtime-retirement-preparation-01/manifest.json)
confirm that donor matches the recorded `e5cbbaaf…` source and `18da89e4…`
ROM. Choose fresh runtime, display and session names. Before every source read
or copy, verify positive root FD-free results; never substitute either live
working image. From the protocol documentation checkout, prepare the source
with the toolset's `mac_runtime.py prepare` into a fresh
`../mothra/state/mac-runtime/native-recovery-NEW` runtime, using the
`native-board-02` ROM and base disk, as the
[build and runtime preparation guide](https://github.com/leynos/mothra/blob/57aeaac4f12065bfb2de3d47943f4b45622392a9/docs/preparing-a-capture-run.md#build-the-emulator-and-prepare-a-runtime)
describes.

This is source preparation only. Apply the current identity, capacity, managed
capture and fixed-deadline gates before any new boot or protocol contact.

## Boot and guest observation

After a renewed no-owner, free display and port check, the operator started a
managed Xvfb display on `:99` and a managed SheepShaver instance with guest
packet capture. The [service records][services] name the units and commands;
Xvfb PID 1097275, wrapper PID 1099211 and actual emulator PID 1099659 were
observed. `/proc/1099659/exe` resolved to the new runtime binary and hashed to
`9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4`. Ports
15500–15503 listened on loopback. Service acceptance and listening ports alone
did not establish application readiness.

Mac OS 9 displayed an improper-shutdown warning and automatically ran Disk
First Aid on the disposable working image. Work stopped for supervisor review.
The supervisor expressly allowed the already-running automatic check to finish,
with no manual repair or restart. It reported “Verification and repairs
completed successfully” in [the saved screen][repair-screen]. The operator
dismissed **Done**, observed the Finder desktop, and launched the visible
`HLserver19` icon from `/Hotline19`. The [application screen][app-screen] shows
Hotline Server 1.9, the log entry `Hotline Server started` at guest address
10.0.2.15, and an initially empty connection counter. A Sound Manager warning
was dismissed; the runtime was configured with `nosound true`.

The preboot fork hashes identify the stopped base image. They do not prove the
hash of the loaded application after Disk First Aid, nor the current contents
of the mounted working image. The guest was left running; no post-repair disk
snapshot was taken.

## Read-only readiness smokes

Both plans sent a 12-byte Hotline handshake, read its exact eight-byte reply,
logged in with the existing disposable administrator fixture, read the login
ACK and the 354/109 pushes, requested 348 account enumeration, then closed.
Both [reports][report1] completed ten actions with status-zero ACKs and exactly
two 101 account values: `administrator` and `fixture-low`. Neither plan
requested an account, preference or filesystem mutation.

The first run lacked an independent host pcap. Its report retains the exact
host sent and received bytes, and its guest snapshot is retained, but it is not
paired packet-capture evidence. The supervisor authorized exactly one identical
correction run. For smoke 002, `tcpdump` was confirmed listening and the new
host pcap header existed **before** the connection. It recorded 20 packets and
zero kernel drops. The cumulative guest capture contains the two smoke
sessions; the selected smoke-002 SYN matches the host local port and precedes
the guest SYN by 199 microseconds. The host and guest reassembled streams equal
the [smoke-002 report][report2] in both directions: 108 bytes sent and 468
received. No third run was made.

Replay the immutable evidence without contacting the guest:

```sh
cd ../mothra
RECOVERY=evidence/gap-remediation/2026-11-13/native-runtime-recovery-01
bash "$RECOVERY/verify-smoke.txt" "$PWD"
```

The replay checks root-relative SHA-256 sums, both recorder reports, frame
order/status, exact two-account nested names, one host/guest SYN pair and both
byte streams. The [as-run transcript][as-run] gives exact preparation, service,
snapshot and capture commands. On an occupied source, changed hash, new repair
choice, failed application startup or unexpected account inventory, stop and
preserve the guest and capture handles for review. Do not restart the original
runtime or mutate original accounts to make a smoke pass.

[batch]: ../../evidence/gap-remediation/2026-11-13/native-runtime-recovery-01/manifest.json
[as-run]: ../../evidence/gap-remediation/2026-11-13/native-runtime-recovery-01/as-run-recovery.txt
[gate]: ../../evidence/gap-remediation/2026-11-13/native-runtime-recovery-01/preboot-gate.json
[forks]: ../../evidence/gap-remediation/2026-11-13/native-runtime-recovery-01/preboot-app/extraction.json
[services]: ../../evidence/gap-remediation/2026-11-13/native-runtime-recovery-01/sheep-service.json
[repair-screen]: ../../evidence/gap-remediation/2026-11-13/native-runtime-recovery-01/boot-observation-03.png
[app-screen]: ../../evidence/gap-remediation/2026-11-13/native-runtime-recovery-01/app-observation-02.png
[report1]: ../../evidence/gap-remediation/2026-11-13/native-runtime-recovery-01/smoke-001/report.json
[report2]: ../../evidence/gap-remediation/2026-11-13/native-runtime-recovery-01/smoke-002/report.json
