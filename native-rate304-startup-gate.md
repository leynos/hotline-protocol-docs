# Native rate 304 lab: startup observation gate

The second disposable rate 304 lab stopped **before protocol contact**. Its
five-second emulator observation gate timed out while guest capture FD16 was
absent. This is a preparation failure, not a Hotline protocol response, server
crash, 304 limit, or reset observation. The immutable
[corpus](../mothra/evidence/gap-remediation/2026-11-14/native-rate304-startup-gate-01/manifest.json)
keeps the as-run commands, checks, raw failure, and retirement receipts.
The first failed rate 304 pair remains a separate
[wire witness](native-rate304-first-pair.md); neither failed working image is
reused.

## Stopped preparation

The owned `native-rate304-02` runtime was prepared from the **stopped,
immutable** `native-board-02/base.dsk` (SHA `e5cbbaaf…`, mode 0444) and ROM
(SHA `18da89e4…`). Root fuser returned no holder for both sources before
source-byte reads or copying; hashes and metadata matched afterward. The new
base, working disk, and ROM had independent inodes 77099976, 65602436, and
65578607. A stopped HFS read found only the original admin and fixture-low
accounts, baseline Prefs and server DATA/RSRC hashes, empty MessageBoard
DATA/RSRC, and no allocated `Banned` path. Future display `:120`, ports
15880–83, and epoch directory were absent at preparation time.

Eight future launch/readiness/case scripts were written before boot and bound
by `preparation/script-SHA256SUMS`. Their proposed 35-module Python import
closure and two Mothra helpers are frozen in `preparation/proposed-sources/`.
Root supplied the two exact B91 source pins. Bash syntax, ShellCheck, Python
compile, and Markdown checks passed offline. The case launcher requires a
separate START, actual namespace, source parity, and at least 390 seconds
remaining in a 720-second epoch. It was **not invoked**.

## Sole boot attempt and boundary

One approved boot fixed the epoch at **11:09:10.863154–11:21:10.863154 UTC**.
A finite exclusive lease and host primary-port SYN recorder started first;
then the owned display, isolated bridge, and SheepShaver started. The new
root-only `wait-emulator-r02.py` required one actual UID1000 emulator with a
pinned executable, FD6 on the owned working disk, FD16 on the guest PCAP,
and a valid 24-byte PCAP header within five seconds.

That helper timed out. A direct root `/proc` inspection immediately afterward
saw actual SheepShaver **PID 2626535**, start tick **7925773**, UID1000,
namespace inode **4026533665**, and FD6 on the owned working disk inode
**65602436**. FD16 and the guest PCAP file were absent at that observation.
The executable path contained the pinned build name, but the failed helper
did not complete its executable-byte hash or full readiness gate. The
readiness receipt, namespace recorder, 18-action control preflight, and 304
case never started. The 24-byte host PCAP recorded zero packets and zero
kernel drops. There is no guest screenshot from this pre-UI failure.

The boot script exited 1. Owned sheep, bridges, display, lease, and host
recorder were stopped by 11:10:16 UTC. The actual emulator PID disappeared;
root fuser then found the stopped working image FD-free. Ports 15880–83 were
absent, the exclusive lock was free, and original primary/client start ticks
were unchanged. This was unit retirement before guest readiness, **not** an
orderly Mac OS shutdown or a persistence test. The working image is
quarantined. No read of its bytes occurred while the emulator held it.

The five-second timeout establishes only that this gate did not observe FD16
in its window. It does not establish why FD16 was absent, whether it would
have appeared later, or any native server behaviour. A separate A110 source
audit must precede a redesigned observation gate; this document authorises
no VM retry.

## Offline check

From the `mothra` repository root, verify the complete repository-relative
inventory:

```sh
sha256sum --check evidence/gap-remediation/2026-11-14/native-rate304-startup-gate-01/SHA256SUMS
```

`manifest.json` fixes the failed precontact status and process/epoch identity.
The corpus contains the preparation scripts, pins, source closure, HFS checks,
boot stderr, direct `/proc` receipt, host capture, unit logs, and FD-free
retirement proof. It excludes disks, ROMs, emulator binaries, caches, and
generated Python bytecode.
