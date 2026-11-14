# Native board lab: aborted readiness

The [frozen corpus](../mothra/evidence/gap-remediation/2026-11-14/native-board-readiness-failure-01/manifest.json)
records an isolated Hotline Server 1.9 board lab on 14 November 2026. The VM
booted and the server opened its owned listener. The **18-action control
readiness did not run**, and the board case did not run. The namespace PCAP has
only its 24-byte header: no protocol connection or request was made. This is
an operator receipt failure, with no observed native protocol defect.

The fixed epoch began at 08:44:02.051250 UTC and had a hard deadline of
08:56:02.051250 UTC. The actual emulator was PID 1364862, start tick 7054838,
namespace inode 4026532471, with FD6 on the owned working image inode
3290903959 and FD16 on the guest capture. The host primary-port and lab
namespace recorders each retained an empty 24-byte PCAP. Their terminal
journals report zero captured and zero kernel drops. The guest capture records
boot activity; it is not a board request witness. The original primary and
client process start ticks were unchanged.

Two procedural failures are retained separately:

1. The first readiness unit exited 1 before opening a socket. Its receipt
   copied two extra, truthful systemd fields into `managed_lock.unit_properties`
   and omitted `ActiveEnterTimestampMonotonic`. The live gate compares that
   dictionary to the exact six properties returned by `systemctl show`, so it
   raised `ValueError: Managed service changed`. The actual lock service was
   active and the separate 900-second coverage record retained the extra
   fields.
2. A non-root correction attempt could not rewrite the root-owned receipt
   (`PermissionError`). A non-strict shell then launched a corrected unit
   before its script existed. That unit exited 127 with “No such file or
   directory”, also before opening a socket. The original receipt, failed
   units, commands and logs are all preserved. The exact six-field receipt
   and script were subsequently prepared, but no third unit was launched:
   the required 08:49:10 launch cutoff had passed at the observed 08:49:19
   check. No claim is made that the prepared correction passed live.

The board source plan was generated with the actual runtime identity but was
**never executed**. It does not demonstrate post 103, read 101, update 102,
formatting, access control, or durability. The next lab requires a fresh,
separately authorised runtime and a receipt builder that validates its exact
six-field lock properties before any readiness unit starts. Such a builder
was planned by root as B82; this packet does not claim it is implemented or
validated.

The native application was quit and the owned SheepShaver unit stopped.
The Mac OS was not shut down orderly. At 08:50:49 UTC the actual PID was
gone, owned ports were absent, the working image had no holder, the lock was
free, and the original services retained their start ticks. Only after that
FD-free gate, read-only TSK checks found the original two UserData forks,
Prefs, and server DATA/RSRC forks byte-identical to the stopped preflight.
`/Hotline19/MessageBoard.txt` remained an allocated `TEXT`/`ttxt` file:
its data fork was zero bytes; `istat` reported resource size zero, and TSK
found no separate resource attribute. This is a stopped, named-fork check,
not a claim about every byte of the mutable image.

Offline checks from the Mothra corpus directory:

```sh
sha256sum --quiet -c SHA256SUMS
python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path('raw/sources').resolve()))
from pcap_tcp import read_packets
assert read_packets(Path('raw/primary-syn.pcap')) == []
assert read_packets(Path('raw/lab-namespace.pcap')) == []
PY
```

The two raw captures, both failed unit transcripts, the original and corrected
receipts, prepared plans, source snapshots, screenshots, terminal proof and
stopped fork hashes are retained under the corpus inventory. This record does
not change the open native board requirement or reset the owned lab image.
