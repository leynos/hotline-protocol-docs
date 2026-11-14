# Native temporary-ban first epoch

This control-only witness records the **first** epoch of a temporary ban on a
disposable Hotline Server 1.9 lab. It does not establish the expiry boundary.
The full file-transfer A7 baseline was **not exercised** in this lab.

## Reproducible record

The portable corpus is
[`native-ban-expiry-first-01`](../mothra/evidence/gap-remediation/2026-11-14/native-ban-expiry-first-01/manifest.json).
Its manifest binds the original preboot image and native binary identities,
the actual emulator PID 774195, start tick 5983214, image inode 3290756512,
namespace `net:[4026533397]`, capture units, fixed 05:56:51 UTC deadline,
12 generated plans, and the exact as-run protocol source. The frozen controller
SHA-256 is `f5e46930ec466030dca62ee12ca79f8af856aa29ef88de34afaac50f4b0f0210`.
The live source may be hardened later; this copy preserves what actually ran.

C75 ran the 18-action control readiness plan before any mutation. C76's first
managed controller launched outside the lab namespace: it failed with
`ConnectionRefusedError`, **zero completed actions and zero events**. This is
a controller launch failure, not a native-server result. C77 set
`NetworkNamespacePath=/proc/774195/ns/net`, independently checked the actual
runner namespace, and completed the nine planned cases once each.

The cases guarded two absent account names, seeded a zero-access target and a
protected control, tested kick option 0 and a fresh successful login, tested
the protected error path, then issued one option-1 temporary ban and an
immediate valid login probe. The protected case produced a type-302 packet
after the Recorder stopped reading that socket: the exact 28-byte tail appears
in **both** packet views and is retained by replay. The 35-second pause after
readiness had no namespace packets. That is a bounded, recorded interval;
traffic after capture stop was not observed by these recorders.

The ban request's host bracket is
`2026-11-14T05:55:01.616113+00:00` through
`2026-11-14T05:55:01.632067+00:00` (ACK). The separate guest-clock screenshots
show visible seconds and have host before/after command timestamps. They are
read-only clock observations, not a calibration of guest `GetDateTime` or
proof of one-second guest progression.

Thirteen control connections have SYN-scoped client-to-server and
server-to-client byte streams matched independently in the namespace and
guest PCAPs. The primary-port recorder had a 24-byte header and no captured
SYN; both managed recorders reported zero kernel drops. The app sockets were
closed, capture units and oracle lease were stopped, and original primary and
client PIDs were stable at the terminal receipt. The lab VM and its guest PCAP
FD remained live for a later, separately authorised epoch; this export contains
only a stable first-epoch PCAP prefix and no working disk.

## Offline replay

From this protocol repository beside the Mothra repository:

```sh
python scripts/verify_native_ban_expiry_first.py
python -m unittest discover -s scripts -p test_native_ban_expiry_first.py
```

The verifier checks the corpus inventory and source snapshots, the original
generic Recorder semantics, the frozen B68 case gates, actual runner identity,
packet-level settle, timing, paired TCP bytes, and terminal capture/cleanup
receipts. B68 case reports use a different metadata shape from the generic
capture verifier. Replay adapts **metadata only in a temporary directory**;
the raw report events, frames and streams remain unaltered, and the frozen B68
gate evaluates the original report. Fault tests rehash mutated corpora so the
semantic checks must reject wrong UID/ACL/notice/timing/namespace/deadline,
paired bytes, and capture provenance independently of the SHA inventory.

This record supports an immediate temporary-ban response only. Expiry,
release at a later timestamp, persistence, broader native conformance, and
unobserved idle traffic require later evidence.
