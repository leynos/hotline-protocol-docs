# GAP-037 transfer-state diagnostic attempt

This packet attempted to capture a
[native](../glossary.md#native) [Hotline Server 1.9](../glossary.md#hotline-server-19)
`303` reply while an owned transfer was active and another was queued. The
fixture upload failed before that state could be prepared. The
[retained batch][batch] records the failure, one guarded cleanup capture, and
the unchanged baseline. It does not supply an active-transfer or
near-1,024-byte diagnostic example. The [earlier idle examples][idle] remain
the positive 303 evidence.

This document belongs to the [Hotline 1.9 wire protocol](README.md) set; the
[glossary](../glossary.md) defines the terms it uses.

## Bounded preparation and failure

The operator leased the recovered Mac OS 9 native oracle without restarting it.
General Options showed port 5500, download limits 100 globally and 10 per
client, and five connections per IP. Both [screenshots][options] show those
values; no option was changed. Preflight captured the complete root Files view
(41 entries), exactly the two existing accounts, absence of the 31-byte owned
name `m-diag37-` plus 22 `x` bytes, and an idle self-303 using a UID from that
same connection's unique admin roster.

The second plan used the existing 1 MiB DATA pattern and resource fork helper
to upload only that new name with 203/HTXF. The server accepted 203 with status
zero and returned reference `00014c8e`. The recorder passed 1,049,088 HTXF
bytes to the host socket, then its read-for-EOF failed with
`ConnectionResetError`
104. Host and guest packet records retain only 193,913 and 74,295 incoming
bytes respectively, both strict prefixes of the recorder's send. The host
capture contains a server-side proxy RST. The guest terminal reset travels from
client to server, so these views do not establish a native-server-initiated
reset. The [guest log screen][abort] says “Upload aborted”. The planned 206
success confirmation was never reached. The packet does not identify why this
upload aborted; a successful send call does not prove complete delivery to the
guest.

## Positive partial-file cleanup

The operator stopped the active/queue and formatting-boundary work. A single
supervisor-approved [conditional cleanup][cleanup] then logged in and read 206
plus the full Files view before any deletion. Both independently identified the
exact preflight-absent owned name. The 206 response included raw field 205
bytes spelling `Incomplete File`; this is observed metadata, not a guessed
fork-length or transfer state. Only after that positive match did the plan send
204 field 201 for the owned name. It returned status zero. A later 206 reported
absence, the full Files view matched all preflight bytes, and the two-account
348 enumeration and idle self-303 were restored. The selected plan is retained
with its exact report and as-run coordinator source hash. No other file was
deleted.

The [offline verifier][verifier] checks the failed status and action boundary,
positive owned identity before 204, exact deletion target, final Files/account
baselines, same-session UID, and idle diagnostic. It reconciles preflight,
seed-control and cleanup TCP lifetimes across host and guest. It deliberately
checks **prefixes**, rather than claiming the failed seed's 1,049,088 bytes
arrived at the guest. The three host recorders reported zero kernel drops.

From `mothra` with the adjacent protocol repository:

```sh
sha256sum -c evidence/gap-remediation/2026-11-13/native-diagnostic-load-01/SHA256SUMS
python3 ../hotline-protocol-docs/scripts/verify_native_diagnostic_load.py \
  evidence/gap-remediation/2026-11-13/native-diagnostic-load-01
python3 -m unittest discover -s ../hotline-protocol-docs/scripts \
  -p test_native_diagnostic_load.py
```

> Record note (2026-11-16): the commands above are quoted as they were run. The
> tests have since moved to `scripts/tests/` and run under pytest; the same
> tests now run with
> `uv run --group dev pytest scripts/tests/test_native_diagnostic_load.py`.

The exact [as-run commands][as-run] and host/guest snapshots are portable in
the batch. The source-side 303 formatting bound remains `0x400`; no new field
101 length near it was measured. The active-transfer/queue example, boundary
example, and exact-text release policy remain open under the original GAP-037
criterion. A later packet needs a new owned fixture plan and review; this run
authorizes no blind upload retry or additional guest mutation.

> Status note (2026-11-16): the register now lists
> [GAP-037](../../gap-analysis.md#gap-037) as Resolved. Its closure text
> records the criterion as met for mandatory and descriptive content and
> representative replies, and claims no at-cap native clipping fixture.

[batch]: ../../evidence/gap-remediation/2026-11-13/native-diagnostic-load-01/manifest.json
[idle]: diagnostic-replies.md
[options]: ../../evidence/gap-remediation/2026-11-13/native-diagnostic-load-01/options-after-cleanup.png
[abort]: ../../evidence/gap-remediation/2026-11-13/native-diagnostic-load-01/guest-after-seed-failure.png
[cleanup]: ../../evidence/gap-remediation/2026-11-13/native-diagnostic-load-01/cleanup/report.json
[verifier]: ../../scripts/verify_native_diagnostic_load.py
[as-run]: ../../evidence/gap-remediation/2026-11-13/native-diagnostic-load-01/as-run.txt
