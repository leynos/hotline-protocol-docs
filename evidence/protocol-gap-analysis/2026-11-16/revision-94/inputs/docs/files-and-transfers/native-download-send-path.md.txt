# Native ordinary-download send path

This static trace follows a successful Hotline Server 1.9 request **202** into
an attached HTXF ordinary download. It explains the variables that could be
measured in a future stall investigation. It does **not** explain the
98,304-byte prefix observed in the
[failed lab baseline](native-transfer-stall.md). The frozen
[C39–C41 corpus][corpus] contains the seven earlier decompilations, the two
read-only headless query runs, their exact invocation scripts, the unannotated
caller result, project-file hash maps and source provenance. No program
database, binary, disk or ROM is exported.

## Request, attachment and producer

| Stage           | Frozen function         | Established action                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| --------------- | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dispatch        | `1000acf0`              | Kind 202 calls `100121a0`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Request         | `100121a0`              | Checks access and path; initializes or resumes the flattened file, computes its advertised length, allocates an ordinary-download entry and returns size/reference in the ACK. The entry starts with send allowance `0x19000` (102,400 bytes). It joins the active list or the waiting queue according to capacity.                                                                                                                                                                                                                                               |
| Data attachment | `1000bd20` → `1000e600` | An odd ordinary HTXF reference selects the matching active or waiting entry and stores the data transport. A waiting entry still needs admission.                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Admission       | `1000cfa0`              | Moves an eligible waiting entry into the active list.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Producer        | `1000c200`              | For an attached live transport and open file, sends when its transport count is at most the entry allowance **or** its readiness predicate is true. It increases allowance by `0x19000` under its zero-count and recent-send conditions, capped at `0x200000` (2 MiB), serializes up to the remaining advertised bytes, enqueues the handle and increments its own requested/enqueued byte count. At that count reaching advertised size it closes the file and marks the stream inactive. This does not itself close the TCP connection or prove client receipt. |

The inspected OpenTransport branch of `1006e040` reaches `10071650`, which sums
`node[3] - node[2]` over the pending-send list at transport object `+0x3c`.
This is the number of **queued bytes remaining in those nodes**. Its alternate
branch reaches unqueried `100778d0`; the live transfer's branch flag was not
measured. The inspected readiness branch reaches `10071950`, which returns true
if that list is absent or its first node's next pointer is zero. Its wrapper
`10074b10` can also force false for an absent object or alternate mode. This
predicate is not a direct TCP ACK or receive-window test.

The inspected enqueue path, `10070d20`, tries `OTSnd` immediately when the
pending list is empty. A negative result is treated as zero bytes accepted. If
fewer than the handle's bytes were accepted, it records the accepted count in a
node and links the remainder; with an existing list it appends a node.
`10071770` checks list state before dispatching callback event `0x66` through
`10028dc0`; its wrapper `100749b0` only calls it in the inspected ordinary
mode. The callback recipient and later scheduling are still untraced.

These counts have different meanings:

| Count                         | Meaning                                                          | What it cannot prove alone                   |
| ----------------------------- | ---------------------------------------------------------------- | -------------------------------------------- |
| ACK field 108 / entry `+0x14` | Advertised flattened-file length                                 | That all bytes were produced                 |
| Worker entry `+0x18`          | Bytes requested for serialization/enqueue                        | `OTSnd` acceptance or client receipt         |
| Transport pending-list sum    | Queued bytes not yet accepted by `OTSnd` in the inspected branch | Peer TCP ACK or disk persistence             |
| C38 packet ACK at 98,304      | TCP acknowledged that many bytes in the frozen flow              | The worker's state or why production stopped |

The observed prefix is 4,096 bytes below the initial 102,400-byte allowance.
The frozen path does not identify 98,304 as a chunk, queue or stop threshold.
The serializer `1002d830` calls fork reader `1002e300`, which uses
`PBReadSync`; the serializer ignores that helper's return. That fact does not
establish a short read or error in the failed session.

## Limits and next proof

C40 found one direct call site, `100017e0`, into `1000c200`, but the saved
1,840-function project assigns no containing function there. The eighth C40
content query returned `FUNCTION_NOT_FOUND` for decompilation at that site. C41
did not inspect the alternate count helper `100778d0`, send-list drain
callbacks, `10028dc0` dispatch or the unannotated caller. Runtime branch mode,
worker revisits, queue-node state and the cause of the C35 stall remain open. A
later bounded test would need one reference's advertised and producer counts,
allowance, queued-node bytes, `OTSnd` acceptance, callback firings and worker
visits over the silent period. No such test was run here.

Replay the exported corpus without Ghidra, the VM or any live server:

```sh
python3 scripts/verify_native_download_send_path.py \
  evidence/gap-remediation/2026-11-13/native-download-send-path-01
python3 -m unittest discover -s scripts -p 'test_native_download_send_path.py'
```

The verifier checks the full SHA inventory and source provenance, exact PEF
identity and unchanged saved project hashes, read-only query flags and query
budget, the request/worker chain, and the inspected counter, enqueue and
callback conditions. Fault controls reseal altered oracle results and verify
that changed counter, negative-send queueing, callback or identity claims are
rejected. The source queries were `1006e040`, `1006e1a0`, `1006de10`,
`1006e0b0`, `1006ddb0`, `1002e300`, the caller graph for `1000c200`, and
`100017e0` (which had no assigned function); C41 queried `10074930`, `10071650`,
`10074b10`, `10071950`, `100742a0`, `10070d20`, `100749b0` and `10071770`.
Both headless runs used `--no-analyze --discard` on the separate saved project
with PEF SHA-256
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`.

[corpus]: ../../evidence/gap-remediation/2026-11-13/native-download-send-path-01/manifest.json
