# Native settings persistence control corpus

This corpus records one controlled phase before and one after a restart of the
**same** disposable Mac OS 9 working image. The control-only readiness profile
checked two accounts, 41 Files entries, agreement, roster and idle diagnostic.
It did not run the full file download baseline.

The A46 plan contained 64 actions; its unchanged runner wrote two additional
EOF observations at actions 64 and 65. The original plan/report/checksums are
retained under `phase1/phase1/`. The generic capture verifier must reject that
original format. The protocol verifier pins the old source hashes, validates
the original checksums and semantic gates, and uses a temporary normalized
copy only to replay frames and streams. No normalized copy is published as an
as-run capture.

The A48 plan contained 26 observation actions and two planned EOF actions.
Its 28-action capture passes the unmodified generic verifier. Both phases
retain separate readiness and application captures, complete namespace and
guest PCAPs, a primary host PCAP, paired-stream receipts, stopped path-based
HFS data forks and image hash/stat records. The service journal records boot
starts but no explicit natural-exit status. The timestamped operator timeline
labels PID absence and pre-extraction FD-free observations separately from
machine-retained proof. Source files are exact historical
copies. The actual ROM, disks, server application and live image are excluded.

**Operational deviation:** A48 did not hold `oracle.lock`. The supervisor had
granted the exclusive native lease; the captured primary host interface had
zero packets, and the lab identity and three controlled TCP lifetimes were
verified. This supports bounded evidence review. It is not full procedure
conformance. The postpublication FD-free receipt is a current offline recheck,
not a retroactive timestamp for either fork extraction.

Replay from the adjacent protocol checkout without a VM or Ghidra project:

```sh
python3 scripts/verify_native_settings_persistence.py \
  ../mothra/evidence/gap-remediation/2026-11-14/native-settings-persistence-01
```

The verifier checks the SHA inventory, original source and plan hashes, A46's
legacy 64+2 contract, A48's strict 28-action contract, stage gates, paired
streams, zero primary traffic and drops, same image inode, and all three
unchanged stopped data forks. Fresh login reruns the settings helper; the
result does not prove power-loss durability or the state of every storage path.
