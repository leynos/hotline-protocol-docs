# A126 corpus provenance review

This review compares the unpublished corpus with the frozen preparation and
native epoch. It does not assess B107's portable semantic verifier or close
GAP-047.

## Copy and source identity

- Before adding this review, the corpus had 236 files: 234 manifest-listed
  content files, the manifest,
  and `SHA256SUMS`. All 235 listed hashes verify from the Mothra root.
  The manifest's content map matches the actual files. No ROM, disk image,
  database, bytecode cache, or raw account fork is present.
- The original 138 epoch files, 20 preparation files, 40 proposed-source
  files, and 26 stopped-marker-fork files are byte-identical to their
  respective originals. Nine preparation scripts were placed in a `scripts`
  subdirectory; each basename and hash matches its original.
- `raw/epoch/source-freeze.json` pins 37 protocol modules and three Mothra
  helpers. All copied source hashes and both approved 37/3 pin files agree.
  The plan, case report, and runtime pins refer to these frozen inputs.

## Packet evidence

- Namespace and guest PCAPs contain the same two service SYN lifetimes,
  client ports 52304 and 39238. The primary capture has a valid 24-byte
  header and zero TCP packets.
- Closed readiness: namespace 30 packets, guest 34; both directions match
  the report's 231 sent and 2,759 received application bytes exactly.
  Completed case: namespace 222 packets, guest 293; both match the report's
  11,529 sent and 8,295 received bytes exactly.
- FIN/ACK terminals have no extra TCP payload. The case report has an EOF
  terminal and an empty unparsed tail. It records 12 cells, 82 requests,
  20 mutations, 84 frames, and 173 Recorder events.
- The retained capture journal reports namespace 252 packets captured,
  host zero captured, and zero drops for both. The 504 namespace packets
  received by filter are a filter counter, not 504 captured packets.

## Retirement and stopped HFS readback

- The fixed epoch began at 13:57:46 UTC. Native app File > Quit was clicked
  at 14:02:19; emulator retirement was recorded at 14:02:55, capture units
  stopped at 14:03:37, and stopped HFS summary ran at 14:04:10, before the
  14:09:46 deadline. The emulator received TERM after app Quit. An orderly
  guest OS shutdown is **not established**.
- `emulator-retire.json` and `stopped-marker-forks/fd-free-before-read.json`
  record PID 1058709 absent, working image inode 5999397982, and root fuser
  exit 1 with no listed owner before HFS fork reads. Original primary and
  client start ticks remained unchanged.
- The stopped catalogue has 11 allocated owned Trash entries: News category
  and folder, Files wrapper, H, S, and p0 through p5. The new 11 `istat`
  outputs are tied to those IDs. The owned category is a 1,024-byte DATA
  file, type `HLNZ`, creator `HTLS`, with reported resource fork size zero
  and no resource attribute. Its retained DATA hash is
  `7d82b5826175ca1971249907692fa51823998e11d77dbd577226ee2bde97cd1a`.
  The other ten entries are folders. All 12 stopped read commands exited
  zero and their output sizes and hashes match the receipts.
- These are post-cleanup locations. Live 200/206 replies prove the earlier
  selected parent; the stopped catalogue alone does not. TSK's displayed
  high-byte name differs from literal wire byte `9a`, so it is evidence of
  selected object identity, not a returned-name byte round trip.

## Scope and disposition

The draft 202/212/325 tables use the source-backed 2,048-byte reader cap,
observed 2,048/2,049-byte prefix cases, and finite root/nested fixtures.
The field-325 wording was corrected to say the raw component contains `9a`
and resolves the owned high-byte folder. No universal path normalization,
2049th-byte parsing, crash durability, or normal shutdown follows.

Within this provenance scope, no consequential copy, checksum, paired-flow,
or stopped-readback defect was found. B107 replay and root's final contract
review remain separate acceptance gates.
