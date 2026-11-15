# A141: first alias-positive attempt, independent frozen-prefix review

Read-only review of the uncommitted
`evidence/gap-remediation/2026-11-14/native-alias-positive-first-01` corpus.
No native service, image, UI, protocol request, or mxd action was taken.

## Copy and source provenance

- `SHA256SUMS` verified all 272 listed raw files. A separate byte comparison
  matched all 123 `raw/epoch` copies to the original O directory, 145
  `raw/preparation` copies to P, and four service records to their display
  or runtime originals. Manifest size and SHA entries match every file;
  there are exactly 272 raw files and no unlisted file. A Python import in
  this review briefly generated an unlisted `__pycache__/pcap_tcp` bytecode
  file in the corpus; I removed that exact byproduct and rechecked 272/272.
- The frozen root approval records proposal SHA
  `2eab41d2f6d52ab3e38737158ce518295ea50ccf2ac115435ccc67b473c3ed74`,
  with exact 2 M1, 35 module, three helper, two launcher, and ten operator
  script pin counts. P's approved pin files and raw snapshots match the
  copied bytes. Runtime identifies actual emulator PID 2881568/start 9866291,
  namespace 4026533819, and working inode 1815238450.
- The five original preparation `icat` fork-byte outputs for admin,
  fixture-low, Prefs, server DATA, and server RSRC are explicitly excluded
  from this corpus; no ROM, working/base disk, or original fork bytes occur
  among the listed raw paths. Stopped *hash/size receipts* for those five
  forks remain, as required for the bounded baseline comparison.

## Wire and failure boundary

- Closed readiness completed 18 actions, six numbered requests, with
  231 sent and 2759 received bytes. The single case report is **failed**:
  `ValueError: Reviewed Finder receipt absent`, at
  `awaiting-reviewed-Finder-receipt`. It records three numbered requests,
  one owned-folder mutation, five frames, 14 events, 160 sent and 2173
  received bytes, EOF, and empty unparsed tail. The case plan names five
  numbered requests (login, 205, 200, 200, 206); only login, 205, and the
  first 200 ran. Thus nine observed numbered requests across both flows
  versus 11 planned. `operator` and `positive206` are null. No alias, copy,
  Get Info, host unlink, second 200, or 206 was observed.
- I independently parsed the frozen namespace and guest PCAPs with the
  frozen `pcap_tcp.py`. Both have exactly two unique SYN lifetimes. Readiness
  stream is 231/2759 bytes and case stream 160/2173 bytes in **both** views;
  each full-direction byte string equals its corresponding report and the
  retained `paired-streams.json`. Namespace has 51 TCP packets, guest 61,
  with two FIN and zero RST packets in each side of each flow. Primary SYN
  PCAP is a valid 24-byte header with zero TCP packets. The journal records
  namespace 51 captured/zero dropped and host zero captured/zero dropped.
- `case-ready-screen.png` shows a saver image; `case-wake-click.png` shows
  Hotline Server windows and the owned folder-create log line after the
  guarded wake click. These images do not identify the Unix target or prove
  why the operator could not reach the alias action before the cutoff.

## Retirement and conclusion

- Case SYSTEM unit exited status 1. Terminal evidence records a **forced VM
  stop**, with no native app Quit or orderly Mac shutdown claim. The actual
  PID was gone and working-image `fuser` returned 1 with empty output before
  stopped HFS reads. Original primary/client PID start ticks were unchanged.
- Stopped HFS catalogue shows allocated empty owned wrapper
  `/Hotline19/Files/m-alias54-only` at ID 11748. The baseline two active
  users, absent Banned, zero board DATA, unchanged external target and `.finf`,
  and five named fork hashes match the preparation receipts. These are
  stopped-state observations after forced retirement, not durability proof.

This corpus is a trustworthy **failed pre-alias prefix**. It contributes no
positive missing-alias resolution, target-metadata, or rejection result.
GAP-054 remains Investigating. I found no consequential copy/provenance
defect in this bounded review.
