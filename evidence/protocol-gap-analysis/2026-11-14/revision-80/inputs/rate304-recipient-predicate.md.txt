# Native 1.9 notification recipient predicates

This is a bounded static reading of Hotline Server 1.9. The frozen
[oracle and source corpus](../mothra/evidence/gap-remediation/2026-11-14/rate304-recipient-predicate-01/manifest.json)
records the PEF DATA SHA `ad7040db…`, PowerPC big-endian 32-bit language,
1,840 saved functions, the exact query, and equal program identities before
and after the read-only `--no-analyze --discard` session. The A104 and A105
reports are retained as text beside the raw result. No new live 304 test was
run for this finding.

## Connection bit and recipient gate

The untruncated [`10058600` result](../mothra/evidence/gap-remediation/2026-11-14/rate304-recipient-predicate-01/oracle/raw/decompile-10058600.json)
reads the high bit of the byte at `connection+0x4c` and returns 0 or 1 for a
nonnull connection. Its null path calls `10027c30`; the retained body does
not establish whether that call returns. The same connection field is
`((undefined4 *)connection)[0x13]` in the decompiled handlers.

The dispatcher [`1000acf0`](../mothra/evidence/gap-remediation/2026-11-14/rate304-recipient-predicate-01/sources/D-1000acf0.c)
calls [`10058650`](../mothra/evidence/gap-remediation/2026-11-14/rate304-recipient-predicate-01/sources/D-10058650.c)
to read a TRTP header. On an accepted `HOTL` subversion 2 or 3, it calls
[`10058770`](../mothra/evidence/gap-remediation/2026-11-14/rate304-recipient-predicate-01/sources/D-10058770.c).
That helper queues an eight-byte `TRTP`/zero response and sets the high bit
of `connection+0x4c`. Thus the bit is **set on the accepted TRTP response
path**. The source does not prove that queued response bytes reached the
client before the bit was set. The inspected
[`100590e0`](../mothra/evidence/gap-remediation/2026-11-14/rate304-recipient-predicate-01/sources/D-100590e0.c)
frame-read branch checks that high bit; its invalid-size write sets bit 4
without clearing bit 7. The retained writer search was local, not an
exhaustive connection-lifetime analysis.

[`10005510`](../mothra/evidence/gap-remediation/2026-11-14/rate304-recipient-predicate-01/sources/B06-D-10005510.c)
walks recipient sessions for 301 and invokes the enqueue helper only when
**both** the recipient connection's `10058600` result is nonzero and the
recipient session's `+0x14a` online sign is set. This is a recipient test.
It does not inspect the sender's requested name, icon, option flags, status
field 112, or presence of field 102. In the A103/A105 direct icon-only 304 chain,
omitting 102 changes a requested-name field but shows no edge clearing this
recipient bit or online sign. That is a bounded source observation, not a
claim that no other path can clear either state.

## Roster uses a different predicate

The dispatcher maps transaction 300 to
[`10011870`](../mothra/evidence/gap-remediation/2026-11-14/rate304-recipient-predicate-01/sources/D-10011870.c).
It includes a session row when the `+0x14a` online sign is set **and** the
effective name at `+0x38` is nonempty. It does not call `10058600` or test
`connection+0x4c`. A two-row roster is positive evidence for those roster
conditions at that moment; it alone does not prove the 301 recipient bit.

The C107 observer did receive the subject's initial 301 with icon 1 before
the first 304, which is positive wire evidence for passing its recipient
gate then. The paced subject's icon 2 301 and numbered 500 ACK arrived after
the fixture's 0.55-second wait, while the observer was already closing.
These observations do not prove uninterrupted recipient eligibility, a
specific scheduling cause, delivery to the closing observer, or a general
absence of 301. They do not establish the native 304 limit or reset rule.

## Replay and provenance

From the `mothra` checkout:

```sh
cd evidence/gap-remediation/2026-11-14/rate304-recipient-predicate-01
sha256sum --check SHA256SUMS
```

`manifest.json` maps every copied source to its original repository path
and SHA. `oracle/original-SHA256SUMS.txt` preserves the as-run A104 hashes.
The corpus excludes the saved Ghidra project, binary, cache, and native
runtime. Cross-check the dynamic failed-pair boundary in
[`native-rate304-first-pair.md`](native-rate304-first-pair.md); this source
reading does not revise those packet observations.
`reports/a106-b91-pipeline-review.md.txt` separately records the later
offline coordinator rehearsal; it is not native runtime evidence.
