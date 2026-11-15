# Native 1.9 settings persistence witness (A46/A48)

The
[portable control corpus](../../evidence/gap-remediation/2026-11-14/native-settings-persistence-01/manifest.json)
records a bounded before/after restart test on one disposable Mac OS 9 working
image. It addresses the persistence clause of GAP-029 alongside the existing
[same-session 304 transitions](native-settings-transition-witness.md) and
[delayed 121 defaults](native-121-default-witness.md). The original criterion
asks for field-by-field update, default and persistence rules with before/after
state and emitted 301 fixtures. The gap status remains for the parent audit.

## Controlled sequence

- **Initial image:** the private working image and separate immutable base
  both had SHA-256 `e5cbbaaf…`; working inode `2214366960`. ROM `18da89e4…`,
  emulator `9c943042…`, native server data fork `ad7040db…`.
- **A46 readiness:** 18 control actions checked two original accounts, 41
  Files entries, agreement, roster and idle 303. The full file download was
  **not exercised**.
- **A46 phase one:** 64 planned observations plus two runner-added EOFs.
  Fixed admin 107 used name `A41-Baseline` and icon 3. Three 304 stages enabled
  `A41-Persist-On`/icon 17/113=`0004`/215=`a41-explicit-auto`, disabled with
  `A41-Persist-Off`/icon 18 and absent 113/215, then re-enabled. All 15
  identity, 301 and PM gates passed.
- **A46 shutdown:** both owned sockets stayed open through native File > Quit
  and the recognized Quit Now confirmation; the runner saw both EOFs. After
  Finder Special > Shut Down, the operator observed PID `355862` absent by
  03:45:49 UTC and retained a black display image. Stopped image SHA-256 was
  `e7ff4056…`.
- **A48 preboot:** the **same** working path/inode had SHA-256 `e7ff4056…`;
  it was not recopied or restored. A46's stopped network metadata was archived.
  New emulator PID `464176`, start tick `5380630` and namespace were proved.
- **A48 phase two:** the two fixed login 107 wire vectors matched A46 byte
  for byte. The 18-action readiness passed again. Fresh subject login returned
  to `A41-Baseline`/icon 3; one PM had no automatic reply. Its 26 observations
  and two **planned** EOF actions completed with three gates.
- **A48 shutdown:** the same File > Quit/Quit Now and Finder Special > Shut
  Down sequence was selected. The operator observed PID `464176` absent by
  04:08:34 UTC. Final stopped image SHA-256 was `be0b2c95…`.

The
[A41 baseline](../../evidence/gap-remediation/2026-11-14/native-settings-persistence-01/baseline/a41-assets.json)
and path-based stopped reads resolve admin UserData to catalogue 11193 (734
bytes), fixture-low UserData to 11201 (734 bytes), and `/Hotline19/Prefs` to
11202 (175 bytes). All three complete data-fork hashes matched the baseline
after **both** operator-observed guest shutdown sequences: `26612ad4…`,
`fce81359…`, and `4ed2b3e1…`. The base image remained `e5cbbaaf…`; image-level
hashes changed across boots as expected. The
[timeline and byte-identified screenshots](../../evidence/gap-remediation/2026-11-14/native-settings-persistence-01/baseline/operator-timeline.json)
retain the observed order. The
[user service journal](../../evidence/gap-remediation/2026-11-14/native-settings-persistence-01/baseline/user-sheep-journal.txt)
records both owned boots but **no explicit emulator exit status**. PID absence
and the lack of a prior host stop were contemporaneous operator observations,
not independent machine-watcher receipts; FD-free was gated before the HFS
reads but that gate's empty output was not retained. Therefore the lifecycle
evidence supports an orderly-shutdown interpretation with this proof limit. The
[offline FD-free recheck](../../evidence/gap-remediation/2026-11-14/native-settings-persistence-01/baseline/postpublication-fd-free.json)
is explicitly dated after extraction and is not a retroactive timestamp.

Static native handler `10016ad0` calls helper `10004d50` with a zero account
argument for the 304 path; the account-file writer belongs to a separate path.
Together with the measured 301/PM transitions, unchanged account and Prefs data
forks, and return to baseline on the fixed fresh login, this supports
**session-only 304 state in this controlled path**. The fresh 107 itself reruns
the helper, so its output alone does not prove the absence of other stored
state. No power-loss, all-storage, 121 durability, or general supplied-text
encoding claim follows.

## Replay and provenance

The two 900-second managed recorders were ready before the first socket in each
phase. Every phase has exactly three SYN-scoped control lifetimes: readiness,
observer, and subject. Host namespace, guest Ethernet and Recorder application
streams match byte for byte in both directions for all six flows; there are no
unread application tails. The primary host capture is exactly a 24-byte PCAP
header with zero packets. Both namespace recorders reported zero kernel drops.
Reset diagnostics, if present, remain in packet evidence and are not counted as
application bytes.

A46's as-run plan, report and checksums remain **unchanged**. Its plan has 64
actions while its custom runner reported 66 after EOFs, so the unmodified
generic `verify_capture` correctly rejects that original as-run format. The
verifier pins old generator `ecd3bba4…` and runner `9122c142…`, checks the
original checksums, EOF actions 64/65, all 15 semantic gates, and compares raw
events/frames/streams through a temporary normalized plan. That temporary plan
is analysis only and is never presented as the as-run source. A48 pins generator
`29ad770a…` and runner `a2474c41…`: its **original** 28-action capture passes
both generic `verify_capture` and its three-gate semantic verifier. The
[independent A46 replay receipt](../../evidence/gap-remediation/2026-11-14/native-settings-persistence-01/baseline/a46-parent-verification.json)
is retained.

```sh
python3 scripts/verify_native_settings_persistence.py \
  evidence/gap-remediation/2026-11-14/native-settings-persistence-01
python3 -m unittest discover -s scripts \
  -p test_native_settings_persistence_witness.py
```

**Procedure deviation:** the A48 live window did not hold the prescribed
`oracle.lock`. The supervisor granted an exclusive native lease, peer work was
offline, the actual private image/process/namespace were identified, and the
primary capture had zero packets. These controls support the bounded evidence
above; A48 does **not** establish full procedure conformance. A future run
should use a finite managed lock holder. No second attempt was made to conceal
or repair this omission.

For GAP-029's unchanged criterion, the combined static rules, A33/A37 defaults,
and these before/after 301, PM, restart and stopped-fork fixtures support a
**bounded native 1.9 criterion-met proposal**. The parent alone decides status
and wording in the central register and protocol contract.
