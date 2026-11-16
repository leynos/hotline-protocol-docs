# Native roster overlap witness

This control-only Hotline Server 1.9 lab exercised one outstanding roster
request (300) while another session changed its own name and icon (304). The
portable
[corpus](../../evidence/gap-remediation/2026-11-14/native-roster-overlap-01/manifest.json)
contains the original plans, reports, source snapshots, both packet views, and
retirement receipts. Replay it without a VM:

```sh
python3 scripts/verify_native_roster_overlap.py
python3 -m unittest discover -s scripts -p test_native_roster_overlap_witness.py
```

## Scope and result

The disposable Mac lab used two connections authenticated as the existing admin
account. The preflight and postflight each completed the same 18-action control
readiness: two original accounts, 41 Files descriptors, agreement, metadata,
roster, and idle checks. The full file transfer A7 baseline was **not
exercised** in this lab. No account, file, configuration, or clock change was
requested. The stopped original account forks, Prefs, server DATA, and server
RSRC match their preboot hashes. This bounds checked storage changes; it is not
a claim that every disk byte remained unchanged.

| State                                      | A name/icon   | B name/icon     |
| ------------------------------------------ | ------------- | --------------- |
| Initial 300 ID10 on both connections       | `Order A` / 1 | `Order B` / 2   |
| A's outstanding 300 ID11                   | `Order A` / 1 | `Order B` / 2   |
| A's final 300 ID13 after both 500 barriers | `Order A` / 1 | `Order New` / 3 |

The dynamic B UID was `0003` in the initial observer 301, both initial rosters,
both rename 301 updates, and the final roster. A and B each received one rename
301 carrying B's new name and icon. Both 500 requests received correlated
type-0, successful ACKs; A's earlier 300 ID11 also received a correlated
successful ACK. No direct 304 ACK was observed or required by the fixture. A's
ID11 reply contained the complete **old** B pair; its later ID13 reply
contained the complete **new** pair. The collector accepted either complete old
or complete new ID11 pair and checked for torn or extra rows.

The source-declared coordinator sent A/300 ID11, B/304 ID20, then A/B 500 ID12
before its two-socket drain. Its retained operation map connects every send and
receive to the plan and byte streams. The returned snapshot is one observed
scheduling outcome. A send before another socket's receive does not establish
which request the server handled first. `arrival_ns` records local frame
completion, not the server's transaction instant, and no global order across
the two sockets follows. This fixture does not establish universal atomic
roster snapshots or a race-free subscription algorithm.

Four SYN-scoped TCP lifetimes cover preflight, A, B, and postflight. Their
namespace and guest views have equal complete bidirectional application bytes,
including tails and two FINs per lifetime: preflight 231/2759 bytes, A 166/680,
B 169/479, postflight 231/2759 (client/server respectively). The host
primary-port SYN capture has zero packets; both recorders report zero kernel
drops. The lab's frontend and guest addresses are scoped to its owned
namespace. The fixed primary bridge existed there but was unused.

The retained system unit has `NetworkNamespacePath=/proc/953125/ns/net`, and
the B71 controller executed its namespace guard. Its two-second lifetime ended
before a separate `/proc` sample of the runner could be captured, so there is
**no observed runner PID/netns receipt**. Packet pairing independently supports
endpoint placement. The lab emulator was PID 953125, start tick 6421050,
executable SHA `9c943042…`, netns `4026532547`, and working-image inode
5973041789. Owned emulator, recorders, lease, bridges, and display were stopped
before the fixed 07:09:57 UTC deadline; a later read-only check found the lab
ports absent, original process start ticks unchanged, the image FD free, and
the oracle lock available. The server app was quit through its UI; the emulator
was then stopped forcibly. This was not an orderly Mac OS shutdown.

Two offline operator errors remain in the record. A parent replay first used
the nonexistent `captures/readiness` path; the actual `readiness` result was
then verified before overlap traffic. The first stopped `icat` invocation
returned 127 because `LD_LIBRARY_PATH` omitted the bundled Sleuth Kit library;
it was rerun on the stopped image with the correct path, and all five named
fork hashes matched preflight. Neither error was a native protocol failure, and
neither erased the original failure record.

For [GAP-035](../../gap-analysis.md#gap-035), this supplies one native
snapshot-race trace alongside existing initial-login and rename evidence.
Eligibility, recipient, and ordering rules still need reconciliation against
the original closure criterion; that decision belongs in the central gap
register after independent review.
