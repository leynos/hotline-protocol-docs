# Native 1.9 delayed 121 default response (A37)

The
[portable A37 corpus](../../evidence/gap-remediation/2026-11-14/native-121-defaults-01/manifest.json)
records one 70-action, two-case delayed agreement observation between exact
full A7 preflight and postflight readbacks. The pinned Hotline Server 1.9
binary has SHA-256
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`. No account,
file, server option or agreement content was changed.

The observer used the existing admin account. Each sequential subject also used
admin but omitted both 102 and 104 during 107, selecting the delayed branch.
Each received a successful 107 ACK and a 109 containing exactly 242 agreement
bytes (SHA-256
`5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7`). Before 121
the observer roster contained only itself. Each subject then sent 121 with a
distinct 102 name and 104 icon, bitmap 113=`0004`, and either absent or
zero-length 215. Its 121 success ACK had no fields. The observer received the
matching 301 and the subject received its own 354 privileges; each also
received one optional banner 122. The post-121 roster included the new subject.
Admin's naming privilege made the requested session names effective;
account-name fallback for other privilege profiles is separate.

| 215 input   | Current UID/name/icon       | Measured automatic 104       |
| ----------- | --------------------------- | ---------------------------- |
| Absent      | `0040`, `A35-absent-215`, 7 | Option 4, exact default text |
| Zero length | `0041`, `A35-empty-215`, 8  | Option 4, exact default text |

One uniquely labelled option-1 PM per subject received an empty success ACK and
original delivery. The observer received one automatic 104 with subject
UID/name and field 101 exactly the 52 ASCII bytes
`I'm not able to respond right now. Please try later!` (SHA-256
`fc1c491daeb3942d1df958851ed8c0fa4359fcefab44c0cccbe7581d7e352b62`). Both
sessions closed; each produced a matching 302 and a subject-free observer
roster. All 27 live semantic gates passed, including identity and 301 checks
before dependent PMs and full cleanup before the second login. The frozen
`10011ee0` call order is 121 ACK, settings-helper 301, own 354 and optional
122. The ACK and 354 order is also visible on each subject TCP flow. The 301
travels to the observer on a separate flow; this capture does not establish a
global cross-socket receipt order.

The A7 preflight and postflight each completed 29 actions and a 1,049,073-byte
FILP stream, with two accounts, 41 Files entries, unchanged fixture metadata
and matching DATA/MACR hashes. Both retained the original 242-byte agreement
and admin privilege bitmap `fff3cfefff800000`. The direct host recorder was
ready before the first socket, captured 3,284 packets with zero kernel drops
and stopped inactive with MainPID 0. Seven TCP lifetimes pair by SYN across
host and guest views. Client-to-server streams exactly match the Recorder;
server-to-client streams have the Recorder bytes as their prefixes. All seven
unread application tails are empty. The full host and guest scoped-flow PCAPs
retain terminal packets.

The committed corpus holds exact plans/reports, stage gates, A7 readbacks,
source hashes, as-run script, packet reconciliation and lifecycle receipts.
Full cumulative guest PCAPs remain ignored; their lengths, hashes and verified
prefix relation are recorded. Portable replay checks all seven complete scoped
flows without a VM or project. Supplying the optional ignored raw session
rechecks cumulative snapshot hashes and prefix order. From adjacent repository
exports:

```sh
python3 evidence/gap-remediation/2026-11-14/native-121-defaults-01/verify_packets.py
python3 -m unittest discover -s \
  evidence/gap-remediation/2026-11-14/native-121-defaults-01 \
  -p test_verify_packets.py
```

This witness covers two delayed 121 defaults only. It does not establish
re-login or restart persistence, filesystem durability, or general non-ASCII
encoding. Combined review with the 304 and PM corpora accepts GAP-030; the
[acceptance decision](../../evidence/gap-remediation/2026-11-14/settings-default-acceptance-01/decision.json)
records its unchanged criterion and limits. The
[later persistence witness](native-settings-persistence-witness.md) and
shared-helper trace address GAP-029 with explicit evidence limits. General
supplied-text encoding remains GAP-018.
