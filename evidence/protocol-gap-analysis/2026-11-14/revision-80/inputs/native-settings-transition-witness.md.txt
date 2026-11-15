# Native 1.9 same-session 304 transition witness (A33)

The [portable A33 corpus](../mothra/evidence/gap-remediation/2026-11-13/native-settings-transitions-01/manifest.json)
records one eight-stage transaction 304 sequence between exact full A7
preflight and postflight readbacks. The pinned server binary has SHA-256
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`.
This is measured behaviour of that server and these inputs. It does not close
the unchanged GAP-029/030 criteria by itself.

The subject used the existing admin account. Its 354 bitmap was
`fff3cfefff800000`, with naming privilege bit 26 set under the documented
MSB-first numbering. The `***` results below are from that naming-allowed
branch; an account-name fallback is a different branch.

The subject's UID `0032` came from its announcement on the current observer
connection. The observer's own UID was established from the same-session 300
roster. Every stage read 301 on both sockets, checked the 108 success ACK,
observed the original PM and expected automatic feedback, then used 500
ACK/quiet barriers. The live runner checked identity before any 304 and each
301 before sending that stage's PM. All 129 observation actions completed.

| Stage | 304 inputs | Measured 301 name/icon; PM feedback |
| --- | --- | --- |
| Explicit | 102=`A32-Explicit`, 104=7, 113=4, 215=`a32-explicit` | Same name/icon; option-4 104 text `a32-explicit` |
| Omitted | 102/104/215 absent, 113=4 | `***`/0; exact default option-4 text |
| Empty | 102/104/215 empty, 113=4 | `***`/0; exact default option-4 text |
| Unknown only | 102=`A32-Unknown`, 104=9, 113=8 | Same name/icon; no auto 104 |
| Mixed unknown | 102=`A32-Mixed`, 104=10, 113=12 | Same name/icon; default option-4 text |
| Disable absent | 102=`A32-Off-A`, 104=11, 113 absent | Same name/icon; no auto 104 |
| Disable zero | 102=`A32-Off-Z`, 104=12, 113=0 | Same name/icon; no auto 104 |
| Re-enable | 102=`A32-Reenable`, 104=13, 113=4, 215 absent | Same name/icon; default option-4 text |

In every stage the original option-1 PM reached the subject. The default
field-101 bytes were exactly ASCII
`I'm not able to respond right now. Please try later!`. The absent and
zero-length 215 controls both selected those bytes. The unknown-only `8`
and mixed `12` controls match the three-bit extraction in frozen helper
`10004d50`; they do not prove behaviour of every higher bit or field width.
301 exposed name/icon/UID, while the PM feedback or its absence provided
behavioural evidence for automatic-response state. Transaction-108/104
option values remain enumerants, distinct from 304's 113 bitmap.

The A7 preflight and postflight each completed 29 actions and a 1,049,073-byte
FILP stream. Both showed two accounts, 41 Files entries, matching fixture
metadata, and unchanged DATA and MACR fork hashes. The subject's settings
were restored and both owned sessions closed before postflight. The host
recorder was ready before the first socket, captured 3,353 packets with zero
kernel drops, and stopped inactive with MainPID 0. All six TCP lifetimes
pair by SYN and connection port across host and guest packet views: every
client-to-server stream exactly matches the Recorder, and every
server-to-client stream has the Recorder bytes as its prefix. The sole
unread application tail is the same 28-byte type-302 departure for UID
`0032` on the observer stream in both views. It is outside the Recorder's
read boundary, not another PM. The other five tails are empty.

The committed corpus contains the complete six-lifetime host and guest
PCAPs, all plans/reports, stage gates, full A7 readbacks, source hashes,
operator script, capture receipts and packet reconciliation. Original
cumulative guest PCAPs remain ignored; their hashes, lengths and verified
prefix relation are recorded. Portable replay checks the complete scoped
streams, but can only recheck cumulative snapshot prefix identity with the
optional ignored raw session supplied. Run from adjacent `mothra` and
`hotline-protocol-docs` exports:

```sh
python3 evidence/gap-remediation/2026-11-13/native-settings-transitions-01/verify_packets.py
python3 -m unittest discover -s \
  evidence/gap-remediation/2026-11-13/native-settings-transitions-01 \
  -p test_verify_packets.py
```

The observed 304 sequence does not test agreement transaction 121,
re-login, process restart, account-file durability or general non-ASCII
text encoding. The [delayed-121 witness](native-121-default-witness.md)
adds the separate default-text cases. Combined acceptance closes GAP-030;
the [later persistence witness](native-settings-persistence-witness.md)
addresses GAP-029's separate clause. General encoding remains GAP-018.
