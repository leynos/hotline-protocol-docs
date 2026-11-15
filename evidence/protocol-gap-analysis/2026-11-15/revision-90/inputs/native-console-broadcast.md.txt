# Native console broadcast and client 355: bounded D1 witness

This is one controlled Hotline Server 1.9 guest session, not a general
client/server compatibility rule. The [D1 corpus][corpus] retains the plan,
50-action capture report, host PCAP, before/after guest PCAP snapshots, one
operator console-send transcript and two selected screenshots. Four local
connections were open: online `ConsoleSender`, online `ConsoleRefuse` (Login107
options 113=`0003`), a Login107 `ConsoleWaiting` connection still awaiting 121,
and a handshake-only unauthenticated connection. One 20-second pause bounded
one console UI send of `D1-console-message`. The input-event log was not saved:
operator action order is a transcription, and screenshots and packet order
bound it; they do not supply an exact click time.

| Origin and point                        | `ConsoleSender`                        | `ConsoleRefuse`                                    | `ConsoleWaiting`                                   | Unauthenticated |
| --------------------------------------- | -------------------------------------- | -------------------------------------------------- | -------------------------------------------------- | --------------- |
| Client 355 id 2, `D1-client-before`     | Type 0 ACK; no 355                     | 355 with 103=`000f`, 102=`ConsoleSender`, 101=data | No 355 before 121                                  | No 355          |
| Console UI send                         | 104 with only 101=`D1-console-message` | Same data-only 104                                 | No 104 before 121                                  | No 104          |
| Client 121 id 2 completes waiting login | Online                                 | Online                                             | Type 0 ACK, 354 and 122                            | Handshake only  |
| Client 355 id 3, `D1-client-after`      | Type 0 ACK; no 355                     | Same 355 schema                                    | 355 with 103=`000f`, 102=`ConsoleSender`, 101=data | No 355          |

The `355` examples are **client-originated** requests with one field 101 each;
the console UI emits **104**, not an on-wire 355 in this capture. Console 104
has only field 101 and no observed sender identity. The client 355 fan-out
includes sender UID and name, excludes the sender, and includes the online peer
with refuse option `0003`. The waiting peer receives the later 355 only after
121 activation. These are observed state/field combinations for this one run;
they do not establish a universal recipient rule or finish GAP-044's other 104
variants. A 302 departure frame for UID `0012` followed the recorded reads on
each authenticated socket; the verifier retains all three 28-byte packet tails
and does not silently trim them.

The host loopback recorder started before the capture driver, but its PCAP
begins at the first sender's **server handshake**. It lacks that connection's
SYN and 12-byte client handshake. The guest PCAP contains the full sender flow;
host sender bytes after the missing handshake and all inbound bytes match guest
bytes. The other three connections have complete SYN-scoped host/guest streams.
Do not call the first host view complete. Recorder logs record start/stop, but
there is no retained raw drop-count output.

The independent 29-action postflight completed after all owned connections
closed. Its two account entries, 41 root Files descriptors, fixture 206
metadata, idle 303 and exact 1,049,073-byte FILP response match the earlier A7
full baseline where stable; the new guest PCAP delta matches the postflight
socket streams. Dynamic roster/session bytes are not forced to match old UIDs.
No account, file or server-option mutation was part of D1.

From a fresh adjacent `mothra` and `hotline-protocol-docs` export, run:

```sh
sha256sum --quiet -c evidence/gap-remediation/2026-11-13/native-console-broadcast-01/SHA256SUMS
python3 ../hotline-protocol-docs/scripts/verify_native_console_broadcast.py \
  evidence/gap-remediation/2026-11-13/native-console-broadcast-01
python3 -m unittest discover -s ../hotline-protocol-docs/scripts \
  -p 'test_native_console_broadcast.py'
```

The verifier checks retained capture reports and hashes, decoded frame fields,
complete guest flows, the explicit host-prefix exception, teardown tails and A7
postflight bytes. Four focused tests include checksum-updated guest-byte,
host-SYN and operator-scope forgeries. GAP-076 closure is a separate decision;
GAP-044 remains broader than this console notice.

[corpus]: evidence/gap-remediation/2026-11-13/native-console-broadcast-01/manifest.json
