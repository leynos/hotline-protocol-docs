# A113: closed 18-action preflight flow only

Read-only one-pass snapshot at the root READY notification; no VM, service,
signal, protocol request, oracle, mxd or tracked-file change. Source is
`state/native-sessions/native-rate304-epoch-03/` with actual emulator
PID 3125063 and fixed deadline 2026-11-14T11:50:21.652926Z. The copied
report and three PCAPs are under this ignored directory. This is a snapshot
while the later rate case may be active, not a terminal capture of that case.

Method: frozen `sources/pcap_tcp.py` read the snapshot PCAPs. The report's
`main` connect at local 127.0.0.1:36960 to namespace 127.0.0.1:15880,
with `started_at_utc` plus connect elapsed time, selected one unique SYN
lifetime in the namespace and guest captures. Guest mapping was
10.0.2.2:36960 to 10.0.2.15:5500. Both lifetimes closed with FIN/ACK
and have no RST payload. Namespace had 30 TCP packets; guest had 31
(one guest FIN retransmission). Packet counts need not equal for byte parity.

| Direction | Recorder bytes | Namespace stream | Guest stream | Tails |
| --- | ---: | ---: | ---: | ---: |
| Client to server | 231 | 231 | 231 | 0 / 0 |
| Server to client | 2,759 | 2,759 | 2,759 | 0 / 0 |

The recorder concatenates only the completed `main` send/receive events.
Both namespace streams equal their guest streams and the corresponding
recorder bytes exactly. Their SHA-256 values are respectively
`5eecc6b4d737fcadbb8356aa0839119da65a3d2e77dca799bc23d39e6f4487b2`
and `7f5cad68aaca975d221a5216ac98a6d4241c3557a543afb83e66799a1da23dc2`.
No raw credentials are reproduced in this note.

`primary-syn.pcap` is 24 bytes with zero TCP packets in this snapshot;
its SHA-256 is
`704e5e5b3234433c01fcfd1b20a306e77e985038120492dc53965c3edd38a4ea`.
The copied namespace and guest PCAP SHA-256 values are
`592d1a0192706e6ae4baa337289a4adfcd13418afa23ea5dcb2ec28e7b680c5b`
and `a3f675e2df73f8fcb44e59ceb6d637d964c65ff9959cc8b57ad77025f69e8d62`.
The report SHA-256 is
`9c82a554d1c2a78df33874a2581b5d40d438551ccbecaff74f9778422b107cf9`;
the plan SHA-256 is
`1de1ba838538a2764ed0bc59520e3d6920588140ecbd036ea78833674ca73e1f`.
Machine-readable counts and hashes are in `audit.json`.

This proves paired byte completeness for **only** the closed preflight
TCP lifetime. It does not prove later rate-case semantics, capture drops,
whole-lab egress, terminal cleanup or storage durability.
