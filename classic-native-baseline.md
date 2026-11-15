# Classic client to native Hotline 1.9 baseline through the fixed proxy

The [portable B46/B47 corpus][corpus] records two controlled local attempts on
14 November 2026. Both used the identified Classic PowerPC client and native
Hotline Server 1.9 guest. The proxy's `baseline` variant passed the successful
Login107 ACK byte-for-byte; field 161 remained `0000`. No altered 161 or 162
variant ran. The client distribution filename and app label say **1.9.2**,
while embedded `vers` resources say **1.9.1.0**. The client DATA and RSRC
SHA-256 values are pinned in `manifest.json` and the
[static acquisition record][candidate]. Neither label establishes vendor
authenticity or a universal client release profile.

## Provenance and finite result

| Observation              | B46                          | B47                                       |
| ------------------------ | ---------------------------- | ----------------------------------------- |
| Action                   | Return                       | Return, then Agree                        |
| Proxy stop               | ACK + 28.097 s               | ACK + 28.132 s                            |
| Control wire             | 61 client / 310 server bytes | 150 client / 514 server bytes             |
| Client numbered requests | 107 only                     | 107, 121, 300, 212                        |
| Data attachment          | None                         | 16-byte `HTXF`, 58-byte `GIF89a` response |
| UI                       | Agreement open at cutoff     | One online user: `unnamed`                |

B46's attempted Agree click followed the cutoff. A connection-closed alert
blocked it, so B46 has no 121 and cannot measure agreement acceptance. B47
clicked Agree promptly on the same stock dialog. The native reply to Login107
contained fields 160 `00be` and 161 `0000`. Notification 109 carried the exact
controlled 242-byte agreement (SHA-256
`5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7`). The client
sent 121 with display name `unnamed`; native returned an ACK, 354 bitmap, 122
URL, a 300 roster reply, and a 212 ACK. The 212 reference `003f7729` matched
the later `HTXF` data header. The 122 URL used the controlled `example.invalid`
fixture. The 58-byte response reached the client, but its UI still said
**Loading banner image**; image decoding or display completion is unproved.

The verifier selects one SYN lifetime for each pinned route and requires
complete, identical byte streams at five views: client guest, proxy namespace
ingress, proxy namespace upstream, host loopback, and server guest. B46's
control streams are 61/310 bytes. B47's control and data streams are 150/514
and 16/58 bytes. Full guest PCAP snapshots include their prior prefix and
untrimmed later packets. B47 host and namespace recorders remained active
through the exact A7 postflight. B46's postflight has its full protocol-capture
report; its recorders had already stopped. Proxy `report.json` entries are
checked against reassembled wire bytes; raw and forwarded fields match. The
cutoff was a proxy action and is **not** a native or client rejection. Its
receipt proves relay teardown by ACK plus 30 seconds for each attempt. The
runtime used a separate client namespace with only `lo`, fixed 15652/15653
listeners and 15500/15501 upstreams.

Both attempts passed the exact 29-action native A7 preflight and postflight:
two accounts, 41 Files entries, the same 1,049,073-byte full FILP stream, DATA
fork SHA-256
`fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83`, and MACR
fork SHA-256
`40a42dbcf2d879e22d9a5a9acf46bf15fa9fe3a77837f757a990e514436801e5`. The
retained B42/B43/B45 receipts document earlier **zero-contact** staging; they
supply no field-tolerance observations. The original B13 public HTTP safety
stop and B21 isolated direct session remain separate evidence.

## Offline replay

From adjacent `mothra` and `hotline-protocol-docs` checkouts:

```sh
cd ../mothra
sha256sum --quiet -c evidence/gap-remediation/2026-11-14/classic-proxy-baseline-01/SHA256SUMS
python3 ../hotline-protocol-docs/scripts/verify_classic_native_baseline.py \
  evidence/gap-remediation/2026-11-14/classic-proxy-baseline-01
python3 -m unittest discover -s ../hotline-protocol-docs/scripts \
  -p 'test_classic_native_baseline.py'
```

Ten tests include incorrect reply type/ID, changed 161 and agreement,
fabricated B46 activation, a mismatched capture view, missing SYN, late
teardown, a false rejection label, and changed banner bytes. `as-run.txt`,
`manifest.json`, raw PCAPs, frozen as-run proxy and parser sources at revision
`79d867d`, screenshots, A7 reports, and root-relative `SHA256SUMS` make this
finite result portable. The verifier checks those historical source snapshots
even after later proxy edits. The app was quit and owned
proxy/listeners/sockets were gone after each attempt; the native and client
emulator processes and fixed bridges remained live. This is evidence for one
baseline path, not full peer interoperability, optional-field tolerance,
universal banner behaviour, or a scheduling rule.

[corpus]: ../mothra/evidence/gap-remediation/2026-11-14/classic-proxy-baseline-01/
[candidate]: ../mothra/docs/delegation/mac-peer-candidate.md
