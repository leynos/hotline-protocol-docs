# Classic Login107 proxy rehearsal and zero-contact attempts

The [portable corpus][corpus] separates one successful **synthetic** proxy
rehearsal from two real Classic UI attempts that never opened a connection.
Neither B30 nor B31 tested acceptance of a field-161 variant, or even a
Classic-to-native baseline through the proxy.

## B29: synthetic serve path

A direct system service ran as UID/GID 1000 with `PrivateNetwork=yes` and a
60-second service cap. Its namespace inode `4026532547` differed from the host
`4026531840` and live isolated client `4026532479`; it had only `lo` and empty
IPv4/IPv6 main routes. The runner bound **fake** `127.0.0.1:15500/15501`
upstreams inside that namespace. The proxy's fixed `15652/15653` listeners
relayed the exact Classic greeting, successful synthetic Login107 direct ACK
with field 161 `0000`, following 109 frame, and `PING`/`PONG` data bytes. After
client control `SHUT_WR`, the fake server kept its write side open. The
independent watchdog fired and full relay teardown completed `28.097680969`
seconds after ACK send completion, within the 30-second bound. The proxy
reported `intentional-observation-cutoff`, exited zero, and its PID was absent;
the owned unit was then stopped. The raw/forwarded ACK hashes match. These are
synthetic loopback observations, not native-server or Classic peer behaviour.

## B30/B31: no connection

B30 started the proxy before preparing the Classic Connect dialog. Its
180-second system service limit expired while the address was corrected. There
was no Connect click. B31 staged the exact `10.0.2.2:15652` address, `admin`,
and masked fixture password before proxy start. One Connect click left the
dialog visible and produced no SYN. No second click was made. Both host and
isolated-namespace PCAPs from each attempt are exactly 24-byte headers. The
recorder terminal counts are retained as labelled operator transcriptions. The
Classic app was quit after each attempt; the original server and both guests
remained live. Each exact 29-action A7 postflight completed, with 41 root Files
and a full 1,049,073-byte FILP download matching the prior baseline. Large
guest and A7 raw files remain ignored in the canonical runtime; their local
hashes are metadata in `manifest.json`, not portable full-raw proof.

The B31 saved helper used XTest Button 1 down/up at `(626, 484)`, with 80 ms
flush delays and no explicit modifier calls; ambient modifier state was not
measured. The earlier successful A24 helper on the same display used 150 ms
before press and 120 ms down/up delays. That is an observed input timing
difference, not an established cause of B31's nonactivation. The B21 capture
proves a successful Connect at its recorded time, but no exact as-run button
event log was retained for a byte-level input comparison. No new UI trial is
authorized by this record.

## Offline check

From the mothra root in a fresh paired export:

```sh
sha256sum --quiet -c evidence/gap-remediation/2026-11-13/classic-proxy-rehearsal-01/SHA256SUMS
python3 scripts/verify_classic_proxy_rehearsal.py \
  evidence/gap-remediation/2026-11-13/classic-proxy-rehearsal-01
python3 -m unittest discover -s scripts -p 'test_classic_proxy_rehearsal.py'
```

The verifier checks retained hashes, frame order and unchanged bytes, ACK field
161, data exchange, namespace and process receipts, timing, and the four
header-only PCAPs. Fault controls reject a native-evidence claim, a late
teardown, reversed greetings, and a false PID-gone receipt. It verifies
retained statements and bytes; it cannot establish live process state or
Classic tolerance from synthetic data.

[corpus]: ../../evidence/gap-remediation/2026-11-13/classic-proxy-rehearsal-01/
