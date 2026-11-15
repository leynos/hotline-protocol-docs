# Classic client: first roster reply with field 115

This is one controlled observation of the identified Classic Hotline client
against Hotline Server 1.9. The archive labels the client “1.9.2 Classic”; its
retained `vers` short string is `1.9.1.0`. Its DATA and resource-fork SHA-256
values are pinned in the
[portable manifest](evidence/gap-remediation/2026-11-14/classic-roster-subject-115-01/manifest.json).
Vendor authenticity has not been established.

## B62 session, 14 November 2026

The client connected once to the isolated proxy at `10.0.2.2:15652`. The proxy
forwarded to the fixed native server bridge at `127.0.0.1:15500`; its data
listener forwarded to `15501`. Before contact, an exact 29-action A7 readback
confirmed two accounts, 41 Files entries, both forks of the 1,049,073-byte FILP
fixture, and the known 242-byte agreement. The same A7 readback passed after
the client quit. The controlled native account and fixture were unchanged.

The client sent control requests 107, 121, 300, and 212, IDs 1–4. The native
Login107 ACK was exactly 34 bytes, with field 160=`00be` and field 161=`0000`;
it reached the client unchanged. The first successful direct roster ACK for the
client's observed 300 ID 3 was the only transformed frame. Its 41 raw bytes
became 60 forwarded bytes: the proxy retained the entire original header
semantics, the packed 300 record including its actual UID, and all existing
fields, while updating sizes/count and appending outer field 115 with 15 ASCII
bytes `fixture-subject`. The byte hashes, full frame reconstruction, and exact
fields are checked by the
[offline verifier](scripts/verify_classic_roster_subject_115.py). The
subsequent replies and all client requests were byte-identical across the five
SYN-scoped capture views. The automatic data connection carried a 16-byte HTXF
request and 58-byte GIF response with the matching reference.

The
[connected screenshot](evidence/gap-remediation/2026-11-14/classic-roster-subject-115-01/run/after-agree-1s.png)
shows `unnamed` in Online Users while the client remained connected. The
transformed packet reached the client guest at 04:18:25.744557 UTC; the
screenshot source file mtime was 04:18:26.672474 UTC, about 0.928 seconds
later. The screenshot itself has no trusted embedded timestamp. The retained
as-run receipt binds the packet timestamp, host file metadata, and image hash;
it supports a finite after-delivery display observation. The client sent 212
before roster delivery, so 212 alone would not establish roster processing. The
image does not show field 115 rendered as a subject or topic.

The independent 28-second watchdog closed the connection. Its measured Login
ACK-to-relay teardown was 28.129110855 seconds, within the 30-second validity
bound. The resulting “Connection Closed” alert reflects this intentional
cutoff, not a native or client rejection. The banner task still read Loading;
GIF bytes on the wire do not prove the UI rendered them.

## Provenance and replay

The
[corpus](evidence/gap-remediation/2026-11-14/classic-roster-subject-115-01/manifest.json)
retains four selected PCAPs containing complete SYN lifetimes and tails for
five control and five data views, the full A7 reports, proxy audit,
screenshots, managed capture receipts/journals, and SHA inventory. The as-run
proxy source and packet parser are frozen as text snapshots. The original
cumulative PCAPs remain ignored under
`mothra/state/native-sessions/native-proxy-roster-115-01/`; the manifest
records their hashes and selected record indexes.

Run from `hotline-protocol-docs` with the adjacent `mothra` checkout:

```sh
python3 scripts/verify_classic_roster_subject_115.py evidence/gap-remediation/2026-11-14/classic-roster-subject-115-01
python3 -m unittest discover -s scripts -p test_classic_roster_subject_115.py
```

The managed oracle lease unit ran from 04:13:37 to 04:19:31 UTC. Its retained
journal proves its service lifecycle; the before-process FD and independent
busy/free flock observations are explicitly labelled operator transcripts in
`lock-receipt.json`, because their raw tool output was not saved as a file. The
capture journals report zero kernel drops and all four owned services had
inactive/zero-PID terminal properties. This trial is a bounded acceptance
witness for this one ASCII field-115 value and the observed roster display. It
does not establish field semantics, arbitrary 115 values, a client refresh
policy, or full client/server interoperability.
